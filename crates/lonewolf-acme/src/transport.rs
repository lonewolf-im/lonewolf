// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::future::Future;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::{Pin, pin};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use bytes::Bytes;
use futures_channel::oneshot;
use futures_util::future::{Either, poll_fn, select};
use futures_util::task::AtomicWaker;
use http_body_util::BodyExt;
use lonewolf_util::blocking::BlockingExecutor;
use parking_lot::Mutex as PlMutex;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use ureq::RequestExt;
use ureq::unversioned::transport::time::Duration as UreqDuration;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, TcpConnector, Transport,
    TransportAdapter,
};

use crate::resolver::{BoundedResolver, authority};
use crate::types::{AcmeError, AcmeErrorKind};

const GLOBAL_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 1024 * 1024;
const MAX_REQUEST: usize = 64 * 1024;

#[derive(Default)]
pub struct TransportOptions {
    pub ca_certificates_path: Option<PathBuf>,
}

type RetryHint = Arc<PlMutex<Option<SystemTime>>>;

/// Requests require a Compio runtime on their first poll, driven until completion or cancellation.
#[derive(Clone)]
pub struct AcmeHttpClient {
    inner: Arc<Inner>,
    retry: Arc<PlMutex<RetryHint>>,
}

struct Inner {
    agent: ureq::Agent,
    executor: BlockingExecutor,
    admission: PlMutex<Admission>,
    request_timeout: Duration,
}

struct Admission {
    accepting: bool,
    active: usize,
    waiters: Vec<Weak<AtomicWaker>>,
}

struct Operation(Arc<Inner>);

impl Drop for Operation {
    fn drop(&mut self) {
        let waiters = {
            let mut admission = self.0.admission.lock();
            admission.active -= 1;
            if admission.active != 0 {
                return;
            }
            std::mem::take(&mut admission.waiters)
        };
        for waiter in waiters {
            if let Some(waiter) = waiter.upgrade() {
                waiter.wake();
            }
        }
    }
}

impl AcmeHttpClient {
    pub async fn new(options: TransportOptions) -> Result<Self, AcmeError> {
        let executor = BlockingExecutor::new(const { NonZeroUsize::new(2).unwrap() });
        let roots = executor
            .run(move || load_roots(options.ca_certificates_path))
            .await?;
        let agent = build_agent(roots, GLOBAL_TIMEOUT)?;
        Ok(Self {
            inner: Arc::new(Inner {
                agent,
                executor,
                request_timeout: GLOBAL_TIMEOUT,
                admission: PlMutex::new(Admission {
                    accepting: true,
                    active: 0,
                    waiters: Vec::new(),
                }),
            }),
            retry: Arc::new(PlMutex::new(Arc::new(PlMutex::new(None)))),
        })
    }

    /// Shares request capacity and shutdown state, with an independent retry context.
    pub fn for_attempt(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            retry: Arc::new(PlMutex::new(Arc::new(PlMutex::new(None)))),
        }
    }

    /// Discards hints from completed and outstanding requests in this context.
    pub fn reset_retry_hint(&self) {
        *self.retry.lock() = Arc::new(PlMutex::new(None));
    }
    pub fn retry_not_before(&self) -> Option<SystemTime> {
        *self.retry.lock().lock()
    }

    /// Requires a Compio runtime and permanently closes shared admission, including on cancellation.
    pub async fn drain(&self, deadline: Instant) -> Result<(), AcmeError> {
        let waiter = Arc::new(AtomicWaker::new());
        {
            let mut admission = self.inner.admission.lock();
            admission.accepting = false;
            if admission.active == 0 {
                return Ok(());
            }
            admission
                .waiters
                .retain(|waiter| waiter.strong_count() != 0);
            admission.waiters.push(Arc::downgrade(&waiter));
        }
        if Instant::now() >= deadline {
            return Err(AcmeError::new(AcmeErrorKind::Timeout));
        }
        let complete = poll_fn(|context| {
            waiter.register(context.waker());
            if self.inner.admission.lock().active == 0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        });
        match select(pin!(compio::time::sleep_until(deadline)), pin!(complete)).await {
            Either::Left(_) => Err(AcmeError::new(AcmeErrorKind::Timeout)),
            Either::Right(_) => Ok(()),
        }
    }

    fn admit(&self) -> Result<Operation, AcmeError> {
        let mut admission = self.inner.admission.lock();
        if !admission.accepting {
            return Err(AcmeError::new(AcmeErrorKind::Closed));
        }
        if admission.active >= 2 {
            return Err(AcmeError::new(AcmeErrorKind::Unavailable));
        }
        admission.active += 1;
        Ok(Operation(self.inner.clone()))
    }
}

impl instant_acme::HttpClient for AcmeHttpClient {
    fn request(
        &self,
        req: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let client = self.clone();
        Box::pin(async move {
            let deadline = Instant::now()
                .checked_add(client.inner.request_timeout)
                .ok_or_else(|| protocol_error(AcmeError::new(AcmeErrorKind::Timeout)))?;
            let operation = Arc::new(client.admit().map_err(protocol_error)?);
            let (_cancel_timer, timeout) =
                deadline_bridge(deadline, operation.clone()).map_err(protocol_error)?;
            let retry = client.retry.lock().clone();
            let (parts, body) = req.into_parts();
            if authority(&parts.uri).is_err() {
                return Err(protocol_error(AcmeError::new(AcmeErrorKind::InvalidInput)));
            }
            let body = body
                .collect()
                .await
                .map_err(|_| protocol_error(AcmeError::new(AcmeErrorKind::Other)))?
                .to_bytes();
            if body.len() > MAX_REQUEST {
                return Err(protocol_error(AcmeError::new(AcmeErrorKind::InvalidInput)));
            }
            let agent = client.inner.agent.clone();
            let request = http::Request::from_parts(parts, body);
            let work = client.inner.executor.run(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    perform(&agent, request, &retry, deadline)
                }));
                (operation, outcome)
            });
            match select(pin!(timeout), pin!(work)).await {
                Either::Left(_) => Err(protocol_error(AcmeError::new(AcmeErrorKind::Timeout))),
                Either::Right(((_operation, outcome), _)) => match outcome {
                    Ok(result) => result.map_err(protocol_error),
                    Err(panic) => std::panic::resume_unwind(panic),
                },
            }
        })
    }
}

fn deadline_bridge(
    deadline: Instant,
    operation: Arc<Operation>,
) -> Result<(oneshot::Sender<()>, oneshot::Receiver<()>), AcmeError> {
    let (cancel, cancelled) = oneshot::channel();
    let (expired, timeout) = oneshot::channel();
    compio::runtime::Runtime::try_with_current(|runtime| {
        runtime
            .spawn(async move {
                let elapsed = {
                    let sleep = pin!(compio::time::sleep_until(deadline));
                    let cancelled = pin!(cancelled);
                    matches!(select(sleep, cancelled).await, Either::Left(_))
                };
                if elapsed {
                    let _ = expired.send(());
                }
                drop(operation);
            })
            .detach();
    })
    .map_err(|_| AcmeError::new(AcmeErrorKind::Unavailable))?;
    Ok((cancel, timeout))
}

fn build_agent(roots: RootCertStore, timeout: Duration) -> Result<ureq::Agent, AcmeError> {
    let tls = ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| AcmeError::new(AcmeErrorKind::Crypto))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .timeout_resolve(Some(CONNECT_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .max_response_header_size(32 * 1024)
        .max_idle_connections(0)
        .build();
    let connector = TcpConnector::default().chain(AcmeTlsConnector {
        config: Arc::new(tls),
    });
    Ok(ureq::Agent::with_parts(config, connector, BoundedResolver))
}

fn protocol_error(error: AcmeError) -> instant_acme::Error {
    instant_acme::Error::Other(Box::new(error))
}

fn perform(
    agent: &ureq::Agent,
    request: http::Request<Bytes>,
    retry: &PlMutex<Option<SystemTime>>,
    deadline: Instant,
) -> Result<instant_acme::BytesResponse, AcmeError> {
    let (parts, body) = request.into_parts();
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(AcmeError::new(AcmeErrorKind::Timeout));
    }
    let mut response = http::Request::from_parts(parts, body.as_ref())
        .with_agent(agent)
        .configure()
        .timeout_global(Some(remaining))
        .run()
        .map_err(map_error)?;
    let status = response.status().as_u16();
    capture_retry(response.headers(), retry, SystemTime::now());
    if response.status().is_redirection()
        || response
            .headers()
            .contains_key(http::header::CONTENT_ENCODING)
    {
        return Err(AcmeError::with_status(AcmeErrorKind::InvalidInput, status));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY as u64)
        .read_to_vec()
        .map_err(|error| AcmeError::with_status(map_error(error).kind(), status))?;
    let (parts, _) = response.into_parts();
    Ok(instant_acme::BytesResponse::from(
        http::Response::from_parts(parts, http_body_util::Full::new(Bytes::from(body))),
    ))
}

fn map_error(error: ureq::Error) -> AcmeError {
    let kind = match error {
        ureq::Error::Timeout(_) => AcmeErrorKind::Timeout,
        ureq::Error::Io(ref error) if error.kind() == io::ErrorKind::TimedOut => {
            AcmeErrorKind::Timeout
        }
        ureq::Error::Io(ref error) if error.kind() == io::ErrorKind::WouldBlock => {
            AcmeErrorKind::Unavailable
        }
        ureq::Error::HostNotFound => AcmeErrorKind::Unavailable,
        _ => AcmeErrorKind::Other,
    };
    AcmeError::new(kind)
}

fn capture_retry(headers: &http::HeaderMap, retry: &PlMutex<Option<SystemTime>>, now: SystemTime) {
    for value in headers.get_all(http::header::RETRY_AFTER) {
        let Some(deadline) = value
            .to_str()
            .ok()
            .and_then(|value| retry_deadline(value, now))
        else {
            continue;
        };
        let mut hint = retry.lock();
        *hint = Some(hint.map_or(deadline, |previous| previous.max(deadline)));
    }
}

fn retry_deadline(value: &str, now: SystemTime) -> Option<SystemTime> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        now.checked_add(Duration::from_secs(value.parse::<u64>().ok()?))
    } else {
        httpdate::parse_http_date(value).ok()
    }
}

fn load_roots(path: Option<PathBuf>) -> Result<RootCertStore, AcmeError> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = path {
        let file = std::fs::File::open(path)
            .map_err(|_| AcmeError::new(AcmeErrorKind::InvalidCaBundle))?;
        let mut pem = Vec::new();
        file.take(MAX_BODY as u64 + 1)
            .read_to_end(&mut pem)
            .map_err(|_| AcmeError::new(AcmeErrorKind::InvalidCaBundle))?;
        if pem.len() > MAX_BODY {
            return Err(AcmeError::new(AcmeErrorKind::InvalidCaBundle));
        }
        add_roots(&mut roots, &pem)?;
    }
    Ok(roots)
}

fn add_roots(roots: &mut RootCertStore, pem: &[u8]) -> Result<(), AcmeError> {
    let invalid = || AcmeError::new(AcmeErrorKind::InvalidCaBundle);
    let mut text = std::str::from_utf8(pem).map_err(|_| invalid())?.trim();
    let mut count = 0;
    while !text.is_empty() {
        text = text
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .ok_or_else(invalid)?;
        let (encoded, remainder) = text
            .split_once("-----END CERTIFICATE-----")
            .ok_or_else(invalid)?;
        let encoded: String = encoded
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid())?;
        roots
            .add(CertificateDer::from(der))
            .map_err(|_| invalid())?;
        count += 1;
        text = remainder.trim();
    }
    if count == 0 {
        return Err(invalid());
    }
    Ok(())
}

struct AcmeTlsConnector {
    config: Arc<ClientConfig>,
}

impl fmt::Debug for AcmeTlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcmeTlsConnector")
    }
}

impl<In: Transport> Connector<In> for AcmeTlsConnector {
    type Out = AcmeTlsTransport;
    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let (hostname, _) = authority(details.uri)?;
        let transport = chained.ok_or(ureq::Error::ConnectionFailed)?;
        if transport.is_tls() {
            return Err(ureq::Error::ConnectionFailed);
        }
        let name = ServerName::try_from(hostname.to_owned())
            .map_err(|_| ureq::Error::Tls("invalid hostname"))?;
        let mut connection = ClientConnection::new(self.config.clone(), name)?;
        let start = match details.now {
            ureq::unversioned::transport::time::Instant::Exact(start) => start,
            _ => Instant::now(),
        };
        let deadline = start
            .checked_add(*details.timeout.after)
            .ok_or(ureq::Error::Timeout(details.timeout.reason))?;
        let budget = Arc::new(PlMutex::new(Budget {
            deadline,
            reason: details.timeout.reason,
        }));
        let transport = DeadlineTransport {
            inner: transport.boxed(),
            budget: budget.clone(),
        };
        let mut socket = TransportAdapter::new(transport);
        socket.set_timeout(details.timeout);
        connection.complete_io(&mut socket)?;
        Ok(Some(AcmeTlsTransport {
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: StreamOwned::new(connection, socket),
            budget,
        }))
    }
}

struct DeadlineTransport {
    inner: Box<dyn Transport>,
    budget: Arc<PlMutex<Budget>>,
}

struct Budget {
    deadline: Instant,
    reason: ureq::Timeout,
}

impl fmt::Debug for DeadlineTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcmeDeadlineTransport")
    }
}

impl DeadlineTransport {
    fn remaining(&self, timeout: NextTimeout) -> Result<NextTimeout, ureq::Error> {
        let budget = self.budget.lock();
        let remaining = budget.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ureq::Error::Timeout(budget.reason));
        }
        Ok(NextTimeout {
            after: UreqDuration::Exact(remaining.min(*timeout.after)),
            reason: budget.reason,
        })
    }
}

impl Transport for DeadlineTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.inner.transmit_output(amount, self.remaining(timeout)?)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.inner.await_input(self.remaining(timeout)?)
    }
    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }
}

struct AcmeTlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter<DeadlineTransport>>,
    budget: Arc<PlMutex<Budget>>,
}

impl fmt::Debug for AcmeTlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcmeTlsTransport")
    }
}

impl AcmeTlsTransport {
    fn set_timeout(&mut self, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let transport = &mut self.stream.sock;
        let deadline = Instant::now()
            .checked_add(*timeout.after)
            .ok_or(ureq::Error::Timeout(timeout.reason))?;
        *self.budget.lock() = Budget {
            deadline,
            reason: timeout.reason,
        };
        transport.set_timeout(timeout);
        Ok(())
    }
}

impl Transport for AcmeTlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.set_timeout(timeout)?;
        self.stream.write_all(&self.buffers.output()[..amount])?;
        Ok(())
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.set_timeout(timeout)?;
        let amount = self.stream.read(self.buffers.input_append_buf())?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }
    fn is_open(&mut self) -> bool {
        self.stream.sock.get_mut().is_open()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
