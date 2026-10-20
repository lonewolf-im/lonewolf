// SPDX-License-Identifier: Apache-2.0

use std::{
    future::{Future, poll_fn},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use crate::cpu::CpuPool;
use futures_rustls::TlsConnector;
use rustls::{
    ClientConfig, RootCertStore,
    client::Resumption,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use zeroize::Zeroizing;

use super::{
    BenchResult, ConnectFailureKind, ConnectObservation, ConnectStage, ConnectTimings, EventSink,
    KeyMode, MessageRoute, NegotiatedTls, PreparedAccount, ReceiveRoute, ReceivedEvent,
    ReceivedKind, ResolvedTarget, SessionIdentity, StageFailure, WriteCommand, WriterEvent,
    failure, micros, scram::Exchange, xml,
};

pub type TlsTransport = Compat<futures_rustls::client::TlsStream<Compat<TcpStream>>>;
pub type SessionWriter = Writer<WriteHalf<TlsTransport>>;

pub fn remote_tls_config(extra_pem: Option<&[u8]>) -> BenchResult<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_pem {
        let mut count = 0;
        for certificate in CertificateDer::pem_slice_iter(pem) {
            roots
                .add(certificate.map_err(|_| failure("tls_roots"))?)
                .map_err(|_| failure("tls_roots"))?;
            count += 1;
        }
        if count == 0 {
            return Err(failure("tls_roots"));
        }
    }
    tls_config(roots)
}

pub fn local_tls_config(certificate: CertificateDer<'static>) -> BenchResult<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate).map_err(|_| failure("tls_roots"))?;
    tls_config(roots)
}

fn tls_config(roots: RootCertStore) -> BenchResult<Arc<ClientConfig>> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| failure("tls_config"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

impl ConnectObservation {
    fn timings(&self) -> ConnectTimings {
        let (Some(t0), Some(t1), Some(t2), Some(t3), Some(t4)) = (
            self.connect_started_at,
            self.tcp_connected_at,
            self.tls_ready_at,
            self.authenticated_at,
            self.bound_at,
        ) else {
            unreachable!("successful login has every protocol boundary");
        };
        ConnectTimings {
            tcp_us: micros(t1.duration_since(t0)),
            starttls_us: micros(t2.duration_since(t1)),
            authenticate_us: micros(t3.duration_since(t2)),
            bind_us: micros(t4.duration_since(t3)),
            total_us: micros(t4.duration_since(t0)),
        }
    }
}

pub struct ClientSession {
    reader: xml::Parser<ReadHalf<TlsTransport>>,
    writer: SessionWriter,
    identity: SessionIdentity,
    route: Option<ReceiveRoute>,
}

impl ClientSession {
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }

    pub fn set_receive_route(&mut self, route: ReceiveRoute) -> BenchResult<()> {
        let from = xml::canonical_jid(&route.from)?;
        if !from.contains('/') || route.body_bytes > 262_000 {
            return Err(failure("route_invalid"));
        }
        self.route = Some(ReceiveRoute { from, ..route });
        Ok(())
    }

    pub(crate) fn configure_messages(&mut self, setup: &MessageSetup) -> BenchResult<()> {
        self.writer.configure_prepared_messages(setup)
    }

    pub fn into_parts(self) -> (SessionReader, SessionWriter, SessionIdentity) {
        let reader = SessionReader::start(
            self.reader,
            self.identity.bound_jid.clone(),
            self.route,
            self.writer.retirement.clone(),
            const { NonZeroUsize::new(256).unwrap() },
        );
        (reader, self.writer, self.identity)
    }
}

/// A deadline or cancellation drops the transport and can consume the account's priming password.
pub async fn connect(
    target: &ResolvedTarget,
    account: &mut PreparedAccount,
    resource: &str,
    key_mode: KeyMode,
    deadline: Instant,
    cpu: &CpuPool,
) -> BenchResult<(ClientSession, ConnectTimings)> {
    connect_observed(
        target,
        account,
        resource,
        key_mode,
        deadline,
        cpu,
        &mut ConnectObservation::default(),
    )
    .await
    .map_err(|failure| failure.error)
}

pub(crate) async fn connect_observed(
    target: &ResolvedTarget,
    account: &mut PreparedAccount,
    resource: &str,
    key_mode: KeyMode,
    deadline: Instant,
    cpu: &CpuPool,
    observation: &mut ConnectObservation,
) -> Result<(ClientSession, ConnectTimings), StageFailure> {
    let mut attempt = ConnectAttempt {
        observation,
        deadline,
        expired: false,
    };
    let result = before_deadline(
        deadline,
        connect_inner(target, account, resource, key_mode, cpu, &mut attempt),
    )
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            let (kind, error) = match other {
                Ok(Err(error)) => (
                    if attempt.expired {
                        ConnectFailureKind::Deadline
                    } else {
                        ConnectFailureKind::Error
                    },
                    error,
                ),
                Err(()) => (ConnectFailureKind::Deadline, failure("connect_deadline")),
                Ok(Ok(_)) => unreachable!(),
            };
            Err(attempt.observation.failure(kind, error))
        }
    }
}

async fn before_deadline<T>(deadline: Instant, work: impl Future<Output = T>) -> Result<T, ()> {
    let mut work = std::pin::pin!(work);
    let mut timer = std::pin::pin!(sleep_until(deadline));
    poll_fn(|cx| {
        if Instant::now() >= deadline {
            return Poll::Ready(Err(()));
        }
        if let Poll::Ready(value) = work.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        if timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(()))
        } else {
            Poll::Pending
        }
    })
    .await
}

struct ConnectAttempt<'a> {
    observation: &'a mut ConnectObservation,
    deadline: Instant,
    expired: bool,
}

impl ConnectObservation {
    fn failure(&self, kind: ConnectFailureKind, error: crate::error::BenchError) -> StageFailure {
        StageFailure {
            stage: self.stage,
            kind,
            at: Instant::now(),
            error,
        }
    }
}

async fn connect_inner(
    target: &ResolvedTarget,
    account: &mut PreparedAccount,
    resource: &str,
    key_mode: KeyMode,
    cpu: &CpuPool,
    attempt: &mut ConnectAttempt<'_>,
) -> BenchResult<(ClientSession, ConnectTimings)> {
    let observation = &mut attempt.observation;
    let server_name =
        ServerName::try_from(target.xmpp_domain.clone()).map_err(|_| failure("tls_identity"))?;
    if !matches!(server_name, ServerName::DnsName(_)) {
        return Err(failure("tls_identity"));
    }
    let expected = xml::canonical_jid(&format!("{}/{resource}", account.bare_jid()))?;
    if expected
        .split_once('/')
        .map(|p| p.0.rsplit_once('@').map(|p| p.1))
        != Some(Some(target.xmpp_domain.as_str()))
    {
        return Err(failure("account_domain"));
    }
    let mut connecting = std::pin::pin!(TcpStream::connect(target.address));
    let stream = poll_fn(|cx| {
        if Instant::now() >= attempt.deadline {
            attempt.expired = true;
            return Poll::Ready(Err(failure("connect_deadline")));
        }
        if observation.connect_started_at.is_none() {
            observation.connect_started_at = Some(Instant::now());
            observation.stage = Some(ConnectStage::Tcp);
        }
        connecting
            .as_mut()
            .poll(cx)
            .map(|result| result.map_err(|_| failure("tcp_connect")))
    })
    .await?;
    let tcp_at = Instant::now();
    observation.tcp_connected_at = Some(tcp_at);
    observation.stage = Some(ConnectStage::Starttls);
    stream
        .set_nodelay(true)
        .map_err(|_| failure("tcp_nodelay"))?;
    let (read, mut write) = tokio::io::split(stream);
    let mut parser = xml::parser(read);
    let header = xml::stream_header(&target.xmpp_domain)?;
    write_all(&mut write, header.as_bytes()).await?;
    xml::features(&mut parser, &target.xmpp_domain, "starttls", xml::TLS_NS).await?;
    write_all(
        &mut write,
        b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )
    .await?;
    xml::proceed(&mut parser).await?;
    let read = parser.into_inner();
    if !read.buffer().is_empty() {
        return Err(failure("starttls_buffered_plaintext"));
    }
    let stream = read.into_inner().unsplit(write);
    let mut config = (*target.tls).clone();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = true;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream.compat())
        .await
        .map_err(|_| failure("tls_handshake"))?;
    let connection = tls.get_ref().1;
    let negotiated = NegotiatedTls {
        version: connection
            .protocol_version()
            .ok_or_else(|| failure("tls_negotiation"))?,
        cipher: connection
            .negotiated_cipher_suite()
            .ok_or_else(|| failure("tls_negotiation"))?
            .suite(),
    };
    let tls_at = Instant::now();
    observation.tls_ready_at = Some(tls_at);
    observation.stage = Some(ConnectStage::Authenticate);
    let (read, mut write) = tokio::io::split(tls.compat());
    let mut parser = xml::parser(read);
    write_all(&mut write, header.as_bytes()).await?;
    xml::features(&mut parser, &target.xmpp_domain, "mechanisms", xml::SASL_NS).await?;
    let exchange = Exchange::new(account)?;
    let auth = Zeroizing::new(format!(
        "<auth xmlns='{}' mechanism='SCRAM-SHA-256'>{}</auth>",
        xml::SASL_NS,
        *exchange.first
    ));
    write_all(&mut write, auth.as_bytes()).await?;
    let challenge = exchange.challenge(&xml::sasl(&mut parser, "challenge").await?)?;
    let proof = exchange.respond(account, challenge, key_mode, cpu).await?;
    let response = Zeroizing::new(format!(
        "<response xmlns='{}'>{}</response>",
        xml::SASL_NS,
        *proof.response
    ));
    write_all(&mut write, response.as_bytes()).await?;
    proof.verify(&xml::sasl(&mut parser, "success").await?)?;
    let auth_at = Instant::now();
    observation.authenticated_at = Some(auth_at);
    observation.stage = Some(ConnectStage::Bind);
    parser = parser.restart().map_err(|_| failure("stream_restart"))?;
    write_all(&mut write, header.as_bytes()).await?;
    xml::features(&mut parser, &target.xmpp_domain, "bind", xml::BIND_NS).await?;
    let mut bind = String::from(
        "<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>",
    );
    xml::escape(&mut bind, resource)?;
    bind.push_str("</resource></bind></iq>");
    write_all(&mut write, bind.as_bytes()).await?;
    let bound_jid = xml::binding(&mut parser, &expected).await?;
    let bound_at = Instant::now();
    observation.bound_at = Some(bound_at);
    let identity = SessionIdentity {
        bound_jid,
        tls: negotiated,
    };
    let writer = Writer::new(write, Retirement::new());
    let timings = observation.timings();
    Ok((
        ClientSession {
            reader: parser,
            writer,
            identity,
            route: None,
        },
        timings,
    ))
}

async fn write_all<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> BenchResult<()> {
    writer
        .write_all(bytes)
        .await
        .map_err(|_| failure("transport_write"))?;
    writer.flush().await.map_err(|_| failure("transport_flush"))
}

#[derive(Clone)]
pub(super) struct Retirement {
    signal: watch::Sender<bool>,
    invalid: Arc<AtomicBool>,
}

impl Retirement {
    pub(super) fn new() -> Self {
        let (signal, _) = watch::channel(false);
        Self {
            signal,
            invalid: Arc::new(AtomicBool::new(false)),
        }
    }
    fn retire(&self) {
        self.signal.send_replace(true);
    }
    fn retired(&self) -> bool {
        *self.signal.borrow()
    }
}

pub struct SessionReader {
    events: mpsc::Receiver<ReceivedEvent>,
    task: Option<JoinHandle<BenchResult<()>>>,
    retirement: Retirement,
}

impl SessionReader {
    #[cfg(test)]
    pub(crate) fn test_stream(input: tokio::io::DuplexStream, capacity: NonZeroUsize) -> Self {
        Self::start(
            xml::parser(input),
            "test@localhost/bench".into(),
            None,
            Retirement::new(),
            capacity,
        )
    }

    pub(super) fn start<R: AsyncRead + Unpin + Send + 'static>(
        mut parser: xml::Parser<R>,
        bound_jid: String,
        route: Option<ReceiveRoute>,
        retirement: Retirement,
        capacity: NonZeroUsize,
    ) -> Self {
        let (sender, events) = mpsc::channel(capacity.get());
        let mut signal = retirement.signal.subscribe();
        let retired = retirement.clone();
        let task = tokio::spawn(async move {
            loop {
                if *signal.borrow() {
                    return Ok(());
                }
                let event = tokio::select! {
                    biased;
                    _ = signal.changed() => return Ok(()),
                    event = xml::next(&mut parser) => event,
                };
                let outcome =
                    event.and_then(|event| xml::received(event, &bound_jid, route.as_ref()));
                let event = match outcome {
                    Ok(event) => event,
                    Err(error) => {
                        retired.retire();
                        return Err(error);
                    }
                };
                let terminal = matches!(
                    event.kind,
                    ReceivedKind::StreamEnd | ReceivedKind::StreamError
                );
                if matches!(event.kind, ReceivedKind::StreamError) {
                    retired.retire();
                }
                if sender.try_send(event).is_err() {
                    retired.invalid.store(true, Ordering::Release);
                    retired.retire();
                    return Err(failure("event_queue_overflow"));
                }
                if terminal {
                    return Ok(());
                }
            }
        });
        Self {
            events,
            task: Some(task),
            retirement,
        }
    }

    /// Cancellation stops only the queue wait; the parser task keeps its pending read.
    pub async fn next(&mut self) -> BenchResult<ReceivedEvent> {
        if let Some(event) = self.events.recv().await {
            return Ok(event);
        }
        self.join().await?;
        Err(failure("connection_closed"))
    }

    pub fn run_invalid(&self) -> bool {
        self.retirement.invalid.load(Ordering::Acquire)
    }

    /// Await this method before dropping a retired reader to join its parser task.
    pub async fn retire(&mut self) -> BenchResult<()> {
        self.retirement.retire();
        if let Some(task) = &self.task {
            task.abort();
        }
        self.join().await
    }

    /// Joins the parser and drains every queued event, including after a callback error.
    pub async fn retire_and_drain(
        &mut self,
        received: &mut impl FnMut(ReceivedEvent) -> BenchResult<()>,
    ) -> BenchResult<()> {
        let mut result = self.retire().await;
        while let Ok(event) = self.events.try_recv() {
            let outcome = received(event);
            if result.is_ok() {
                result = outcome;
            }
        }
        result
    }

    async fn join(&mut self) -> BenchResult<()> {
        if let Some(task) = self.task.as_mut() {
            let result = task.await;
            self.task.take();
            match result {
                Ok(result) => result,
                Err(error) if error.is_cancelled() => Ok(()),
                Err(_) => Err(failure("reader_task_failed")),
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for SessionReader {
    fn drop(&mut self) {
        self.retirement.retire();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(crate) struct MessageSetup {
    routes: Arc<[MessageRoute]>,
    payload: Arc<str>,
    stanza_capacity: usize,
}

impl MessageSetup {
    pub(crate) fn new(routes: Arc<[MessageRoute]>, payload: Arc<str>) -> BenchResult<Self> {
        if !payload.bytes().all(|byte| byte == b'x') || payload.len() > 262_000 {
            return Err(failure("payload_invalid"));
        }
        let mut escaped = String::new();
        let mut max_to_bytes = 0;
        for route in routes.iter() {
            if xml::canonical_jid(&route.to)? != route.to || !route.to.contains('/') {
                return Err(failure("route_invalid"));
            }
            escaped.clear();
            xml::escape(&mut escaped, &route.to)?;
            max_to_bytes = max_to_bytes.max(escaped.len());
        }
        let stanza_capacity = max_to_bytes
            + payload.len()
            + 55
            + "<message type='chat' to='' id=''><body></body></message>".len();
        if stanza_capacity > 262_144 {
            return Err(failure("stanza_size"));
        }
        Ok(Self {
            routes,
            payload,
            stanza_capacity,
        })
    }

    pub(crate) fn payload(&self) -> Arc<str> {
        self.payload.clone()
    }
}

pub struct Writer<W: AsyncWrite + Unpin> {
    transport: Option<W>,
    retirement: Retirement,
    buffer: String,
    routes: Arc<[MessageRoute]>,
    payload: Arc<str>,
    closed: bool,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(super) fn new(transport: W, retirement: Retirement) -> Self {
        Self {
            transport: Some(transport),
            retirement,
            buffer: String::new(),
            routes: Arc::from([]),
            payload: Arc::from(""),
            closed: false,
        }
    }

    pub fn configure_messages(
        &mut self,
        routes: Arc<[MessageRoute]>,
        payload: Arc<str>,
    ) -> BenchResult<()> {
        let setup = MessageSetup::new(routes, payload)?;
        self.configure_prepared_messages(&setup)
    }

    fn configure_prepared_messages(&mut self, setup: &MessageSetup) -> BenchResult<()> {
        self.buffer
            .try_reserve(setup.stanza_capacity.saturating_sub(self.buffer.len()))
            .map_err(|_| failure("writer_buffer_allocation"))?;
        self.routes = setup.routes.clone();
        self.payload = setup.payload.clone();
        Ok(())
    }

    /// Cancellation or failure after WriteStarted prevents reuse of the connection.
    pub async fn send(&mut self, command: &WriteCommand, events: &EventSink) -> BenchResult<()> {
        if self.closed || self.retirement.retired() {
            return Err(failure("connection_retired"));
        }
        let WriteCommand::Message(command) = command;
        if command.phase != command.operation.phase || command.operation.sequence >= 10_000_000 {
            return Err(failure("command_invalid"));
        }
        let route = self
            .routes
            .get(command.route_index as usize)
            .ok_or_else(|| failure("route_invalid"))?;
        self.buffer.clear();
        self.buffer.push_str("<message type='chat' to='");
        xml::escape(&mut self.buffer, &route.to)?;
        self.buffer.push_str("' id='");
        use std::fmt::Write;
        write!(self.buffer, "{}", command.operation).map_err(|_| failure("xml_encode"))?;
        self.buffer.push_str("'><body>");
        self.buffer.push_str(&self.payload);
        self.buffer.push_str("</body></message>");
        if self.buffer.len() > 262_144 {
            return Err(failure("stanza_size"));
        }
        let mut guard = WriteGuard::new(&mut self.transport, &self.retirement);
        events.emit(WriterEvent::WriteStarted {
            operation: command.operation,
            at: Instant::now(),
        })?;
        let result = write_all(guard.transport()?, self.buffer.as_bytes()).await;
        match result {
            Ok(()) => {
                events.emit(WriterEvent::WriteCompleted {
                    operation: command.operation,
                    at: Instant::now(),
                    bytes: self.buffer.len(),
                })?;
                guard.complete();
                Ok(())
            }
            Err(error) => {
                let _ = events.emit(WriterEvent::WriteFailed {
                    operation: command.operation,
                    at: Instant::now(),
                });
                Err(error)
            }
        }
    }

    pub async fn close_stream(&mut self) -> BenchResult<()> {
        if self.closed || self.retirement.retired() {
            return Err(failure("connection_retired"));
        }
        self.closed = true;
        let mut guard = WriteGuard::new(&mut self.transport, &self.retirement);
        write_all(guard.transport()?, b"</stream:stream>").await?;
        guard.complete();
        Ok(())
    }

    pub async fn shutdown_tls(&mut self) -> BenchResult<()> {
        let mut guard = WriteGuard::new(&mut self.transport, &self.retirement);
        guard
            .transport()?
            .shutdown()
            .await
            .map_err(|_| failure("tls_shutdown"))?;
        guard.complete();
        self.transport.take();
        Ok(())
    }

    pub fn retire(&mut self) {
        self.retirement.retire();
        self.transport.take();
    }
}

impl<W: AsyncWrite + Unpin> Drop for Writer<W> {
    fn drop(&mut self) {
        self.retirement.retire();
    }
}

struct WriteGuard<'a, W> {
    transport: &'a mut Option<W>,
    retirement: &'a Retirement,
    complete: bool,
}

impl<'a, W> WriteGuard<'a, W> {
    fn new(transport: &'a mut Option<W>, retirement: &'a Retirement) -> Self {
        Self {
            transport,
            retirement,
            complete: false,
        }
    }
    fn transport(&mut self) -> BenchResult<&mut W> {
        self.transport
            .as_mut()
            .ok_or_else(|| failure("connection_retired"))
    }
    fn complete(mut self) {
        self.complete = true;
    }
}

impl<W> Drop for WriteGuard<'_, W> {
    fn drop(&mut self) {
        if !self.complete {
            self.retirement.retire();
            self.transport.take();
        }
    }
}

/// Joins the reader and passes queued events to the callback, including after a close deadline.
/// After cancellation, retire the writer and await reader.retire_and_drain before dropping either owner.
pub async fn shutdown(
    reader: &mut SessionReader,
    writer: &mut SessionWriter,
    shutdown_timeout: Duration,
    received: &mut impl FnMut(ReceivedEvent) -> BenchResult<()>,
) -> BenchResult<()> {
    shutdown_parts(reader, writer, shutdown_timeout, received).await
}

pub(super) async fn shutdown_parts<W: AsyncWrite + Unpin>(
    reader: &mut SessionReader,
    writer: &mut Writer<W>,
    shutdown_timeout: Duration,
    received: &mut impl FnMut(ReceivedEvent) -> BenchResult<()>,
) -> BenchResult<()> {
    let result = timeout(shutdown_timeout, async {
        writer.close_stream().await?;
        loop {
            let event = reader.next().await?;
            let terminal = matches!(event.kind, ReceivedKind::StreamEnd);
            let error = matches!(event.kind, ReceivedKind::StreamError);
            received(event)?;
            match (terminal, error) {
                (true, _) => break,
                (_, true) => return Err(failure("close_stream_error")),
                _ => {}
            }
        }
        writer.shutdown_tls().await?;
        reader.join().await
    })
    .await
    .unwrap_or_else(|_| Err(failure("close_deadline")));
    writer.retire();
    let cleaned = reader.retire_and_drain(received).await;
    result.and(cleaned)
}

#[cfg(test)]
mod ownership_tests {
    use std::{
        error::Error,
        future::{Future, pending},
        io,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };

    use super::*;
    use crate::client::{BodyValidation, CorrelationId, TrafficPhase};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn prepared_messages_validate_once_before_sharing_routes_and_payload() -> TestResult {
        for to in [
            "receiver@example.test",
            "RECEIVER@example.test/resource",
            "bad jid",
        ] {
            assert!(
                MessageSetup::new(
                    Arc::from([MessageRoute { to: to.into() }]),
                    Arc::from("xxx")
                )
                .is_err()
            );
        }
        assert!(MessageSetup::new(Arc::from([]), Arc::from("xyx")).is_err());
        let setup = MessageSetup::new(
            Arc::from([MessageRoute {
                to: "receiver@example.test/resource".into(),
            }]),
            Arc::from("xxx"),
        )?;
        for _ in 0..2 {
            let mut writer = Writer::new(tokio::io::sink(), Retirement::new());
            writer.configure_prepared_messages(&setup)?;
            assert!(writer.buffer.capacity() >= setup.stanza_capacity);
            assert!(Arc::ptr_eq(&writer.routes, &setup.routes));
            assert!(Arc::ptr_eq(&writer.payload, &setup.payload));
        }
        Ok(())
    }

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct ControlledWriter {
        _dropped: DropProbe,
        polls: Arc<std::sync::atomic::AtomicUsize>,
        pending_write: bool,
        pending_flush: bool,
    }

    impl AsyncWrite for ControlledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls.fetch_add(1, Ordering::AcqRel);
            if self.pending_write {
                Poll::Pending
            } else {
                Poll::Ready(Ok(bytes.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.pending_flush {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct Owners {
        reader: SessionReader,
        writer: Writer<ControlledWriter>,
        sender: mpsc::Sender<ReceivedEvent>,
        reader_dropped: Arc<AtomicBool>,
        writer_dropped: Arc<AtomicBool>,
        write_polls: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn owners(pending_write: bool, pending_flush: bool) -> Result<Owners, Box<dyn Error>> {
        let retirement = Retirement::new();
        let (sender, events) = mpsc::channel(8);
        let reader_dropped = Arc::new(AtomicBool::new(false));
        let probe = DropProbe(reader_dropped.clone());
        let producer = sender.clone();
        let (started, entered) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _probe = probe;
            let _producer = producer;
            let _ = started.send(());
            pending::<BenchResult<()>>().await
        });
        entered.await?;
        let reader = SessionReader {
            events,
            task: Some(task),
            retirement: retirement.clone(),
        };
        let writer_dropped = Arc::new(AtomicBool::new(false));
        let write_polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer = Writer::new(
            ControlledWriter {
                _dropped: DropProbe(writer_dropped.clone()),
                polls: write_polls.clone(),
                pending_write,
                pending_flush,
            },
            retirement,
        );
        Ok(Owners {
            reader,
            writer,
            sender,
            reader_dropped,
            writer_dropped,
            write_polls,
        })
    }

    fn receipt(at: Instant, sequence: u64) -> ReceivedEvent {
        ReceivedEvent {
            at,
            kind: ReceivedKind::Chat {
                correlation: Some(CorrelationId {
                    run_nonce: [7; 16],
                    phase: TrafficPhase::Measurement,
                    sequence,
                }),
                from: Some("sender@example.test/resource".to_owned()),
                to: Some("receiver@example.test/resource".to_owned()),
                body: BodyValidation {
                    bytes: 3,
                    ascii_x: true,
                },
                route_valid: true,
            },
        }
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    fn assert_joined(reader: &SessionReader, dropped: &AtomicBool) {
        assert!(reader.task.is_none());
        assert!(reader.events.is_closed());
        assert!(reader.events.is_empty());
        assert!(dropped.load(Ordering::Acquire));
    }

    fn assert_receipt(event: &ReceivedEvent, at: Instant, sequence: u64) {
        assert_eq!(event.at, at);
        assert!(
            matches!(event.kind, ReceivedKind::Chat { correlation: Some(id), .. } if id.sequence == sequence)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_footer_write_or_flush_keeps_owners_and_queued_receipt() -> TestResult {
        for (pending_write, pending_flush) in [(true, false), (false, true)] {
            let Owners {
                mut reader,
                mut writer,
                sender,
                reader_dropped,
                writer_dropped,
                write_polls,
            } = owners(pending_write, pending_flush).await?;
            let at = Instant::now();
            sender.try_send(receipt(at, 1))?;
            drop(sender);
            let mut observed = Vec::new();
            let mut received = |event| {
                observed.push(event);
                Ok(())
            };
            let mut closing = Box::pin(shutdown_parts(
                &mut reader,
                &mut writer,
                Duration::from_secs(1),
                &mut received,
            ));
            assert!(poll(closing.as_mut()).is_pending());
            drop(closing);
            let polls = write_polls.load(Ordering::Acquire);
            assert!(reader.task.is_some());
            tokio::time::advance(Duration::from_secs(2)).await;
            writer.retire();
            reader.retire_and_drain(&mut received).await?;
            assert_joined(&reader, &reader_dropped);
            assert!(writer_dropped.load(Ordering::Acquire));
            assert_eq!(write_polls.load(Ordering::Acquire), polls);
            assert_eq!(observed.len(), 1);
            assert_receipt(&observed[0], at, 1);
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_peer_footer_wait_preserves_receipt_queued_before_drop() -> TestResult {
        let Owners {
            mut reader,
            mut writer,
            sender,
            reader_dropped,
            writer_dropped,
            write_polls,
        } = owners(false, false).await?;
        let mut observed = Vec::new();
        let mut received = |event| {
            observed.push(event);
            Ok(())
        };
        let mut closing = Box::pin(shutdown_parts(
            &mut reader,
            &mut writer,
            Duration::from_secs(1),
            &mut received,
        ));
        assert!(poll(closing.as_mut()).is_pending());
        let at = Instant::now();
        sender.try_send(receipt(at, 2))?;
        drop(sender);
        drop(closing);
        tokio::time::advance(Duration::from_secs(2)).await;
        writer.retire();
        reader.retire_and_drain(&mut received).await?;
        assert_joined(&reader, &reader_dropped);
        assert!(writer_dropped.load(Ordering::Acquire));
        assert_eq!(write_polls.load(Ordering::Acquire), 1);
        assert_eq!(observed.len(), 1);
        assert_receipt(&observed[0], at, 2);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_graceful_join_retains_accumulator_and_handle_without_replay() -> TestResult {
        let Owners {
            mut reader,
            mut writer,
            sender,
            reader_dropped,
            writer_dropped,
            ..
        } = owners(false, false).await?;
        let at = Instant::now();
        sender.try_send(receipt(at, 3))?;
        sender.try_send(ReceivedEvent {
            at,
            kind: ReceivedKind::StreamEnd,
        })?;
        drop(sender);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = observed.clone();
        let mut received = move |event| {
            recorded.lock().unwrap().push(event);
            Ok(())
        };
        let mut closing = Box::pin(shutdown_parts(
            &mut reader,
            &mut writer,
            Duration::from_secs(1),
            &mut received,
        ));
        assert!(poll(closing.as_mut()).is_pending());
        drop(closing);
        assert_eq!(observed.lock().unwrap().len(), 2);
        assert!(reader.task.is_some());
        tokio::time::advance(Duration::from_secs(2)).await;
        writer.retire();
        reader.retire_and_drain(&mut received).await?;
        assert_joined(&reader, &reader_dropped);
        assert!(writer_dropped.load(Ordering::Acquire));
        reader.retire_and_drain(&mut received).await?;
        let observed = observed.lock().unwrap();
        assert_eq!(observed.len(), 2);
        assert_receipt(&observed[0], at, 3);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_forced_cleanup_join_can_resume_and_drain_once() -> TestResult {
        let Owners {
            mut reader,
            mut writer,
            sender,
            reader_dropped,
            writer_dropped,
            ..
        } = owners(false, false).await?;
        let at = Instant::now();
        sender.try_send(receipt(at, 4))?;
        sender.try_send(receipt(at, 5))?;
        drop(sender);
        let mut observed = Vec::new();
        let mut received = |event| {
            observed.push(event);
            Ok(())
        };
        writer.retire();
        let mut cleanup = Box::pin(reader.retire_and_drain(&mut received));
        assert!(poll(cleanup.as_mut()).is_pending());
        drop(cleanup);
        assert!(reader.task.is_some());
        assert_eq!(reader.events.len(), 2);
        tokio::time::advance(Duration::from_secs(2)).await;
        reader.retire_and_drain(&mut received).await?;
        reader.retire_and_drain(&mut received).await?;
        assert_joined(&reader, &reader_dropped);
        assert!(writer_dropped.load(Ordering::Acquire));
        assert_eq!(observed.len(), 2);
        assert_receipt(&observed[0], at, 4);
        assert_receipt(&observed[1], at, 5);
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_continues_callbacks_and_keeps_first_callback_error() -> TestResult {
        let Owners {
            mut reader,
            mut writer,
            sender,
            reader_dropped,
            writer_dropped,
            ..
        } = owners(false, false).await?;
        let at = Instant::now();
        for sequence in 6..9 {
            sender.try_send(receipt(at, sequence))?;
        }
        drop(sender);
        let mut observed = Vec::new();
        let mut received = |event| {
            observed.push(event);
            match observed.len() {
                1 => Err(failure("first_callback")),
                2 => Err(failure("second_callback")),
                _ => Ok(()),
            }
        };
        writer.retire();
        assert_eq!(
            reader
                .retire_and_drain(&mut received)
                .await
                .unwrap_err()
                .context(),
            "first_callback"
        );
        reader.retire_and_drain(&mut received).await?;
        assert_joined(&reader, &reader_dropped);
        assert!(writer_dropped.load(Ordering::Acquire));
        assert_eq!(observed.len(), 3);
        for (i, event) in observed.iter().enumerate() {
            assert_receipt(event, at, i as u64 + 6);
        }
        Ok(())
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use std::{future::pending, num::NonZeroUsize};
    use tokio::io::AsyncReadExt;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn adjacent_boundaries_include_all_overhead_and_only_floor_individually() {
        let start = Instant::now();
        let observation = ConnectObservation {
            connect_started_at: Some(start),
            tcp_connected_at: Some(start + Duration::from_nanos(1_999)),
            tls_ready_at: Some(start + Duration::from_nanos(4_998)),
            authenticated_at: Some(start + Duration::from_nanos(8_997)),
            bound_at: Some(start + Duration::from_nanos(13_996)),
            stage: Some(ConnectStage::Bind),
        };
        let t = observation.timings();
        assert_eq!(
            (
                t.tcp_us,
                t.starttls_us,
                t.authenticate_us,
                t.bind_us,
                t.total_us
            ),
            (1, 2, 3, 4, 13)
        );
        assert_eq!(
            t.total_us - (t.tcp_us + t.starttls_us + t.authenticate_us + t.bind_us),
            3
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_work_is_never_polled_and_generic_errors_keep_each_active_stage() -> TestResult
    {
        for stage in [
            ConnectStage::Tcp,
            ConnectStage::Starttls,
            ConnectStage::Authenticate,
            ConnectStage::Bind,
        ] {
            let mut observation = ConnectObservation::default();
            let deadline = Instant::now() + Duration::from_millis(1);
            let result = before_deadline(deadline, async {
                observation.stage = Some(stage);
                pending::<BenchResult<()>>().await
            })
            .await;
            assert!(result.is_err());
            let failure =
                observation.failure(ConnectFailureKind::Deadline, failure("connect_deadline"));
            assert_eq!(
                (failure.stage, failure.kind),
                (Some(stage), ConnectFailureKind::Deadline)
            );
            assert_eq!(failure.at, deadline);
            let result = before_deadline(deadline + Duration::from_secs(1), async {
                Err::<(), _>(super::failure("xml_read"))
            })
            .await
            .map_err(|_| "unexpected expiry")?;
            let failure = observation.failure(ConnectFailureKind::Error, result.unwrap_err());
            assert_eq!(
                (failure.stage, failure.error.context()),
                (Some(stage), "xml_read")
            );
        }
        let polled = std::cell::Cell::new(false);
        assert!(
            before_deadline(Instant::now(), async {
                polled.set(true);
            })
            .await
            .is_err()
        );
        assert!(!polled.get());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn unpolled_and_expired_connects_have_no_stage_or_tcp_timestamp() -> TestResult {
        let target = ResolvedTarget {
            address: "127.0.0.1:9".parse()?,
            xmpp_domain: "example.test".into(),
            tls: remote_tls_config(None)?,
        };
        let mut account = PreparedAccount::new("user@example.test", "password".into())?;
        let cpu = CpuPool::new(NonZeroUsize::MIN);
        let mut observation = ConnectObservation::default();
        let unpolled = connect_observed(
            &target,
            &mut account,
            "bench",
            KeyMode::Prime,
            Instant::now() + Duration::from_secs(1),
            &cpu,
            &mut observation,
        );
        drop(unpolled);
        assert!(observation.connect_started_at.is_none());
        assert!(observation.stage.is_none());
        let result = connect_observed(
            &target,
            &mut account,
            "bench",
            KeyMode::Prime,
            Instant::now(),
            &cpu,
            &mut observation,
        )
        .await;
        let failure = result.err().ok_or("expired connection succeeded")?;
        assert_eq!(
            (failure.kind, failure.stage, failure.error.context()),
            (ConnectFailureKind::Deadline, None, "connect_deadline")
        );
        assert!(observation.connect_started_at.is_none());
        assert_eq!(account.cached_scram_iterations(), None);
        Ok(())
    }

    #[tokio::test]
    async fn first_tcp_poll_is_recorded_once_and_cancellation_drops_transport() -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target = ResolvedTarget {
            address: listener.local_addr()?,
            xmpp_domain: "example.test".into(),
            tls: remote_tls_config(None)?,
        };
        let mut account = PreparedAccount::new("user@example.test", "password".into())?;
        let cpu = CpuPool::new(NonZeroUsize::MIN);
        let mut observation = ConnectObservation::default();
        let before = Instant::now();
        let mut work = Box::pin(connect_observed(
            &target,
            &mut account,
            "bench",
            KeyMode::Prime,
            before + Duration::from_secs(2),
            &cpu,
            &mut observation,
        ));
        let accepted = tokio::select! {result=listener.accept()=>result?, _=&mut work=>return Err("unexpected connect completion".into())};
        let mut peer = accepted.0;
        let mut bytes = [0; 1024];
        tokio::select! {result=peer.read(&mut bytes)=>{assert!(result?>0);}, _=&mut work=>return Err("unexpected connect completion".into())};
        drop(work);
        assert_eq!(observation.stage, Some(ConnectStage::Starttls));
        assert!(
            observation
                .connect_started_at
                .is_some_and(|at| at >= before)
        );
        assert!(observation.tcp_connected_at >= observation.connect_started_at);
        assert!(observation.tls_ready_at.is_none());
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read(&mut bytes)).await??,
            0
        );
        Ok(())
    }
}
