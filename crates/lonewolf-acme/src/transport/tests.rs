// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::net::TcpListener;
use std::sync::mpsc;
use std::task::{Context, Waker};
use std::thread;

use crate::crypto::CertificateSigner;

use instant_acme::HttpClient as _;
use rustls::pki_types::PrivateKeyDer;

const WAIT: Duration = Duration::from_secs(5);

fn block_on<F: Future>(future: F) -> F::Output {
    compio::runtime::Runtime::new().unwrap().block_on(future)
}

fn certificate(name: &str, expired: bool) -> (Vec<u8>, Vec<u8>) {
    let signer = CertificateSigner::generate().unwrap();
    let mut parameters = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    parameters.serial_number = Some(rcgen::SerialNumber::from(1));
    if expired {
        parameters.not_after = rcgen::date_time_ymd(2000, 1, 1);
    }
    let certificate = parameters.self_signed(&signer).unwrap();
    (certificate.der().to_vec(), signer.pkcs8().unwrap().to_vec())
}

fn server_config(certificate: Vec<u8>, key: Vec<u8>) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate)],
                PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap(),
    )
}

fn client_with_root(root: &[u8], timeout: Duration) -> AcmeHttpClient {
    let mut roots = load_roots(None).unwrap();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    AcmeHttpClient {
        inner: Arc::new(Inner {
            agent: build_agent(roots, timeout).unwrap(),
            request_timeout: timeout,
            executor: BlockingExecutor::new(NonZeroUsize::new(2).unwrap()),
            admission: PlMutex::new(Admission {
                accepting: true,
                active: 0,
                waiters: vec![],
            }),
        }),
        retry: Arc::new(PlMutex::new(Arc::new(PlMutex::new(None)))),
    }
}

fn serve(
    config: Arc<rustls::ServerConfig>,
    action: impl FnOnce(&mut rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>)
    + Send
    + 'static,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://127.0.0.1:{}/directory",
        listener.local_addr().unwrap().port()
    );
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream.set_write_timeout(Some(WAIT)).unwrap();
        let mut stream =
            rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), stream);
        let mut request = vec![];
        let mut byte = [0];
        while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            request.push(byte[0]);
        }
        action(&mut stream);
    });
    (url, worker)
}

fn request(url: &str) -> http::Request<instant_acme::BodyWrapper<Bytes>> {
    http::Request::builder()
        .uri(url)
        .body(instant_acme::BodyWrapper::default())
        .unwrap()
}

fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn public_anchors_keep_all_mozilla_constraints_with_extra_roots() {
    let (certificate, _) = certificate("127.0.0.1", false);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&certificate)
    );
    let mut roots = load_roots(None).unwrap();
    add_roots(&mut roots, pem.as_bytes()).unwrap();
    assert_eq!(roots.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len() + 1);
    for (actual, expected) in roots.roots.iter().zip(webpki_roots::TLS_SERVER_ROOTS) {
        assert_eq!(actual.subject, expected.subject);
        assert_eq!(
            actual.subject_public_key_info,
            expected.subject_public_key_info
        );
        assert_eq!(actual.name_constraints, expected.name_constraints);
    }
    for invalid in [
        b"".as_slice(),
        b"garbage",
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
    ] {
        assert_eq!(
            add_roots(&mut roots, invalid).unwrap_err().kind(),
            AcmeErrorKind::InvalidCaBundle
        );
    }
    let mut invalid_suffix = pem.into_bytes();
    invalid_suffix.extend_from_slice(b"junk");
    assert!(add_roots(&mut roots, &invalid_suffix).is_err());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&invalid_suffix).unwrap();
    assert!(
        block_on(AcmeHttpClient::new(TransportOptions {
            ca_certificates_path: Some(file.path().into())
        }))
        .is_err()
    );
}

#[test]
fn trusted_https_and_acme_error_status_preserve_bounded_response_and_retry() {
    let (certificate, key) = certificate("127.0.0.1", false);
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    write!(
        ca,
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(&certificate)
    )
    .unwrap();
    let client = block_on(AcmeHttpClient::new(TransportOptions {
        ca_certificates_path: Some(ca.path().into()),
    }))
    .unwrap();
    assert!(client.inner.agent.config().proxy().is_none());
    assert!(client.inner.agent.config().https_only());
    assert_eq!(client.inner.agent.config().max_redirects(), 0);
    for status in [200, 400, 429, 503] {
        let body = format!(
            "HTTP/1.1 {status} Test\r\nRetry-After: 60\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        let (url, worker) = serve(
            server_config(certificate.clone(), key.clone()),
            move |stream| {
                let _ = stream.write_all(body.as_bytes());
            },
        );
        client.reset_retry_hint();
        let mut response = block_on(client.request(request(&url))).unwrap();
        assert_eq!(response.parts.status.as_u16(), status);
        assert_eq!(response.parts.headers[http::header::RETRY_AFTER], "60");
        assert_eq!(block_on(response.body.into_bytes()).unwrap(), "{}");
        assert!(client.retry_not_before().unwrap() > SystemTime::now());
        worker.join().unwrap();
    }
}

#[test]
fn untrusted_wrong_name_and_expired_certificates_fail() {
    for (name, expired, trusted) in [
        ("127.0.0.1", false, false),
        ("other.example", false, true),
        ("127.0.0.1", true, true),
    ] {
        let (certificate, key) = certificate(name, expired);
        let client = if trusted {
            client_with_root(&certificate, GLOBAL_TIMEOUT)
        } else {
            block_on(AcmeHttpClient::new(TransportOptions::default())).unwrap()
        };
        let (url, worker) = serve(server_config(certificate, key), |_| {
            panic!("unverified TLS reached HTTP")
        });
        assert!(block_on(client.request(request(&url))).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn plain_http_invalid_urls_and_oversized_requests_fail_before_network() {
    let client = block_on(AcmeHttpClient::new(TransportOptions::default())).unwrap();
    for url in [
        "http://127.0.0.1:1/",
        "https://user@example.com/",
        "https://example.com:0/",
    ] {
        let error = block_on(client.request(request(url))).err().unwrap();
        assert!(format!("{error:?}").contains("InvalidInput"));
    }
    let long_url = format!("https://example.com/{}", "a".repeat(8192));
    assert!(block_on(client.request(request(&long_url))).is_err());
    let oversized = http::Request::builder()
        .uri("https://127.0.0.1:1/")
        .body(instant_acme::BodyWrapper::from(vec![0; MAX_REQUEST + 1]))
        .unwrap();
    assert!(block_on(client.request(oversized)).is_err());
}

#[test]
fn redirects_compression_and_oversized_headers_and_bodies_fail() {
    let (certificate, key) = certificate("127.0.0.1", false);
    let client = client_with_root(&certificate, GLOBAL_TIMEOUT);
    let cases = [
        "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n"
            .to_owned(),
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_owned(),
        format!(
            "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
            "a".repeat(33 * 1024)
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            MAX_BODY + 1,
            "a".repeat(MAX_BODY + 1)
        ),
    ];
    for response in cases {
        let (url, worker) = serve(
            server_config(certificate.clone(), key.clone()),
            move |stream| {
                let _ = stream.write_all(response.as_bytes());
            },
        );
        assert!(block_on(client.request(request(&url))).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn retry_hints_parse_checked_dates_deltas_maxima_and_isolate_reset() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert_eq!(
        retry_deadline("120", now),
        now.checked_add(Duration::from_secs(120))
    );
    assert_eq!(
        retry_deadline("Sun, 06 Nov 1994 08:49:37 GMT", now),
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(784111777))
    );
    for invalid in [
        "",
        "-1",
        "invalid",
        "18446744073709551616",
        "99999999999999999999999999999999",
    ] {
        assert!(retry_deadline(invalid, now).is_none());
    }
    assert!(retry_deadline("18446744073709551615", now).is_none());
    let client = block_on(AcmeHttpClient::new(TransportOptions::default())).unwrap();
    let a = client.for_attempt();
    let b = client.for_attempt();
    let late = a.retry.lock().clone();
    a.reset_retry_hint();
    let mut headers = http::HeaderMap::new();
    headers.append(http::header::RETRY_AFTER, "120".parse().unwrap());
    headers.append(http::header::RETRY_AFTER, "60".parse().unwrap());
    capture_retry(&headers, &late, now);
    assert!(a.retry_not_before().is_none());
    capture_retry(&headers, &a.retry.lock(), now);
    assert_eq!(
        a.retry_not_before(),
        now.checked_add(Duration::from_secs(120))
    );
    assert!(b.retry_not_before().is_none());
    assert!(client.retry_not_before().is_none());
}

#[test]
fn response_retry_hint_survives_rejected_compression() {
    let (certificate, key) = certificate("127.0.0.1", false);
    let client = client_with_root(&certificate, GLOBAL_TIMEOUT);
    let (url, worker) = serve(server_config(certificate, key), |stream| {
        let _ = stream.write_all(b"HTTP/1.1 503 Unavailable\r\nRetry-After: 60\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n");
    });
    assert!(block_on(client.request(request(&url))).is_err());
    assert!(client.retry_not_before().is_some());
    worker.join().unwrap();
}

#[test]
fn cancelled_http_futures_retain_capacity_until_closures_finish() {
    block_on(async {
        let (certificate, key) = certificate("127.0.0.1", false);
        let client = client_with_root(&certificate, GLOBAL_TIMEOUT);
        let mut releases = vec![];
        let mut workers = vec![];
        for _ in 0..2 {
            let (entered, started) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let (url, worker) = serve(
                server_config(certificate.clone(), key.clone()),
                move |stream| {
                    entered.send(()).unwrap();
                    gate.recv_timeout(WAIT).unwrap();
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                },
            );
            let mut future = client.request(request(&url));
            assert!(poll(future.as_mut()).is_pending());
            started.recv_timeout(WAIT).unwrap();
            drop(future);
            releases.push(release);
            workers.push(worker);
        }
        assert_eq!(client.inner.admission.lock().active, 2);
        let (entered, started) = mpsc::channel();
        let mut queued = Box::pin(client.inner.executor.run(move || entered.send(()).unwrap()));
        assert!(poll(queued.as_mut()).is_pending());
        assert!(matches!(started.try_recv(), Err(mpsc::TryRecvError::Empty)));
        releases.remove(0).send(()).unwrap();
        queued.await;
        started.recv_timeout(WAIT).unwrap();
        releases.remove(0).send(()).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
        compio::runtime::Runtime::new().unwrap().block_on(async {
            client.drain(Instant::now() + WAIT).await.unwrap();
        });
        assert_eq!(client.inner.admission.lock().active, 0);
    });
}

#[test]
fn drain_cancellation_permanently_rejects_all_clones_and_attempts() {
    compio::runtime::Runtime::new().unwrap().block_on(async {
        let client = AcmeHttpClient::new(TransportOptions::default())
            .await
            .unwrap();
        let cloned = client.clone();
        let attempt = client.for_attempt();
        let operation = client.admit().unwrap();
        let mut draining = Box::pin(client.drain(Instant::now() + WAIT));
        assert!(poll(draining.as_mut()).is_pending());
        drop(draining);
        for handle in [&client, &cloned, &attempt, &client.for_attempt()] {
            assert_eq!(handle.admit().err().unwrap().kind(), AcmeErrorKind::Closed);
        }
        assert_eq!(
            client.drain(Instant::now()).await.unwrap_err().kind(),
            AcmeErrorKind::Timeout
        );
        drop(operation);
        client.drain(Instant::now() + WAIT).await.unwrap();
    });
}

#[test]
fn global_deadline_bounds_handshake_and_response_body_stalls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().unwrap().port()
    );
    let (release, gate) = mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        gate.recv_timeout(WAIT).unwrap();
    });
    let (certificate, key) = certificate("127.0.0.1", false);
    let client = client_with_root(&certificate, Duration::from_millis(100));
    let started = Instant::now();
    assert!(block_on(client.request(request(&url))).is_err());
    assert!(started.elapsed() < WAIT);
    release.send(()).unwrap();
    worker.join().unwrap();
    let (release, gate) = mpsc::channel();
    let (url, worker) = serve(server_config(certificate, key), move |stream| {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na")
            .unwrap();
        gate.recv_timeout(WAIT).unwrap();
    });
    let started = Instant::now();
    assert!(block_on(client.request(request(&url))).is_err());
    assert!(started.elapsed() < WAIT);
    release.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn errors_contain_only_fixed_kind_and_numeric_status() {
    use std::error::Error as _;
    let error = map_error(ureq::Error::Io(io::Error::other("secret URL/key/body")));
    assert_eq!(format!("{error}"), "ACME Other");
    assert_eq!(
        format!("{error:?}"),
        "AcmeError { kind: Other, status: None }"
    );
    assert!(error.source().is_none());
    assert_eq!(
        AcmeError::with_status(AcmeErrorKind::Timeout, 503).status(),
        Some(503)
    );
}

fn error_kind(error: &instant_acme::Error) -> AcmeErrorKind {
    let instant_acme::Error::Other(error) = error else {
        panic!("unexpected protocol error")
    };
    error.downcast_ref::<AcmeError>().unwrap().kind()
}

#[test]
fn missing_runtime_fails_with_redacted_unavailable() {
    let client = block_on(AcmeHttpClient::new(TransportOptions::default())).unwrap();
    let error = futures_executor::block_on(client.request(request("https://127.0.0.1:1/")))
        .err()
        .unwrap();
    assert_eq!(error_kind(&error), AcmeErrorKind::Unavailable);
    assert_eq!(client.inner.admission.lock().active, 0);
}

#[test]
fn third_request_is_immediately_unavailable_and_closed_takes_precedence() {
    block_on(async {
        let client = AcmeHttpClient::new(TransportOptions::default())
            .await
            .unwrap();
        let first = client.admit().unwrap();
        let second = client.admit().unwrap();
        let mut third = client.request(request("https://127.0.0.1:1/"));
        let Poll::Ready(Err(error)) = poll(third.as_mut()) else {
            panic!("saturated request waited")
        };
        assert_eq!(error_kind(&error), AcmeErrorKind::Unavailable);
        assert_eq!(client.inner.admission.lock().active, 2);
        client.inner.admission.lock().accepting = false;
        let error = client
            .request(request("https://127.0.0.1:1/"))
            .await
            .err()
            .unwrap();
        assert_eq!(error_kind(&error), AcmeErrorKind::Closed);
        drop((first, second));
    });
}

#[test]
fn queued_worker_times_out_and_never_connects_after_its_deadline() {
    const CHILD: &str = "LONEWOLF_ACME_QUEUED_DEADLINE_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transport::tests::queued_worker_times_out_and_never_connects_after_its_deadline",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("BLOCKING_MAX_THREADS", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    block_on(async {
        let (certificate, _) = certificate("127.0.0.1", false);
        let client = client_with_root(&certificate, Duration::from_millis(100));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        let (entered, started) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let mut blocker = Box::pin(blocking::unblock(move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        }));
        assert!(poll(blocker.as_mut()).is_pending());
        started.recv_timeout(WAIT).unwrap();
        let started = Instant::now();
        let error = client.request(request(&url)).await.err().unwrap();
        assert_eq!(error_kind(&error), AcmeErrorKind::Timeout);
        assert!(started.elapsed() < WAIT);
        assert_eq!(client.inner.admission.lock().active, 1);
        release.send(()).unwrap();
        blocker.await;
        client.drain(Instant::now() + WAIT).await.unwrap();
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    });
}

async fn wait_idle(client: &AcmeHttpClient) {
    let waiter = Arc::new(AtomicWaker::new());
    client
        .inner
        .admission
        .lock()
        .waiters
        .push(Arc::downgrade(&waiter));
    poll_fn(|context| {
        waiter.register(context.waker());
        if client.inner.admission.lock().active == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn fast_completion_and_early_cancellation_retire_timer_groups() {
    block_on(async {
        let (certificate, key) = certificate("127.0.0.1", false);
        let client = client_with_root(&certificate, GLOBAL_TIMEOUT);
        for _ in 0..8 {
            let (url, worker) = serve(server_config(certificate.clone(), key.clone()), |stream| {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            });
            client.request(request(&url)).await.unwrap();
            wait_idle(&client).await;
            worker.join().unwrap();
            assert_eq!(client.inner.admission.lock().active, 0);
        }
        for _ in 0..8 {
            let mut future = client.request(request("http://127.0.0.1:1/"));
            assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(_))));
            drop(future);
            wait_idle(&client).await;
        }
    });
}

#[test]
fn completed_request_releases_admission_before_next_request_without_timer_poll() {
    block_on(async {
        let (certificate, key) = certificate("127.0.0.1", false);
        let client = client_with_root(&certificate, GLOBAL_TIMEOUT);
        for _ in 0..4 {
            let (url, worker) = serve(server_config(certificate.clone(), key.clone()), |stream| {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            });
            client.request(request(&url)).await.unwrap();
            assert_eq!(client.inner.admission.lock().active, 0);
            worker.join().unwrap();
        }
    });
}
