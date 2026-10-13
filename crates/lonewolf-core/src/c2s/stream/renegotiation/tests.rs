// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::future::Future;
use std::io::{self, Cursor};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use futures_rustls::TlsAcceptor;
use futures_util::io::{AsyncRead, AsyncWrite};
use parking_lot::Mutex as PlMutex;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, MessageDecrypter, MessageEncrypter, OutboundPlainMessage,
};
use rustls::pki_types::ServerName;
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, ContentType, KeyLog, ProtocolVersion,
    RootCertStore, ServerConfig, SupportedCipherSuite, Tls12CipherSuite,
};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Default)]
struct Memory {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    reads: usize,
    writes: usize,
    flushes: usize,
    closes: usize,
    read_limit: Option<usize>,
    pending_reads: usize,
    eof: bool,
    error: Option<io::Error>,
    block_write: bool,
}

#[derive(Clone, Default)]
struct ScriptIo(Rc<RefCell<Memory>>);

impl AsyncRead for ScriptIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut memory = self.0.borrow_mut();
        memory.reads += 1;
        if let Some(error) = memory.error.take() {
            return Poll::Ready(Err(error));
        }
        if memory.pending_reads > 0 {
            memory.pending_reads -= 1;
            return Poll::Pending;
        }
        let count = output
            .len()
            .min(memory.input.len() - memory.position)
            .min(memory.read_limit.unwrap_or(usize::MAX));
        if count == 0 && !output.is_empty() && !memory.eof {
            return Poll::Pending;
        }
        output[..count].copy_from_slice(&memory.input[memory.position..memory.position + count]);
        memory.position += count;
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for ScriptIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut memory = self.0.borrow_mut();
        memory.writes += 1;
        if memory.block_write {
            return Poll::Pending;
        }
        memory.output.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.borrow_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.borrow_mut().closes += 1;
        Poll::Ready(Ok(()))
    }
}

struct LoggedSecret {
    client_random: Zeroizing<Vec<u8>>,
    master_secret: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct Secrets(PlMutex<Option<LoggedSecret>>);

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets")
    }
}

impl KeyLog for Secrets {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if label == "CLIENT_RANDOM" {
            *self.0.lock() = Some(LoggedSecret {
                client_random: Zeroizing::new(client_random.to_vec()),
                master_secret: Zeroizing::new(secret.to_vec()),
            });
        }
    }
}

struct Fixture {
    client: ClientConnection,
    server: Arc<ServerConfig>,
    suite: Option<&'static Tls12CipherSuite>,
    secrets: Arc<Secrets>,
}

#[derive(Debug)]
struct Certificate(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Certificate {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn fixture(version: &'static rustls::SupportedProtocolVersion) -> TestResult<Fixture> {
    let mut provider = rustls_graviola::default_provider();
    if version.version == ProtocolVersion::TLSv1_2 {
        provider.cipher_suites.retain(|suite| {
            suite.suite() == CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        });
    }
    let suite = provider
        .cipher_suites
        .first()
        .and_then(|suite| match suite {
            SupportedCipherSuite::Tls12(suite) => Some(*suite),
            _ => None,
        });
    let provider = Arc::new(provider);
    let config = crate::config::Config::default();
    let hosts = crate::hosts::Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
    let key = hosts
        .certified_key("localhost")
        .ok_or("missing localhost certificate")?;
    let certificate = key.cert[0].clone();
    let resolver = Certificate(Arc::new(rustls::sign::CertifiedKey::new(
        key.cert.clone(),
        Arc::clone(&key.key),
    )));
    let server = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let secrets = Arc::new(Secrets::default());
    config.key_log = secrets.clone();
    Ok(Fixture {
        client: ClientConnection::new(Arc::new(config), ServerName::try_from("localhost")?)?,
        server: Arc::new(server),
        suite,
        secrets,
    })
}

fn records(mut bytes: &[u8]) -> TestResult<Vec<(u8, &[u8])>> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 5 {
            return Err("incomplete record header".into());
        }
        let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        let body = bytes.get(5..5 + length).ok_or("incomplete record body")?;
        records.push((bytes[0], body));
        bytes = &bytes[5 + length..];
    }
    Ok(records)
}

fn consume_server(client: &mut ClientConnection, io: &ScriptIo) -> TestResult<Vec<u8>> {
    let output = std::mem::take(&mut io.0.borrow_mut().output);
    let mut input = Cursor::new(&output);
    while input.position() < output.len() as u64 {
        client.read_tls(&mut input)?;
        client.process_new_packets()?;
    }
    Ok(output)
}

fn client_flight(client: &mut ClientConnection, io: &ScriptIo) -> TestResult<Vec<u8>> {
    let mut flight = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut flight)?;
    }
    io.0.borrow_mut().input.extend_from_slice(&flight);
    Ok(flight)
}

type CipherPair = (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>);

fn cipher_pair(fixture: &Fixture, server_flight: &[u8]) -> TestResult<CipherPair> {
    let suite = fixture.suite.ok_or("no TLS 1.2 suite")?;
    let shape = suite.aead_alg.key_block_shape();
    assert_eq!(shape.enc_key_len, 32);
    let records = records(server_flight)?;
    let (_, hello) = records.first().ok_or("no server hello")?;
    assert_eq!(hello[0], 2);
    let secrets = fixture.secrets.0.lock();
    let LoggedSecret {
        client_random,
        master_secret,
    } = secrets.as_ref().ok_or("no client master secret")?;
    let mut seed = Zeroizing::new([0; 64]);
    seed[..32].copy_from_slice(hello.get(6..38).ok_or("missing server random")?);
    seed[32..].copy_from_slice(client_random);
    let mut block = Zeroizing::new(vec![
        0;
        2 * (shape.enc_key_len + shape.fixed_iv_len)
            + shape.explicit_nonce_len
    ]);
    suite
        .prf_provider
        .for_secret(&mut block, master_secret, b"key expansion", &*seed);
    let key: [u8; 32] = block[..32].try_into()?;
    let iv_start = 2 * shape.enc_key_len;
    let iv = &block[iv_start..iv_start + shape.fixed_iv_len];
    let extra = &block[iv_start + 2 * shape.fixed_iv_len..];
    Ok((
        suite.aead_alg.encrypter(AeadKey::from(key), iv, extra),
        suite.aead_alg.decrypter(AeadKey::from(key), iv),
    ))
}

fn encrypt(
    encrypter: &mut dyn MessageEncrypter,
    typ: ContentType,
    sequence: u64,
    bytes: &[u8],
) -> TestResult<Vec<u8>> {
    Ok(encrypter
        .encrypt(
            OutboundPlainMessage {
                typ,
                version: ProtocolVersion::TLSv1_2,
                payload: bytes.into(),
            },
            sequence,
        )?
        .encode())
}

#[test]
fn pinned_adapter_accepts_coalesced_finished_and_first_encrypted_renegotiation() -> TestResult {
    let mut fixture = fixture(&rustls::version::TLS12)?;
    let io = ScriptIo::default();
    let hello = client_flight(&mut fixture.client, &io)?;
    let acceptor = TlsAcceptor::from(Arc::clone(&fixture.server));
    let mut acceptance = Box::pin(acceptor.accept(io.clone()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(acceptance.as_mut().poll(&mut cx).is_pending());
    let server_flight = consume_server(&mut fixture.client, &io)?;
    let finished = client_flight(&mut fixture.client, &io)?;
    let flight_records = records(&finished)?;
    assert_eq!(
        flight_records.iter().map(|r| r.0).collect::<Vec<_>>(),
        [22, 20, 22]
    );
    let (mut encrypter, mut decrypter) = cipher_pair(&fixture, &server_flight)?;
    let _ = finished_plaintext(&mut *decrypter, &finished)?;
    let encrypted_hello = encrypt(&mut *encrypter, ContentType::Handshake, 1, &hello[5..])?;
    io.0.borrow_mut().input.extend_from_slice(&encrypted_hello);
    let Poll::Ready(Ok(mut transport)) = acceptance.as_mut().poll(&mut cx) else {
        return Err("unguarded acceptance did not complete".into());
    };
    assert!(!transport.get_ref().1.is_handshaking());
    assert_eq!(io.0.borrow().position, io.0.borrow().input.len());
    consume_server(&mut fixture.client, &io)?;
    assert!(!fixture.client.is_handshaking());
    io.0.borrow_mut().input.extend_from_slice(&encrypt(
        &mut *encrypter,
        ContentType::ApplicationData,
        2,
        b"still open",
    )?);
    let mut output = [0; 64];
    let Poll::Ready(Ok(count)) = Pin::new(&mut transport).poll_read(&mut cx, &mut output) else {
        return Err("unguarded connection did not continue".into());
    };
    assert_eq!(&output[..count], b"still open");
    Ok(())
}

fn finished_plaintext(
    decrypter: &mut dyn MessageDecrypter,
    flight: &[u8],
) -> TestResult<Zeroizing<Vec<u8>>> {
    let records = records(flight)?;
    assert_eq!(
        records.iter().map(|r| r.0).collect::<Vec<_>>(),
        [22, 20, 22]
    );
    let mut encrypted = Zeroizing::new(records[2].1.to_vec());
    let plaintext = decrypter.decrypt(
        InboundOpaqueMessage::new(
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &mut encrypted,
        ),
        0,
    )?;
    assert_eq!(plaintext.payload[0], 20);
    assert_eq!(plaintext.payload.len(), 16);
    Ok(Zeroizing::new(plaintext.payload.to_vec()))
}

async fn socket_pair() -> TestResult<(compio::net::TcpStream, std::net::TcpStream)> {
    let listener = crate::c2s::bind(std::net::SocketAddr::from((
        std::net::Ipv4Addr::LOCALHOST,
        0,
    )))
    .await?;
    let peer = std::net::TcpStream::connect(listener.local_addr()?)?;
    peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    let (socket, _) = listener.accept().await?;
    Ok((socket, peer))
}

fn progress<F: Future + Unpin>(future: &mut F, cx: &mut Context<'_>) -> Poll<F::Output> {
    for _ in 0..64 {
        if let Poll::Ready(result) = Pin::new(&mut *future).poll(cx) {
            return Poll::Ready(result);
        }
    }
    Poll::Pending
}

#[test]
fn guarded_acceptance_leaves_coalesced_encrypted_renegotiation_unread_then_aborts() -> TestResult {
    use super::{RecordGuard, is_detected};
    compio::runtime::Runtime::new()?.block_on(async {
        let (socket, mut peer) = socket_pair().await?;
        let mut fixture = fixture(&rustls::version::TLS12)?;
        let io = ScriptIo::default();
        let hello = client_flight(&mut fixture.client, &io)?;
        let acceptor = TlsAcceptor::from(Arc::clone(&fixture.server));
        let mut acceptance = Box::pin(acceptor.accept(RecordGuard::new(io.clone(), socket)));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(progress(&mut acceptance, &mut cx).is_pending());
        let server_flight = consume_server(&mut fixture.client, &io)?;
        let finished = client_flight(&mut fixture.client, &io)?;
        let expected_end = io.0.borrow().input.len();
        let (mut encrypter, mut decrypter) = cipher_pair(&fixture, &server_flight)?;
        let _ = finished_plaintext(&mut *decrypter, &finished)?;
        let renegotiation = encrypt(&mut *encrypter, ContentType::Handshake, 1, &hello[5..])?;
        io.0.borrow_mut().input.extend_from_slice(&renegotiation);
        let Poll::Ready(Ok(mut transport)) = progress(&mut acceptance, &mut cx) else {
            return Err("guarded acceptance did not complete".into());
        };
        assert_eq!(io.0.borrow().position, expected_end);
        let version = transport.get_ref().1.protocol_version();
        assert_eq!(version, Some(ProtocolVersion::TLSv1_2));
        transport.get_mut().0.handshake_complete(version);
        let writes = io.0.borrow().writes;
        let output = io.0.borrow().output.len();
        let Poll::Ready(Err(error)) = Pin::new(&mut transport).poll_read(&mut cx, &mut [0; 64])
        else {
            return Err("guard did not reject renegotiation".into());
        };
        assert!(is_detected(&error));
        assert_eq!(io.0.borrow().position, expected_end + 5);
        assert_eq!(io.0.borrow().writes, writes);
        assert_eq!(io.0.borrow().output.len(), output);
        assert_eq!(std::io::Read::read(&mut peer, &mut [0; 1])?, 0);
        assert_rejected(transport.get_mut().0, &io, &mut cx)?;
        Ok(())
    })
}

fn assert_rejected(
    guard: &mut super::RecordGuard<ScriptIo>,
    io: &ScriptIo,
    cx: &mut Context<'_>,
) -> TestResult {
    use super::is_detected;
    let counts = {
        let m = io.0.borrow();
        (m.reads, m.writes, m.flushes, m.closes)
    };
    let Poll::Ready(Err(error)) = Pin::new(&mut *guard).poll_read(cx, &mut [0; 8]) else {
        return Err("rejected read did not fail".into());
    };
    assert!(is_detected(&error));
    let Poll::Ready(Err(error)) = Pin::new(&mut *guard).poll_write(cx, b"XML") else {
        return Err("rejected write did not fail".into());
    };
    assert!(is_detected(&error));
    let Poll::Ready(Err(error)) = Pin::new(&mut *guard).poll_flush(cx) else {
        return Err("rejected flush did not fail".into());
    };
    assert!(is_detected(&error));
    let Poll::Ready(Err(error)) = Pin::new(&mut *guard).poll_close(cx) else {
        return Err("rejected close did not fail".into());
    };
    assert!(is_detected(&error));
    let m = io.0.borrow();
    assert_eq!((m.reads, m.writes, m.flushes, m.closes), counts);
    Ok(())
}

#[test]
fn finished_with_extra_handshake_bytes_in_one_record_fails_acceptance() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for extra in [1, 4, usize::MAX] {
            let (socket, _peer) = socket_pair().await?;
            let mut fixture = fixture(&rustls::version::TLS12)?;
            let io = ScriptIo::default();
            let hello = client_flight(&mut fixture.client, &io)?;
            let acceptor = TlsAcceptor::from(Arc::clone(&fixture.server));
            let mut acceptance =
                Box::pin(acceptor.accept(super::RecordGuard::new(io.clone(), socket)));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(progress(&mut acceptance, &mut cx).is_pending());
            let server_flight = consume_server(&mut fixture.client, &io)?;
            let finished = client_flight(&mut fixture.client, &io)?;
            let (mut encrypter, mut decrypter) = cipher_pair(&fixture, &server_flight)?;
            let mut plaintext = finished_plaintext(&mut *decrypter, &finished)?;
            let extra = extra.min(hello.len() - 5);
            plaintext.extend_from_slice(&hello[5..5 + extra]);
            let start = io.0.borrow().position;
            let prefix_len = finished.len() - 5 - records(&finished)?[2].1.len();
            io.0.borrow_mut().input.truncate(start + prefix_len);
            io.0.borrow_mut().input.extend_from_slice(&encrypt(
                &mut *encrypter,
                ContentType::Handshake,
                0,
                &plaintext,
            )?);
            let Poll::Ready(Err(error)) = progress(&mut acceptance, &mut cx) else {
                return Err("unaligned Finished was accepted".into());
            };
            assert!(!super::is_detected(&error));
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        Ok(())
    })
}

#[test]
fn normal_tls12_and_tls13_exchange_application_data_and_close_cooperatively() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let (socket, _peer) = socket_pair().await?;
            let mut fixture = fixture(version)?;
            let io = ScriptIo::default();
            let acceptor = TlsAcceptor::from(Arc::clone(&fixture.server));
            let mut acceptance =
                Box::pin(acceptor.accept(super::RecordGuard::new(io.clone(), socket)));
            let mut cx = Context::from_waker(Waker::noop());
            client_flight(&mut fixture.client, &io)?;
            assert!(progress(&mut acceptance, &mut cx).is_pending());
            consume_server(&mut fixture.client, &io)?;
            client_flight(&mut fixture.client, &io)?;
            let Poll::Ready(Ok(mut transport)) = progress(&mut acceptance, &mut cx) else {
                return Err("normal acceptance did not complete".into());
            };
            let negotiated = transport.get_ref().1.protocol_version();
            assert_eq!(negotiated, Some(version.version));
            transport.get_mut().0.handshake_complete(negotiated);
            consume_server(&mut fixture.client, &io)?;
            assert!(!fixture.client.is_handshaking());
            std::io::Write::write_all(&mut fixture.client.writer(), b"client data")?;
            client_flight(&mut fixture.client, &io)?;
            let mut output = [0; 64];
            let Poll::Ready(Ok(count)) = Pin::new(&mut transport).poll_read(&mut cx, &mut output)
            else {
                return Err("missing normal client data".into());
            };
            assert_eq!(&output[..count], b"client data");
            assert!(matches!(
                Pin::new(&mut transport).poll_write(&mut cx, b"server data"),
                Poll::Ready(Ok(11))
            ));
            assert!(matches!(
                Pin::new(&mut transport).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            consume_server(&mut fixture.client, &io)?;
            let count = std::io::Read::read(&mut fixture.client.reader(), &mut output)?;
            assert_eq!(&output[..count], b"server data");
            assert!(matches!(
                Pin::new(&mut transport).poll_close(&mut cx),
                Poll::Ready(Ok(()))
            ));
            consume_server(&mut fixture.client, &io)?;
            assert_eq!(
                std::io::Read::read(&mut fixture.client.reader(), &mut output)?,
                0
            );
            fixture.client.send_close_notify();
            client_flight(&mut fixture.client, &io)?;
            assert!(matches!(
                Pin::new(&mut transport).poll_read(&mut cx, &mut output),
                Poll::Ready(Ok(0))
            ));
            assert_eq!(io.0.borrow().closes, 1);
        }
        Ok(())
    })
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![typ, 3, 3];
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn framing_preserves_fragmented_and_adjacent_records_with_exact_acceptance_yields() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for limit in 1..=13 {
            for accepting in [false, true] {
                let (socket, _peer) = socket_pair().await?;
                let io = ScriptIo::default();
                let mut input = record(if accepting { 22 } else { 23 }, &[22, 0, 22, 3, 3, 0, 0]);
                input.extend_from_slice(&record(21, &[22, 0]));
                input.extend_from_slice(&record(23, &[]));
                {
                    let mut memory = io.0.borrow_mut();
                    memory.input = input.clone();
                    memory.read_limit = Some(limit);
                }
                let mut guard = super::RecordGuard::new(io.clone(), socket);
                if !accepting {
                    guard.handshake_complete(Some(ProtocolVersion::TLSv1_2));
                }
                let mut output = [0; 64];
                let mut received = Vec::new();
                let mut yields = 0;
                let mut cx = Context::from_waker(Waker::noop());
                while received.len() < input.len() || guard.yield_boundary {
                    let reads = io.0.borrow().reads;
                    assert!(matches!(
                        Pin::new(&mut guard).poll_read(&mut cx, &mut []),
                        Poll::Ready(Ok(0))
                    ));
                    assert_eq!(io.0.borrow().reads, reads);
                    match Pin::new(&mut guard).poll_read(&mut cx, &mut output) {
                        Poll::Ready(Ok(count)) => {
                            assert!(count > 0);
                            received.extend_from_slice(&output[..count]);
                        }
                        Poll::Pending => {
                            assert_eq!(io.0.borrow().reads, reads);
                            yields += 1;
                        }
                        Poll::Ready(Err(error)) => return Err(error.into()),
                    }
                }
                assert_eq!(received, input);
                assert_eq!(yields, if accepting { 3 } else { 0 });
            }
        }
        Ok(())
    })
}

#[test]
fn every_header_split_rejects_at_first_byte_after_arming_and_never_polls_again() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        for limit in 1..=5 {
            let (socket, mut peer) = socket_pair().await?;
            let io = ScriptIo::default();
            {
                let mut memory = io.0.borrow_mut();
                memory.input = record(22, &[1, 0, 0, 0]);
                memory.read_limit = Some(limit);
            }
            let mut guard = super::RecordGuard::new(io.clone(), socket);
            guard.handshake_complete(Some(ProtocolVersion::TLSv1_2));
            let mut cx = Context::from_waker(Waker::noop());
            let Poll::Ready(Err(error)) = Pin::new(&mut guard).poll_read(&mut cx, &mut [0; 64])
            else {
                return Err("handshake header escaped guard".into());
            };
            assert!(super::is_detected(&error));
            assert_eq!(io.0.borrow().position, limit);
            assert_eq!(std::io::Read::read(&mut peer, &mut [0; 1])?, 0);
            assert_rejected(&mut guard, &io, &mut cx)?;
        }
        Ok(())
    })
}

#[derive(Debug)]
struct OrdinaryFailure;
impl std::fmt::Display for OrdinaryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ordinary failure")
    }
}
impl Error for OrdinaryFailure {}

#[test]
fn pending_cancellation_eof_and_ordinary_errors_keep_record_progress() -> TestResult {
    use futures_util::io::AsyncReadExt as _;
    use futures_util::poll;
    compio::runtime::Runtime::new()?.block_on(async {
        for prefix in 0..=8 {
            let (socket, _peer) = socket_pair().await?;
            let io = ScriptIo::default();
            let input = record(23, &[22, 7, 8, 9]);
            io.0.borrow_mut().input.extend_from_slice(&input[..prefix]);
            let mut guard = super::RecordGuard::new(io.clone(), socket);
            guard.handshake_complete(Some(ProtocolVersion::TLSv1_2));
            let mut output = [0; 64];
            let mut received = Vec::new();
            let mut cx = Context::from_waker(Waker::noop());
            while io.0.borrow().position < prefix {
                let Poll::Ready(Ok(count)) = Pin::new(&mut guard).poll_read(&mut cx, &mut output)
                else {
                    return Err("prefix did not advance".into());
                };
                received.extend_from_slice(&output[..count]);
            }
            {
                let mut cancelled = Box::pin(guard.read(&mut output));
                assert!(poll!(cancelled.as_mut()).is_pending());
            }
            let state = (guard.header, guard.header_used, guard.remaining);
            io.0.borrow_mut().error =
                Some(io::Error::new(io::ErrorKind::InvalidData, OrdinaryFailure));
            let Poll::Ready(Err(error)) = Pin::new(&mut guard).poll_read(&mut cx, &mut output)
            else {
                return Err("ordinary error disappeared".into());
            };
            assert!(
                error
                    .get_ref()
                    .is_some_and(|error| error.is::<OrdinaryFailure>())
            );
            assert_eq!((guard.header, guard.header_used, guard.remaining), state);
            io.0.borrow_mut().eof = true;
            assert!(matches!(
                Pin::new(&mut guard).poll_read(&mut cx, &mut output),
                Poll::Ready(Ok(0))
            ));
            assert_eq!((guard.header, guard.header_used, guard.remaining), state);
            io.0.borrow_mut().eof = false;
            io.0.borrow_mut().input.extend_from_slice(&input[prefix..]);
            while received.len() < input.len() {
                let Poll::Ready(Ok(count)) = Pin::new(&mut guard).poll_read(&mut cx, &mut output)
                else {
                    return Err("repoll did not resume record".into());
                };
                received.extend_from_slice(&output[..count]);
            }
            assert_eq!(received, input);
        }
        Ok(())
    })
}

fn session(
    transport: super::super::session::TlsTransport,
    socket: compio::net::TcpStream,
) -> TestResult<super::super::session::Session<lonewolf_util::arena::GlobalChunkAllocator>> {
    use super::super::session::{ClosingInput, ReadMode, Session};
    use super::super::stanza_rate::StanzaLimiter;
    use futures_util::FutureExt as _;
    use futures_util::io::AsyncReadExt as _;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_util::rate_limited_reader::RateLimitedReader;
    use lonewolf_xmpp::parser::{ParserConfig, XmppParser};
    use std::cell::Cell;
    use std::num::NonZeroUsize;
    use tokio_util::compat::FuturesAsyncReadCompatExt as _;
    let (read, write) = transport.split();
    let closing = Rc::new(Cell::new(ReadMode::Open));
    let parser = XmppParser::new(
        ClosingInput::new(
            RateLimitedReader::new(
                tokio::io::BufReader::new(read.compat()),
                NonZeroUsize::MAX,
                NonZeroUsize::MAX,
            ),
            Rc::clone(&closing),
        ),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid stanza size")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    Ok(Session::new(
        parser,
        write,
        "localhost".into(),
        StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
        closing,
        super::super::close::CloseContext {
            socket,
            shutdown: std::future::pending::<std::time::Instant>()
                .boxed_local()
                .shared(),
            phase_deadline: None,
        },
    ))
}

#[test]
fn tls_detection_during_first_header_and_sasl_restart_skips_rejection_xml() -> TestResult {
    use super::super::outcome::CloseOutcome;
    use compio::io::compat::AsyncStream;
    compio::runtime::Runtime::new()?.block_on(async {
        for restarted in [false, true] {
            let (socket, peer) = socket_pair().await?;
            let fixture = fixture(&rustls::version::TLS12)?;
            let (trigger, wait) = std::sync::mpsc::channel();
            let client = std::thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
                let mut tls = rustls::StreamOwned::new(fixture.client, peer);
                while tls.conn.is_handshaking() { tls.conn.complete_io(&mut tls.sock)?; }
                if restarted {
                    std::io::Write::write_all(&mut tls, b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>")?;
                    std::io::Write::flush(&mut tls)?;
                }
                wait.recv_timeout(std::time::Duration::from_secs(2))?;
                std::io::Write::write_all(&mut tls.sock, &[22])?;
                assert_eq!(std::io::Read::read(&mut tls.sock, &mut [0; 128])?, 0);
                Ok(())
            });
            let mut transport = TlsAcceptor::from(fixture.server)
                .accept(super::RecordGuard::new(Box::pin(AsyncStream::new(socket.clone())), socket.clone()))
                .await?;
            let version = transport.get_ref().1.protocol_version();
            transport.get_mut().0.handshake_complete(version);
            let mut session = session(transport, socket)?;
            let config = crate::config::Config::default();
            let hosts = crate::hosts::Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
            if restarted {
                assert!(session.read_header(&hosts).await.is_ok());
                session.restart()?;
            }
            trigger.send(())?;
            assert!(matches!(session.read_header(&hosts).await, Err(CloseOutcome::TlsFailure)));
            assert!(!session.writer.is_open());
            assert!(session.writer.is_intact());
            assert_eq!(session.finish(CloseOutcome::TlsFailure).await, CloseOutcome::TlsFailure);
            client.join().map_err(|_| "client thread panicked")?.map_err(|error| -> Box<dyn Error> { error })?;
        }
        Ok(())
    })
}

struct ErrorInput(io::Error);

impl tokio::io::AsyncRead for ErrorInput {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(std::mem::replace(
            &mut self.get_mut().0,
            io::Error::other("input failed"),
        )))
    }
}

#[test]
fn real_parser_preserves_only_the_exact_detection_marker_as_tls_failure() -> TestResult {
    use super::super::outcome::CloseOutcome;
    use super::super::session::Reader;
    use super::super::stanza_rate::StanzaLimiter;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, XmppParser};
    use std::num::NonZeroUsize;
    compio::runtime::Runtime::new()?.block_on(async {
        for (error, expected) in [
            (super::rejection(), CloseOutcome::TlsFailure),
            (io::Error::new(io::ErrorKind::InvalidData, "TLS renegotiation is unsupported"), CloseOutcome::TransportError),
            (io::Error::new(io::ErrorKind::BrokenPipe, OrdinaryFailure), CloseOutcome::TransportError),
        ] {
            let mut reader = Reader::new(XmppParser::new(
                tokio::io::BufReader::new(ErrorInput(error)),
                ParserConfig { max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid stanza size")?, arena: ArenaConfig::default() },
                GlobalChunkAllocator,
            ), StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN));
            assert!(matches!(reader.next_event().await, Err(outcome) if outcome == expected));
        }
        let mut parser = XmppParser::new(Cursor::new(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' broken=>"),
            ParserConfig { max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid stanza size")?, arena: ArenaConfig::default() }, GlobalChunkAllocator);
        let error = parser.next_event().await.err().ok_or("malformed header accepted")?;
        assert!(!error.is_transport_error());
        assert_eq!(CloseOutcome::from_parse_error(&error), CloseOutcome::NotWellFormed);
        Ok(())
    })
}

#[test]
fn writer_send_flush_rejection_header_and_stanza_keep_the_detection_marker() -> TestResult {
    use super::super::header::ResponseVersion;
    use super::super::outcome::CloseOutcome;
    use super::super::session::Writer;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
    use std::num::NonZeroUsize;
    compio::runtime::Runtime::new()?.block_on(async {
        for operation in 0..4 {
            let (socket, _peer) = socket_pair().await?;
            let io = ScriptIo::default();
            let mut guard = super::RecordGuard::new(io.clone(), socket);
            guard.handshake_complete(Some(ProtocolVersion::TLSv1_2));
            let error = guard.reject();
            assert!(super::is_detected(&error));
            let mut writer = Writer::new(guard, "localhost".into());
            let result = match operation {
                0 => writer.send("<message/>").await,
                1 => writer.flush().await,
                2 => Err(writer.reject_header(None, false, ResponseVersion::Current, CloseOutcome::ParserError).await),
                _ => {
                    let xml = format!("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><message><body>{}</body></message>", "x".repeat(8192));
                    let mut parser = XmppParser::new(Cursor::new(xml.into_bytes()), ParserConfig { max_stanza_bytes: NonZeroUsize::new(16384).ok_or("invalid stanza size")?, arena: ArenaConfig::default() }, GlobalChunkAllocator);
                    parser.next_event().await?;
                    let Some(StreamEvent::Stanza(stanza)) = parser.next_event().await? else { return Err("no stanza".into()); };
                    writer.write_stanza(&stanza.value().resolve(stanza.arena())?).await
                }
            };
            assert_eq!(result, Err(CloseOutcome::TlsFailure));
            assert!(!writer.is_open());
            assert!(!writer.is_intact());
            assert_eq!(io.0.borrow().writes, 0);
        }
        Ok(())
    })
}

#[test]
fn tls_close_preserves_detection_and_phase_timeout_precedence() -> TestResult {
    use super::super::close::{CloseContext, finish_tls};
    use super::super::outcome::CloseOutcome;
    use compio::io::compat::AsyncStream;
    use futures_util::FutureExt as _;
    compio::runtime::Runtime::new()?.block_on(async {
        for outcome in [CloseOutcome::StreamEnd, CloseOutcome::AuthenticationTimeout] {
            let (socket, peer) = socket_pair().await?;
            let fixture = fixture(&rustls::version::TLS12)?;
            let client = std::thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
                let mut tls = rustls::StreamOwned::new(fixture.client, peer);
                assert_eq!(std::io::Read::read(&mut tls, &mut [0; 1])?, 0);
                std::io::Write::write_all(&mut tls.sock, &[22])?;
                assert_eq!(std::io::Read::read(&mut tls.sock, &mut [0; 128])?, 0);
                Ok(())
            });
            let mut transport = TlsAcceptor::from(fixture.server)
                .accept(super::RecordGuard::new(
                    Box::pin(AsyncStream::new(socket.clone())),
                    socket.clone(),
                ))
                .await?;
            let version = transport.get_ref().1.protocol_version();
            transport.get_mut().0.handshake_complete(version);
            let context = CloseContext {
                socket,
                shutdown: std::future::pending::<std::time::Instant>()
                    .boxed_local()
                    .shared(),
                phase_deadline: None,
            };
            assert_eq!(
                finish_tls(&mut transport, outcome, &context).await,
                if outcome.is_phase_timeout() {
                    outcome
                } else {
                    CloseOutcome::TlsFailure
                }
            );
            client
                .join()
                .map_err(|_| "client thread panicked")?
                .map_err(|error| -> Box<dyn Error> { error })?;
        }
        Ok(())
    })
}
