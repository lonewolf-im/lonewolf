// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use compio::runtime::Runtime;
use compio::time::timeout;
use hmac::{Hmac, KeyInit, Mac};
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::account::{AccountWrites, NewAccount};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use redb::{ReadableTable, TableDefinition};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::authenticate::{SASL_NAMESPACE, account_key, decoy_identity};
use super::establish::{STARTTLS_FEATURES, STARTTLS_NAMESPACE, STARTTLS_PROCEED};
use super::header::STREAM_FOOTER;
use super::*;
use crate::c2s::connection_limit::{ConnectionAdmission, ConnectionLimiter};
use crate::c2s::unauthenticated_limit::{
    Admission as UnauthenticatedAdmission, UnauthenticatedLimiter,
};
use crate::config::Config;
use crate::hosts::HostsError;
use crate::router::Router;
use crate::router::local::LocalRouter;

const TIMEOUT: Duration = Duration::from_secs(5);
const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
const PSI_OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0' xmlns='jabber:client' xml:lang='es' xmlns:xml='http://www.w3.org/XML/1998/namespace'>";
const CLOSE: &str = "</stream:stream>";
const MAX_STANZA_BYTES: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();
static LOG_SUBSCRIBER: OnceLock<Result<(), String>> = OnceLock::new();

thread_local! {
    static LOG_CAPTURE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        LOG_CAPTURE.with(|capture| {
            if let Some(output) = capture.borrow_mut().as_mut() {
                output.extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_logs<R>(run: impl FnOnce() -> R) -> io::Result<(R, String)> {
    LOG_SUBSCRIBER
        .get_or_init(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .without_time()
                .with_max_level(tracing::Level::INFO)
                .with_writer(|| LogWriter)
                .finish();
            tracing::subscriber::set_global_default(subscriber).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))?;
    LOG_CAPTURE.with(|capture| {
        if capture.borrow().is_some() {
            return Err(io::Error::other("nested log capture"));
        }
        capture.replace(Some(Vec::new()));
        let result = run();
        let bytes = capture
            .replace(None)
            .ok_or_else(|| io::Error::other("log capture missing"))?;
        Ok((result, String::from_utf8(bytes).map_err(io::Error::other)?))
    })
}

fn hosts() -> Result<Hosts, HostsError> {
    let config = Config::default();
    Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())
}

async fn test_router(
    hosts: &Hosts,
) -> std::io::Result<(Router<GlobalChunkAllocator>, CoreDispatcher)> {
    let dispatcher = CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)?;
    let local = LocalRouter::start(&dispatcher.handle(), GlobalChunkAllocator).await?;
    Ok((Router::new(hosts.clone(), local), dispatcher))
}

fn auth() -> std::io::Result<(Arc<AuthService>, tempfile::TempDir)> {
    let (auth, _database, directory) = auth_with_database()?;
    Ok((auth, directory))
}

fn auth_with_database() -> std::io::Result<(Arc<AuthService>, RedbStorage, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let storage =
        RedbStorage::open(directory.path().join("accounts.redb")).map_err(std::io::Error::other)?;
    Ok((
        Arc::new(AuthService {
            storage: storage.clone(),
        }),
        storage,
        directory,
    ))
}

fn run_case_with_rate(
    input: &[u8],
    shutdown_write: bool,
    max_stanza_bytes: NonZeroUsize,
    xml_rate: &ByteRate,
) -> Result<(CloseOutcome, Duration, String), Box<dyn Error>> {
    run_case_with_timeouts(
        input,
        shutdown_write,
        max_stanza_bytes,
        xml_rate,
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
}

fn run_case_with_timeouts(
    input: &[u8],
    shutdown_write: bool,
    max_stanza_bytes: NonZeroUsize,
    xml_rate: &ByteRate,
    establishment_timeout: Duration,
    authentication_timeout: Duration,
) -> Result<(CloseOutcome, Duration, String), Box<dyn Error>> {
    Runtime::new()?.block_on(timeout(TIMEOUT, async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let address = listener.local_addr()?;
        let mut client = StdTcpStream::connect(address)?;
        client.set_read_timeout(Some(TIMEOUT))?;
        client.write_all(input)?;
        if shutdown_write {
            client.shutdown(Shutdown::Write)?;
        }
        let (transport, peer) = listener.accept().await?;
        let limiter = ConnectionLimiter::new(1);
        let ConnectionAdmission::Allowed(permit) = limiter.reserve(peer.ip(), Instant::now()).await
        else {
            return Err("first connection was denied".into());
        };
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let UnauthenticatedAdmission::Allowed(unauthenticated_permit) =
            unauthenticated.reserve(Instant::now()).await
        else {
            return Err("first unauthenticated connection was denied".into());
        };
        let hosts = hosts()?;
        let (auth, _directory) = auth()?;
        let (router, router_dispatcher) = test_router(&hosts).await?;
        let started = Instant::now();
        let stream = XmppStream::new(
            transport,
            StreamAdmission::new(permit, unauthenticated_permit, 0, 0),
            hosts.clone(),
            auth,
            router.handle(),
            StreamSettings::new(
                AuthMechanisms::ALL,
                max_stanza_bytes,
                &crate::config::limits::C2sLimitProfile::default().incoming_stanzas_per_connection,
                xml_rate,
                StreamTimeouts {
                    establishment: establishment_timeout,
                    authentication: authentication_timeout,
                    binding: Duration::from_secs(10),
                },
                NonZeroUsize::new(10).unwrap(),
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
        router.shutdown().await?;
        router_dispatcher.shutdown(TIMEOUT).await?;
        let elapsed = started.elapsed();
        assert!(matches!(
            limiter.reserve(peer.ip(), Instant::now()).await,
            ConnectionAdmission::Allowed(_)
        ));
        assert!(matches!(
            unauthenticated.reserve(Instant::now()).await,
            UnauthenticatedAdmission::Allowed(_)
        ));
        let mut response = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            match client.read(&mut buffer) {
                Ok(0) => break,
                Ok(amount) => response.extend_from_slice(&buffer[..amount]),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => return Err(error.into()),
            }
        }
        let response = String::from_utf8(response)?;
        listener.close().await?;
        Ok((outcome, elapsed, response))
    }))?
}

#[test]
fn elapsed_and_overflowed_phase_deadlines_have_no_remaining_time() {
    let now = Instant::now();
    assert_eq!(phase_remaining(now, Duration::ZERO), Duration::ZERO);
    assert_eq!(phase_remaining(now, Duration::MAX), Duration::ZERO);
}

fn read_through(stream: &mut impl Read, marker: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut byte = [0];
    while response.len() < 16 * 1024 && !response.ends_with(marker) {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    if response.ends_with(marker) {
        Ok(response)
    } else {
        Err(std::io::Error::other("response marker missing"))
    }
}

fn run_starttls_restart_case_with_timeout(
    restart_open: &str,
    authentication_timeout: Duration,
    wait_for_timeout: bool,
) -> Result<(CloseOutcome, String, String), Box<dyn Error + Send + Sync>> {
    let restart_open = restart_open.to_owned();
    Runtime::new()?.block_on(timeout(TIMEOUT, async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let hosts = hosts()?;
        let mut roots = RootCertStore::empty();
        let certificate = hosts
            .certified_key("localhost")
            .ok_or("missing certificate")?
            .cert[0]
            .clone();
        roots.add(certificate)?;
        let tls_config =
            ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let address = listener.local_addr()?;
        let client = std::thread::spawn(
            move || -> Result<(String, String), Box<dyn Error + Send + Sync>> {
                let mut socket = StdTcpStream::connect(address)?;
                socket.set_read_timeout(Some(TIMEOUT))?;
                socket.set_write_timeout(Some(TIMEOUT))?;
                socket.write_all(PSI_OPEN.as_bytes())?;
                let response = read_through(&mut socket, b"</stream:features>")?;
                let before_tls = String::from_utf8(response)?;
                socket.write_all(format!("<starttls xmlns='{STARTTLS_NAMESPACE}'/>").as_bytes())?;
                assert_eq!(
                    read_through(&mut socket, STARTTLS_PROCEED.as_bytes())?,
                    STARTTLS_PROCEED.as_bytes()
                );
                let connection = ClientConnection::new(
                    Arc::new(tls_config),
                    ServerName::try_from("localhost")?,
                )?;
                let mut tls = StreamOwned::new(connection, socket);
                tls.write_all(restart_open.as_bytes())?;
                let mut after_tls = if restart_open == PSI_OPEN {
                    let features = read_through(&mut tls, b"</stream:features>")?;
                    if wait_for_timeout {
                        std::thread::sleep(authentication_timeout + Duration::from_millis(50));
                        return Ok((before_tls, String::from_utf8(features)?));
                    }
                    tls.write_all(CLOSE.as_bytes())?;
                    String::from_utf8(features)?
                } else {
                    String::new()
                };
                after_tls.push_str(&String::from_utf8(read_through(
                    &mut tls,
                    CLOSE.as_bytes(),
                )?)?);
                if restart_open != PSI_OPEN {
                    tls.write_all(CLOSE.as_bytes())?;
                }
                tls.conn.send_close_notify();
                tls.flush()?;
                tls.read_to_string(&mut after_tls)?;
                Ok((before_tls, after_tls))
            },
        );
        let (transport, peer) = listener.accept().await?;
        let limiter = ConnectionLimiter::new(1);
        let ConnectionAdmission::Allowed(permit) = limiter.reserve(peer.ip(), Instant::now()).await
        else {
            return Err("first connection was denied".into());
        };
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let UnauthenticatedAdmission::Allowed(unauthenticated_permit) =
            unauthenticated.reserve(Instant::now()).await
        else {
            return Err("first unauthenticated connection was denied".into());
        };
        let (auth, _directory) = auth()?;
        let (router, router_dispatcher) = test_router(&hosts).await?;
        let stream = XmppStream::new(
            transport,
            StreamAdmission::new(permit, unauthenticated_permit, 0, 0),
            hosts,
            auth,
            router.handle(),
            StreamSettings::new(
                AuthMechanisms::ALL,
                MAX_STANZA_BYTES,
                &crate::config::limits::C2sLimitProfile::default().incoming_stanzas_per_connection,
                &ByteRate::default(),
                StreamTimeouts {
                    establishment: Duration::from_secs(10),
                    authentication: authentication_timeout,
                    binding: Duration::from_secs(10),
                },
                NonZeroUsize::new(10).unwrap(),
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
        router.shutdown().await?;
        router_dispatcher.shutdown(TIMEOUT).await?;
        let (before_tls, after_tls) = client.join().map_err(|_| "client thread panicked")??;
        listener.close().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>((outcome, before_tls, after_tls))
    }))?
}

#[test]
fn authentication_deadline_starts_after_sasl_offer() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (outcome, before_tls, after_tls) =
        run_starttls_restart_case_with_timeout(PSI_OPEN, Duration::from_millis(50), true)?;
    assert_eq!(outcome, CloseOutcome::AuthenticationTimeout);
    assert!(before_tls.contains(STARTTLS_FEATURES));
    assert!(after_tls.contains(sasl_features(AuthMechanisms::ALL).as_str()));
    Ok(())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn hmac_scram(
    hash: ScramHash,
    key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    match hash {
        ScramHash::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key)?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        ScramHash::Sha256 => Ok(hmac_sha256(key, message)?.to_vec()),
    }
}

fn run_sasl_case_with_iterations<F>(
    tls_open: &str,
    stored_iterations: Option<u32>,
    mechanisms: AuthMechanisms,
    exchange: F,
) -> Result<CloseOutcome, Box<dyn Error + Send + Sync>>
where
    F: FnOnce(
            &mut StreamOwned<ClientConnection, StdTcpStream>,
        ) -> Result<(), Box<dyn Error + Send + Sync>>
        + Send
        + 'static,
{
    let tls_open = tls_open.to_owned();
    Runtime::new()?.block_on(timeout(TIMEOUT, async {
        let hosts = hosts()?;
        let mut roots = RootCertStore::empty();
        roots.add(
            hosts
                .certified_key("localhost")
                .ok_or("no certificate")?
                .cert[0]
                .clone(),
        )?;
        let tls_config =
            ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let address = listener.local_addr()?;
        let client = std::thread::spawn(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut socket = StdTcpStream::connect(address)?;
            socket.set_read_timeout(Some(TIMEOUT))?;
            socket.set_write_timeout(Some(TIMEOUT))?;
            socket.write_all(PSI_OPEN.as_bytes())?;
            read_through(&mut socket, b"</stream:features>")?;
            socket.write_all(format!("<starttls xmlns='{STARTTLS_NAMESPACE}'/>").as_bytes())?;
            read_through(&mut socket, STARTTLS_PROCEED.as_bytes())?;
            let connection =
                ClientConnection::new(Arc::new(tls_config), ServerName::try_from("localhost")?)?;
            let mut tls = StreamOwned::new(connection, socket);
            tls.write_all(tls_open.as_bytes())?;
            read_through(&mut tls, b"</stream:features>")?;
            exchange(&mut tls)
        });
        let (transport, peer) = listener.accept().await?;
        let limiter = ConnectionLimiter::new(1);
        let ConnectionAdmission::Allowed(permit) = limiter.reserve(peer.ip(), Instant::now()).await
        else {
            return Err("connection denied".into());
        };
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let UnauthenticatedAdmission::Allowed(unauthenticated_permit) =
            unauthenticated.reserve(Instant::now()).await
        else {
            return Err("unauthenticated connection denied".into());
        };
        let (auth, database, _directory) = auth_with_database()?;
        if let Some(stored_iterations) = stored_iterations {
            let key = account_key("alice", "localhost").ok_or("invalid account key")?;
            let verifier = ScramVerifier::derive(
                ScramHash::Sha256,
                "pencil",
                [7; 16],
                ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?,
            )?;
            let mut transaction = auth.storage.begin_write().await?;
            transaction
                .create_account(NewAccount {
                    key: key.clone(),
                    credentials: ScramCredentials::new(verifier),
                })
                .await?;
            transaction.commit().await?;
            if stored_iterations != SCRAM_POLICY_ITERATIONS.get() {
                let transaction = database.as_ref().begin_write()?;
                {
                    let mut table = transaction
                        .open_table(TableDefinition::<&str, &[u8]>::new("lonewolf_accounts"))?;
                    let mut record = table
                        .get(key.as_str())?
                        .ok_or("missing account record")?
                        .value()
                        .to_vec();
                    record[18..22].copy_from_slice(&stored_iterations.to_le_bytes());
                    table.insert(key.as_str(), record.as_slice())?;
                }
                transaction.commit()?;
            }
        }
        let (router, router_dispatcher) = test_router(&hosts).await?;
        let outcome = XmppStream::new(
            transport,
            StreamAdmission::new(permit, unauthenticated_permit, 0, 0),
            hosts,
            auth,
            router.handle(),
            StreamSettings::new(
                mechanisms,
                MAX_STANZA_BYTES,
                &crate::config::limits::C2sLimitProfile::default().incoming_stanzas_per_connection,
                &ByteRate::default(),
                StreamTimeouts {
                    establishment: Duration::from_secs(10),
                    authentication: Duration::from_secs(10),
                    binding: Duration::from_secs(10),
                },
                NonZeroUsize::new(10).unwrap(),
                GlobalChunkAllocator,
            ),
        )
        .run()
        .await;
        router.shutdown().await?;
        router_dispatcher.shutdown(TIMEOUT).await?;
        client.join().map_err(|_| "client thread panicked")??;
        listener.close().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(outcome)
    }))?
}

fn sasl_auth(mechanism: &str, first: &str) -> String {
    format!(
        "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{}</auth>",
        STANDARD.encode(first)
    )
}

fn sasl_challenge(tls: &mut impl Read) -> Result<String, Box<dyn Error + Send + Sync>> {
    let challenge = String::from_utf8(read_through(tls, b"</challenge>")?)?;
    let encoded = challenge
        .split_once('>')
        .ok_or("invalid challenge")?
        .1
        .strip_suffix("</challenge>")
        .ok_or("invalid challenge")?;
    Ok(String::from_utf8(STANDARD.decode(encoded)?)?)
}

#[test]
fn legacy_iteration_account_gets_decoy_challenge_and_cannot_log_in()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let outcome =
        run_sasl_case_with_iterations(PSI_OPEN, Some(4096), AuthMechanisms::ALL, |tls| {
            tls.write_all(sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=clientnonce").as_bytes())?;
            let challenge = sasl_challenge(tls)?;
            let (nonce, parameters) = challenge
                .split_once(",s=")
                .ok_or("missing challenge salt")?;
            let (encoded_salt, iterations) = parameters
                .split_once(",i=")
                .ok_or("missing challenge iterations")?;
            assert_eq!(iterations, SCRAM_POLICY_ITERATIONS.get().to_string());
            assert_ne!(encoded_salt, STANDARD.encode([7; 16]));
            let salt = STANDARD.decode(encoded_salt)?;
            let mut salted = [0; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(
                b"pencil",
                &salt,
                SCRAM_POLICY_ITERATIONS.get(),
                &mut salted,
            );
            let client_key = hmac_scram(ScramHash::Sha256, &salted, b"Client Key")?;
            let stored_key = Sha256::digest(&client_key);
            let without_proof = format!("c=biws,{nonce}");
            let auth_message = format!("n=alice,r=clientnonce,{challenge},{without_proof}");
            let signature = hmac_scram(ScramHash::Sha256, &stored_key, auth_message.as_bytes())?;
            let mut proof = client_key;
            for (byte, signature) in proof.iter_mut().zip(signature) {
                *byte ^= signature;
            }
            let response = format!("{without_proof},p={}", STANDARD.encode(proof));
            tls.write_all(
                format!(
                    "<response xmlns='{SASL_NAMESPACE}'>{}</response>",
                    STANDARD.encode(response)
                )
                .as_bytes(),
            )?;
            let failure = String::from_utf8(read_through(tls, b"</failure>")?)?;
            assert!(failure.contains("<not-authorized/>"), "{failure}");
            tls.write_all(CLOSE.as_bytes())?;
            let rest = String::from_utf8(read_through(tls, CLOSE.as_bytes())?)?;
            tls.conn.send_close_notify();
            tls.flush()?;
            assert!(rest.ends_with(STREAM_FOOTER));
            Ok(())
        })?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    Ok(())
}

#[test]
fn decoy_identity_separates_hosts_and_invalid_account_names()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let localhost = account_key("Alice", "localhost").ok_or("invalid account key")?;
    let other_host = account_key("alice", "other.example").ok_or("invalid account key")?;
    assert_eq!(
        decoy_identity(Some(&localhost), "Alice", "localhost"),
        decoy_identity(Some(&localhost), "alice", "localhost")
    );
    assert_ne!(
        decoy_identity(Some(&localhost), "Alice", "localhost"),
        decoy_identity(Some(&other_host), "alice", "other.example")
    );
    assert_ne!(
        decoy_identity(None, "Alice", "localhost"),
        decoy_identity(Some(&localhost), "alice", "localhost")
    );
    Ok(())
}

#[test]
fn stream_whitespace_consumes_xml_allowance() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN} {CLOSE}");
    let rate = ByteRate {
        bytes_per_second: NonZeroUsize::new(10).ok_or("invalid rate")?,
        burst_bytes: NonZeroUsize::new(OPEN.len() + CLOSE.len()).ok_or("invalid burst")?,
    };
    let (outcome, elapsed, _) =
        run_case_with_rate(input.as_bytes(), false, MAX_STANZA_BYTES, &rate)?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    assert!(elapsed >= Duration::from_millis(50));
    Ok(())
}

#[test]
fn cancelled_rate_wait_releases_connection() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let mut client = StdTcpStream::connect(listener.local_addr()?)?;
        client.write_all(OPEN.as_bytes())?;
        let (transport, peer) = listener.accept().await?;
        let limiter = ConnectionLimiter::new(1);
        let ConnectionAdmission::Allowed(permit) = limiter.reserve(peer.ip(), Instant::now()).await
        else {
            return Err("first connection was denied".into());
        };
        let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
        let UnauthenticatedAdmission::Allowed(unauthenticated_permit) =
            unauthenticated.reserve(Instant::now()).await
        else {
            return Err("first unauthenticated connection was denied".into());
        };
        let rate = ByteRate {
            bytes_per_second: NonZeroUsize::MIN,
            burst_bytes: NonZeroUsize::MIN,
        };
        let hosts = hosts()?;
        let (auth, _directory) = auth()?;
        let (router, router_dispatcher) = test_router(&hosts).await?;
        let stream = XmppStream::new(
            transport,
            StreamAdmission::new(permit, unauthenticated_permit, 0, 0),
            hosts.clone(),
            auth,
            router.handle(),
            StreamSettings::new(
                AuthMechanisms::ALL,
                MAX_STANZA_BYTES,
                &crate::config::limits::C2sLimitProfile::default().incoming_stanzas_per_connection,
                &rate,
                StreamTimeouts {
                    establishment: Duration::from_secs(10),
                    authentication: Duration::from_secs(10),
                    binding: Duration::from_secs(10),
                },
                NonZeroUsize::new(10).unwrap(),
                GlobalChunkAllocator,
            ),
        );
        assert!(
            timeout(Duration::from_millis(20), stream.run())
                .await
                .is_err()
        );
        assert!(matches!(
            limiter.reserve(peer.ip(), Instant::now()).await,
            ConnectionAdmission::Allowed(_)
        ));
        assert!(matches!(
            unauthenticated.reserve(Instant::now()).await,
            UnauthenticatedAdmission::Allowed(_)
        ));
        listener.close().await?;
        router.shutdown().await?;
        router_dispatcher.shutdown(TIMEOUT).await?;
        Ok::<_, Box<dyn Error>>(())
    })
}

#[test]
fn cancelled_binding_phase_logs_disconnection() -> io::Result<()> {
    let ((), logs) = capture_logs(|| {
        drop(ConnectionLifecycle {
            connection_id: 7,
            listener_id: 2,
            worker_id: 3,
            accepted_at: Instant::now(),
            stream_phase: "binding",
            outcome: None,
        });
    })?;
    assert!(logs.contains("stream disconnected"), "{logs}");
    assert!(logs.contains("connection_type=\"c2s\""), "{logs}");
    assert!(logs.contains("stream_phase=\"binding\""), "{logs}");
    assert!(logs.contains("outcome=\"cancelled\""), "{logs}");
    Ok(())
}

#[test]
fn unpolled_admission_logs_disconnection() -> Result<(), Box<dyn Error>> {
    let (result, logs) = capture_logs(|| {
        Runtime::new()?.block_on(async {
            let limiter = ConnectionLimiter::new(1);
            let ConnectionAdmission::Allowed(permit) = limiter
                .reserve(Ipv4Addr::LOCALHOST.into(), Instant::now())
                .await
            else {
                return Err("connection denied".into());
            };
            let unauthenticated = Arc::new(UnauthenticatedLimiter::new(NonZeroUsize::MIN));
            let UnauthenticatedAdmission::Allowed(unauthenticated_permit) =
                unauthenticated.reserve(Instant::now()).await
            else {
                return Err("unauthenticated connection denied".into());
            };
            drop(StreamAdmission::new(permit, unauthenticated_permit, 2, 3));
            assert_eq!(unauthenticated.active_count(), 0);
            Ok::<_, Box<dyn Error>>(())
        })
    })?;
    result?;
    assert!(logs.contains("stream disconnected"), "{logs}");
    assert!(logs.contains("connection_type=\"c2s\""), "{logs}");
    assert!(logs.contains("listener_id=2"), "{logs}");
    assert!(logs.contains("worker_id=3"), "{logs}");
    assert!(logs.contains("outcome=\"cancelled\""), "{logs}");
    Ok(())
}

#[test]
fn internal_failure_sends_a_stream_error_before_closing() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let output = super::header::stream_error_xml(CloseOutcome::InternalError).ok_or("missing error")?;
        assert_eq!(output, "<stream:error><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>");
        Ok(())
    })
}

#[test]
fn panicking_phase_closes_its_socket_before_waiting_for_tracked_work() -> Result<(), Box<dyn Error>>
{
    Runtime::new()?.block_on(async {
        let listener = crate::c2s::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let mut client = StdTcpStream::connect(listener.local_addr()?)?;
        client.set_read_timeout(Some(Duration::from_secs(1)))?;
        let (transport, _) = listener.accept().await?;
        let mut work = crate::delivery::WorkGroup::new();
        let guard = work.start();
        let mut completion = Box::pin(async {
            let outcome = finish_phases(async { panic!("phase failure") }, &transport).await;
            work.drain().await;
            outcome
        });
        assert!(futures_util::poll!(completion.as_mut()).is_pending());
        assert_eq!(client.read(&mut [0; 1])?, 0);
        drop(guard);
        assert_eq!(completion.await, CloseOutcome::InternalError);
        listener.close().await?;
        Ok(())
    })
}
