// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use compio::runtime::Runtime;
use compio::time::timeout;
use hmac::{Hmac, KeyInit, Mac};
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::account::{AccountRepository, NewAccount};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_xmpp::stream::STREAM_ERROR_NAMESPACE;
use redb::{ReadableTable, TableDefinition};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::*;
use crate::c2s::connection_limit::{ConnectionAdmission, ConnectionLimiter};
use crate::c2s::unauthenticated_limit::{
    Admission as UnauthenticatedAdmission, UnauthenticatedLimiter,
};
use crate::config::Config;
use crate::hosts::HostsError;

const TIMEOUT: Duration = Duration::from_secs(5);
const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
const PSI_OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' to='localhost' version='1.0' xmlns='jabber:client' xml:lang='es' xmlns:xml='http://www.w3.org/XML/1998/namespace'>";
const CLOSE: &str = "</stream:stream>";
const MAX_STANZA_BYTES: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

fn hosts() -> Result<Hosts, HostsError> {
    let config = Config::default();
    Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())
}

fn auth() -> std::io::Result<(Arc<AuthService>, tempfile::TempDir)> {
    let (auth, _database, directory) = auth_with_database()?;
    Ok((auth, directory))
}

fn auth_with_database() -> std::io::Result<(Arc<AuthService>, RedbDatabase, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let database = RedbDatabase::open(directory.path().join("accounts.redb"))
        .map_err(std::io::Error::other)?;
    let accounts =
        RedbAccountRepository::from_database(database.clone()).map_err(std::io::Error::other)?;
    let decoy = accounts.scram_decoy();
    Ok((
        Arc::new(AuthService { accounts, decoy }),
        database,
        directory,
    ))
}

fn run_case(
    input: &[u8],
    shutdown_write: bool,
    max_stanza_bytes: NonZeroUsize,
) -> Result<CloseOutcome, Box<dyn Error>> {
    Ok(run_case_with_rate(
        input,
        shutdown_write,
        max_stanza_bytes,
        &ByteRate::default(),
    )?
    .0)
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
        let started = Instant::now();
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts.clone(),
            auth,
            StreamSettings::new(
                max_stanza_bytes,
                xml_rate,
                establishment_timeout,
                authentication_timeout,
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
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
fn connection_establishment_has_one_deadline_from_accept() -> Result<(), Box<dyn Error>> {
    let (outcome, elapsed, _) = run_case_with_timeouts(
        &[],
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
        Duration::from_millis(50),
        Duration::from_secs(10),
    )?;
    assert_eq!(outcome, CloseOutcome::EstablishmentTimeout);
    assert!(elapsed >= Duration::from_millis(50));
    Ok(())
}

#[test]
fn stream_footer_closes_without_tcp_eof() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN}{CLOSE}");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    assert!(response.contains(" from='localhost'"));
    assert!(response.contains(" id='"));
    assert!(response.contains(" version='1.0' xml:lang='en'"));
    assert!(response.contains(STARTTLS_FEATURES));
    assert!(response.ends_with(STREAM_FOOTER));
    Ok(())
}

#[test]
fn tcp_eof_before_stream_footer_releases_connection() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        run_case(OPEN.as_bytes(), true, MAX_STANZA_BYTES)?,
        CloseOutcome::Eof
    );
    assert_eq!(run_case(&[], true, MAX_STANZA_BYTES)?, CloseOutcome::Eof);
    Ok(())
}

#[test]
fn early_stanza_closes_without_tcp_eof() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN}<message/>");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::UnsupportedInput);
    assert!(response.contains("<not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"));
    Ok(())
}

#[test]
fn unknown_host_returns_stream_error() -> Result<(), Box<dyn Error>> {
    let input = OPEN
        .replace("to='localhost'", "to='elsewhere.example'")
        .replace(
            "version='1.0'",
            "from='Alice@LOCALHOST/Phone' version='1.0'",
        );
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::HostUnknown);
    assert!(response.contains("<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"));
    assert!(response.contains(" to='alice@localhost'"));
    assert!(!response.contains(STARTTLS_FEATURES));
    Ok(())
}

#[test]
fn absent_to_uses_default_host() -> Result<(), Box<dyn Error>> {
    let input = format!("{}{CLOSE}", OPEN.replace(" to='localhost'", ""));
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    assert!(response.contains(" from='localhost'"));
    Ok(())
}

#[test]
fn invalid_stream_opening_returns_stream_error() -> Result<(), Box<dyn Error>> {
    for (input, outcome, condition) in [
        (
            OPEN.replace("to='localhost'", "to='alice@localhost'"),
            CloseOutcome::HostUnknown,
            "host-unknown",
        ),
        (
            OPEN.replace("to='localhost'", "to='localhost/phone'"),
            CloseOutcome::HostUnknown,
            "host-unknown",
        ),
        (
            OPEN.replace("version='1.0'", "version='0.9'"),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
        (
            OPEN.replace(" version='1.0'", ""),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
        (
            OPEN.replace("version='1.0'", "version='+1.0'"),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
        (
            OPEN.replace("version='1.0'", "version='1.x'"),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
        (
            OPEN.replace("version='1.0'", "xml:lang='en_US' version='1.0'"),
            CloseOutcome::InvalidLanguage,
            "bad-format",
        ),
        (
            OPEN.replace("version='1.0'", "xml:lang='' version='1.0'"),
            CloseOutcome::InvalidLanguage,
            "bad-format",
        ),
        (
            OPEN.replace("http://etherx.jabber.org/streams", "urn:invalid:stream"),
            CloseOutcome::InvalidNamespace,
            "invalid-namespace",
        ),
    ] {
        let (actual, _, response) = run_case_with_rate(
            input.as_bytes(),
            false,
            MAX_STANZA_BYTES,
            &ByteRate::default(),
        )?;
        assert_eq!(actual, outcome, "{input}");
        assert!(
            response.contains(&format!("<{condition} xmlns='{STREAM_ERROR_NAMESPACE}'/>")),
            "{input}: {response}"
        );
        if outcome == CloseOutcome::UnsupportedVersion {
            assert!(
                !response.contains(" version='1.0' xml:lang"),
                "{input}: {response}"
            );
        }
        assert!(!response.contains(STARTTLS_FEATURES));
    }
    Ok(())
}

#[test]
fn stream_version_numbers_are_compared_numerically() -> Result<(), Box<dyn Error>> {
    for version in ["01.000", "1.13", "12.3", "999999999999999999999.0"] {
        let input = format!(
            "{}{CLOSE}",
            OPEN.replace("version='1.0'", &format!("version='{version}'"))
        );
        let (outcome, _, response) = run_case_with_rate(
            input.as_bytes(),
            false,
            MAX_STANZA_BYTES,
            &ByteRate::default(),
        )?;
        assert_eq!(outcome, CloseOutcome::StreamEnd, "{version}");
        assert!(response.contains(" version='1.0'"));
    }
    Ok(())
}

#[test]
fn response_uses_bare_client_from() -> Result<(), Box<dyn Error>> {
    let input = OPEN.replace(
        "version='1.0'",
        "from='Alice@LOCALHOST/Phone' version='1.0'",
    );
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        true,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::Eof);
    assert!(response.contains(" to='alice@localhost'"));
    Ok(())
}

#[test]
fn invalid_client_from_returns_stream_error() -> Result<(), Box<dyn Error>> {
    let input = OPEN.replace("version='1.0'", "from='@' version='1.0'");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::InvalidFrom);
    assert!(response.contains("<invalid-from xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"));
    Ok(())
}

#[test]
fn wrong_content_namespace_returns_stream_error() -> Result<(), Box<dyn Error>> {
    let input = OPEN.replace("xmlns='jabber:client'", "xmlns='jabber:server'");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::InvalidNamespace);
    assert!(response.contains("<invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"));
    Ok(())
}

#[test]
fn response_preserves_prefix_free_namespace_style() -> Result<(), Box<dyn Error>> {
    for input in [
        format!("{}{CLOSE}", OPEN.replace(" xmlns='jabber:client'", "")),
        "<stream xmlns='http://etherx.jabber.org/streams' to='localhost' version='1.0'></stream>"
            .to_owned(),
    ] {
        let (outcome, _, response) = run_case_with_rate(
            input.as_bytes(),
            false,
            MAX_STANZA_BYTES,
            &ByteRate::default(),
        )?;
        assert_eq!(outcome, CloseOutcome::StreamEnd);
        assert!(!response.contains("xmlns='jabber:client'"));
        assert!(response.contains(STARTTLS_FEATURES));
    }
    Ok(())
}

#[test]
fn starttls_rejects_nonempty_request() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN}<starttls xmlns='{STARTTLS_NAMESPACE}'><x/></starttls>");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::StartTlsRejected);
    assert!(response.contains(STARTTLS_FAILURE));
    Ok(())
}

#[test]
fn starttls_rejects_explicit_attribute() -> Result<(), Box<dyn Error>> {
    let input = format!("{PSI_OPEN}<starttls xmlns='{STARTTLS_NAMESPACE}' flag='1'/>");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::StartTlsRejected);
    assert!(response.contains(STARTTLS_FAILURE));
    Ok(())
}

#[test]
fn starttls_rejects_text_content() -> Result<(), Box<dyn Error>> {
    let input = format!("{PSI_OPEN}<starttls xmlns='{STARTTLS_NAMESPACE}'>text</starttls>");
    let (outcome, _, response) = run_case_with_rate(
        input.as_bytes(),
        false,
        MAX_STANZA_BYTES,
        &ByteRate::default(),
    )?;
    assert_eq!(outcome, CloseOutcome::StartTlsRejected);
    assert!(response.contains(STARTTLS_FAILURE));
    Ok(())
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

fn stream_id(response: &str) -> Option<&str> {
    response
        .split(" id='")
        .nth(1)
        .and_then(|tail| tail.split_once('\''))
        .map(|(id, _)| id)
}

fn run_starttls_restart_case(
    restart_open: &str,
) -> Result<(CloseOutcome, String, String), Box<dyn Error + Send + Sync>> {
    run_starttls_restart_case_with_timeout(restart_open, Duration::from_secs(10), false)
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
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts,
            auth,
            StreamSettings::new(
                MAX_STANZA_BYTES,
                &ByteRate::default(),
                Duration::from_secs(10),
                authentication_timeout,
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
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
    assert!(after_tls.contains(SASL_FEATURES));
    Ok(())
}

#[test]
fn starttls_restarts_stream_and_offers_authentication() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let (outcome, before_tls, after_tls) = run_starttls_restart_case(PSI_OPEN)?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    assert!(before_tls.contains(STARTTLS_FEATURES));
    assert!(after_tls.contains(" from='localhost'"));
    assert!(after_tls.contains(SASL_FEATURES));
    assert!(!after_tls.contains(STARTTLS_FEATURES));
    assert_ne!(stream_id(&before_tls), stream_id(&after_tls));
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

fn run_sasl_case<F>(
    tls_open: &str,
    known_account: bool,
    exchange: F,
) -> Result<CloseOutcome, Box<dyn Error + Send + Sync>>
where
    F: FnOnce(
            &mut StreamOwned<ClientConnection, StdTcpStream>,
        ) -> Result<(), Box<dyn Error + Send + Sync>>
        + Send
        + 'static,
{
    run_sasl_case_with_iterations(
        tls_open,
        known_account.then_some(SCRAM_POLICY_ITERATIONS.get()),
        exchange,
    )
}

fn run_sasl_case_with_iterations<F>(
    tls_open: &str,
    stored_iterations: Option<u32>,
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
            auth.accounts
                .create(NewAccount {
                    key: key.clone(),
                    credentials: ScramCredentials::new(verifier),
                })
                .await?;
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
        let outcome = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts,
            auth,
            StreamSettings::new(
                MAX_STANZA_BYTES,
                &ByteRate::default(),
                Duration::from_secs(10),
                Duration::from_secs(10),
                GlobalChunkAllocator,
            ),
        )
        .run()
        .await;
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
fn malformed_scram_final_does_not_reveal_account_existence()
-> Result<(), Box<dyn Error + Send + Sync>> {
    for known_account in [false, true] {
        let outcome = run_sasl_case(PSI_OPEN, known_account, |tls| {
            tls.write_all(sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=clientnonce").as_bytes())?;
            sasl_challenge(tls)?;
            tls.write_all(
                format!(
                    "<response xmlns='{SASL_NAMESPACE}'>{}</response>",
                    STANDARD.encode("x=1")
                )
                .as_bytes(),
            )?;
            let failure = String::from_utf8(read_through(tls, b"</failure>")?)?;
            assert!(failure.contains("<malformed-request/>"), "{failure}");
            tls.write_all(CLOSE.as_bytes())?;
            let mut rest = String::new();
            tls.read_to_string(&mut rest)?;
            assert!(rest.ends_with(STREAM_FOOTER));
            Ok(())
        })?;
        assert_eq!(outcome, CloseOutcome::StreamEnd);
    }
    Ok(())
}

#[test]
fn missing_account_challenge_uses_normalized_identity() -> Result<(), Box<dyn Error + Send + Sync>>
{
    for (known_account, usernames) in [(false, ["Mallory", "mallory"]), (true, ["Alice", "alice"])]
    {
        let outcome = run_sasl_case(PSI_OPEN, known_account, move |tls| {
            let mut parameters = None;
            for username in usernames {
                tls.write_all(
                    sasl_auth("SCRAM-SHA-256", &format!("n,,n={username},r=clientnonce"))
                        .as_bytes(),
                )?;
                let challenge = sasl_challenge(tls)?;
                let current = challenge.split_once(",s=").ok_or("missing SCRAM salt")?.1;
                if let Some(previous) = parameters.as_deref() {
                    assert_eq!(current, previous);
                } else {
                    parameters = Some(current.to_owned());
                }
                tls.write_all(format!("<abort xmlns='{SASL_NAMESPACE}'/>").as_bytes())?;
                let failure = String::from_utf8(read_through(tls, b"</failure>")?)?;
                assert!(failure.contains("<aborted/>"));
            }
            tls.write_all(CLOSE.as_bytes())?;
            let mut rest = String::new();
            tls.read_to_string(&mut rest)?;
            assert!(rest.ends_with(STREAM_FOOTER));
            Ok(())
        })?;
        assert_eq!(outcome, CloseOutcome::StreamEnd);
    }
    Ok(())
}

#[test]
fn legacy_iteration_account_gets_decoy_challenge_and_cannot_log_in()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let outcome = run_sasl_case_with_iterations(PSI_OPEN, Some(4096), |tls| {
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
        pbkdf2::pbkdf2_hmac::<Sha256>(b"pencil", &salt, SCRAM_POLICY_ITERATIONS.get(), &mut salted);
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
        let mut rest = String::new();
        tls.read_to_string(&mut rest)?;
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
fn unsupported_scram_binding_uses_standard_sasl_condition()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let outcome = run_sasl_case(PSI_OPEN, false, |tls| {
        tls.write_all(
            sasl_auth("SCRAM-SHA-256-PLUS", "p=unknown-binding,,n=alice,r=nonce").as_bytes(),
        )?;
        let failure = String::from_utf8(read_through(tls, b"</failure>")?)?;
        assert!(failure.contains("<malformed-request/>"), "{failure}");
        assert!(!failure.contains("channel-binding-not-supported"));
        tls.write_all(CLOSE.as_bytes())?;
        let mut rest = String::new();
        tls.read_to_string(&mut rest)?;
        assert!(rest.ends_with(STREAM_FOOTER));
        Ok(())
    })?;
    assert_eq!(outcome, CloseOutcome::StreamEnd);
    Ok(())
}

#[test]
fn new_auth_replaces_both_pending_scram_challenges() -> Result<(), Box<dyn Error + Send + Sync>> {
    for empty_initial in [false, true] {
        let outcome = run_sasl_case(PSI_OPEN, false, move |tls| {
            if empty_initial {
                tls.write_all(
                    format!("<auth xmlns='{SASL_NAMESPACE}' mechanism='SCRAM-SHA-256'/>")
                        .as_bytes(),
                )?;
                let challenge = String::from_utf8(read_through(tls, b"/>")?)?;
                assert!(challenge.contains("<challenge"));
            } else {
                tls.write_all(
                    sasl_auth("SCRAM-SHA-256", "n,,n=discarded,r=firstnonce").as_bytes(),
                )?;
                sasl_challenge(tls)?;
            }
            tls.write_all(sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=secondnonce").as_bytes())?;
            let challenge = sasl_challenge(tls)?;
            assert!(challenge.contains("r=secondnonce"), "{challenge}");
            let nonce = challenge
                .split(',')
                .next()
                .ok_or("missing nonce")?
                .strip_prefix("r=")
                .ok_or("missing nonce")?;
            let response = format!("c=biws,r={nonce},p={}", STANDARD.encode([0; 32]));
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
            let mut rest = String::new();
            tls.read_to_string(&mut rest)?;
            assert!(rest.ends_with(STREAM_FOOTER));
            Ok(())
        })?;
        assert_eq!(outcome, CloseOutcome::StreamEnd);
    }
    Ok(())
}

#[test]
fn replacement_auth_counts_toward_attempt_cap() -> Result<(), Box<dyn Error + Send + Sync>> {
    let outcome = run_sasl_case(PSI_OPEN, false, |tls| {
        for index in 0..MAX_AUTH_ATTEMPTS {
            tls.write_all(
                sasl_auth("SCRAM-SHA-256", &format!("n,,n=missing,r=nonce{index}")).as_bytes(),
            )?;
            sasl_challenge(tls)?;
        }
        tls.write_all(sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=lastnonce").as_bytes())?;
        let mut response = String::new();
        tls.read_to_string(&mut response)?;
        assert!(
            response.contains("<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>")
        );
        assert!(!response.contains("<failure"));
        Ok(())
    })?;
    assert_eq!(outcome, CloseOutcome::AuthenticationAttemptsExceeded);
    Ok(())
}

fn run_scram(
    hash: ScramHash,
    binding: Option<&'static str>,
    tls_open: &str,
    expected_outcome: CloseOutcome,
    authentication_timeout: Duration,
    post_auth_delay: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram_with_restart(
        hash,
        binding,
        tls_open,
        expected_outcome,
        authentication_timeout,
        post_auth_delay,
        None,
    )
}

fn run_scram_with_restart(
    hash: ScramHash,
    binding: Option<&'static str>,
    tls_open: &str,
    expected_outcome: CloseOutcome,
    authentication_timeout: Duration,
    post_auth_delay: Duration,
    post_auth_restart: Option<(&str, &str)>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tls_open = tls_open.to_owned();
    let post_auth_restart =
        post_auth_restart.map(|(opening, condition)| (opening.to_owned(), condition.to_owned()));
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
        let endpoint = hosts
            .tls_server_end_point("localhost")
            .ok_or("no endpoint binding")?
            .to_vec();
        let tls_config =
            ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let salt: [u8; 16] = STANDARD
            .decode("W22ZaJ0SNY7soEsUEjb6gQ==")?
            .try_into()
            .map_err(|_| "bad salt")?;
        let salted = match hash {
            ScramHash::Sha1 => {
                let mut salted = [0; 20];
                pbkdf2::pbkdf2_hmac::<Sha1>(
                    b"pencil",
                    &salt,
                    SCRAM_POLICY_ITERATIONS.get(),
                    &mut salted,
                );
                salted.to_vec()
            }
            ScramHash::Sha256 => {
                let mut salted = [0; 32];
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    b"pencil",
                    &salt,
                    SCRAM_POLICY_ITERATIONS.get(),
                    &mut salted,
                );
                salted.to_vec()
            }
        };
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
            let features = String::from_utf8(read_through(&mut tls, b"</stream:features>")?)?;
            assert!(features.contains(SASL_FEATURES));
            let gs2 = match binding {
                Some("tls-exporter") => "p=tls-exporter,,",
                Some("tls-server-end-point") => "p=tls-server-end-point,,",
                Some(_) => return Err("unsupported binding test".into()),
                None => "n,,",
            };
            let first = format!("{gs2}n=alice,r=clientnonce");
            let mechanism = match (hash, binding.is_some()) {
                (ScramHash::Sha1, false) => "SCRAM-SHA-1",
                (ScramHash::Sha1, true) => "SCRAM-SHA-1-PLUS",
                (ScramHash::Sha256, false) => "SCRAM-SHA-256",
                (ScramHash::Sha256, true) => "SCRAM-SHA-256-PLUS",
            };
            tls.write_all(
                format!(
                    "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{}</auth>",
                    STANDARD.encode(first)
                )
                .as_bytes(),
            )?;
            let challenge = String::from_utf8(read_through(&mut tls, b"</challenge>")?)?;
            let challenge = challenge.split_once('>').ok_or("invalid challenge")?.1;
            let challenge = challenge
                .strip_suffix("</challenge>")
                .ok_or("invalid challenge")?;
            let challenge = String::from_utf8(STANDARD.decode(challenge)?)?;
            let nonce = challenge
                .split(',')
                .next()
                .ok_or("missing nonce")?
                .strip_prefix("r=")
                .ok_or("missing nonce")?;
            let mut channel_binding = gs2.as_bytes().to_vec();
            if binding == Some("tls-exporter") {
                let mut exporter = [0; 32];
                tls.conn.export_keying_material(
                    &mut exporter,
                    b"EXPORTER-Channel-Binding",
                    None,
                )?;
                channel_binding.extend_from_slice(&exporter);
            } else if binding == Some("tls-server-end-point") {
                channel_binding.extend_from_slice(&endpoint);
            }
            let without_proof = format!("c={},r={nonce}", STANDARD.encode(channel_binding));
            let auth_message = format!("n=alice,r=clientnonce,{challenge},{without_proof}");
            let client_key = hmac_scram(hash, &salted, b"Client Key")?;
            let stored_key = match hash {
                ScramHash::Sha1 => Sha1::digest(&client_key).to_vec(),
                ScramHash::Sha256 => Sha256::digest(&client_key).to_vec(),
            };
            let signature = hmac_scram(hash, &stored_key, auth_message.as_bytes())?;
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
            if expected_outcome == CloseOutcome::InvalidFrom && post_auth_restart.is_none() {
                let mut response = String::new();
                tls.read_to_string(&mut response)?;
                assert!(
                    response
                        .contains("<invalid-from xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>")
                );
                assert!(!response.contains("<success"));
                return Ok(());
            }
            let success = String::from_utf8(read_through(&mut tls, b"</success>")?)?;
            let success = success
                .split_once('>')
                .ok_or("invalid success")?
                .1
                .strip_suffix("</success>")
                .ok_or("invalid success")?;
            let success = String::from_utf8(STANDARD.decode(success)?)?;
            let server_key = hmac_scram(hash, &salted, b"Server Key")?;
            assert_eq!(
                success,
                format!(
                    "v={}",
                    STANDARD.encode(hmac_scram(hash, &server_key, auth_message.as_bytes())?)
                )
            );
            std::thread::sleep(post_auth_delay);
            if let Some((opening, _)) = &post_auth_restart {
                tls.write_all(opening.as_bytes())?;
            } else {
                tls.write_all(format!("{PSI_OPEN}{CLOSE}").as_bytes())?;
            }
            let mut rest = String::new();
            tls.read_to_string(&mut rest)?;
            if let Some((_, condition)) = &post_auth_restart {
                let opening = rest
                    .find("<stream:stream")
                    .ok_or("server stream opening missing")?;
                let error = rest.find("<stream:error>").ok_or("stream error missing")?;
                assert!(opening < error, "{rest}");
                assert!(
                    rest.contains(&format!("<{condition} xmlns='{STREAM_ERROR_NAMESPACE}'/>")),
                    "{rest}"
                );
                assert!(!rest.contains(EMPTY_FEATURES));
            } else {
                assert!(rest.contains(EMPTY_FEATURES));
            }
            assert!(rest.ends_with(STREAM_FOOTER));
            Ok(())
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
        let (auth, _directory) = auth()?;
        let key = account_key("alice", "localhost").ok_or("invalid account key")?;
        let verifier = ScramVerifier::derive(
            hash,
            "pencil",
            salt,
            ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?,
        )?;
        auth.accounts
            .create(NewAccount {
                key,
                credentials: ScramCredentials::new(verifier),
            })
            .await?;
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts,
            auth,
            StreamSettings::new(
                MAX_STANZA_BYTES,
                &ByteRate::default(),
                Duration::from_secs(10),
                authentication_timeout,
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
        client.join().map_err(|_| "client thread panicked")??;
        listener.close().await?;
        assert_eq!(outcome, expected_outcome);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }))?
}

#[test]
fn invalid_post_auth_opening_starts_server_stream_before_error()
-> Result<(), Box<dyn Error + Send + Sync>> {
    for (opening, outcome, condition) in [
        (
            PSI_OPEN.replace("version='1.0'", "version='0.9'"),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
        (
            PSI_OPEN.replace("to='localhost'", "to='unknown.example'"),
            CloseOutcome::HostUnknown,
            "host-unknown",
        ),
        (
            PSI_OPEN.replace("to='localhost'", "from='bob@localhost' to='localhost'"),
            CloseOutcome::InvalidFrom,
            "invalid-from",
        ),
        (
            PSI_OPEN.replace("xmlns='jabber:client'", "xmlns='jabber:server'"),
            CloseOutcome::InvalidNamespace,
            "invalid-namespace",
        ),
        (
            PSI_OPEN.replace("version='1.0'", "version='1.0' to='localhost'"),
            CloseOutcome::ParserError,
            "bad-format",
        ),
    ] {
        run_scram_with_restart(
            ScramHash::Sha256,
            None,
            PSI_OPEN,
            outcome,
            Duration::from_secs(10),
            Duration::ZERO,
            Some((&opening, condition)),
        )?;
    }
    Ok(())
}

#[test]
fn scram_sha256_authenticates_and_restarts_with_empty_features()
-> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram(
        ScramHash::Sha256,
        None,
        PSI_OPEN,
        CloseOutcome::StreamEnd,
        Duration::from_secs(10),
        Duration::ZERO,
    )
}

#[test]
fn scram_sha256_plus_uses_tls_exporter() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram(
        ScramHash::Sha256,
        Some("tls-exporter"),
        PSI_OPEN,
        CloseOutcome::StreamEnd,
        Duration::from_secs(10),
        Duration::ZERO,
    )
}

#[test]
fn scram_sha256_plus_uses_tls_server_end_point() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram(
        ScramHash::Sha256,
        Some("tls-server-end-point"),
        PSI_OPEN,
        CloseOutcome::StreamEnd,
        Duration::from_secs(10),
        Duration::ZERO,
    )
}

#[test]
fn authentication_deadline_ends_at_sasl_success() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram(
        ScramHash::Sha256,
        None,
        PSI_OPEN,
        CloseOutcome::StreamEnd,
        Duration::from_secs(1),
        Duration::from_millis(1200),
    )
}

#[test]
fn scram_sha1_authenticates() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_scram(
        ScramHash::Sha1,
        None,
        PSI_OPEN,
        CloseOutcome::StreamEnd,
        Duration::from_secs(10),
        Duration::ZERO,
    )
}

#[test]
fn scram_sha1_plus_authenticates_with_both_bindings() -> Result<(), Box<dyn Error + Send + Sync>> {
    for binding in ["tls-exporter", "tls-server-end-point"] {
        run_scram(
            ScramHash::Sha1,
            Some(binding),
            PSI_OPEN,
            CloseOutcome::StreamEnd,
            Duration::from_secs(10),
            Duration::ZERO,
        )?;
    }
    Ok(())
}

#[test]
fn protected_from_must_match_authenticated_account() -> Result<(), Box<dyn Error + Send + Sync>> {
    let matching = PSI_OPEN.replace(
        "to='localhost'",
        "from='Alice@LOCALHOST/Phone' to='localhost'",
    );
    run_scram(
        ScramHash::Sha256,
        None,
        &matching,
        CloseOutcome::StreamEnd,
        Duration::from_secs(10),
        Duration::ZERO,
    )?;
    let mismatching = PSI_OPEN.replace("to='localhost'", "from='bob@localhost' to='localhost'");
    run_scram(
        ScramHash::Sha256,
        None,
        &mismatching,
        CloseOutcome::InvalidFrom,
        Duration::from_secs(10),
        Duration::ZERO,
    )
}

#[test]
fn unknown_account_gets_three_scram_attempts_before_stream_closes()
-> Result<(), Box<dyn Error + Send + Sync>> {
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
            tls.write_all(PSI_OPEN.as_bytes())?;
            read_through(&mut tls, b"</stream:features>")?;
            for _ in 0..MAX_AUTH_ATTEMPTS {
                tls.write_all(
                    format!(
                        "<auth xmlns='{SASL_NAMESPACE}' mechanism='SCRAM-SHA-256'>{}</auth>",
                        STANDARD.encode("n,,n=missing,r=clientnonce")
                    )
                    .as_bytes(),
                )?;
                let challenge = String::from_utf8(read_through(&mut tls, b"</challenge>")?)?;
                let challenge = challenge.split_once('>').ok_or("invalid challenge")?.1;
                let challenge = String::from_utf8(
                    STANDARD.decode(
                        challenge
                            .strip_suffix("</challenge>")
                            .ok_or("invalid challenge")?,
                    )?,
                )?;
                let nonce = challenge
                    .split(',')
                    .next()
                    .ok_or("missing nonce")?
                    .strip_prefix("r=")
                    .ok_or("missing nonce")?;
                let response = format!("c=biws,r={nonce},p={}", STANDARD.encode([0; 32]));
                tls.write_all(
                    format!(
                        "<response xmlns='{SASL_NAMESPACE}'>{}</response>",
                        STANDARD.encode(response)
                    )
                    .as_bytes(),
                )?;
                let failure = String::from_utf8(read_through(&mut tls, b"</failure>")?)?;
                assert!(failure.contains("<not-authorized/>"));
            }
            let mut rest = String::new();
            tls.read_to_string(&mut rest)?;
            assert!(
                rest.contains("<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>")
            );
            Ok(())
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
        let (auth, _directory) = auth()?;
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts,
            auth,
            StreamSettings::new(
                MAX_STANZA_BYTES,
                &ByteRate::default(),
                Duration::from_secs(10),
                Duration::from_secs(10),
                GlobalChunkAllocator,
            ),
        );
        let outcome = stream.run().await;
        client.join().map_err(|_| "client thread panicked")??;
        listener.close().await?;
        assert_eq!(outcome, CloseOutcome::AuthenticationAttemptsExceeded);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }))?
}

#[test]
fn restarted_stream_header_is_validated() -> Result<(), Box<dyn Error + Send + Sync>> {
    for (open, outcome, condition) in [
        (
            PSI_OPEN.replace("to='localhost'", "to='elsewhere.example'"),
            CloseOutcome::HostUnknown,
            "host-unknown",
        ),
        (
            PSI_OPEN.replace("xml:lang='es'", "xml:lang='en_US'"),
            CloseOutcome::InvalidLanguage,
            "bad-format",
        ),
        (
            PSI_OPEN.replace("version='1.0'", "version='0.9'"),
            CloseOutcome::UnsupportedVersion,
            "unsupported-version",
        ),
    ] {
        let (actual, before_tls, after_tls) = run_starttls_restart_case(&open)?;
        assert_eq!(actual, outcome, "{open}");
        assert!(before_tls.contains(STARTTLS_FEATURES));
        assert!(
            after_tls.contains(&format!("<{condition} xmlns='{STREAM_ERROR_NAMESPACE}'/>")),
            "{open}: {after_tls}"
        );
        assert!(!after_tls.contains(STARTTLS_FEATURES));
    }
    Ok(())
}

#[test]
fn configured_stanza_size_is_enforced() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN}<message><body>{}", "x".repeat(10_000));
    assert_eq!(
        run_case(input.as_bytes(), false, MAX_STANZA_BYTES)?,
        CloseOutcome::SizeLimitExceeded
    );
    Ok(())
}

#[test]
fn invalid_xml_closes_connection() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        run_case(b"invalid", false, MAX_STANZA_BYTES)?,
        CloseOutcome::ParserError
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
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts.clone(),
            auth,
            StreamSettings::new(
                MAX_STANZA_BYTES,
                &rate,
                Duration::from_secs(10),
                Duration::from_secs(10),
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
        Ok::<_, Box<dyn Error>>(())
    })
}
