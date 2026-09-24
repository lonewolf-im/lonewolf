// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream as StdTcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use compio::time::timeout;
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_xmpp::stream::STREAM_ERROR_NAMESPACE;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

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
        let started = Instant::now();
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts.clone(),
            StreamSettings::new(max_stanza_bytes, xml_rate, GlobalChunkAllocator),
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

fn read_through(stream: &mut StdTcpStream, marker: &[u8]) -> std::io::Result<Vec<u8>> {
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
                let mut after_tls = String::new();
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
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts,
            StreamSettings::new(MAX_STANZA_BYTES, &ByteRate::default(), GlobalChunkAllocator),
        );
        let outcome = stream.run().await;
        let (before_tls, after_tls) = client.join().map_err(|_| "client thread panicked")??;
        listener.close().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>((outcome, before_tls, after_tls))
    }))?
}

#[test]
fn starttls_restarts_stream_and_stops_before_authentication()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let (outcome, before_tls, after_tls) = run_starttls_restart_case(PSI_OPEN)?;
    assert_eq!(outcome, CloseOutcome::AuthenticationUnavailable);
    assert!(before_tls.contains(STARTTLS_FEATURES));
    assert!(after_tls.contains(" from='localhost'"));
    assert!(
        after_tls.contains("<internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>")
    );
    assert!(!after_tls.contains(STARTTLS_FEATURES));
    assert_ne!(stream_id(&before_tls), stream_id(&after_tls));
    Ok(())
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
        let stream = XmppStream::new(
            transport,
            permit,
            unauthenticated_permit,
            hosts.clone(),
            StreamSettings::new(MAX_STANZA_BYTES, &rate, GlobalChunkAllocator),
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
