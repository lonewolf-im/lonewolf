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

use super::*;
use crate::c2s::connection_limit::{ConnectionAdmission, ConnectionLimiter};
use crate::c2s::unauthenticated_limit::{
    Admission as UnauthenticatedAdmission, UnauthenticatedLimiter,
};
use crate::config::Config;
use crate::hosts::HostsError;

const TIMEOUT: Duration = Duration::from_secs(5);
const OPEN: &str =
    "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>";
const CLOSE: &str = "</stream:stream>";
const MAX_STANZA_BYTES: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

fn hosts() -> Result<Arc<Hosts>, HostsError> {
    let config = Config::default();
    Ok(Arc::new(Hosts::new(
        &config.hosts,
        config.xmpp.default_host.as_deref(),
    )?))
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
) -> Result<(CloseOutcome, Duration), Box<dyn Error>> {
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
            Arc::clone(&hosts),
            StreamSettings::new(max_stanza_bytes, xml_rate, GlobalChunkAllocator),
        );
        assert_eq!(Arc::strong_count(&hosts), 2);
        let outcome = stream.run().await;
        assert_eq!(Arc::strong_count(&hosts), 1);
        let elapsed = started.elapsed();
        assert!(matches!(
            limiter.reserve(peer.ip(), Instant::now()).await,
            ConnectionAdmission::Allowed(_)
        ));
        assert!(matches!(
            unauthenticated.reserve(Instant::now()).await,
            UnauthenticatedAdmission::Allowed(_)
        ));
        let mut remaining = [0; 1];
        assert_eq!(client.read(&mut remaining)?, 0);
        listener.close().await?;
        Ok((outcome, elapsed))
    }))?
}

#[test]
fn stream_footer_closes_without_tcp_eof() -> Result<(), Box<dyn Error>> {
    let input = format!("{OPEN}{CLOSE}");
    assert_eq!(
        run_case(input.as_bytes(), false, MAX_STANZA_BYTES)?,
        CloseOutcome::StreamEnd
    );
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
    assert_eq!(
        run_case(input.as_bytes(), false, MAX_STANZA_BYTES)?,
        CloseOutcome::UnsupportedInput
    );
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
    let (outcome, elapsed) = run_case_with_rate(input.as_bytes(), false, MAX_STANZA_BYTES, &rate)?;
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
            Arc::clone(&hosts),
            StreamSettings::new(MAX_STANZA_BYTES, &rate, GlobalChunkAllocator),
        );
        assert_eq!(Arc::strong_count(&hosts), 2);
        assert!(
            timeout(Duration::from_millis(20), stream.run())
                .await
                .is_err()
        );
        assert_eq!(Arc::strong_count(&hosts), 1);
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
