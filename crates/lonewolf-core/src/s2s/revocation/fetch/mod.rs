// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lonewolf_util::blocking::BlockingExecutor;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver as HttpResolver};
use ureq::unversioned::transport::{NextTimeout, TcpConnector};

use crate::hosts::revocation::{CrlLoadError, CrlNumber, parse_crl_with_cost_limit};
use crate::s2s::dns::Resolver;

use super::address::AddressPolicy;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CrlUrl {
    text: Box<str>,
    host: Box<str>,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnsupportedUrl;

impl CrlUrl {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn parse(text: &str) -> Result<Self, UnsupportedUrl> {
        if text.len() > 2048 || text.contains('#') {
            return Err(UnsupportedUrl);
        }
        let uri: http::Uri = text.parse().map_err(|_| UnsupportedUrl)?;
        if !uri
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        {
            return Err(UnsupportedUrl);
        }
        let authority = uri.authority().ok_or(UnsupportedUrl)?;
        if authority.as_str().contains('@') {
            return Err(UnsupportedUrl);
        }
        let host = authority.host();
        if host.is_empty() {
            return Err(UnsupportedUrl);
        }
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'));
        if let Some(host) = unbracketed {
            host.parse::<Ipv6Addr>().map_err(|_| UnsupportedUrl)?;
        } else if host.parse::<IpAddr>().is_err() {
            idna::domain_to_ascii_strict(host).map_err(|_| UnsupportedUrl)?;
        }
        let port = match &authority.as_str()[host.len()..] {
            "" => 80,
            tail => tail
                .strip_prefix(':')
                .ok_or(UnsupportedUrl)?
                .parse::<u16>()
                .map_err(|_| UnsupportedUrl)?,
        };
        if port == 0 {
            return Err(UnsupportedUrl);
        }
        let path = uri.path_and_query().map_or("/", |path| path.as_str());
        Ok(Self {
            text: format!("http://{authority}{path}").into(),
            host: unbracketed.unwrap_or(host).into(),
            port,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
    pub(crate) fn host(&self) -> &str {
        &self.host
    }
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FetchLimits {
    pub(crate) connect_timeout: Duration,
    pub(crate) total_timeout: Duration,
    pub(crate) max_crl_bytes: usize,
    pub(crate) max_crl_cost: usize,
}

impl FetchLimits {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) const DEFAULT: Self = Self {
        connect_timeout: Duration::from_secs(3),
        total_timeout: Duration::from_secs(10),
        max_crl_bytes: 4 * 1024 * 1024,
        max_crl_cost: 16 * 1024 * 1024,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FetchFailure {
    DnsFailed,
    BlockedAddress,
    ConnectFailed,
    Timeout,
    HttpStatus,
    TooLarge,
    Invalid,
    Stale,
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) struct FetchedCrl {
    pub(crate) crl: webpki::CertRevocationList<'static>,
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: SystemTime,
    pub(crate) crl_number: Option<CrlNumber>,
    pub(crate) cost: usize,
}

pub(crate) struct CrlFetcher {
    resolver: Arc<Resolver>,
    policy: AddressPolicy,
    limits: FetchLimits,
    executor: BlockingExecutor,
}

impl CrlFetcher {
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(resolver: Arc<Resolver>, policy: AddressPolicy, limits: FetchLimits) -> Self {
        Self {
            resolver,
            policy,
            limits,
            executor: BlockingExecutor::new(const { NonZeroUsize::new(4).unwrap() }),
        }
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) async fn fetch(
        &self,
        url: &CrlUrl,
        now: SystemTime,
    ) -> Result<FetchedCrl, FetchFailure> {
        let mut addresses = self
            .resolver
            .resolve_host(url.host())
            .await
            .map_err(|_| FetchFailure::DnsFailed)?;
        addresses.retain(|address| self.policy.allows(*address));
        if addresses.is_empty() {
            return Err(FetchFailure::BlockedAddress);
        }
        let text = url.as_str().to_owned();
        let limits = self.limits;
        self.executor
            .run(move || perform(&text, addresses, limits, now))
            .await
    }
}

#[derive(Debug)]
struct FixedResolver(Vec<IpAddr>);

impl HttpResolver for FixedResolver {
    fn resolve(
        &self,
        uri: &http::Uri,
        _: &ureq::config::Config,
        _: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let port = uri.port_u16().unwrap_or(80);
        let mut addresses = self.empty();
        for address in &self.0 {
            addresses.push(SocketAddr::new(*address, port));
        }
        Ok(addresses)
    }
}

fn perform(
    text: &str,
    addresses: Vec<IpAddr>,
    limits: FetchLimits,
    now: SystemTime,
) -> Result<FetchedCrl, FetchFailure> {
    let config = ureq::Agent::config_builder()
        .https_only(false)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_global(Some(limits.total_timeout))
        .timeout_connect(Some(limits.connect_timeout))
        .max_response_header_size(16 * 1024)
        .max_idle_connections(0)
        .build();
    let agent = ureq::Agent::with_parts(config, TcpConnector::default(), FixedResolver(addresses));
    let mut response = agent.get(text).call().map_err(map_error)?;
    if response.status() != http::StatusCode::OK {
        return Err(FetchFailure::HttpStatus);
    }
    if response
        .headers()
        .contains_key(http::header::CONTENT_ENCODING)
    {
        return Err(FetchFailure::Invalid);
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(limits.max_crl_bytes as u64)
        .read_to_vec()
        .map_err(map_error)?;
    let parsed = parse_crl_with_cost_limit(&body, now, limits.max_crl_cost)
        .map_err(|error| match error {
            CrlLoadError::Stale => FetchFailure::Stale,
            CrlLoadError::Invalid | CrlLoadError::Unreadable => FetchFailure::Invalid,
        })?
        .ok_or(FetchFailure::TooLarge)?;
    Ok(FetchedCrl {
        crl: parsed.crl,
        this_update: parsed.this_update,
        next_update: parsed.next_update,
        crl_number: parsed.crl_number,
        cost: parsed.cost,
    })
}

fn map_error(error: ureq::Error) -> FetchFailure {
    match error {
        ureq::Error::Timeout(_) => FetchFailure::Timeout,
        ureq::Error::Io(ref error) if error.kind() == io::ErrorKind::TimedOut => {
            FetchFailure::Timeout
        }
        ureq::Error::BodyExceedsLimit(_) => FetchFailure::TooLarge,
        _ => FetchFailure::ConnectFailed,
    }
}

#[cfg(test)]
mod tests;
