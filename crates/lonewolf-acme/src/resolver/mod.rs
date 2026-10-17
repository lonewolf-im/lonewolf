// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

use crate::types::validate_url;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
type Lookup = dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync;

struct Job {
    host: String,
    port: u16,
    reply: mpsc::SyncSender<io::Result<Vec<SocketAddr>>>,
}

struct Pool {
    sender: mpsc::SyncSender<Job>,
}

impl Pool {
    fn new(lookup: Arc<Lookup>) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(2);
        let receiver = Arc::new(PlMutex::new(receiver));
        for _ in 0..2 {
            let receiver = receiver.clone();
            let lookup = lookup.clone();
            thread::Builder::new()
                .name("acme-dns".into())
                .spawn(move || {
                    loop {
                        let job = receiver.lock().recv();
                        let Ok(job) = job else { break };
                        let _ = job.reply.send(lookup(&job.host, job.port));
                    }
                })?;
        }
        Ok(Self { sender })
    }
}

static POOL: OnceLock<io::Result<Pool>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(crate) struct BoundedResolver;

pub(crate) fn authority(uri: &http::Uri) -> Result<(&str, u16), ureq::Error> {
    let length = uri.scheme_str().map_or(0, str::len)
        + uri
            .authority()
            .map_or(0, |authority| authority.as_str().len())
        + uri.path_and_query().map_or(0, |path| path.as_str().len())
        + 3;
    if length > 8 * 1024 {
        return Err(ureq::Error::BadUri("HTTPS URL exceeds limit".into()));
    }
    validate_url(&uri.to_string())
        .map_err(|_| ureq::Error::BadUri("invalid HTTPS authority".into()))?;
    let authority = uri.authority().ok_or(ureq::Error::HostNotFound)?;
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    rustls::pki_types::ServerName::try_from(host)
        .map_err(|_| ureq::Error::BadUri("invalid HTTPS hostname".into()))?;
    Ok((host, authority.port_u16().unwrap_or(443)))
}

impl Resolver for BoundedResolver {
    fn resolve(
        &self,
        uri: &http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let (host, port) = authority(uri)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            let mut result = self.empty();
            result.push(SocketAddr::new(ip, port));
            return Ok(result);
        }
        let pool = POOL
            .get_or_init(|| {
                Pool::new(Arc::new(|host, port| {
                    (host, port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.take(16).collect())
                }))
            })
            .as_ref()
            .map_err(|_| unavailable())?;
        resolve_with(pool, host, port, config, timeout)
    }
}

fn unavailable() -> ureq::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "ACME resolver unavailable").into()
}

fn resolve_with(
    pool: &Pool,
    host: &str,
    port: u16,
    config: &ureq::config::Config,
    timeout: NextTimeout,
) -> Result<ResolvedSocketAddrs, ureq::Error> {
    let (reply, response) = mpsc::sync_channel(1);
    pool.sender
        .try_send(Job {
            host: host.into(),
            port,
            reply,
        })
        .map_err(|_| unavailable())?;
    let duration = (*timeout.after).min(DNS_TIMEOUT);
    let addresses = response
        .recv_timeout(duration)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => ureq::Error::Timeout(timeout.reason),
            mpsc::RecvTimeoutError::Disconnected => unavailable(),
        })?
        .map_err(|_| ureq::Error::HostNotFound)?;
    let mut result = BoundedResolver.empty();
    for address in config
        .ip_family()
        .keep_wanted(addresses.into_iter())
        .take(16)
    {
        result.push(address);
    }
    if result.is_empty() {
        Err(ureq::Error::HostNotFound)
    } else {
        Ok(result)
    }
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolverPool")
    }
}

#[cfg(test)]
mod tests;
