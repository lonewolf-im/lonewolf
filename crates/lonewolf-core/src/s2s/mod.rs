// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::sync::atomic::AtomicU64;

use compio::net::TcpStream;
use socket2::SockRef;

pub(crate) mod dns;
mod expiry;
pub(crate) mod inbound;
pub(crate) mod ingress;
pub(crate) mod metrics;
pub(crate) mod outbound;
pub(crate) mod revocation;
pub(crate) mod stream;

fn log_domain(domain: &str) -> Cow<'_, str> {
    if domain
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
    {
        Cow::Borrowed("<literal>")
    } else if domain.len() <= 253 && !domain.chars().any(char::is_control) {
        Cow::Borrowed(domain)
    } else {
        Cow::Owned(
            domain
                .chars()
                .take(253)
                .map(|ch| if ch.is_control() { '?' } else { ch })
                .collect(),
        )
    }
}

static NEXT_S2S_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

struct ConnectionSocket(TcpStream);

impl Drop for ConnectionSocket {
    fn drop(&mut self) {
        let _ = SockRef::from(&self.0).shutdown(std::net::Shutdown::Both);
    }
}
