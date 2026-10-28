// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicU64;

use compio::net::TcpStream;
use socket2::SockRef;

pub(crate) mod dns;
pub(crate) mod inbound;
pub(crate) mod metrics;
pub(crate) mod outbound;
pub(crate) mod stream;

static NEXT_S2S_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

struct ConnectionSocket(TcpStream);

impl Drop for ConnectionSocket {
    fn drop(&mut self) {
        let _ = SockRef::from(&self.0).shutdown(std::net::Shutdown::Both);
    }
}
