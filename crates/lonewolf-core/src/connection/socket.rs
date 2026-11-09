// SPDX-License-Identifier: Apache-2.0

use compio::net::TcpStream;
use socket2::SockRef;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(crate) struct ConnectionSocket(pub(crate) TcpStream);
impl Drop for ConnectionSocket {
    fn drop(&mut self) {
        let _ = SockRef::from(&self.0).shutdown(std::net::Shutdown::Both);
    }
}

// The socket must shut down before the future drops its transport adapters.
pub(crate) struct ConnectionTask<F, S = ConnectionSocket> {
    pub(crate) _socket: S,
    pub(crate) future: Pin<Box<F>>,
}

impl<F: Future<Output = ()>, S: Unpin> Future for ConnectionTask<F, S> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(context)
    }
}
