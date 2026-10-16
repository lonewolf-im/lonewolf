// SPDX-License-Identifier: Apache-2.0

#[path = "acme/ca.rs"]
mod ca;
#[allow(dead_code)]
#[path = "client.rs"]
mod client;
#[path = "acme/process.rs"]
pub mod process;
#[path = "acme/proxy.rs"]
mod proxy;
#[allow(dead_code)]
#[path = "tls.rs"]
pub mod tls;
#[allow(dead_code)]
#[path = "xml.rs"]
pub mod xml;

pub use ca::{AcmeFault, AcmeStage, FakeAcmeCa, http_get};
pub use client::{Client, PlainClient};
pub use process::AcmeServer as C2sSuite;
pub use proxy::ChallengeProxy;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
pub const PASSWORD: &str = "ocean copper lantern meadow";
pub const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
pub const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
pub const ROSTER_VERSIONING_NAMESPACE: &str = "urn:xmpp:features:rosterver";
pub const PRE_APPROVAL_NAMESPACE: &str = "urn:xmpp:features:pre-approval";
pub const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='xmpp.example.test' version='1.0'>";

pub const STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";

fn prepare_blocking_stream(socket: &std::net::TcpStream) -> std::io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn accepted_nonblocking_stream_is_normalized_for_bounded_http_io() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let mut client = TcpStream::connect_timeout(&listener.local_addr()?, TIMEOUT)?;
        client.set_read_timeout(Some(TIMEOUT))?;
        client.set_write_timeout(Some(TIMEOUT))?;
        let (mut accepted, _) = listener.accept()?;
        accepted.set_nonblocking(true)?;
        let mut byte = [0];
        assert_eq!(
            accepted.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        prepare_blocking_stream(&accepted)?;
        assert!(!socket2::SockRef::from(&accepted).nonblocking()?);
        assert_eq!(accepted.read_timeout()?, Some(TIMEOUT));
        assert_eq!(accepted.write_timeout()?, Some(TIMEOUT));
        client.write_all(b"GET /directory HTTP/1.1\r\nHost: ca.example.test\r\n\r\n")?;
        let request = ca::read_request(&mut accepted)?;
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/directory");
        assert_eq!(request.host, "ca.example.test");
        accepted.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")?;
        drop(accepted);
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert_eq!(response, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        Ok(())
    }
}
