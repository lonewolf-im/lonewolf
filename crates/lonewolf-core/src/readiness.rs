// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fmt::Write;
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// Builds a service manager readiness message that lists C2S addresses in configuration order.
pub(crate) fn message(c2s: &[SocketAddr], metrics: Option<SocketAddr>) -> String {
    let mut message = String::from("READY=1\nX_LONEWOLF_C2S_ADDRESSES=");
    for (index, address) in c2s.iter().enumerate() {
        if index > 0 {
            message.push(',');
        }
        let _ = write!(message, "{address}");
    }
    message.push('\n');
    if let Some(address) = metrics {
        let _ = writeln!(message, "X_LONEWOLF_METRICS_ADDRESS={address}");
    }
    message
}

pub(crate) fn notify(message: &str) {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Err(error) = send(&socket, message.as_bytes()) {
        tracing::error!(
            error_kind = ?error.kind(),
            "service manager notification failed"
        );
    }
}

fn send(socket: &OsStr, message: &[u8]) -> io::Result<()> {
    let client = UnixDatagram::unbound()?;
    client.set_nonblocking(true)?;
    let sent = match socket.as_bytes() {
        [b'/', ..] => client.send_to(message, Path::new(socket))?,
        #[cfg(target_os = "linux")]
        [b'@', name @ ..] => {
            use std::os::linux::net::SocketAddrExt;
            let address = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
            client.send_to_addr(message, &address)?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported service manager socket address",
            ));
        }
    };
    if sent == message.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "service manager notification was truncated",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn message_lists_listeners_in_order_and_the_metrics_address() {
        assert_eq!(
            message(
                &[
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 5222)),
                    SocketAddr::from((Ipv6Addr::LOCALHOST, 5223)),
                ],
                Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9090))),
            ),
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:5222,[::1]:5223\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:9090\n"
        );
    }

    #[test]
    fn message_omits_the_metrics_address_when_metrics_are_disabled() {
        assert_eq!(
            message(&[SocketAddr::from((Ipv4Addr::LOCALHOST, 5222))], None),
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:5222\n"
        );
    }

    #[test]
    fn send_delivers_one_datagram_to_a_path_socket() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path)?;
        send(path.as_os_str(), b"READY=1\n")?;
        let mut buffer = [0; 64];
        let received = receiver.recv(&mut buffer)?;
        assert_eq!(&buffer[..received], b"READY=1\n");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_delivers_one_datagram_to_an_abstract_socket() -> TestResult {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("lonewolf-readiness-{}", std::process::id());
        let receiver = UnixDatagram::bind_addr(
            &std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?,
        )?;
        send(OsStr::new(&format!("@{name}")), b"READY=1\n")?;
        let mut buffer = [0; 64];
        let received = receiver.recv(&mut buffer)?;
        assert_eq!(&buffer[..received], b"READY=1\n");
        Ok(())
    }

    #[test]
    fn send_rejects_relative_and_unknown_socket_addresses() {
        for socket in ["notify.sock", "vsock:2:1", ""] {
            assert_eq!(
                send(OsStr::new(socket), b"READY=1\n").unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{socket}"
            );
        }
    }

    #[test]
    fn send_does_not_block_when_the_receiver_queue_is_full() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("notify.sock");
        let _receiver = UnixDatagram::bind(&path)?;
        let message = [0; 1024];
        assert!((0..100_000).any(|_| send(path.as_os_str(), &message).is_err()));
        Ok(())
    }
}
