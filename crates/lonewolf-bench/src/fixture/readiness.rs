// SPDX-License-Identifier: Apache-2.0

use super::{BenchResult, failure};
use std::{
    io,
    net::SocketAddr,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
};

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Readiness {
    pub(super) c2s: SocketAddr,
    pub(super) metrics: SocketAddr,
}

pub(super) struct Notifications {
    socket: UnixDatagram,
    path: PathBuf,
}
impl Notifications {
    pub(super) fn bind(path: PathBuf) -> BenchResult<Self> {
        let socket = UnixDatagram::bind(&path).map_err(|_| failure("fixture_notify_socket"))?;
        socket
            .set_nonblocking(true)
            .map_err(|_| failure("fixture_notify_socket"))?;
        Ok(Self { socket, path })
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn try_receive(&self) -> BenchResult<Option<Readiness>> {
        let mut buffer = [0; 1024];
        loop {
            match self.socket.recv(&mut buffer) {
                Ok(length) => {
                    if let Some(readiness) = parse(&buffer[..length])? {
                        return Ok(Some(readiness));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(failure("fixture_notify_receive")),
            }
        }
    }
}

fn parse(message: &[u8]) -> BenchResult<Option<Readiness>> {
    let invalid = || failure("fixture_startup_notification");
    let message = std::str::from_utf8(message).map_err(|_| invalid())?;
    let mut ready = false;
    let mut c2s = None;
    let mut metrics = None;
    for line in message.lines() {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        let address = match key {
            "READY" => {
                ready = value == "1";
                continue;
            }
            "X_LONEWOLF_C2S_ADDRESSES" => &mut c2s,
            "X_LONEWOLF_METRICS_ADDRESS" => &mut metrics,
            _ => continue,
        };
        let parsed = value
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.port() != 0)
            .ok_or_else(invalid)?;
        if address.replace(parsed).is_some() {
            return Err(invalid());
        }
    }
    if !ready {
        return Ok(None);
    }
    Ok(Some(Readiness {
        c2s: c2s.ok_or_else(invalid)?,
        metrics: metrics.ok_or_else(invalid)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_reports_the_listener_and_metrics_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let notifications = Notifications::bind(directory.path().join("notify.sock"))?;
        assert_eq!(notifications.try_receive()?, None);
        let sender = UnixDatagram::unbound()?;
        sender.send_to(b"STATUS=starting\n", notifications.path())?;
        sender.send_to(
            b"READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:1234\nX_LONEWOLF_METRICS_ADDRESS=[::1]:2345\nX_OTHER=1\n",
            notifications.path(),
        )?;
        assert_eq!(
            notifications.try_receive()?,
            Some(Readiness {
                c2s: "127.0.0.1:1234".parse()?,
                metrics: "[::1]:2345".parse()?,
            })
        );
        assert_eq!(notifications.try_receive()?, None);
        Ok(())
    }

    #[test]
    fn readiness_rejects_malformed_missing_and_duplicate_addresses() {
        for message in [
            "READY=1\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2345\n",
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:1234\n",
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:1234,127.0.0.1:1235\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2345\n",
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:0\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2345\n",
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=127.0.0.1:1234\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2345\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2346\n",
            "READY=1\nX_LONEWOLF_C2S_ADDRESSES=port=1234\nX_LONEWOLF_METRICS_ADDRESS=127.0.0.1:2345\n",
            "READY=1\nmalformed\n",
        ] {
            assert!(parse(message.as_bytes()).is_err(), "{message}");
        }
        assert!(matches!(parse(b"READY=0\n"), Ok(None)));
        assert!(parse(&[0xff]).is_err());
    }
}
