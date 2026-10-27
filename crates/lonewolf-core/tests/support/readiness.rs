// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::SocketAddr;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub struct Readiness {
    pub c2s: Vec<SocketAddr>,
    pub metrics: Option<SocketAddr>,
}

pub struct ReadinessSocket {
    socket: UnixDatagram,
    path: PathBuf,
    _directory: tempfile::TempDir,
}

impl ReadinessSocket {
    pub fn bind() -> io::Result<Self> {
        // Unix socket paths have a short length limit, so the socket gets its own directory.
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("notify.sock");
        let socket = UnixDatagram::bind(&path)?;
        Ok(Self {
            socket,
            path,
            _directory: directory,
        })
    }

    pub fn configure<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        command.env("NOTIFY_SOCKET", &self.path)
    }

    pub fn receive(&self, timeout: Duration) -> io::Result<Option<Readiness>> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buffer = [0; 4096];
        match self.socket.recv(&mut buffer) {
            Ok(length) => parse(&buffer[..length]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

fn parse(message: &[u8]) -> io::Result<Option<Readiness>> {
    let invalid = |detail: &str| io::Error::new(io::ErrorKind::InvalidData, detail.to_owned());
    let message = std::str::from_utf8(message).map_err(|_| invalid("readiness is not UTF-8"))?;
    let mut ready = false;
    let mut c2s = None;
    let mut metrics = None;
    for line in message.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("readiness line has no value"))?;
        match key {
            "READY" => ready = value == "1",
            "X_LONEWOLF_C2S_ADDRESSES" => {
                c2s = Some(
                    value
                        .split(',')
                        .filter(|address| !address.is_empty())
                        .map(str::parse)
                        .collect::<Result<Vec<SocketAddr>, _>>()
                        .map_err(|_| invalid("invalid C2S address"))?,
                );
            }
            "X_LONEWOLF_METRICS_ADDRESS" => {
                metrics = Some(
                    value
                        .parse()
                        .map_err(|_| invalid("invalid metrics address"))?,
                );
            }
            _ => {}
        }
    }
    if !ready {
        return Ok(None);
    }
    Ok(Some(Readiness {
        c2s: c2s.ok_or_else(|| invalid("readiness has no C2S addresses"))?,
        metrics,
    }))
}
