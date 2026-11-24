// SPDX-License-Identifier: Apache-2.0

use std::io::{self, ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

pub(super) struct RefusedEndpoint {
    pub(super) address: SocketAddr,
    _accepted: TcpStream,
    _keeper: TcpStream,
}

impl RefusedEndpoint {
    pub(super) fn reserve() -> io::Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(false)?;
        socket.set_reuse_port(false)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        socket.listen(1)?;
        let listener: TcpListener = socket.into();
        let address = listener.local_addr()?;
        let keeper = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
        let (accepted, _) = listener.accept()?;
        // The reservation carries no data and must not leave its port in TIME_WAIT.
        socket2::SockRef::from(&accepted).set_linger(Some(Duration::ZERO))?;
        // A bound, non-listening socket can drop connection attempts on macOS.
        drop(listener);
        let endpoint = Self {
            address,
            _accepted: accepted,
            _keeper: keeper,
        };
        loop {
            let connection = TcpStream::connect_timeout(&address, remaining(deadline)?);
            remaining(deadline)?;
            match connection {
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => return Ok(endpoint),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                            | ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
                Ok(mut probe) => loop {
                    probe.set_read_timeout(Some(remaining(deadline)?))?;
                    let received = probe.read(&mut [0]);
                    remaining(deadline)?;
                    match received {
                        Ok(0) => break,
                        Ok(_) => {
                            return Err(io::Error::other(
                                "refusal probe received application data",
                            ));
                        }
                        Err(error) if error.kind() == ErrorKind::Interrupted => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::ConnectionReset
                                    | ErrorKind::ConnectionAborted
                                    | ErrorKind::NotConnected
                            ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                },
            }
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "refused endpoint deadline expired"))
}
