// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub struct RefusedEndpoint {
    address: SocketAddr,
    _accepted: TcpStream,
    _keeper: TcpStream,
}

impl RefusedEndpoint {
    pub fn reserve(deadline: Instant) -> io::Result<Self> {
        remaining(deadline)?;
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
        remaining(deadline)?;
        let accepted = accept_until(&listener, deadline)?;
        // A bound, non-listening socket can silently drop connection attempts on macOS.
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
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    return Ok(endpoint);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
                Ok(mut probe) => {
                    let mut byte = [0];
                    loop {
                        probe.set_read_timeout(Some(remaining(deadline)?))?;
                        let received = probe.read(&mut byte);
                        remaining(deadline)?;
                        match received {
                            Ok(0) => break,
                            Ok(_) => {
                                return Err(io::Error::other(
                                    "refusal probe received application data",
                                ));
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::NotConnected
                                ) =>
                            {
                                break;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

pub fn accept_until(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    remaining(deadline)?;
    listener.set_nonblocking(true)?;
    loop {
        remaining(deadline)?;
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                remaining(deadline)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        let budget = remaining(deadline)?;
        let milliseconds = i32::try_from(
            budget.as_millis() + u128::from(!budget.subsec_nanos().is_multiple_of(1_000_000)),
        )
        .map_err(io::Error::other)?;
        let mut readiness = nix::libc::pollfd {
            fd: listener.as_raw_fd(),
            events: nix::libc::POLLIN,
            revents: 0,
        };
        // SAFETY: The listener and initialized descriptor remain live during poll.
        let result = unsafe { nix::libc::poll(&mut readiness, 1, milliseconds) };
        let error = (result < 0).then(io::Error::last_os_error);
        remaining(deadline)?;
        if let Some(error) = error {
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if readiness.revents & nix::libc::POLLNVAL != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid listener",
            ));
        }
        if readiness.revents & (nix::libc::POLLERR | nix::libc::POLLHUP) != 0 {
            return Err(listener
                .take_error()?
                .unwrap_or_else(|| io::Error::other("listener readiness failed")));
        }
        if result > 0 && readiness.revents & nix::libc::POLLIN == 0 {
            return Err(io::Error::other("unexpected listener readiness"));
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TCP fixture deadline expired"))
}
