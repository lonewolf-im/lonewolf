// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

fn reusable_socket(address: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

pub struct PortReservation {
    _accepted: TcpStream,
    _keeper: TcpStream,
}

pub fn reserve_listener_address() -> io::Result<(PortReservation, SocketAddr)> {
    reserve_loopback_address(Ipv4Addr::LOCALHOST.into())
}

pub fn reserve_loopback_address(loopback: IpAddr) -> io::Result<(PortReservation, SocketAddr)> {
    let socket = reusable_socket((loopback, 0).into())?;
    socket.listen(1)?;
    let listener: TcpListener = socket.into();
    // A fork can retain the auxiliary listener, so it must not own the reserved port.
    let socket = reusable_socket((loopback, 0).into())?;
    socket.connect_timeout(&listener.local_addr()?.into(), Duration::from_secs(5))?;
    let keeper: TcpStream = socket.into();
    let address = keeper.local_addr()?;
    let (accepted, _) = listener.accept()?;
    // Forked children can retain either endpoint, so both use abortive close.
    socket2::SockRef::from(&accepted).set_linger(Some(Duration::ZERO))?;
    socket2::SockRef::from(&keeper).set_linger(Some(Duration::ZERO))?;
    let reservation = PortReservation {
        _accepted: accepted,
        _keeper: keeper,
    };
    Ok((reservation, address))
}

pub fn bind_released_listener(address: SocketAddr, deadline: Instant) -> io::Result<Socket> {
    loop {
        let result = reusable_socket(address).and_then(|socket| {
            socket.listen(128)?;
            Ok(socket)
        });
        match result {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("listener {address} remains in use after the cleanup deadline"),
                    ));
                }
                std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
            }
            Err(error) => return Err(error),
        }
    }
}
