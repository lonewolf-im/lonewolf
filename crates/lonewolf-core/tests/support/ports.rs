// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
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

pub fn reserve_listener_address() -> io::Result<(Socket, SocketAddr)> {
    // A wildcard reservation excludes automatic port allocation without taking the exact endpoint.
    let reservation = reusable_socket((Ipv4Addr::UNSPECIFIED, 0).into())?;
    let address = reservation
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("missing reservation address"))?;
    Ok((reservation, (Ipv4Addr::LOCALHOST, address.port()).into()))
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
