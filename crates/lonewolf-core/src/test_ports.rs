// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

fn bind_reusable_socket(address: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

pub(crate) fn reserve_listener_address() -> io::Result<(Socket, SocketAddr)> {
    // A wildcard reservation excludes automatic port allocation without taking the exact endpoint.
    let reservation = bind_reusable_socket((Ipv4Addr::UNSPECIFIED, 0).into())?;
    let address = reservation
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("missing reservation address"))?;
    Ok((reservation, (Ipv4Addr::LOCALHOST, address.port()).into()))
}

pub(crate) fn bind_reusable_listener(address: SocketAddr) -> io::Result<Socket> {
    let socket = bind_reusable_socket(address)?;
    socket.listen(128)?;
    Ok(socket)
}

pub(crate) async fn bind_released_listener(
    address: SocketAddr,
    deadline: Instant,
) -> io::Result<Socket> {
    loop {
        match bind_reusable_listener(address) {
            Ok(socket) => return Ok(socket),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("listener {address} remains in use after the cleanup deadline"),
                    ));
                }
                compio::time::sleep_until((now + Duration::from_millis(5)).min(deadline)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn release_probe_rejects_a_live_listener_and_waits_for_delayed_release()
-> Result<(), Box<dyn std::error::Error>> {
    compio::runtime::Runtime::new()?.block_on(async {
        let (_reservation, address) = reserve_listener_address()?;
        let listener = bind_reusable_listener(address)?;
        let deadline = Instant::now() + Duration::from_millis(20);
        assert_eq!(
            bind_released_listener(address, deadline)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(Instant::now() >= deadline);
        let (replacement, ()) = futures_util::future::join(
            bind_released_listener(address, Instant::now() + Duration::from_secs(2)),
            async {
                compio::time::sleep(Duration::from_millis(5)).await;
                drop(listener);
            },
        )
        .await;
        let _replacement = replacement?;
        Ok(())
    })
}
