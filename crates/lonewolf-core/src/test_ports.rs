// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

fn bind_reusable_socket(address: SocketAddr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

pub(crate) struct PortReservation {
    _accepted: TcpStream,
    _keeper: TcpStream,
}

pub(crate) fn reserve_listener_address() -> io::Result<(PortReservation, SocketAddr)> {
    let socket = bind_reusable_listener((Ipv4Addr::LOCALHOST, 0).into())?;
    let listener: TcpListener = socket.into();
    // A fork can retain the auxiliary listener, so it must not own the reserved port.
    let socket = bind_reusable_socket((Ipv4Addr::LOCALHOST, 0).into())?;
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
    // A sibling process spawn can retain socket copies and delay the last close.
    const CHILD: &str = "LONEWOLF_CORE_PORT_RELEASE_TEST";
    const COMPLETED: i32 = 42;
    if std::env::var_os(CHILD).is_none() {
        let thread = std::thread::current();
        let test = thread
            .name()
            .filter(|name| {
                name.starts_with("test_ports::")
                    && name.ends_with(
                        "::release_probe_rejects_a_live_listener_and_waits_for_delayed_release",
                    )
            })
            .ok_or("missing qualified release-probe test name")?;
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, "1")
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(COMPLETED),
            "status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let result: Result<(), Box<dyn std::error::Error>> =
        compio::runtime::Runtime::new()?.block_on(async {
            let (reservation, address) = reserve_listener_address()?;
            let exclusive = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            assert_eq!(
                exclusive.bind(&address.into()).unwrap_err().kind(),
                io::ErrorKind::AddrInUse
            );
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
            drop(replacement?);
            // Keep both endpoints bound; Linux rechecks conflicts when listen starts.
            let released = bind_reusable_socket(address)?;
            let auxiliary = reservation._accepted.local_addr()?;
            let released_auxiliary = bind_reusable_socket(auxiliary)?;
            released.set_reuse_address(false)?;
            released_auxiliary.set_reuse_address(false)?;
            drop(reservation);
            released.listen(128).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("listen {address} after reservation cleanup: {error}"),
                )
            })?;
            released_auxiliary.listen(128).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("listen {auxiliary} after reservation cleanup: {error}"),
                )
            })?;
            Ok(())
        });
    result?;
    std::process::exit(COMPLETED);
}
