// SPDX-License-Identifier: Apache-2.0

#[path = "support/process.rs"]
mod process;

use process::{Server, TIMEOUT, field, request};

#[path = "../support/ports.rs"]
mod ports;

use std::error::Error;
use std::net::{Ipv4Addr, TcpListener};
use std::time::Instant;

use nix::sys::signal::Signal;

type TestResult = Result<(), Box<dyn Error>>;

impl Server {
    fn ready(&mut self, metrics_enabled: bool) -> Result<String, Box<dyn Error>> {
        self.ready_when(|logs| {
            logs.contains("c2s TCP listener started")
                && (!metrics_enabled || logs.contains("metrics service started"))
        })
    }
}

#[test]
fn enabled_metrics_serve_openmetrics_and_stop_with_the_server() -> TestResult {
    let (_reservation, address) = ports::reserve_listener_address()?;
    let mut server = Server::start(
        &format!(
            "[logging]\nlevel = 'debug'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[metrics]\nenabled = true\naddress = '{address}'\n[admin]\nenabled = false\n"
        ),
        2,
    )?;
    let logs = server.ready(true)?;
    let line = logs
        .lines()
        .find(|line| line.contains("metrics service started"))
        .ok_or("missing metrics start log")?;
    let port = field(line, "port=")?.try_into()?;
    assert_eq!(port, address.port());
    let response = request(port, "/metrics")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("missing response body")?;
    assert!(headers.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("content-type: application/openmetrics-text; version=1.0.0; charset=utf-8"),
        "{headers}"
    );
    assert!(
        body.lines().any(|line| line.starts_with(&format!(
            "lonewolf_build_info{{version=\"{}\"",
            env!("CARGO_PKG_VERSION")
        ))),
        "{body}"
    );
    assert!(
        body.lines()
            .any(|line| line.starts_with("process_cpu_seconds_total ")),
        "{body}"
    );
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_log_dropped_lines_total 0"),
        "{body}"
    );
    assert!(body.ends_with("# EOF\n"), "{body}");
    assert!(request(port, "/missing")?.starts_with("HTTP/1.1 404"));
    server.stop(Signal::SIGTERM)?;
    assert!(server.logs()?.contains("metrics service stopped"));
    let _listener = ports::bind_released_listener(address, Instant::now() + TIMEOUT)?;
    Ok(())
}

#[test]
fn occupied_metrics_address_stops_startup_before_client_listeners() -> TestResult {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut server = Server::start(
        &format!(
            "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[metrics]\nenabled = true\naddress = '{}'\n",
            occupied.local_addr()?
        ),
        2,
    )?;
    assert_eq!(server.wait()?.code(), Some(1));
    let logs = server.logs()?;
    assert!(logs.contains("metrics service failed"), "{logs}");
    assert!(!logs.contains("c2s TCP listener started"), "{logs}");
    assert!(
        !server
            .directory
            .path()
            .join("run/lonewolf/admin.sock")
            .exists()
    );
    Ok(())
}

#[test]
fn metrics_are_disabled_by_default() -> TestResult {
    let mut server = Server::start(
        "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[admin]\nenabled = false\n",
        2,
    )?;
    server.ready(false)?;
    server.stop(Signal::SIGINT)?;
    assert!(!server.logs()?.contains("metrics service started"));
    Ok(())
}
