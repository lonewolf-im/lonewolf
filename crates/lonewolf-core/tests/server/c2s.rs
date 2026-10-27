// SPDX-License-Identifier: Apache-2.0

#[path = "support/process.rs"]
mod process;

use process::{Server, TIMEOUT, field, request};

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

type TestResult = Result<(), Box<dyn Error>>;
const OPEN: &[u8] =
    b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
const FEATURES_END: &[u8] = b"</stream:features>";
const CLOSED: &str = "lonewolf_c2s_connections_closed_total{";
const REJECTED: &str = "lonewolf_c2s_connections_rejected_total{";

impl Server {
    fn with_metrics(config: &str, workers: usize) -> Result<Self, Box<dyn Error>> {
        Self::start(
            &format!("{config}\n[metrics]\nenabled = true\naddress = '127.0.0.1:0'\n"),
            workers,
        )
    }

    fn ready(&mut self, listener_count: usize) -> Result<String, Box<dyn Error>> {
        self.ready_when(|logs| {
            logs.matches("c2s TCP listener started").count() == listener_count
                && logs.contains("metrics service started")
        })
    }

    fn metrics(&self) -> Result<String, Box<dyn Error>> {
        let logs = self.logs()?;
        let started = logs
            .lines()
            .find(|line| line.contains("metrics service started"))
            .ok_or("missing metrics start log")?;
        let response = request(u16::try_from(field(started, "port=")?)?, "/metrics")?;
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or("missing metrics body")?;
        Ok(body.to_owned())
    }

    fn wait_for_metrics(&self, ready: impl Fn(&str) -> bool) -> Result<String, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let body = self.metrics()?;
            if ready(&body) {
                return Ok(body);
            }
            if Instant::now() >= deadline {
                return Err(format!("metrics did not reach the expected values: {body}").into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Returns the full log after a clean stop and fails if earlier lines were dropped.
    fn stop_with_logs(&mut self, signal: Signal) -> Result<String, Box<dyn Error>> {
        let body = self.metrics()?;
        assert!(
            body.lines()
                .any(|line| line == "lonewolf_log_dropped_lines_total 0"),
            "{body}"
        );
        self.stop(signal)?;
        Ok(self.logs()?)
    }
}

fn total(body: &str, family: &str, label: &str) -> u64 {
    body.lines()
        .filter(|line| line.starts_with(family) && line.contains(label))
        .filter_map(|line| line.rsplit_once(' '))
        .filter_map(|(_, value)| value.parse::<u64>().ok())
        .sum()
}

fn connect_until_eof(port: u16) -> TestResult {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    match stream.shutdown(Shutdown::Write) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
        Err(error) => return Err(error.into()),
    }
    assert_eq!(stream.read(&mut [0; 1])?, 0);
    Ok(())
}

fn read_features(stream: &mut TcpStream) -> TestResult {
    let mut response = Vec::new();
    let mut byte = [0];
    while response.len() < 16 * 1024 && !response.ends_with(FEATURES_END) {
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    assert!(response.ends_with(FEATURES_END));
    assert!(
        response
            .windows(b"<required/>".len())
            .any(|part| part == b"<required/>")
    );
    Ok(())
}

fn read_until_closed(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(response),
            Ok(amount) => response.extend_from_slice(&buffer[..amount]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(response);
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn multiple_endpoints_share_ports_across_workers_and_shutdown_with_admin() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        workers,
    )?;
    let logs = server.ready(2)?;
    let admin_started = logs
        .find("admin service started")
        .ok_or("missing admin start log")?;
    let waiting = logs
        .find("waiting for stop signal")
        .ok_or("missing wait log")?;
    assert!(admin_started < waiting);
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        assert!(line.contains(" INFO "));
        assert_eq!(field(line, "worker_count=")?, workers);
        assert!(!line.contains("worker_id="));
        assert!(logs.find(line).ok_or("missing listener start log")? < waiting);
        let listener = field(line, "listener_id=")?;
        assert!(listener < 2);
        assert_eq!(ports[listener], 0);
        ports[listener] = field(line, "port=")?.try_into()?;
    }
    assert_ne!(ports[0], ports[1]);
    assert!(!ports.contains(&0));
    for port in ports {
        for _ in 0..16 {
            connect_until_eof(port)?;
        }
    }
    let socket = server.directory.path().join("run/lonewolf/admin.sock");
    let mut admin = UnixStream::connect(&socket)?;
    admin.set_read_timeout(Some(TIMEOUT))?;
    admin.write_all(b"GET /v1/accounts HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut response = String::new();
    admin.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"));
    server.wait_for_metrics(|body| total(body, CLOSED, "") == 32)?;
    let logs = server.stop_with_logs(Signal::SIGTERM)?;
    assert!(!socket.exists());
    let mut sockets = std::collections::BTreeSet::new();
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP worker listener started"))
    {
        assert!(line.contains(" DEBUG "));
        let listener = field(line, "listener_id=")?;
        let worker = field(line, "worker_id=")?;
        assert!(listener < 2);
        assert!(worker < workers);
        assert!(sockets.insert((listener, worker)));
        assert_eq!(usize::from(ports[listener]), field(line, "port=")?);
    }
    assert_eq!(sockets.len(), 2 * workers);
    assert_eq!(
        logs.matches("c2s TCP worker listener stopped").count(),
        2 * workers
    );
    let workers_stopped = logs
        .rfind("c2s TCP worker listener stopped")
        .ok_or("missing worker stop log")?;
    let dispatcher_stopped = logs
        .find("core dispatcher stopped")
        .ok_or("missing dispatcher stop log")?;
    let mut stopped_listeners = std::collections::BTreeSet::new();
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener stopped"))
    {
        let offset = logs.find(line).ok_or("missing listener stop log")?;
        assert!(line.contains(" INFO "));
        assert!(workers_stopped < offset);
        assert!(offset < dispatcher_stopped);
        assert_eq!(field(line, "worker_count=")?, workers);
        assert!(stopped_listeners.insert(field(line, "listener_id=")?));
    }
    assert_eq!(stopped_listeners, std::collections::BTreeSet::from([0, 1]));
    assert!(logs.contains("core dispatcher stopped"));
    assert!(!logs.contains("127.0.0.1"));
    for port in ports {
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
    }
    Ok(())
}

#[test]
fn c2s_runs_without_admin_and_stops_on_sigint() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[admin]\nenabled = false\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        workers,
    )?;
    let logs = server.ready(1)?;
    assert!(!logs.contains("admin service started"));
    let started = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener started"))
        .ok_or("missing listener start log")?;
    assert_eq!(field(started, "worker_count=")?, workers);
    let logs = server.stop_with_logs(Signal::SIGINT)?;
    assert_eq!(logs.matches("c2s TCP listener started").count(), 1);
    let stopped = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener stopped"))
        .ok_or("missing listener stop log")?;
    assert!(stopped.contains(" INFO "));
    assert_eq!(field(stopped, "worker_count=")?, workers);
    assert_eq!(field(stopped, "listener_id=")?, 0);
    assert_eq!(logs.matches("c2s TCP listener stopped").count(), 1);
    assert!(!logs.contains("c2s TCP worker listener"));
    assert!(!logs.contains("worker_id="));
    assert!(logs.contains("core dispatcher stopped"));
    Ok(())
}

#[test]
fn listener_rejects_excess_connection_attempts_from_one_ip() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s.profiles.default]\nconnection_attempts_per_ip = { per_second = 1, burst = 1 }\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        workers,
    )?;
    let logs = server.ready(1)?;
    let started = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener started"))
        .ok_or("missing listener start log")?;
    let port = u16::try_from(field(started, "port=")?)?;
    for _ in 0..16 {
        connect_until_eof(port)?;
    }
    server.wait_for_metrics(|body| {
        total(body, CLOSED, "outcome=\"eof\"") == 1
            && total(body, REJECTED, "reason=\"connection_attempts_per_ip\"") == 15
    })?;
    let logs = server.stop_with_logs(Signal::SIGINT)?;
    assert_eq!(
        logs.matches("c2s connection attempt rejected").count(),
        1,
        "{logs}"
    );
    assert!(!logs.contains("127.0.0.1"));
    Ok(())
}

#[test]
fn connection_limit_holds_capacity_until_eof_and_releases_it_on_shutdown() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s.profiles.default]\nmax_connections_per_ip = 1\nconnection_attempts_per_ip = { per_second = 1000, burst = 1000 }\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n",
        workers,
    )?;
    let logs = server.ready(1)?;
    let started = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener started"))
        .ok_or("missing listener start log")?;
    let address = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        u16::try_from(field(started, "port=")?)?,
    ));
    let mut first = TcpStream::connect_timeout(&address, TIMEOUT)?;
    first.set_read_timeout(Some(Duration::from_millis(200)))?;
    first.write_all(OPEN)?;
    read_features(&mut first)?;
    assert!(matches!(
        first.read(&mut [0; 1]),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    let mut rejected = TcpStream::connect_timeout(&address, TIMEOUT)?;
    rejected.set_read_timeout(Some(TIMEOUT))?;
    assert_eq!(rejected.read(&mut [0; 1])?, 0);
    first.shutdown(Shutdown::Write)?;
    assert_eq!(first.read(&mut [0; 1])?, 0);
    server.wait_for_metrics(|body| {
        total(body, CLOSED, "outcome=\"eof\"") == 1
            && total(body, REJECTED, "reason=\"max_connections_per_ip\"") == 1
    })?;
    let mut replacement = TcpStream::connect_timeout(&address, TIMEOUT)?;
    replacement.set_read_timeout(Some(Duration::from_millis(200)))?;
    replacement.write_all(OPEN)?;
    read_features(&mut replacement)?;
    assert!(matches!(
        replacement.read(&mut [0; 1]),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    let logs = server.stop_with_logs(Signal::SIGINT)?;
    replacement.set_read_timeout(Some(TIMEOUT))?;
    assert_eq!(read_until_closed(&mut replacement)?, b"<stream:error><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>");
    assert!(!logs.contains("127.0.0.1"));
    Ok(())
}

#[test]
fn listeners_with_the_same_profile_have_separate_connection_caps() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s.profiles.shared]\nmax_connections_per_ip = 1\nconnection_attempts_per_ip = { per_second = 1000, burst = 1000 }\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'shared'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'shared'\n",
        workers,
    )?;
    let logs = server.ready(2)?;
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        ports[field(line, "listener_id=")?] = u16::try_from(field(line, "port=")?)?;
    }
    assert!(!ports.contains(&0));
    let mut held = Vec::with_capacity(2);
    for port in ports {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut first = TcpStream::connect_timeout(&address, TIMEOUT)?;
        first.set_read_timeout(Some(Duration::from_millis(200)))?;
        first.write_all(OPEN)?;
        read_features(&mut first)?;
        assert!(matches!(
            first.read(&mut [0; 1]),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        ));
        let mut rejected = TcpStream::connect_timeout(&address, TIMEOUT)?;
        rejected.set_read_timeout(Some(TIMEOUT))?;
        assert_eq!(rejected.read(&mut [0; 1])?, 0);
        held.push(first);
    }
    server.wait_for_metrics(|body| {
        ["0", "1"].iter().all(|listener| {
            body.lines().any(|line| {
                line == format!(
                    "{REJECTED}listener=\"{listener}\",reason=\"max_connections_per_ip\"}} 1"
                )
            })
        })
    })?;
    server.stop(Signal::SIGINT)?;
    for mut stream in held {
        stream.set_read_timeout(Some(TIMEOUT))?;
        assert_eq!(read_until_closed(&mut stream)?, b"<stream:error><system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>");
    }
    Ok(())
}

#[test]
fn listener_uses_its_selected_stanza_size_limit() -> TestResult {
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s]\ndefault = 'large'\n[limits.c2s.profiles.large]\nmax_stanza_bytes = 262144\n[limits.c2s.profiles.small]\nmax_stanza_bytes = 10000\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'small'\n",
        1,
    )?;
    let logs = server.ready(2)?;
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        ports[field(line, "listener_id=")?] = u16::try_from(field(line, "port=")?)?;
    }
    assert!(!ports.contains(&0));
    let mut large = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0]))?;
    let mut small = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[1]))?;
    large.set_read_timeout(Some(Duration::from_millis(200)))?;
    small.set_read_timeout(Some(TIMEOUT))?;
    let payload = format!("<message><body>{}", "x".repeat(12_000));
    large.write_all(OPEN)?;
    large.write_all(payload.as_bytes())?;
    small.write_all(OPEN)?;
    small.write_all(payload.as_bytes())?;
    read_features(&mut large)?;
    read_features(&mut small)?;
    assert!(matches!(
        large.read(&mut [0; 1]),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    let response = read_until_closed(&mut small)?;
    assert!(
        response
            .windows(b"<policy-violation".len())
            .any(|part| part == b"<policy-violation")
    );
    large.shutdown(Shutdown::Write)?;
    large.set_read_timeout(Some(TIMEOUT))?;
    assert_eq!(large.read(&mut [0; 1])?, 0);
    server.wait_for_metrics(|body| {
        body.lines().any(|line| {
            line.starts_with(&format!("{CLOSED}listener=\"1\","))
                && line.ends_with(",outcome=\"size_limit_exceeded\"} 1")
        })
    })?;
    let logs = server.stop_with_logs(Signal::SIGINT)?;
    assert!(!logs.contains("127.0.0.1"));
    Ok(())
}

#[test]
fn listener_uses_its_selected_xml_byte_rate() -> TestResult {
    let payload = [OPEN, b"</stream:stream>"].concat();
    let config = format!(
        "[admin]\nenabled = false\n[limits.c2s]\ndefault = 'fast'\n[limits.c2s.profiles.fast]\nincoming_xml_per_connection = {{ bytes_per_second = 1000000, burst_bytes = 1000000 }}\n[limits.c2s.profiles.slow]\nincoming_xml_per_connection = {{ bytes_per_second = 1, burst_bytes = {} }}\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'slow'\n",
        payload.len() - 1
    );
    let mut server = Server::with_metrics(&config, 1)?;
    let logs = server.ready(2)?;
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        ports[field(line, "listener_id=")?] = u16::try_from(field(line, "port=")?)?;
    }
    assert!(!ports.contains(&0));
    let mut slow = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[1]))?;
    slow.set_read_timeout(Some(Duration::from_millis(100)))?;
    slow.write_all(&payload)?;
    read_features(&mut slow)?;
    assert!(matches!(
        slow.read(&mut [0; 1]),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
    ));
    let mut fast = TcpStream::connect((Ipv4Addr::LOCALHOST, ports[0]))?;
    fast.set_read_timeout(Some(TIMEOUT))?;
    fast.write_all(&payload)?;
    read_features(&mut fast)?;
    assert_eq!(read_until_closed(&mut fast)?, b"</stream:stream>");
    slow.set_read_timeout(Some(TIMEOUT))?;
    assert_eq!(read_until_closed(&mut slow)?, b"</stream:stream>");
    server.stop(Signal::SIGINT)?;
    Ok(())
}

#[test]
fn listeners_with_the_same_profile_have_separate_attempt_buckets() -> TestResult {
    let workers = thread::available_parallelism()?.get().min(2);
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s.profiles.shared]\nconnection_attempts_per_ip = { per_second = 1, burst = 1 }\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'shared'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'shared'\n",
        workers,
    )?;
    let logs = server.ready(2)?;
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        ports[field(line, "listener_id=")?] = u16::try_from(field(line, "port=")?)?;
    }
    assert!(!ports.contains(&0));
    for port in ports {
        for _ in 0..2 {
            connect_until_eof(port)?;
        }
    }
    server.wait_for_metrics(|body| {
        ["0", "1"].iter().all(|listener| {
            total(body, CLOSED, &format!("listener=\"{listener}\"")) == 1
                && body.lines().any(|line| {
                    line == format!("{REJECTED}listener=\"{listener}\",reason=\"connection_attempts_per_ip\"}} 1")
                })
        })
    })?;
    let logs = server.stop_with_logs(Signal::SIGINT)?;
    assert!(!logs.contains("127.0.0.1"));
    Ok(())
}

#[test]
fn listener_uses_its_selected_attempt_limit_profile() -> TestResult {
    let mut server = Server::with_metrics(
        "[logging]\nlevel = 'trace'\n[admin]\nenabled = false\n[limits.c2s]\ndefault = 'strict'\n[limits.c2s.profiles.strict]\nconnection_attempts_per_ip = { per_second = 1, burst = 1 }\n[limits.c2s.profiles.relaxed]\nconnection_attempts_per_ip = { per_second = 1, burst = 3 }\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'relaxed'\n",
        1,
    )?;
    let logs = server.ready(2)?;
    let mut ports = [0_u16; 2];
    for line in logs
        .lines()
        .filter(|line| line.contains("c2s TCP listener started"))
    {
        ports[field(line, "listener_id=")?] = u16::try_from(field(line, "port=")?)?;
    }
    assert!(!ports.contains(&0));
    for port in ports {
        for _ in 0..2 {
            connect_until_eof(port)?;
        }
    }
    let metrics = server.wait_for_metrics(|body| {
        total(body, CLOSED, "outcome=\"eof\"") == 3 && total(body, REJECTED, "") == 1
    })?;
    assert_eq!(
        total(
            &metrics,
            REJECTED,
            "listener=\"0\",reason=\"connection_attempts_per_ip\""
        ),
        1,
        "{metrics}"
    );
    server.stop(Signal::SIGINT)?;
    Ok(())
}

#[test]
fn empty_listener_list_fails_before_starting_services() -> TestResult {
    for admin_enabled in [true, false] {
        let mut server = Server::start(
            &format!("[admin]\nenabled = {admin_enabled}\n[c2s]\nlisteners = []\n"),
            1,
        )?;
        assert_eq!(server.wait()?.code(), Some(1));
        let logs = server.logs()?;
        assert!(logs.contains("c2s.listeners must define at least one listener"));
        assert!(!logs.contains("core dispatcher started"));
        assert!(!server.directory.path().join("data").exists());
        assert!(!server.directory.path().join("run").exists());
    }
    Ok(())
}

#[test]
fn occupied_endpoint_stops_started_listeners_and_removes_admin_socket() -> TestResult {
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let mut server = Server::start(
        &format!(
            "[logging]\nlevel = 'trace'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[[c2s.listeners]]\naddress = '{}'\n",
            occupied.local_addr()?
        ),
        1,
    )?;
    assert_eq!(server.wait()?.code(), Some(1));
    let logs = server.logs()?;
    assert!(logs.contains("c2s listener service failed: listener 1 on worker 0"));
    assert!(logs.contains("c2s TCP worker listener stopped"));
    assert!(logs.contains("core dispatcher stopped"));
    assert!(
        !server
            .directory
            .path()
            .join("run/lonewolf/admin.sock")
            .exists()
    );
    let started = logs
        .lines()
        .find(|line| line.contains("c2s TCP listener started"))
        .ok_or("missing listener start log")?;
    let port = u16::try_from(field(started, "port=")?)?;
    let _rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    Ok(())
}
