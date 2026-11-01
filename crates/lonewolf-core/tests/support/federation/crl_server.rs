// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex as PlMutex;

use super::super::TestResult;

pub enum CrlResponse {
    Body(Vec<u8>),
    Status(u16),
}
#[derive(Default)]
struct State {
    responses: HashMap<String, Arc<CrlResponse>>,
    requests: HashMap<String, usize>,
}
pub struct CrlServer {
    address: SocketAddr,
    state: Arc<PlMutex<State>>,
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl CrlServer {
    pub fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let state = Arc::new(PlMutex::new(State::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&state);
        let stop = Arc::clone(&stopped);
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let mut stream = match super::tcp::accept_until(
                    &listener,
                    Instant::now() + Duration::from_secs(10),
                ) {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                    Err(error) => return Err(error),
                };
                if stop.load(Ordering::Acquire) {
                    break;
                }
                if let Err(error) = respond(&mut stream, &shared)
                    && !matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::NotConnected
                    )
                {
                    return Err(error);
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            state,
            stopped,
            thread: Some(thread),
        })
    }
    pub fn port(&self) -> u16 {
        self.address.port()
    }
    pub fn url(&self, path: &str) -> String {
        format!(
            "http://127.0.0.1:{}/{}",
            self.port(),
            path.trim_start_matches('/')
        )
    }
    pub fn serve(&self, path: &str, response: CrlResponse) {
        self.state
            .lock()
            .responses
            .insert(path.trim_start_matches('/').into(), Arc::new(response));
    }
    pub fn requests(&self, path: &str) -> usize {
        self.state
            .lock()
            .requests
            .get(path.trim_start_matches('/'))
            .copied()
            .unwrap_or(0)
    }
    pub fn stop(&mut self) -> TestResult {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        thread.join().map_err(|_| "CRL server worker panicked")??;
        Ok(())
    }
}
impl Drop for CrlServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "CRL fixture request timed out"))
}
fn respond(stream: &mut TcpStream, state: &PlMutex<State>) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut headers = Vec::new();
    let mut byte = [0];
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() == 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CRL fixture request too large",
            ));
        }
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
    }
    let headers = std::str::from_utf8(&headers).map_err(io::Error::other)?;
    let mut request = headers
        .lines()
        .next()
        .ok_or_else(|| io::Error::other("missing HTTP request"))?
        .split_whitespace();
    if request.next() != Some("GET") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected HTTP GET",
        ));
    }
    let path = request
        .next()
        .ok_or_else(|| io::Error::other("missing HTTP path"))?
        .trim_start_matches('/');
    let response = {
        let mut state = state.lock();
        *state.requests.entry(path.into()).or_default() += 1;
        state.responses.get(path).cloned()
    };
    let (status, body) = match response.as_deref() {
        Some(CrlResponse::Body(body)) => (200, body.as_slice()),
        Some(CrlResponse::Status(status)) => (*status, &[][..]),
        None => (404, &[][..]),
    };
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(body)
}
