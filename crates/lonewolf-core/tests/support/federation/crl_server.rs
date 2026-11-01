// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar as PlCondvar, Mutex as PlMutex};

use super::super::TestResult;

pub enum CrlResponse {
    Body(Vec<u8>),
    Status(u16),
    Delayed(Duration, Box<CrlResponse>),
    Hang,
}
#[derive(Default)]
struct State {
    responses: HashMap<String, Arc<CrlResponse>>,
    requests: HashMap<String, usize>,
}
#[derive(Default)]
struct Stop {
    stopped: PlMutex<bool>,
    changed: PlCondvar,
}
impl Stop {
    fn stopped(&self) -> bool {
        *self.stopped.lock()
    }

    fn wait(&self, duration: Option<Duration>) -> bool {
        let deadline = duration.map(|duration| Instant::now() + duration);
        let mut stopped = self.stopped.lock();
        while !*stopped {
            if let Some(deadline) = deadline {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                self.changed.wait_for(&mut stopped, remaining);
            } else {
                self.changed.wait(&mut stopped);
            }
        }
        *stopped
    }

    fn stop(&self) {
        *self.stopped.lock() = true;
        self.changed.notify_all();
    }
}
pub struct CrlServer {
    address: SocketAddr,
    state: Arc<PlMutex<State>>,
    stopped: Arc<Stop>,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl CrlServer {
    pub fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let state = Arc::new(PlMutex::new(State::default()));
        let stopped = Arc::new(Stop::default());
        let shared = Arc::clone(&state);
        let stop = Arc::clone(&stopped);
        let thread = thread::spawn(move || {
            let mut workers = Vec::new();
            let result = loop {
                if stop.stopped() {
                    break Ok(());
                }
                let mut stream = match super::tcp::accept_until(
                    &listener,
                    Instant::now() + Duration::from_secs(10),
                ) {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
                    Err(error) => break Err(error),
                };
                if stop.stopped() {
                    break Ok(());
                }
                let shared = Arc::clone(&shared);
                let stop = Arc::clone(&stop);
                workers.push(thread::spawn(move || {
                    match respond(&mut stream, &shared, &stop) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::BrokenPipe
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::NotConnected
                            ) =>
                        {
                            Ok(())
                        }
                        result => result,
                    }
                }));
            };
            stop.stop();
            let mut result = result;
            for worker in workers {
                let completed = worker
                    .join()
                    .map_err(|_| io::Error::other("CRL connection worker panicked"))
                    .and_then(|result| result);
                if result.is_ok() {
                    result = completed;
                }
            }
            result
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
        self.stopped.stop();
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
fn respond(stream: &mut TcpStream, state: &PlMutex<State>, stop: &Stop) -> io::Result<()> {
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
    let mut response = response.as_deref();
    let (status, body) = loop {
        match response {
            Some(CrlResponse::Body(body)) => break (200, body.as_slice()),
            Some(CrlResponse::Status(status)) => break (*status, &[][..]),
            Some(CrlResponse::Delayed(delay, next)) => {
                if stop.wait(Some(*delay)) {
                    return Ok(());
                }
                response = Some(next);
            }
            Some(CrlResponse::Hang) => {
                stop.wait(None);
                return Ok(());
            }
            None => break (404, &[][..]),
        }
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(body)
}
