// SPDX-License-Identifier: Apache-2.0

use super::ca::read_request;
use super::{TIMEOUT, TestResult};
use parking_lot::Mutex as PlMutex;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct ChallengeProxy {
    pub address: SocketAddr,
    pub requests: Arc<PlMutex<Vec<(String, String)>>>,
    target: Arc<PlMutex<SocketAddr>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl ChallengeProxy {
    pub fn start(target: SocketAddr) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let requests = Arc::new(PlMutex::new(Vec::new()));
        let observed = requests.clone();
        let target = Arc::new(PlMutex::new(target));
        let forwarding_target = target.clone();
        let thread = thread::spawn(move || {
            while !running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let result = (|| -> TestResult {
                            socket.set_read_timeout(Some(TIMEOUT))?;
                            socket.set_write_timeout(Some(TIMEOUT))?;
                            let request = read_request(&mut socket)?;
                            observed
                                .lock()
                                .push((request.host.clone(), request.path.clone()));
                            let target = *forwarding_target.lock();
                            let mut upstream = TcpStream::connect_timeout(&target, TIMEOUT)?;
                            upstream.set_read_timeout(Some(TIMEOUT))?;
                            upstream.set_write_timeout(Some(TIMEOUT))?;
                            write!(
                                upstream,
                                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                                request.method, request.path, request.host
                            )?;
                            let mut response = Vec::new();
                            upstream.take(32 * 1024).read_to_end(&mut response)?;
                            socket.write_all(&response)?;
                            Ok(())
                        })();
                        if let Err(error) = result {
                            eprintln!("challenge proxy: {error}");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            requests,
            target,
            stop,
            thread: Some(thread),
        })
    }
    pub fn set_target(&self, target: SocketAddr) {
        *self.target.lock() = target;
    }
}
impl Drop for ChallengeProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
