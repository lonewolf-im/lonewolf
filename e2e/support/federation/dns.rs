// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, SRV},
};
use parking_lot::Mutex as PlMutex;

use super::super::{TIMEOUT, TestResult};

const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Answers {
    names: HashMap<String, NameAnswers>,
}

#[derive(Default)]
struct NameAnswers {
    records: HashMap<RecordType, Vec<RData>>,
    failure: Option<Option<ResponseCode>>,
    counts: HashMap<RecordType, usize>,
    observers: HashMap<RecordType, Vec<std::sync::mpsc::SyncSender<()>>>,
}

pub struct FakeDns {
    address: SocketAddr,
    answers: Arc<PlMutex<Answers>>,
    stopped: Arc<AtomicBool>,
    joined: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl FakeDns {
    pub fn start() -> TestResult<Self> {
        let (tcp, udp) = loop {
            // UDP can select a port held by a TCP reservation.
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            match UdpSocket::bind(tcp.local_addr()?) {
                Ok(udp) => break (tcp, udp),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error.into()),
            }
        };
        let address = udp.local_addr()?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        tcp.set_nonblocking(true)?;
        let answers = Arc::new(PlMutex::new(Answers::default()));
        let stopped = Arc::new(AtomicBool::new(false));
        let joined = Arc::new(AtomicBool::new(false));
        let worker = {
            let answers = Arc::clone(&answers);
            let stopped = Arc::clone(&stopped);
            thread::Builder::new()
                .name("federation-dns".into())
                .spawn(move || serve(udp, tcp, &answers, &stopped))?
        };
        Ok(Self {
            address,
            answers,
            stopped,
            joined,
            worker: Some(worker),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn join_receipt(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.joined)
    }

    pub fn srv(&self, domain: &str, records: &[(u16, u16, u16, &str)]) {
        self.service_srv("_xmpp-server", domain, records);
    }
    pub fn direct_srv(&self, domain: &str, records: &[(u16, u16, u16, &str)]) {
        self.service_srv("_xmpps-server", domain, records);
    }
    pub fn srv_with_mode(
        &self,
        mode: lonewolf_core::config::TlsMode,
        domain: &str,
        records: &[(u16, u16, u16, &str)],
    ) {
        match mode {
            lonewolf_core::config::TlsMode::StartTls => self.srv(domain, records),
            lonewolf_core::config::TlsMode::Direct => self.direct_srv(domain, records),
        }
    }
    fn service_srv(&self, service: &str, domain: &str, records: &[(u16, u16, u16, &str)]) {
        let records = records
            .iter()
            .map(|&(priority, weight, port, target)| {
                let target = Name::from_ascii(target)
                    .unwrap_or_else(|error| panic!("invalid fake DNS target: {error}"));
                RData::SRV(SRV::new(priority, weight, port, target))
            })
            .collect();
        self.set(
            &format!("{service}._tcp.{domain}"),
            RecordType::SRV,
            records,
        );
    }
    pub fn a(&self, name: &str, address: Ipv4Addr) {
        self.set(name, RecordType::A, vec![RData::A(A(address))]);
    }
    pub fn aaaa(&self, name: &str, address: Ipv6Addr) {
        self.set(name, RecordType::AAAA, vec![RData::AAAA(AAAA(address))]);
    }
    fn set(&self, name: &str, kind: RecordType, records: Vec<RData>) {
        let mut answers = self.answers.lock();
        let answer = answers.names.entry(canonical(name)).or_default();
        answer.failure = None;
        answer.records.insert(kind, records);
    }
    pub fn nxdomain(&self, name: &str) {
        self.failure(name, Some(ResponseCode::NXDomain));
    }
    pub fn servfail(&self, name: &str) {
        self.failure(name, Some(ResponseCode::ServFail));
    }
    pub fn drop_queries(&self, name: &str) {
        self.failure(name, None);
    }
    fn failure(&self, name: &str, code: Option<ResponseCode>) {
        self.answers
            .lock()
            .names
            .entry(canonical(name))
            .or_default()
            .failure = Some(code);
    }
    pub fn no_service(&self, domain: &str) {
        self.srv(domain, &[(0, 0, 0, ".")])
    }
    pub fn query_count(&self, name: &str, kind: RecordType) -> usize {
        self.answers
            .lock()
            .names
            .get(&canonical(name))
            .and_then(|answer| answer.counts.get(&kind))
            .copied()
            .unwrap_or(0)
    }

    pub fn observe_query(&self, name: &str, kind: RecordType) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut answers = self.answers.lock();
        let answer = answers.names.entry(canonical(name)).or_default();
        if answer.counts.get(&kind).copied().unwrap_or(0) > 0 {
            let _ = sender.try_send(());
        }
        answer.observers.entry(kind).or_default().push(sender);
        receiver
    }

    pub fn stop(&mut self) -> TestResult {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            self.joined.store(true, Ordering::Release);
            result.map_err(|_| "fake DNS worker panicked")??;
        }
        Ok(())
    }
}
impl Drop for FakeDns {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn canonical(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.').to_ascii_lowercase())
}

fn answer(bytes: &[u8], answers: &PlMutex<Answers>) -> io::Result<Option<Vec<u8>>> {
    let request = Message::from_vec(bytes).map_err(io::Error::other)?;
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    let mut answers = answers.lock();
    for query in &request.queries {
        response.add_query(query.clone());
        let answer = answers
            .names
            .entry(canonical(&query.name().to_ascii()))
            .or_default();
        *answer.counts.entry(query.query_type()).or_default() += 1;
        if let Some(observers) = answer.observers.get(&query.query_type()) {
            for observer in observers {
                let _ = observer.try_send(());
            }
        }
        if let Some(code) = answer.failure {
            let Some(code) = code else {
                return Ok(None);
            };
            response.metadata.response_code = code;
        } else if let Some(records) = answer.records.get(&query.query_type()) {
            for data in records {
                response.add_answer(Record::from_rdata(query.name().clone(), 1, data.clone()));
            }
        }
    }
    response.to_vec().map(Some).map_err(io::Error::other)
}

fn serve(
    udp: UdpSocket,
    tcp: TcpListener,
    answers: &PlMutex<Answers>,
    stopped: &AtomicBool,
) -> io::Result<()> {
    thread::scope(|scope| {
        let mut workers = Vec::new();
        let result = serve_queries(udp, tcp, answers, stopped, |stream| {
            let mut index = 0;
            while index < workers.len() {
                let worker: &thread::ScopedJoinHandle<'_, io::Result<()>> = &workers[index];
                if worker.is_finished() {
                    workers
                        .swap_remove(index)
                        .join()
                        .map_err(|_| io::Error::other("fake DNS TCP worker panicked"))??;
                } else {
                    index += 1;
                }
            }
            workers.push(scope.spawn(move || serve_tcp(stream, answers, stopped)));
            Ok(())
        });
        stopped.store(true, Ordering::Release);
        let mut outcome = result;
        for worker in workers {
            let result = worker
                .join()
                .map_err(|_| io::Error::other("fake DNS TCP worker panicked"))
                .and_then(std::convert::identity);
            if outcome.is_ok() {
                outcome = result;
            }
        }
        outcome
    })
}

fn serve_queries(
    udp: UdpSocket,
    tcp: TcpListener,
    answers: &PlMutex<Answers>,
    stopped: &AtomicBool,
    mut accept: impl FnMut(TcpStream) -> io::Result<()>,
) -> io::Result<()> {
    let mut bytes = [0; 65535];
    while !stopped.load(Ordering::Acquire) {
        let mut descriptors = [udp.as_raw_fd(), tcp.as_raw_fd()].map(|fd| nix::libc::pollfd {
            fd,
            events: nix::libc::POLLIN,
            revents: 0,
        });
        // SAFETY: Both sockets and the descriptor array remain live during poll.
        let ready = unsafe { nix::libc::poll(descriptors.as_mut_ptr(), 2, 100) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptors[0].revents & nix::libc::POLLIN != 0 {
            let (length, peer) = udp.recv_from(&mut bytes)?;
            if let Some(response) = answer(&bytes[..length], answers)? {
                udp.send_to(&response, peer)?;
            }
        }
        if descriptors[1].revents & nix::libc::POLLIN != 0 {
            match tcp.accept() {
                Ok((stream, _)) => accept(stream)?,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn serve_tcp(
    mut stream: TcpStream,
    answers: &PlMutex<Answers>,
    stopped: &AtomicBool,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let mut bytes = Vec::new();
    while !stopped.load(Ordering::Acquire) {
        let deadline = Instant::now() + TIMEOUT;
        let mut length = [0; 2];
        if !read_exact_until(&mut stream, &mut length, stopped, deadline)? {
            return Ok(());
        }
        bytes.resize(usize::from(u16::from_be_bytes(length)), 0);
        if !read_exact_until(&mut stream, &mut bytes, stopped, deadline)? {
            return Ok(());
        }
        if let Some(response) = answer(&bytes, answers)? {
            stream.set_write_timeout(Some(TIMEOUT))?;
            stream.write_all(&(response.len() as u16).to_be_bytes())?;
            stream.write_all(&response)?;
        }
    }
    Ok(())
}

fn read_exact_until(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    stopped: &AtomicBool,
    deadline: Instant,
) -> io::Result<bool> {
    while !bytes.is_empty() {
        if stopped.load(Ordering::Acquire) {
            return Ok(false);
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(false);
        };
        if remaining.is_zero() {
            return Ok(false);
        }
        stream.set_read_timeout(Some(remaining.min(STOP_POLL_INTERVAL)))?;
        match stream.read(bytes) {
            Ok(0) => return Ok(false),
            Ok(amount) => bytes = &mut bytes[amount..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}
