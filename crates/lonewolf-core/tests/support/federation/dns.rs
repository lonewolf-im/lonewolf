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
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, SRV},
};
use parking_lot::Mutex as PlMutex;

use super::super::TestResult;

#[derive(Default)]
struct Answers {
    names: HashMap<String, NameAnswers>,
}

#[derive(Default)]
struct NameAnswers {
    records: HashMap<RecordType, Vec<RData>>,
    failure: Option<Option<ResponseCode>>,
    counts: HashMap<RecordType, usize>,
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
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            match TcpListener::bind(udp.local_addr()?) {
                Ok(tcp) => break (udp, tcp),
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
        let records = records
            .iter()
            .map(|&(priority, weight, port, target)| {
                let target = Name::from_ascii(target)
                    .unwrap_or_else(|error| panic!("invalid fake DNS target: {error}"));
                RData::SRV(SRV::new(priority, weight, port, target))
            })
            .collect();
        self.set(
            &format!("_xmpp-server._tcp.{domain}"),
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
                Ok((stream, _)) => serve_tcp(stream, answers, stopped)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
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
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut bytes = Vec::new();
    while !stopped.load(Ordering::Acquire) {
        let mut length = [0; 2];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        bytes.resize(usize::from(u16::from_be_bytes(length)), 0);
        if let Err(error) = stream.read_exact(&mut bytes) {
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                return Ok(());
            }
            return Err(error);
        }
        if let Some(response) = answer(&bytes, answers)? {
            stream.write_all(&(response.len() as u16).to_be_bytes())?;
            stream.write_all(&response)?;
        }
    }
    Ok(())
}
