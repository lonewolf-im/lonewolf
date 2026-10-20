// SPDX-License-Identifier: Apache-2.0

use crate::bench_support::{SECRET, TestResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::Mutex as PlMutex;
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type PeerResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Behavior {
    Normal,
    Fragmented,
    NoMechanism,
    BadNonce,
    BadProof,
    BindError,
    WrongBind,
    Duplicate,
    WrongBody,
    WrongRoute,
    StanzaError,
    Delayed,
    Late,
    Disconnect,
    NoRead,
    NoReceipt,
}

pub struct Peer {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<PeerResult>>,
    pub messages: Arc<std::sync::atomic::AtomicUsize>,
    bindings: mpsc::Receiver<(String, bool)>,
}
impl Peer {
    pub fn start(directory: &Path, behavior: Behavior) -> TestResult<Self> {
        crate::support::tls::configure(directory)?;
        let cert = CertificateDer::from_pem_slice(&fs::read(directory.join("certificate.pem"))?)?;
        let key = PrivateKeyDer::from_pem_slice(&fs::read(directory.join("private-key.pem"))?)?;
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let routes = Arc::new(PlMutex::new(BTreeMap::new()));
        let messages = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = messages.clone();
        let (bindings, bound) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut workers = vec![];
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false)?;
                        if behavior == Behavior::NoRead {
                            socket2::SockRef::from(&stream).set_recv_buffer_size(1024)?;
                        }
                        stream.set_read_timeout(Some(Duration::from_millis(50)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                        stream.set_nodelay(true)?;
                        let (config, routes, stopped, messages) = (
                            config.clone(),
                            routes.clone(),
                            stopped.clone(),
                            observed.clone(),
                        );
                        let bindings = bindings.clone();
                        workers.push(thread::spawn(move || {
                            serve(
                                stream, config, behavior, routes, stopped, messages, bindings,
                            )
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            for worker in workers {
                // Malformed peers and deliberate disconnects can end either side of the TLS exchange.
                let _ = worker.join().map_err(|_| "peer worker panic")?;
            }
            Ok(())
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
            messages,
            bindings: bound,
        })
    }
    pub fn assert_bound_route(&self, jid: &str) -> TestResult {
        let (bound, registered) = self.bindings.recv_timeout(Duration::from_secs(10))?;
        assert_eq!(bound, jid);
        assert!(registered, "bind reply published before route registration");
        Ok(())
    }
    pub fn finish(mut self) -> TestResult {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| "peer panic")?
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Frames<S> {
    stream: S,
    buffer: Vec<u8>,
}
impl<S: Read + Write> Frames<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: vec![],
        }
    }
    fn send(&mut self, text: &str, fragmented: bool) -> PeerResult {
        if fragmented {
            for chunk in text.as_bytes().chunks(7) {
                self.stream.write_all(chunk)?;
                self.stream.flush()?;
            }
        } else {
            self.stream.write_all(text.as_bytes())?;
            self.stream.flush()?;
        }
        Ok(())
    }
    fn next(&mut self, stop: &AtomicBool) -> PeerResult<String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(end) = frame_end(&self.buffer) {
                return Ok(String::from_utf8(self.buffer.drain(..end).collect())?);
            }
            if self.buffer.len() > 1_048_576 {
                return Err("peer frame limit".into());
            }
            if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("peer stopped".into());
            }
            let mut bytes = [0; 8192];
            match self.stream.read(&mut bytes) {
                Ok(0) => return Err("peer EOF".into()),
                Ok(count) => self.buffer.extend_from_slice(&bytes[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}
fn frame_end(bytes: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.starts_with("<stream:stream") || text.starts_with("</stream:stream") {
        return text.find('>').map(|i| i + 1);
    }
    let first = text.find('>')?;
    if text[..first].ends_with('/') {
        return Some(first + 1);
    }
    let name = text.strip_prefix('<')?.split([' ', '>']).next()?;
    let closing = format!("</{name}>");
    text.find(&closing).map(|i| i + closing.len())
}
fn attr<'a>(text: &'a str, name: &str) -> PeerResult<&'a str> {
    let start = text.find(&format!(" {name}=")).ok_or("attribute")? + name.len() + 2;
    let quote = text.as_bytes()[start] as char;
    let rest = &text[start + 1..];
    Ok(&rest[..rest.find(quote).ok_or("attribute end")?])
}
fn text(text: &str) -> PeerResult<&str> {
    Ok(text
        .split_once('>')
        .ok_or("text")?
        .1
        .split_once('<')
        .ok_or("text end")?
        .0)
}
fn mac(key: &[u8], text: &[u8]) -> PeerResult<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(text);
    Ok(mac.finalize().into_bytes().to_vec())
}

type Routes = Arc<PlMutex<BTreeMap<String, mpsc::Sender<String>>>>;
fn serve(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    behavior: Behavior,
    routes: Routes,
    stop: Arc<AtomicBool>,
    messages: Arc<std::sync::atomic::AtomicUsize>,
    bindings: mpsc::Sender<(String, bool)>,
) -> PeerResult {
    let mut plain = Frames::new(stream);
    let fragment = behavior == Behavior::Fragmented;
    let opening = plain.next(&stop)?;
    assert!(opening.starts_with("<stream:stream"));
    let domain = attr(&opening, "to")?;
    if !matches!(domain, "localhost" | "wrong.example.test") {
        return Err("unexpected stream domain".into());
    }
    let header = format!(
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' from='{domain}' id='peer' version='1.0'>"
    );
    plain.send(&format!("{header}<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"), fragment)?;
    assert!(plain.next(&stop)?.starts_with("<starttls"));
    plain.send(
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        fragment,
    )?;
    assert!(plain.buffer.is_empty());
    let connection = ServerConnection::new(config)?;
    let mut tls = Frames::new(StreamOwned::new(connection, plain.stream));
    tls.next(&stop)?;
    let mechanism = if behavior == Behavior::NoMechanism {
        "PLAIN"
    } else {
        "SCRAM-SHA-256"
    };
    tls.send(&format!("{header}<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>{mechanism}</mechanism></mechanisms></stream:features>"), fragment)?;
    let auth = tls.next(&stop)?;
    let first = String::from_utf8(STANDARD.decode(text(&auth)?)?)?;
    let bare = first.strip_prefix("n,,").ok_or("SCRAM first")?;
    let username = bare
        .strip_prefix("n=")
        .and_then(|s| s.split_once(",r="))
        .ok_or("SCRAM nonce")?;
    let nonce = if behavior == Behavior::BadNonce {
        "wrong".into()
    } else {
        format!("{}server", username.1)
    };
    let challenge = format!("r={nonce},s=c2FsdHNhbHQ=,i=4096");
    tls.send(
        &format!(
            "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</challenge>",
            STANDARD.encode(&challenge)
        ),
        fragment,
    )?;
    let response = tls.next(&stop)?;
    let final_message = String::from_utf8(STANDARD.decode(text(&response)?)?)?;
    let without_proof = final_message.rsplit_once(",p=").ok_or("SCRAM final")?.0;
    let mut salted = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(SECRET.as_bytes(), b"saltsalt", 4096, &mut salted);
    let server_key = mac(&salted, b"Server Key")?;
    let signature = mac(
        &server_key,
        format!("{bare},{challenge},{without_proof}").as_bytes(),
    )?;
    let signature = if behavior == Behavior::BadProof {
        vec![0; 32]
    } else {
        signature
    };
    tls.send(
        &format!(
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</success>",
            STANDARD.encode(format!("v={}", STANDARD.encode(signature)))
        ),
        fragment,
    )?;
    tls.next(&stop)?;
    tls.send(&format!("{header}<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"), fragment)?;
    let bind = tls.next(&stop)?;
    let resource = bind
        .split_once("<resource>")
        .and_then(|s| s.1.split_once("</resource>"))
        .ok_or("resource")?
        .0;
    let jid = format!("{}@localhost/{resource}", username.0);
    let bound = if behavior == Behavior::WrongBind {
        "other@localhost/wrong"
    } else {
        &jid
    };
    let reply = if behavior == Behavior::BindError {
        format!(
            "<iq type='error' id='{}'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
            attr(&bind, "id")?
        )
    } else {
        format!(
            "<iq type='result' id='{}'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{bound}</jid></bind></iq>",
            attr(&bind, "id")?
        )
    };
    let (send, receive) = mpsc::channel();
    routes.lock().insert(jid.clone(), send);
    let result = (|| {
        let binding = (jid.clone(), routes.lock().contains_key(&jid));
        tls.send(&reply, fragment)?;
        bindings.send(binding)?;
        traffic(&mut tls, behavior, &jid, &routes, receive, &stop, &messages)
    })();
    routes.lock().remove(&jid);
    result
}

fn traffic(
    tls: &mut Frames<StreamOwned<ServerConnection, TcpStream>>,
    behavior: Behavior,
    jid: &str,
    routes: &Routes,
    receive: mpsc::Receiver<String>,
    stop: &AtomicBool,
    messages: &std::sync::atomic::AtomicUsize,
) -> PeerResult {
    let fragment = behavior == Behavior::Fragmented;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut delayed: Vec<(Instant, String)> = vec![];
    loop {
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Ok(());
        }
        if behavior != Behavior::NoRead {
            for delivery in receive.try_iter() {
                let delay = match behavior {
                    Behavior::Delayed => 100,
                    Behavior::Late => 500,
                    _ => 0,
                };
                delayed.push((Instant::now() + Duration::from_millis(delay), delivery));
            }
            while delayed.first().is_some_and(|(at, _)| Instant::now() >= *at) {
                let (_, delivery) = delayed.remove(0);
                tls.send(&delivery, fragment)?;
            }
            if let Some(end) = frame_end(&tls.buffer) {
                let frame = String::from_utf8(tls.buffer.drain(..end).collect())?;
                if frame == "</stream:stream>" {
                    tls.send("</stream:stream>", fragment)?;
                    tls.stream.conn.send_close_notify();
                    tls.stream.flush()?;
                    return Ok(());
                }
                if frame.starts_with("<message") {
                    messages.fetch_add(1, Ordering::Relaxed);
                    if behavior == Behavior::Disconnect {
                        return Ok(());
                    }
                    if behavior == Behavior::NoReceipt {
                        continue;
                    }
                    let id = attr(&frame, "id")?;
                    let to = attr(&frame, "to")?;
                    if behavior == Behavior::StanzaError {
                        tls.send(&format!("<message type='error' id='{id}' from='{to}' to='{jid}'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>"), fragment)?;
                    } else {
                        let body = frame
                            .split_once("<body>")
                            .and_then(|s| s.1.split_once("</body>"))
                            .ok_or("body")?
                            .0;
                        let body = if behavior == Behavior::WrongBody {
                            "WRONG"
                        } else {
                            body
                        };
                        let from = if behavior == Behavior::WrongRoute {
                            "other@localhost/other"
                        } else {
                            jid
                        };
                        let delivery = format!(
                            "<message type='chat' id='{id}' from='{from}' to='{to}'><body>{body}</body></message>"
                        );
                        if let Some(recipient) = routes.lock().get(to) {
                            recipient.send(if behavior == Behavior::Duplicate {
                                format!("{delivery}{delivery}")
                            } else {
                                delivery
                            })?;
                        }
                    }
                }
                continue;
            }
            let mut bytes = [0; 8192];
            match tls.stream.read(&mut bytes) {
                Ok(0) => return Ok(()),
                Ok(count) => tls.buffer.extend_from_slice(&bytes[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }
}
