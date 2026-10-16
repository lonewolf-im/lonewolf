// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use graviola::hashing::{Hash, Sha256};
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey, VerifyingKey};
use parking_lot::{Condvar as PlCondvar, Mutex as PlMutex};
use rcgen::{CertificateParams, PublicKeyData};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::{Value, json};
use x509_cert::der::{Decode, Encode};

use super::{TIMEOUT, TestResult, prepare_blocking_stream};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AcmeStage {
    Directory,
    Nonce,
    Account,
    NewOrder,
    Order,
    Authorization,
    Challenge,
    Finalize,
    Certificate,
    Ari,
}

#[derive(Clone, Debug)]
pub enum AcmeFault {
    Hold,
    Status(u16, u64),
    Denied,
    Oversized,
    Invalid,
    WrongKey,
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct RequestCounts {
    pub stages: BTreeMap<AcmeStage, usize>,
    pub accounts: Vec<Value>,
    pub orders: Vec<(String, String)>,
    pub csrs: Vec<Vec<u8>>,
    pub callbacks: Vec<(String, String, String)>,
    pub errors: Vec<String>,
}
impl RequestCounts {
    pub fn at(&self, stage: AcmeStage) -> usize {
        self.stages.get(&stage).copied().unwrap_or(0)
    }
}

struct Order {
    replaces: Value,
    dns: String,
    account: usize,
    ready: bool,
    certificate: Option<String>,
    token: String,
}
struct State {
    counts: RequestCounts,
    faults: BTreeMap<AcmeStage, AcmeFault>,
    nonces: HashSet<String>,
    nonce: usize,
    orders: Vec<Order>,
    callback: SocketAddr,
    renewal: bool,
    lifetime: i64,
    closed: bool,
}
struct Shared {
    state: PlMutex<State>,
    changed: PlCondvar,
}

pub struct FakeAcmeCa {
    _directory: tempfile::TempDir,
    trust_bundle: std::path::PathBuf,
    base: String,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    pub roots: rustls::RootCertStore,
}

impl FakeAcmeCa {
    pub fn start() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let signer = Signer::new()?;
        let mut params = CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])?;
        params.serial_number = Some(1u64.into());
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![11, 22, 33]);
        let issuer = rcgen::CertifiedIssuer::self_signed(params, signer)?;
        let root_pem = pem("CERTIFICATE", issuer.der())?;
        fs::write(directory.path().join("roots.pem"), &root_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(issuer.der().clone())?;
        let https_key = Signer::new()?;
        let mut https_params =
            CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])?;
        https_params.serial_number = Some(2u64.into());
        let https_certificate = https_params.signed_by(&https_key, &issuer)?;
        let mut key_buf = [0; 512];
        let key = https_key.key.to_pkcs8_der(&mut key_buf)?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls_graviola::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![https_certificate.der().clone()],
            PrivatePkcs8KeyDer::from(key.to_vec()).into(),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let base = format!("https://{}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            state: PlMutex::new(State {
                counts: RequestCounts::default(),
                faults: BTreeMap::new(),
                nonces: HashSet::new(),
                nonce: 0,
                orders: Vec::new(),
                callback: "127.0.0.1:1".parse()?,
                renewal: false,
                lifetime: 86_400,
                closed: false,
            }),
            changed: PlCondvar::new(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let serving_stop = stop.clone();
        let serving_shared = shared.clone();
        let serving_base = base.clone();
        let config = Arc::new(config);
        let issuer = Arc::new(issuer);
        let thread = thread::spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            while !serving_stop.load(Ordering::SeqCst) {
                let mut i = 0;
                while i < workers.len() {
                    if workers[i].is_finished() {
                        let _ = workers.swap_remove(i).join();
                    } else {
                        i += 1;
                    }
                }
                match listener.accept() {
                    Ok((socket, _)) if workers.len() < 4 => {
                        let shared = serving_shared.clone();
                        let config = config.clone();
                        let base = serving_base.clone();
                        let issuer = issuer.clone();
                        let root_pem = root_pem.clone();
                        workers.push(thread::spawn(move || {
                            let result = serve(socket, config, &base, &issuer, &root_pem, &shared);
                            if let Err(error) = result {
                                let mut state = shared.state.lock();
                                if !state.closed {
                                    state.counts.errors.push(error.to_string());
                                    shared.changed.notify_all();
                                }
                            }
                        }));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            trust_bundle: directory.path().join("roots.pem"),
            _directory: directory,
            base,
            shared,
            stop,
            thread: Some(thread),
            roots,
        })
    }
    pub fn directory_url(&self) -> String {
        format!("{}/directory", self.base)
    }
    pub fn alternate_directory_url(&self) -> String {
        format!("{}/alternate", self.base)
    }
    pub fn trust_bundle_path(&self) -> &Path {
        &self.trust_bundle
    }
    pub fn callback(&self, address: SocketAddr) {
        self.shared.state.lock().callback = address;
    }
    pub fn set_fault(&self, stage: AcmeStage, fault: AcmeFault) {
        self.shared.state.lock().faults.insert(stage, fault);
    }
    pub fn wait_for(&self, stage: AcmeStage) -> TestResult {
        self.wait_count(stage, 1)
    }
    pub fn wait_count(&self, stage: AcmeStage, count: usize) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        let mut state = self.shared.state.lock();
        while state.counts.at(stage) < count {
            if self
                .shared
                .changed
                .wait_until(&mut state, deadline)
                .timed_out()
            {
                return Err(
                    format!("CA did not reach {stage:?} #{count}: {:?}", state.counts).into(),
                );
            }
        }
        Ok(())
    }
    pub fn release(&self, stage: AcmeStage) {
        self.shared.state.lock().faults.remove(&stage);
        self.shared.changed.notify_all();
    }
    pub fn renew(&self) {
        self.shared.state.lock().renewal = true;
    }
    pub fn lifetime(&self, seconds: i64) {
        self.shared.state.lock().lifetime = seconds;
    }
    pub fn counts(&self) -> RequestCounts {
        self.shared.state.lock().counts.clone()
    }
    pub fn offline(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        {
            let mut state = self.shared.state.lock();
            state.closed = true;
            state.faults.clear();
        }
        self.shared.changed.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for FakeAcmeCa {
    fn drop(&mut self) {
        self.offline();
    }
}

fn serve(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    base: &str,
    issuer: &rcgen::CertifiedIssuer<'_, Signer>,
    root_pem: &str,
    shared: &Shared,
) -> TestResult {
    prepare_blocking_stream(&socket)?;
    let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, socket);
    let request = read_request(&mut tls)?;
    let stage = stage(&request.path)?;
    let response = {
        let mut state = shared.state.lock();
        let response = respond(&request, stage, base, issuer, root_pem, &mut state)?;
        *state.counts.stages.entry(stage).or_default() += 1;
        shared.changed.notify_all();
        while matches!(state.faults.get(&stage), Some(AcmeFault::Hold)) && !state.closed {
            shared.changed.wait(&mut state);
        }
        if state.closed {
            return Ok(());
        }
        match state.faults.get(&stage) {
            Some(AcmeFault::Status(code, delay)) => Response { status: *code, headers: format!("Retry-After: {delay}\r\n"), body: json!({"type":"urn:ietf:params:acme:error:rateLimited","detail":"PRIVATE-CA-DETAIL"}).to_string() },
            Some(AcmeFault::Oversized) => Response::body("X".repeat(1024*1024+1)),
            Some(AcmeFault::Invalid) => Response::body("PRIVATE-INVALID-CERTIFICATE".into()),
            Some(AcmeFault::WrongKey) => Response::body(wrong_certificate(issuer, root_pem, &state.orders.last().ok_or("order")?.dns)?),
            Some(AcmeFault::Denied) => Response::json(json!({"identifier":{"type":"dns","value":state.orders.last().ok_or("no order")?.dns},"status":"invalid","challenges":[]})),
            _ => response,
        }
    };
    let nonce = {
        let mut state = shared.state.lock();
        state.nonce += 1;
        let nonce = format!("nonce-{}", state.nonce);
        state.nonces.insert(nonce.clone());
        nonce
    };
    write!(
        tls,
        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nReplay-Nonce: {nonce}\r\n{}Connection: close\r\n\r\n{}",
        response.status,
        response.body.len(),
        response.headers,
        response.body
    )?;
    tls.flush()?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

pub struct Request {
    pub path: String,
    pub host: String,
    pub body: Vec<u8>,
    pub method: String,
}
pub fn read_request(reader: &mut impl Read) -> TestResult<Request> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        reader.read_exact(&mut b)?;
        header.push(b[0]);
        if header.len() > 16 * 1024 {
            return Err("HTTP header limit".into());
        }
    }
    let header = std::str::from_utf8(&header)?;
    let mut lines = header.split("\r\n");
    let mut first = lines.next().ok_or("request line")?.split_whitespace();
    let method = first.next().ok_or("method")?.to_owned();
    let path = first.next().ok_or("path")?.to_owned();
    let mut length = 0;
    let mut host = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse()?;
            }
            if name.eq_ignore_ascii_case("host") {
                host = value.trim().into();
            }
        }
    }
    if length > 64 * 1024 {
        return Err("HTTP body limit".into());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    Ok(Request {
        path,
        host,
        body,
        method,
    })
}
struct Response {
    status: u16,
    headers: String,
    body: String,
}
impl Response {
    fn body(body: String) -> Self {
        Self {
            status: 200,
            headers: String::new(),
            body,
        }
    }
    fn json(value: Value) -> Self {
        Self::body(value.to_string())
    }
    fn located(value: Value, url: String) -> Self {
        Self {
            status: 201,
            headers: format!("Location: {url}\r\n"),
            body: value.to_string(),
        }
    }
}
fn stage(path: &str) -> TestResult<AcmeStage> {
    Ok(match path.split('/').nth(1).unwrap_or("") {
        "directory" | "alternate" => AcmeStage::Directory,
        "nonce" => AcmeStage::Nonce,
        "account" => AcmeStage::Account,
        "new-order" => AcmeStage::NewOrder,
        "order" => AcmeStage::Order,
        "authz" => AcmeStage::Authorization,
        "challenge" => AcmeStage::Challenge,
        "finalize" => AcmeStage::Finalize,
        "certificate" => AcmeStage::Certificate,
        "ari" => AcmeStage::Ari,
        _ => return Err("unknown CA path".into()),
    })
}
fn signed_payload(
    request: &Request,
    base: &str,
    state: &mut State,
) -> TestResult<(Value, Option<Value>)> {
    assert_eq!(request.method, "POST");
    let jws: Value = serde_json::from_slice(&request.body)?;
    let protected = jws["protected"].as_str().ok_or("protected")?;
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected)?)?;
    if header["url"] != format!("{base}{}", request.path) || header["alg"] != "ES256" {
        return Err("JWS url/algorithm".into());
    }
    if !state
        .nonces
        .remove(header["nonce"].as_str().ok_or("JWS nonce")?)
    {
        return Err("JWS reused/unknown nonce".into());
    }
    let jwk = if let Some(jwk) = header.get("jwk") {
        jwk.clone()
    } else {
        let kid = header["kid"].as_str().ok_or("JWS kid")?;
        let account = kid
            .strip_prefix(&format!("{base}/account/"))
            .ok_or("foreign account")?
            .parse::<usize>()?;
        state
            .counts
            .accounts
            .get(account)
            .ok_or("unknown account")?
            .clone()
    };
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err("JWK type/curve".into());
    }
    let mut key = vec![4];
    key.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().ok_or("JWK x")?)?);
    key.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().ok_or("JWK y")?)?);
    let verifier = VerifyingKey::<P256>::from_x962_uncompressed(&key)?;
    let payload = jws["payload"].as_str().ok_or("JWS payload")?;
    verifier.verify::<Sha256>(
        &[format!("{protected}.{payload}").as_bytes()],
        &URL_SAFE_NO_PAD.decode(jws["signature"].as_str().ok_or("JWS signature")?)?,
    )?;
    let bytes = URL_SAFE_NO_PAD.decode(payload)?;
    Ok((
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
        Some(jwk),
    ))
}
fn respond(
    request: &Request,
    stage: AcmeStage,
    base: &str,
    issuer: &rcgen::CertifiedIssuer<'_, Signer>,
    root_pem: &str,
    state: &mut State,
) -> TestResult<Response> {
    if stage == AcmeStage::Directory {
        return Ok(Response::json(
            json!({"newNonce":format!("{base}/nonce"),"newAccount":format!("{base}/account"),"newOrder":format!("{base}/new-order"),"renewalInfo":format!("{base}/ari")}),
        ));
    }
    if stage == AcmeStage::Nonce {
        return Ok(Response::body(String::new()));
    }
    if stage == AcmeStage::Ari {
        let now = time::OffsetDateTime::now_utc();
        let start = now + time::Duration::seconds(if state.renewal { -30 } else { 43_200 });
        let end = start + time::Duration::seconds(10);
        state.renewal = false;
        let format = &time::format_description::well_known::Rfc3339;
        return Ok(Response {
            headers: "Retry-After: 3600\r\n".into(),
            ..Response::json(
                json!({"suggestedWindow":{"start":start.format(format)?,"end":end.format(format)?}}),
            )
        });
    }
    let (payload, jwk) = signed_payload(request, base, state)?;
    if let Some(AcmeFault::Status(status, delay)) = state.faults.get(&stage) {
        return Ok(Response {
            status: *status,
            headers: format!("Retry-After: {delay}\r\n"),
            body: json!({"type":"urn:ietf:params:acme:error:rateLimited","detail":"PRIVATE-CA-DETAIL"}).to_string(),
        });
    }
    if stage == AcmeStage::Account {
        let jwk = jwk.ok_or("account JWK")?;
        let index = state
            .counts
            .accounts
            .iter()
            .position(|key| key == &jwk)
            .unwrap_or_else(|| {
                state.counts.accounts.push(jwk);
                state.counts.accounts.len() - 1
            });
        return Ok(Response::located(
            json!({"status":"valid","orders":format!("{base}/orders/{index}")}),
            format!("{base}/account/{index}"),
        ));
    }
    if stage == AcmeStage::NewOrder {
        let dns = payload["identifiers"][0]["value"]
            .as_str()
            .ok_or("DNS identifier")?
            .to_owned();
        if payload["identifiers"].as_array().map(Vec::len) != Some(1)
            || payload["identifiers"][0]["type"] != "dns"
            || !dns.is_ascii()
        {
            return Err("order identifiers".into());
        }
        let account = state
            .counts
            .accounts
            .iter()
            .position(|key| Some(key) == jwk.as_ref())
            .ok_or("order account")?;
        let index = state.orders.len();
        state.orders.push(Order {
            replaces: payload["replaces"].clone(),
            dns: dns.clone(),
            account,
            ready: false,
            certificate: None,
            token: format!("challenge_token_long_enough_{index}"),
        });
        state
            .counts
            .orders
            .push((format!("{base}/order/{index}"), dns));
        return Ok(Response::located(
            order_json(index, base, &state.orders[index]),
            format!("{base}/order/{index}"),
        ));
    }
    let index = request
        .path
        .split('/')
        .nth(2)
        .ok_or("order index")?
        .parse::<usize>()?;
    let order = state.orders.get_mut(index).ok_or("unknown order")?;
    Ok(match stage {
        AcmeStage::Order => Response::json(order_json(index, base, order)),
        AcmeStage::Authorization => Response::json(
            json!({"identifier":{"type":"dns","value":order.dns},"status":if order.ready{"valid"}else{"pending"},"challenges":[{"type":"http-01","url":format!("{base}/challenge/{index}"),"status":if order.ready{"valid"}else{"pending"},"token":order.token}]}),
        ),
        AcmeStage::Challenge => {
            let jwk = &state.counts.accounts[order.account];
            let thumb = json!({"crv":"P-256","kty":"EC","x":jwk["x"],"y":jwk["y"]}).to_string();
            let authorization = format!(
                "{}.{}",
                order.token,
                URL_SAFE_NO_PAD.encode(Sha256::hash(thumb.as_bytes()).as_ref())
            );
            let path = format!("/.well-known/acme-challenge/{}", order.token);
            let response = http_get(state.callback, &order.dns, &path)?;
            let (_, body) = response
                .split_once("\r\n\r\n")
                .ok_or("challenge response")?;
            if !response.starts_with("HTTP/1.1 200 ") || body != authorization {
                return Err("HTTP01 key authorization mismatch".into());
            }
            state
                .counts
                .callbacks
                .push((order.dns.clone(), path, body.into()));
            order.ready = true;
            Response::json(
                json!({"type":"http-01","url":format!("{base}/challenge/{index}"),"token":order.token,"status":"valid"}),
            )
        }
        AcmeStage::Finalize => {
            if !order.ready {
                return Err("unauthorized finalize".into());
            }
            let csr = URL_SAFE_NO_PAD.decode(payload["csr"].as_str().ok_or("CSR payload")?)?;
            let certificate =
                sign_csr(&csr, &order.dns, index as u64 + 100, state.lifetime, issuer)?;
            state.counts.csrs.push(csr);
            order.certificate = Some(format!("{certificate}{root_pem}"));
            Response::json(order_json(index, base, order))
        }
        AcmeStage::Certificate => Response::body(
            order
                .certificate
                .clone()
                .ok_or("certificate not finalized")?,
        ),
        _ => return Err("unexpected CA stage".into()),
    })
}
fn order_json(index: usize, base: &str, order: &Order) -> Value {
    json!({"expires":"2099-01-01T00:00:00Z","replaces":order.replaces,"status":if order.certificate.is_some(){"valid"}else if order.ready{"ready"}else{"pending"},"identifiers":[{"type":"dns","value":order.dns}],"authorizations":[format!("{base}/authz/{index}")],"finalize":format!("{base}/finalize/{index}"),"certificate":order.certificate.as_ref().map(|_|format!("{base}/certificate/{index}"))})
}
fn sign_csr(
    bytes: &[u8],
    dns: &str,
    serial: u64,
    lifetime: i64,
    issuer: &rcgen::CertifiedIssuer<'_, Signer>,
) -> TestResult<String> {
    let csr = x509_cert::request::CertReq::from_der(bytes)?;
    if csr.algorithm.oid.to_string() != "1.2.840.10045.4.3.2" {
        return Err("CSR algorithm".into());
    }
    let key = csr
        .info
        .public_key
        .subject_public_key
        .as_bytes()
        .ok_or("CSR key")?;
    VerifyingKey::<P256>::from_x962_uncompressed(key)?.verify_asn1::<Sha256>(
        &[&csr.info.to_der()?],
        csr.signature.as_bytes().ok_or("CSR signature")?,
    )?;
    let attribute = csr
        .info
        .attributes
        .iter()
        .find(|a| a.oid.to_string() == "1.2.840.113549.1.9.14")
        .ok_or("CSR extensions")?;
    let extensions = x509_cert::request::ExtensionReq::from_der(
        &attribute
            .values
            .iter()
            .next()
            .ok_or("CSR extension value")?
            .to_der()?,
    )?;
    let san = extensions
        .0
        .iter()
        .find(|ext| ext.extn_id.to_string() == "2.5.29.17")
        .ok_or("CSR SAN")?;
    let names = x509_cert::ext::pkix::SubjectAltName::from_der(san.extn_value.as_bytes())?;
    if names.0.len() != 1
        || !matches!(&names.0[0], x509_cert::ext::pkix::name::GeneralName::DnsName(name) if name.as_str()==dns)
    {
        return Err("CSR domain differs from order".into());
    }
    let mut params = CertificateParams::new(vec![dns.into()])?;
    params.serial_number = Some(serial.into());
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(if lifetime < 60 { 1 } else { 60 });
    params.not_after = now + time::Duration::seconds(lifetime);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    let certificate = params.signed_by(&CsrKey(key), issuer)?;
    pem("CERTIFICATE", certificate.der())
}
fn wrong_certificate(
    issuer: &rcgen::CertifiedIssuer<'_, Signer>,
    root: &str,
    dns: &str,
) -> TestResult<String> {
    let mut params = CertificateParams::new(vec![dns.into()])?;
    params.serial_number = Some(999u64.into());
    Ok(format!(
        "{}{root}",
        pem(
            "CERTIFICATE",
            params.signed_by(&Signer::new()?, issuer)?.der()
        )?
    ))
}
struct CsrKey<'a>(&'a [u8]);
impl PublicKeyData for CsrKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
struct Signer {
    key: SigningKey<P256>,
    public: [u8; 65],
}
impl Signer {
    fn new() -> TestResult<Self> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}
impl PublicKeyData for Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}
impl rcgen::SigningKey for Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
pub fn pem(label: &str, der: &[u8]) -> TestResult<String> {
    let mut text = format!("-----BEGIN {label}-----\n");
    let encoded = STANDARD.encode(der);
    for chunk in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk)?);
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    Ok(text)
}
pub fn http_get(address: SocketAddr, host: &str, path: &str) -> TestResult<String> {
    let mut socket = TcpStream::connect_timeout(&address, TIMEOUT)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    write!(
        socket,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    socket.read_to_string(&mut response)?;
    Ok(response)
}
