// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use compio::runtime::Runtime;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    IsCa, KeyIdMethod, KeyUsagePurpose,
};

use graviola::hashing::Sha256;
use graviola::key_agreement::p256::StaticPrivateKey;
use graviola::signing::ecdsa::{P256, SigningKey};

struct TestSigner {
    key: SigningKey<P256>,
    public_key: [u8; 65],
}

impl TestSigner {
    fn new() -> Result<Self, Box<dyn Error>> {
        let key = SigningKey::<P256> {
            private_key: StaticPrivateKey::new_random()?,
        };
        Ok(Self {
            public_key: key.private_key.public_key_uncompressed(),
            key,
        })
    }
}

impl rcgen::PublicKeyData for TestSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut signature = [0; 80];
        self.key
            .sign_asn1::<Sha256>(&[message], &mut signature)
            .map(<[u8]>::to_vec)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

use super::*;
use crate::hosts::revocation::parse_crl;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn crl(stale: bool) -> TestResult<(Vec<u8>, SystemTime, SystemTime, SystemTime)> {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let this = now - Duration::from_secs(3600);
    let next = if stale {
        now - Duration::from_secs(60)
    } else {
        now + Duration::from_secs(3600)
    };
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.serial_number = Some(1u64.into());
    params.distinguished_name.push(DnType::CommonName, "Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = CertifiedIssuer::self_signed(params, TestSigner::new()?)?;
    let crl = CertificateRevocationListParams {
        this_update: this.into(),
        next_update: next.into(),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::PreSpecified(vec![1]),
    }
    .signed_by(&root)?;
    Ok((crl.der().to_vec(), now, this, next))
}

fn fetcher(policy: AddressPolicy, limits: FetchLimits) -> TestResult<CrlFetcher> {
    Ok(CrlFetcher::new(
        Arc::new(Resolver::new(&crate::config::S2sConfig::default())?),
        policy,
        limits,
    ))
}

fn fetch_response(
    status: u16,
    headers: &str,
    body: Vec<u8>,
    limits: FetchLimits,
    now: SystemTime,
) -> TestResult<Result<FetchedCrl, FetchFailure>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let url = CrlUrl::parse(&format!("http://{}/list.crl", listener.local_addr()?))
        .map_err(|_| "invalid test URL")?;
    let headers = headers.to_owned();
    let server = thread::spawn(move || -> io::Result<usize> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.len() > 16 * 1024 {
                return Err(io::Error::other("request too large"));
            }
        }
        assert!(request.starts_with(b"GET /list.crl HTTP/1.1\r\n"));
        write!(
            stream,
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
            body.len()
        )?;
        match stream.write_all(&body) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
            Err(error) => return Err(error),
        }
        listener.set_nonblocking(true)?;
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(1)
    });
    let result = Runtime::new()?.block_on(fetcher(AddressPolicy::Any, limits)?.fetch(&url, now));
    assert_eq!(server.join().map_err(|_| "HTTP server panicked")??, 1);
    Ok(result)
}

#[test]
fn urls_require_bounded_http_authorities_without_credentials_or_fragments() -> TestResult {
    for (text, host, port, normalized) in [
        (
            "http://ca.example/x.crl",
            "ca.example",
            80,
            "http://ca.example/x.crl",
        ),
        (
            "HTTP://CA.example:8080/x?y",
            "CA.example",
            8080,
            "http://CA.example:8080/x?y",
        ),
        ("http://[::1]", "::1", 80, "http://[::1]/"),
    ] {
        let url = CrlUrl::parse(text).map_err(|_| "expected valid URL")?;
        assert_eq!(url.host(), host);
        assert_eq!(url.port(), port);
        assert_eq!(url.as_str(), normalized);
    }
    for text in [
        "https://ca.example/",
        "ldap://ca.example/",
        "ftp://ca.example/",
        "",
        "http://user@ca.example/",
        "http://ca.example/#frag",
        "http://ca.example:0/",
        "http://ca.example:/",
        "http://ca.example:65536/",
        "http://[bad]/",
        "http://bad host/",
    ] {
        assert_eq!(CrlUrl::parse(text), Err(UnsupportedUrl), "{text}");
    }
    assert_eq!(
        CrlUrl::parse(&format!("http://ca.example/{}", "x".repeat(2049))),
        Err(UnsupportedUrl)
    );
    Ok(())
}

#[test]
fn downloads_return_metadata_and_enforce_status_encoding_size_and_material() -> TestResult {
    let (der, now, this, next) = crl(false)?;
    let expected = parse_crl(&der, now).map_err(|error| format!("{error:?}"))?;
    let fetched = fetch_response(200, "", der.clone(), FetchLimits::DEFAULT, now)?
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(fetched.this_update, this);
    assert_eq!(fetched.next_update, next);
    assert_eq!(fetched.crl_number, expected.crl_number);
    assert_eq!(fetched.cost, der.len() + 512);
    assert!(matches!(fetched.crl, webpki::CertRevocationList::Owned(_)));
    for (status, headers, body, limits, failure) in [
        (
            404,
            "",
            Vec::new(),
            FetchLimits::DEFAULT,
            FetchFailure::HttpStatus,
        ),
        (
            301,
            "Location: http://127.0.0.1:1/redirect\r\n",
            Vec::new(),
            FetchLimits::DEFAULT,
            FetchFailure::HttpStatus,
        ),
        (
            200,
            "Content-Encoding: gzip\r\n",
            der.clone(),
            FetchLimits::DEFAULT,
            FetchFailure::Invalid,
        ),
        (
            200,
            "",
            vec![0; 5],
            FetchLimits {
                max_crl_bytes: 4,
                ..FetchLimits::DEFAULT
            },
            FetchFailure::TooLarge,
        ),
        (
            200,
            "",
            der.clone(),
            FetchLimits {
                max_crl_cost: der.len() + 511,
                ..FetchLimits::DEFAULT
            },
            FetchFailure::TooLarge,
        ),
        (
            200,
            "",
            b"garbage".to_vec(),
            FetchLimits::DEFAULT,
            FetchFailure::Invalid,
        ),
        (
            200,
            "",
            crl(true)?.0,
            FetchLimits::DEFAULT,
            FetchFailure::Stale,
        ),
    ] {
        assert!(
            matches!(fetch_response(status, headers, body, limits, now)?, Err(actual) if actual == failure)
        );
    }
    Ok(())
}

#[test]
fn public_policy_never_connects_to_loopback() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let url =
        CrlUrl::parse(&format!("http://{}/", listener.local_addr()?)).map_err(|_| "invalid URL")?;
    assert!(matches!(
        Runtime::new()?.block_on(
            fetcher(AddressPolicy::PublicOnly, FetchLimits::DEFAULT)?
                .fetch(&url, SystemTime::now())
        ),
        Err(FetchFailure::BlockedAddress)
    ));
    listener.set_nonblocking(true)?;
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn fetch_deadline_bounds_a_peer_that_never_answers_and_closed_ports_fail() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let url =
        CrlUrl::parse(&format!("http://{}/", listener.local_addr()?)).map_err(|_| "invalid URL")?;
    let (release, gate) = mpsc::channel();
    let server = thread::spawn(move || -> io::Result<()> {
        let (_stream, _) = listener.accept()?;
        gate.recv_timeout(Duration::from_secs(2))
            .map_err(io::Error::other)?;
        Ok(())
    });
    let limits = FetchLimits {
        total_timeout: Duration::from_millis(300),
        ..FetchLimits::DEFAULT
    };
    let started = Instant::now();
    let result = Runtime::new()?
        .block_on(fetcher(AddressPolicy::Any, limits)?.fetch(&url, SystemTime::now()));
    let elapsed = started.elapsed();
    release.send(())?;
    server.join().map_err(|_| "HTTP server panicked")??;
    assert!(matches!(result, Err(FetchFailure::Timeout)));
    assert!(elapsed < Duration::from_secs(2));
    assert!(matches!(
        Runtime::new()?.block_on(
            fetcher(AddressPolicy::Any, FetchLimits::DEFAULT)?.fetch(&url, SystemTime::now())
        ),
        Err(FetchFailure::ConnectFailed)
    ));
    Ok(())
}
