// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use lonewolf_util::blocking::BlockingExecutor;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{BenchResult, failure, xml};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyMode {
    Prime,
    Reuse,
}

pub struct PreparedAccount {
    bare_jid: String,
    username: String,
    password: Option<Zeroizing<String>>,
    cache: Option<CachedKeys>,
}

impl fmt::Debug for PreparedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedAccount { [redacted] }")
    }
}

pub(super) struct CachedKeys {
    salt: Zeroizing<Vec<u8>>,
    iterations: u32,
    client: Zeroizing<[u8; 32]>,
    server: Zeroizing<[u8; 32]>,
}

impl PreparedAccount {
    pub fn new(bare_jid: &str, password: String) -> BenchResult<Self> {
        let password = Zeroizing::new(password);
        let canonical = xml::canonical_jid(bare_jid)?;
        let (username, _) = canonical
            .split_once('@')
            .ok_or_else(|| failure("account_invalid"))?;
        if canonical.contains('/') {
            return Err(failure("account_invalid"));
        }
        let prepared = stringprep::saslprep(&password).map_err(|_| failure("password_invalid"))?;
        let prepared = Zeroizing::new(prepared.into_owned());
        Ok(Self {
            username: username.to_owned(),
            bare_jid: canonical,
            password: Some(prepared),
            cache: None,
        })
    }

    pub fn bare_jid(&self) -> &str {
        &self.bare_jid
    }

    pub(super) async fn keys(
        &mut self,
        challenge: &Challenge,
        mode: KeyMode,
        cpu: &BlockingExecutor,
    ) -> BenchResult<&CachedKeys> {
        if let Some(cache) = &self.cache {
            if cache.salt.as_slice() != challenge.salt.as_slice()
                || cache.iterations != challenge.iterations
            {
                return Err(failure("scram_parameters_changed"));
            }
        } else {
            if mode == KeyMode::Reuse {
                return Err(failure("scram_not_primed"));
            }
            let password = self
                .password
                .take()
                .ok_or_else(|| failure("scram_not_primed"))?;
            let salt = challenge.salt.clone();
            let iterations = challenge.iterations;
            self.cache = Some(
                cpu.run(move || {
                    let mut salted = Zeroizing::new([0; 32]);
                    pbkdf2::pbkdf2_hmac::<Sha256>(
                        password.as_bytes(),
                        &salt,
                        iterations,
                        salted.as_mut(),
                    );
                    let client = keyed(&salted[..], b"Client Key");
                    let server = keyed(&salted[..], b"Server Key");
                    match (client, server) {
                        (Ok(client), Ok(server)) => Ok(CachedKeys {
                            salt,
                            iterations,
                            client,
                            server,
                        }),
                        _ => Err(failure("scram_crypto")),
                    }
                })
                .await?,
            );
        }
        self.cache
            .as_ref()
            .ok_or_else(|| failure("scram_not_primed"))
    }
}

pub(super) struct Exchange {
    pub first: Zeroizing<String>,
    nonce: String,
    bare: String,
}

impl Exchange {
    pub fn new(account: &PreparedAccount) -> BenchResult<Self> {
        let mut random = Zeroizing::new([0; 24]);
        getrandom::fill(&mut random[..]).map_err(|_| failure("random_failed"))?;
        Self::with_nonce(account, STANDARD.encode(&random[..]))
    }

    pub(super) fn with_nonce(account: &PreparedAccount, nonce: String) -> BenchResult<Self> {
        if nonce.is_empty()
            || nonce.len() > 1024
            || !nonce
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
        {
            return Err(failure("scram_nonce"));
        }
        let username = account.username.replace('=', "=3D").replace(',', "=2C");
        let bare = format!("n={username},r={nonce}");
        let first = Zeroizing::new(STANDARD.encode(format!("n,,{bare}")));
        Ok(Self { first, nonce, bare })
    }

    pub fn challenge(&self, encoded: &str) -> BenchResult<Challenge> {
        let raw = decode(encoded, 4096)?;
        let message = std::str::from_utf8(&raw).map_err(|_| failure("scram_encoding"))?;
        let attributes = attributes(message)?;
        if attributes.len() < 3
            || attributes[0].0 != b'r'
            || attributes[1].0 != b's'
            || attributes[2].0 != b'i'
        {
            return Err(failure("scram_attributes"));
        }
        let nonce = attributes[0].1;
        if nonce.len() > 1024
            || !nonce.starts_with(&self.nonce)
            || nonce.len() <= self.nonce.len()
            || !nonce
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
        {
            return Err(failure("scram_nonce"));
        }
        let salt = decode(attributes[1].1, 64)?;
        if salt.is_empty() {
            return Err(failure("scram_salt"));
        }
        let iteration_text = attributes[2].1;
        if iteration_text.starts_with('0') || !iteration_text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(failure("scram_iterations"));
        }
        let iterations = iteration_text
            .parse::<u32>()
            .map_err(|_| failure("scram_iterations"))?;
        if !(4096..=1_000_000).contains(&iterations) {
            return Err(failure("scram_iterations"));
        }
        Ok(Challenge {
            salt,
            iterations,
            nonce: nonce.to_owned(),
            raw: message.to_owned(),
        })
    }

    pub async fn respond(
        self,
        account: &mut PreparedAccount,
        challenge: Challenge,
        mode: KeyMode,
        cpu: &BlockingExecutor,
    ) -> BenchResult<Proof> {
        let keys = account.keys(&challenge, mode, cpu).await?;
        let final_without_proof = format!("c=biws,r={}", challenge.nonce);
        let auth = Zeroizing::new(format!(
            "{},{},{final_without_proof}",
            self.bare, challenge.raw
        ));
        let mut stored = Sha256::digest(&keys.client[..]);
        let signature = keyed(&stored, auth.as_bytes())?;
        stored.as_mut_slice().zeroize();
        let mut proof = Zeroizing::new(*keys.client);
        for (byte, signature) in proof.iter_mut().zip(signature.iter()) {
            *byte ^= signature;
        }
        let encoded_proof = Zeroizing::new(STANDARD.encode(&proof[..]));
        let response = Zeroizing::new(format!("{final_without_proof},p={}", *encoded_proof));
        let mut verifier = Hmac::<Sha256>::new_from_slice(&keys.server[..])
            .map_err(|_| failure("scram_crypto"))?;
        verifier.update(auth.as_bytes());
        Ok(Proof {
            response: Zeroizing::new(STANDARD.encode(response.as_bytes())),
            verifier,
        })
    }
}

pub(super) struct Challenge {
    salt: Zeroizing<Vec<u8>>,
    iterations: u32,
    nonce: String,
    raw: String,
}

pub(super) struct Proof {
    pub response: Zeroizing<String>,
    verifier: Hmac<Sha256>,
}

impl Proof {
    pub fn verify(self, encoded: &str) -> BenchResult<()> {
        let raw = decode(encoded, 4096)?;
        let message = std::str::from_utf8(&raw).map_err(|_| failure("scram_encoding"))?;
        let attributes = attributes(message)?;
        if attributes.first().map(|a| a.0) != Some(b'v') || attributes.iter().any(|a| a.0 == b'e') {
            return Err(failure("scram_server_proof"));
        }
        let signature = decode(attributes[0].1, 32)?;
        self.verifier
            .verify_slice(&signature)
            .map_err(|_| failure("scram_server_signature"))
    }
}

fn keyed(key: &[u8], data: &[u8]) -> BenchResult<Zeroizing<[u8; 32]>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| failure("scram_crypto"))?;
    mac.update(data);
    let mut output = mac.finalize().into_bytes();
    let result = Zeroizing::new(
        output
            .as_slice()
            .try_into()
            .map_err(|_| failure("scram_crypto"))?,
    );
    output.as_mut_slice().zeroize();
    Ok(result)
}

fn attributes(message: &str) -> BenchResult<Vec<(u8, &str)>> {
    let mut seen = [false; 128];
    let mut result = Vec::new();
    for part in message.split(',') {
        let bytes = part.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b'='
            || seen[usize::from(bytes[0])]
        {
            return Err(failure("scram_attributes"));
        }
        if bytes[0] == b'm' {
            return Err(failure("scram_mandatory_extension"));
        }
        seen[usize::from(bytes[0])] = true;
        result.push((bytes[0], &part[2..]));
    }
    Ok(result)
}

fn decode(encoded: &str, max: usize) -> BenchResult<Zeroizing<Vec<u8>>> {
    if encoded.len() > max.div_ceil(3) * 4 {
        return Err(failure("scram_size"));
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| failure("scram_encoding"))?,
    );
    if decoded.len() > max {
        return Err(failure("scram_size"));
    }
    Ok(decoded)
}
