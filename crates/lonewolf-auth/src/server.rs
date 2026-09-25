// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::digest::Output;
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::scram::{SCRAM_POLICY_ITERATIONS, ScramHash, ScramVerifier, ScramVerifierData};

const MAX_SCRAM_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mechanism {
    Sha1,
    Sha1Plus,
    Sha256,
    Sha256Plus,
}

impl Mechanism {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SCRAM-SHA-1",
            Self::Sha1Plus => "SCRAM-SHA-1-PLUS",
            Self::Sha256 => "SCRAM-SHA-256",
            Self::Sha256Plus => "SCRAM-SHA-256-PLUS",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "SCRAM-SHA-1" => Self::Sha1,
            "SCRAM-SHA-1-PLUS" => Self::Sha1Plus,
            "SCRAM-SHA-256" => Self::Sha256,
            "SCRAM-SHA-256-PLUS" => Self::Sha256Plus,
            _ => return None,
        })
    }

    pub fn hash(self) -> ScramHash {
        match self {
            Self::Sha1 | Self::Sha1Plus => ScramHash::Sha1,
            Self::Sha256 | Self::Sha256Plus => ScramHash::Sha256,
        }
    }

    pub fn is_plus(self) -> bool {
        matches!(self, Self::Sha1Plus | Self::Sha256Plus)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingType {
    TlsExporter,
    TlsServerEndPoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerError {
    Malformed,
    InvalidProof,
    ChannelBindingMismatch,
    UnsupportedBinding,
    HashMismatch,
    RandomUnavailable,
}

pub struct ClientFirst {
    mechanism: Mechanism,
    binding: Option<BindingType>,
    gs2_header: String,
    bare: String,
    username: String,
    authzid: Option<String>,
    nonce: String,
}

impl ClientFirst {
    pub fn parse(
        mechanism: Mechanism,
        input: &[u8],
        channel_binding_offered: bool,
    ) -> Result<Self, ServerError> {
        if input.len() > MAX_SCRAM_BYTES {
            return Err(ServerError::Malformed);
        }
        let input = std::str::from_utf8(input).map_err(|_| ServerError::Malformed)?;
        let first_comma = input.find(',').ok_or(ServerError::Malformed)?;
        let second_comma = input[first_comma + 1..]
            .find(',')
            .map(|offset| first_comma + 1 + offset)
            .ok_or(ServerError::Malformed)?;
        let flag = &input[..first_comma];
        let binding = match flag {
            "n" if !mechanism.is_plus() => None,
            "p=tls-exporter" if mechanism.is_plus() => Some(BindingType::TlsExporter),
            "p=tls-server-end-point" if mechanism.is_plus() => Some(BindingType::TlsServerEndPoint),
            "y" if !mechanism.is_plus() && !channel_binding_offered => None,
            "y" if !mechanism.is_plus() => return Err(ServerError::ChannelBindingMismatch),
            value if value.starts_with("p=") => return Err(ServerError::UnsupportedBinding),
            _ => return Err(ServerError::Malformed),
        };
        let authzid = match &input[first_comma + 1..second_comma] {
            "" => None,
            value if value.starts_with("a=") => Some(unescape(&value[2..])?),
            _ => return Err(ServerError::Malformed),
        };
        let bare = &input[second_comma + 1..];
        let mut attributes = bare.split(',');
        let username = attributes
            .next()
            .and_then(|value| value.strip_prefix("n="))
            .ok_or(ServerError::Malformed)
            .and_then(unescape)?;
        if username.is_empty() {
            return Err(ServerError::Malformed);
        }
        let username = stringprep::saslprep(&username)
            .map_err(|_| ServerError::Malformed)?
            .into_owned();
        let nonce = attributes
            .next()
            .and_then(|value| value.strip_prefix("r="))
            .filter(|value| valid_nonce(value))
            .ok_or(ServerError::Malformed)?;
        for extension in attributes {
            if extension.starts_with("m=") || !valid_extension(extension) {
                return Err(ServerError::Malformed);
            }
        }
        Ok(Self {
            mechanism,
            binding,
            gs2_header: input[..=second_comma].into(),
            bare: bare.into(),
            username,
            authzid,
            nonce: nonce.into(),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn authzid(&self) -> Option<&str> {
        self.authzid.as_deref()
    }

    pub fn binding(&self) -> Option<BindingType> {
        self.binding
    }

    pub fn start(
        self,
        verifier: ScramVerifier,
        server_nonce: &str,
    ) -> Result<(ScramServer, String), ServerError> {
        if verifier.hash() != self.mechanism.hash() {
            return Err(ServerError::HashMismatch);
        }
        if !valid_nonce(server_nonce) {
            return Err(ServerError::Malformed);
        }
        let salt = match &verifier {
            ScramVerifier::Sha1(value) => value.salt(),
            ScramVerifier::Sha256(value) => value.salt(),
        };
        let iterations = match &verifier {
            ScramVerifier::Sha1(value) => value.iterations(),
            ScramVerifier::Sha256(value) => value.iterations(),
        };
        let mut nonce = String::with_capacity(self.nonce.len() + server_nonce.len());
        nonce.push_str(&self.nonce);
        nonce.push_str(server_nonce);
        let mut first = String::with_capacity(nonce.len() + 64);
        first.push_str("r=");
        first.push_str(&nonce);
        first.push_str(",s=");
        STANDARD.encode_string(salt, &mut first);
        first.push_str(",i=");
        first.push_str(&iterations.get().to_string());
        let server = ScramServer {
            verifier,
            binding: self.binding,
            gs2_header: self.gs2_header,
            client_first_bare: self.bare,
            server_first: first.clone(),
            nonce,
        };
        Ok((server, first))
    }
}

pub struct ScramServer {
    verifier: ScramVerifier,
    binding: Option<BindingType>,
    gs2_header: String,
    client_first_bare: String,
    server_first: String,
    nonce: String,
}

impl ScramServer {
    pub fn credential_is_current(&self, current: &ScramVerifier) -> bool {
        match (&self.verifier, current) {
            (ScramVerifier::Sha1(a), ScramVerifier::Sha1(b)) => same_verifier(a, b),
            (ScramVerifier::Sha256(a), ScramVerifier::Sha256(b)) => same_verifier(a, b),
            _ => false,
        }
    }

    pub fn finish(&self, input: &[u8], binding_data: &[u8]) -> Result<String, ServerError> {
        if input.len() > MAX_SCRAM_BYTES {
            return Err(ServerError::Malformed);
        }
        let input = std::str::from_utf8(input).map_err(|_| ServerError::Malformed)?;
        let proof_start = input.rfind(",p=").ok_or(ServerError::Malformed)?;
        let without_proof = &input[..proof_start];
        let proof_text = &input[proof_start + 3..];
        if proof_text.contains(',') {
            return Err(ServerError::Malformed);
        }
        let mut attributes = without_proof.split(',');
        let channel = attributes
            .next()
            .and_then(|value| value.strip_prefix("c="))
            .ok_or(ServerError::Malformed)?;
        let nonce = attributes
            .next()
            .and_then(|value| value.strip_prefix("r="))
            .ok_or(ServerError::Malformed)?;
        if nonce != self.nonce {
            return Err(ServerError::Malformed);
        }
        for extension in attributes {
            if extension.starts_with("m=") || !valid_extension(extension) {
                return Err(ServerError::Malformed);
            }
        }
        let decoded_channel = STANDARD
            .decode(channel)
            .map_err(|_| ServerError::Malformed)?;
        let expected_len = self.gs2_header.len() + binding_data.len();
        if decoded_channel.len() != expected_len
            || !bool::from(
                decoded_channel[..self.gs2_header.len()].ct_eq(self.gs2_header.as_bytes()),
            )
            || !bool::from(decoded_channel[self.gs2_header.len()..].ct_eq(binding_data))
        {
            return Err(ServerError::ChannelBindingMismatch);
        }
        let proof = Zeroizing::new(
            STANDARD
                .decode(proof_text)
                .map_err(|_| ServerError::Malformed)?,
        );
        let mut auth_message = String::with_capacity(
            self.client_first_bare.len() + self.server_first.len() + without_proof.len() + 2,
        );
        auth_message.push_str(&self.client_first_bare);
        auth_message.push(',');
        auth_message.push_str(&self.server_first);
        auth_message.push(',');
        auth_message.push_str(without_proof);
        let mut response = String::with_capacity(46);
        response.push_str("v=");
        match &self.verifier {
            ScramVerifier::Sha1(verifier) => STANDARD.encode_string(
                verify::<Sha1, 20>(verifier, auth_message.as_bytes(), &proof)?,
                &mut response,
            ),
            ScramVerifier::Sha256(verifier) => STANDARD.encode_string(
                verify::<Sha256, 32>(verifier, auth_message.as_bytes(), &proof)?,
                &mut response,
            ),
        }
        Ok(response)
    }

    pub fn binding(&self) -> Option<BindingType> {
        self.binding
    }
}

pub struct ScramDecoy(Zeroizing<[u8; 32]>);

impl ScramDecoy {
    /// The secret must be random and stable for the account store lifetime.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn new() -> Result<Self, ServerError> {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| ServerError::RandomUnavailable)?;
        Ok(Self(secret))
    }

    pub fn verifier(&self, hash: ScramHash, account: &str) -> Result<ScramVerifier, ServerError> {
        let prefix: &[u8] = match hash {
            ScramHash::Sha1 => b"sha1",
            ScramHash::Sha256 => b"sha256",
        };
        let salt = self.derive(prefix, b"salt", account)?;
        let stored = self.derive(prefix, b"stored", account)?;
        let server = self.derive(prefix, b"server", account)?;
        let mut salt16 = [0; 16];
        salt16.copy_from_slice(&salt[..16]);
        Ok(match hash {
            ScramHash::Sha1 => {
                let mut stored20 = [0; 20];
                let mut server20 = [0; 20];
                stored20.copy_from_slice(&stored[..20]);
                server20.copy_from_slice(&server[..20]);
                ScramVerifier::Sha1(ScramVerifierData::new(
                    salt16,
                    SCRAM_POLICY_ITERATIONS,
                    stored20,
                    server20,
                ))
            }
            ScramHash::Sha256 => ScramVerifier::Sha256(ScramVerifierData::new(
                salt16,
                SCRAM_POLICY_ITERATIONS,
                stored,
                server,
            )),
        })
    }

    fn derive(&self, hash: &[u8], purpose: &[u8], account: &str) -> Result<[u8; 32], ServerError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(self.0.as_ref()).map_err(|_| ServerError::Malformed)?;
        mac.update(hash);
        mac.update(&[0]);
        mac.update(purpose);
        mac.update(&[0]);
        mac.update(account.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}

fn verify<H: EagerHash, const N: usize>(
    verifier: &ScramVerifierData<N>,
    message: &[u8],
    proof: &[u8],
) -> Result<[u8; N], ServerError>
where
    [u8; N]: From<Output<H>> + From<Output<Hmac<H>>>,
{
    if proof.len() != N {
        return Err(ServerError::Malformed);
    }
    let signature = keyed_hash::<H, N>(verifier.stored_key(), message)?;
    let mut client_key = Zeroizing::new([0; N]);
    for (index, byte) in proof.iter().enumerate() {
        client_key[index] = byte ^ signature[index];
    }
    let stored_key: [u8; N] = H::digest(&client_key[..]).into();
    if !bool::from(stored_key.ct_eq(verifier.stored_key())) {
        return Err(ServerError::InvalidProof);
    }
    keyed_hash::<H, N>(verifier.server_key(), message)
}

fn keyed_hash<H: EagerHash, const N: usize>(key: &[u8], data: &[u8]) -> Result<[u8; N], ServerError>
where
    [u8; N]: From<Output<Hmac<H>>>,
{
    let mut mac = Hmac::<H>::new_from_slice(key).map_err(|_| ServerError::Malformed)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn same_verifier<const N: usize>(a: &ScramVerifierData<N>, b: &ScramVerifierData<N>) -> bool {
    a.iterations() == b.iterations()
        && bool::from(a.salt().ct_eq(b.salt()))
        && bool::from(a.stored_key().ct_eq(b.stored_key()))
        && bool::from(a.server_key().ct_eq(b.server_key()))
}

fn unescape(value: &str) -> Result<String, ServerError> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('=') {
        output.push_str(&rest[..index]);
        let escape = rest.get(index..index + 3).ok_or(ServerError::Malformed)?;
        output.push(match escape {
            "=2C" => ',',
            "=3D" => '=',
            _ => return Err(ServerError::Malformed),
        });
        rest = &rest[index + 3..];
    }
    output.push_str(rest);
    Ok(output)
}

fn valid_nonce(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b',')
}

fn valid_extension(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && !matches!(bytes[0], b'n' | b'r' | b'c' | b'p' | b'm')
        && bytes[1] == b'='
        && bytes[2..].iter().all(|&byte| !matches!(byte, 0 | b','))
}
