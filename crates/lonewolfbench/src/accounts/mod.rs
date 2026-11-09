// SPDX-License-Identifier: Apache-2.0

mod admin;
#[cfg(test)]
mod tests;

use crate::{
    client::PreparedAccount,
    config::{MAX_ACCOUNTS, normalize_dns},
    error::{BenchError, BenchResult, ErrorCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;

pub use crate::error::ProvisionSummary;
pub use admin::provision_accounts;

const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_PASSWORD: usize = 8192;

pub(crate) fn failure(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::InvalidConfig, context)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest<'a> {
    schema_version: u32,
    domain: String,
    #[serde(borrow)]
    accounts: Vec<RawCredential<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredential<'a> {
    jid: String,
    // Raw borrowing keeps escaped passwords out of the JSON decoder's scratch buffer.
    #[serde(borrow)]
    password: &'a RawValue,
}

pub(crate) struct Credential {
    pub(crate) jid: String,
    pub(crate) password: Zeroizing<String>,
}

fn decode_password(raw: &str) -> BenchResult<Zeroizing<String>> {
    let text = raw
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .ok_or_else(|| failure("credentials_password_encoding"))?;
    let mut output = Zeroizing::new(String::new());
    output
        .try_reserve_exact(text.len().min(MAX_PASSWORD))
        .map_err(|_| failure("credentials_allocation"))?;
    let mut chars = text.chars();
    while let Some(scalar) = chars.next() {
        let decoded = match scalar {
            '\\' => match chars.next() {
                Some(value @ ('"' | '\\' | '/')) => value,
                Some('b') => '\u{8}',
                Some('f') => '\u{c}',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some('u') => {
                    let first = hex_quad(&mut chars)?;
                    let code = if (0xd800..=0xdbff).contains(&first) {
                        if chars.next() != Some('\\') || chars.next() != Some('u') {
                            return Err(failure("credentials_password_encoding"));
                        }
                        let second = hex_quad(&mut chars)?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(failure("credentials_password_encoding"));
                        }
                        0x10000 + u32::from(first - 0xd800) * 1024 + u32::from(second - 0xdc00)
                    } else {
                        u32::from(first)
                    };
                    char::from_u32(code).ok_or_else(|| failure("credentials_password_encoding"))?
                }
                _ => return Err(failure("credentials_password_encoding")),
            },
            '"' | '\u{0}'..='\u{1f}' => return Err(failure("credentials_password_encoding")),
            value => value,
        };
        if decoded.len_utf8() > MAX_PASSWORD.saturating_sub(output.len()) {
            return Err(failure("credentials_password"));
        }
        output.push(decoded);
    }
    Ok(output)
}

fn hex_quad(chars: &mut std::str::Chars<'_>) -> BenchResult<u16> {
    let mut value = 0;
    for _ in 0..4 {
        let digit = chars
            .next()
            .and_then(|scalar| scalar.to_digit(16))
            .ok_or_else(|| failure("credentials_password_encoding"))?;
        value = value * 16 + digit as u16;
    }
    Ok(value)
}

pub struct CredentialSet {
    domain: String,
    pub(crate) accounts: Vec<Credential>,
}

impl CredentialSet {
    pub fn read(
        path: &Path,
        expected_domain: Option<&str>,
        required: Option<usize>,
    ) -> BenchResult<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| failure("credentials_private_open"))?;
        let metadata = file
            .metadata()
            .map_err(|_| failure("credentials_metadata"))?;
        // The opened descriptor prevents a path replacement from bypassing these checks.
        let uid = unsafe { nix::libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_FILE as u64
        {
            return Err(failure("credentials_private_file_required"));
        }
        let mut data = Zeroizing::new(Vec::new());
        data.try_reserve_exact(metadata.len() as usize)
            .map_err(|_| failure("credentials_allocation"))?;
        let mut chunk = Zeroizing::new([0; 8192]);
        loop {
            let count = file
                .read(&mut chunk[..])
                .map_err(|_| failure("credentials_read"))?;
            if count == 0 {
                break;
            }
            if count > MAX_FILE.saturating_sub(data.len()) {
                return Err(failure("credentials_too_large"));
            }
            if data.len() + count > data.capacity() {
                let capacity = (data.capacity().max(8192) * 2)
                    .min(MAX_FILE)
                    .max(data.len() + count);
                let mut expanded = Zeroizing::new(Vec::new());
                expanded
                    .try_reserve_exact(capacity)
                    .map_err(|_| failure("credentials_allocation"))?;
                expanded.extend_from_slice(&data);
                data = expanded;
            }
            data.extend_from_slice(&chunk[..count]);
        }
        let manifest: Manifest<'_> =
            serde_json::from_slice(&data).map_err(|_| failure("credentials_schema"))?;
        let domain = normalize_dns(&manifest.domain)?;
        if domain != manifest.domain || expected_domain.is_some_and(|expected| expected != domain) {
            return Err(failure("credentials_domain"));
        }
        if manifest.schema_version != 1
            || manifest.accounts.is_empty()
            || manifest.accounts.len() > MAX_ACCOUNTS
        {
            return Err(failure("credentials_count_or_version"));
        }
        let mut identities = HashSet::new();
        identities
            .try_reserve(manifest.accounts.len())
            .map_err(|_| failure("credentials_allocation"))?;
        for account in &manifest.accounts {
            let mut arena = Arena::try_new(ArenaConfig::default())
                .map_err(|_| failure("credentials_allocation"))?;
            let jid =
                Jid::parse_in(&account.jid, &mut arena).map_err(|_| failure("credentials_jid"))?;
            let jid = jid
                .resolve(&arena)
                .map_err(|_| failure("credentials_jid"))?;
            if jid.as_str() != account.jid
                || jid.is_full()
                || jid.localpart().is_none()
                || jid.domainpart() != domain
                || !identities.insert(account.jid.as_str())
            {
                return Err(failure("credentials_jid"));
            }
        }
        drop(identities);
        let mut accounts = Vec::new();
        accounts
            .try_reserve_exact(manifest.accounts.len())
            .map_err(|_| failure("credentials_allocation"))?;
        for account in manifest.accounts {
            let password = decode_password(account.password.get())?;
            let _prepared = Zeroizing::new(
                stringprep::saslprep(&password)
                    .map_err(|_| failure("credentials_password"))?
                    .into_owned(),
            );
            accounts.push(Credential {
                jid: account.jid,
                password,
            });
        }
        if let Some(required) = required {
            if required == 0 || required > accounts.len() {
                return Err(failure("credentials_insufficient"));
            }
            accounts.truncate(required);
        }
        Ok(Self { domain, accounts })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn len(&self) -> usize {
        self.accounts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
    pub fn into_prepared(self) -> BenchResult<Vec<PreparedAccount>> {
        self.accounts
            .into_iter()
            .map(|mut account| {
                PreparedAccount::new(&account.jid, std::mem::take(&mut *account.password))
            })
            .collect()
    }
}

pub(crate) fn generated(domain: &str, prefix: &str, count: usize) -> BenchResult<CredentialSet> {
    let normalized = normalize_dns(domain)?;
    let bytes = prefix.as_bytes();
    if normalized != domain
        || bytes.is_empty()
        || bytes.len() > 32
        || !bytes[0].is_ascii_lowercase()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
        || !(1..=MAX_ACCOUNTS).contains(&count)
    {
        return Err(failure("credentials_generation_parameters"));
    }
    let mut accounts = Vec::new();
    accounts
        .try_reserve_exact(count)
        .map_err(|_| failure("credentials_allocation"))?;
    for index in 0..count {
        let mut random = Zeroizing::new([0; 24]);
        let mut password = None;
        for _ in 0..16 {
            getrandom::fill(&mut random[..]).map_err(|_| failure("credentials_random"))?;
            let candidate = Zeroizing::new(URL_SAFE_NO_PAD.encode(&random[..]));
            let mut distinct = [0; 3];
            let mut count = 0;
            for byte in candidate.bytes() {
                if count < distinct.len() && !distinct[..count].contains(&byte) {
                    distinct[count] = byte;
                    count += 1;
                }
            }
            if count == 3 {
                password = Some(candidate);
                break;
            }
        }
        accounts.push(Credential {
            jid: format!("{prefix}-{index:06}@{domain}"),
            password: password.ok_or_else(|| failure("credentials_random"))?,
        });
    }
    Ok(CredentialSet {
        domain: domain.to_owned(),
        accounts,
    })
}

pub fn generate_credentials(
    domain: &str,
    prefix: &str,
    count: usize,
    output: &Path,
) -> BenchResult<()> {
    let credentials = generated(domain, prefix, count)?;
    #[derive(Serialize)]
    struct Account<'a> {
        jid: &'a str,
        password: &'a str,
    }
    #[derive(Serialize)]
    struct Output<'a> {
        schema_version: u32,
        domain: &'a str,
        accounts: Vec<Account<'a>>,
    }
    let manifest = Output {
        schema_version: 1,
        domain: credentials.domain(),
        accounts: credentials
            .accounts
            .iter()
            .map(|account| Account {
                jid: &account.jid,
                password: &account.password,
            })
            .collect(),
    };
    let capacity = 128
        + credentials.domain.len()
        + credentials
            .accounts
            .iter()
            .map(|account| account.jid.len() + account.password.len() + 32)
            .sum::<usize>();
    let mut data = Zeroizing::new(Vec::new());
    data.try_reserve_exact(capacity)
        .map_err(|_| failure("credentials_allocation"))?;
    serde_json::to_writer(&mut *data, &manifest).map_err(|_| failure("credentials_encode"))?;
    if data.len() > MAX_FILE {
        return Err(failure("credentials_too_large"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|_| BenchError::new(ErrorCode::OutputExists, "credentials_output_unavailable"))?;
    file.write_all(&data)
        .and_then(|()| file.sync_all())
        .map_err(|_| failure("credentials_write"))
}
