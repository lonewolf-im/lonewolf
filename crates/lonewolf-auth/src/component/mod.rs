// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const MIN_SECRET_BYTES: usize = 16;
pub const MAX_SECRET_BYTES: usize = 1024;

pub struct ComponentSecret(Zeroizing<Box<str>>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentSecretError {
    Length,
}

impl ComponentSecret {
    pub fn new(value: &str) -> Result<Self, ComponentSecretError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&value.len()) {
            return Err(ComponentSecretError::Length);
        }
        Ok(Self(Zeroizing::new(value.into())))
    }
}

impl Clone for ComponentSecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.as_ref().into()))
    }
}

impl fmt::Debug for ComponentSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentSecret(..)")
    }
}

impl PartialEq for ComponentSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl Eq for ComponentSecret {}

impl fmt::Display for ComponentSecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("component secret must be 16 to 1024 bytes")
    }
}

impl std::error::Error for ComponentSecretError {}

pub fn handshake_matches(secret: &ComponentSecret, stream_id: &str, presented: &str) -> bool {
    let digits = presented
        .trim_matches(|character: char| character.is_ascii_whitespace())
        .as_bytes();
    if digits.len() != 40 {
        return false;
    }

    let mut decoded = [0; 20];
    let (pairs, _) = digits.as_chunks::<2>();
    for (index, &[high_digit, low_digit]) in pairs.iter().enumerate() {
        let Some(high) = hex_value(high_digit) else {
            return false;
        };
        let Some(low) = hex_value(low_digit) else {
            return false;
        };
        decoded[index] = high << 4 | low;
    }

    let digest: [u8; 20] = Sha1::new()
        .chain_update(stream_id.as_bytes())
        .chain_update(secret.0.as_bytes())
        .finalize()
        .into();
    bool::from(digest.ct_eq(&decoded))
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
