// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{AriWindow, CertificateValidity, StateError, StoredCertificate};

pub(crate) fn timestamp(value: u64) -> Result<u64, StateError> {
    if value > i64::MAX as u64 || UNIX_EPOCH.checked_add(Duration::from_secs(value)).is_none() {
        return Err(StateError::InvalidData);
    }
    Ok(value)
}

pub(crate) fn now() -> Result<u64, StateError> {
    timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StateError::InvalidData)?
            .as_secs(),
    )
}

pub(crate) fn add(now: u64, delay: u64) -> Result<u64, StateError> {
    timestamp(now.checked_add(delay).ok_or(StateError::InvalidData)?)
}

pub(crate) fn uniform(maximum: u64) -> Result<u64, StateError> {
    let range = maximum.checked_add(1).ok_or(StateError::InvalidData)?;
    let threshold = range.wrapping_neg() % range;
    loop {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).map_err(|_| StateError::Other)?;
        let value = u64::from_ne_bytes(bytes);
        if value >= threshold {
            return Ok(value % range);
        }
    }
}

pub(crate) fn fallback(
    validity: CertificateValidity,
    random: impl FnOnce(u64) -> Result<u64, StateError>,
) -> Result<u64, StateError> {
    timestamp(validity.not_before_unix)?;
    timestamp(validity.not_after_unix)?;
    let lifetime = validity
        .not_after_unix
        .checked_sub(validity.not_before_unix)
        .filter(|value| *value > 0)
        .ok_or(StateError::InvalidData)?;
    let offset = if lifetime >= 864_000 {
        lifetime / 3 * 2 + lifetime % 3 * 2 / 3
    } else {
        lifetime / 2
    };
    let maximum = lifetime / 20;
    let jitter = random(maximum)?;
    if jitter > maximum {
        return Err(StateError::InvalidData);
    }
    timestamp(
        add(validity.not_before_unix, offset)?
            .checked_sub(jitter)
            .ok_or(StateError::InvalidData)?,
    )
}

pub(crate) fn retry_delay(
    failures: u32,
    random: impl FnOnce(u64) -> Result<u64, StateError>,
) -> Result<u64, StateError> {
    let base = match failures {
        1 => 60,
        2 => 600,
        3 => 6000,
        _ => 86400,
    };
    let jitter = random(base / 10)?;
    if jitter > base / 10 {
        return Err(StateError::InvalidData);
    }
    Ok(base + jitter)
}

pub(crate) fn ari_delay(failures: u32, temporary: bool) -> u64 {
    if !temporary {
        return 43_200;
    }
    match failures {
        1 => 60,
        2 => 600,
        3 => 6000,
        _ => 43_200,
    }
}

pub(crate) fn apply_window(
    certificate: &mut StoredCertificate,
    start: u64,
    end: u64,
    random: impl FnOnce(u64) -> Result<u64, StateError>,
) -> Result<bool, StateError> {
    if timestamp(start).is_err()
        || timestamp(end).is_err()
        || end <= start
        || end > certificate.not_after_unix
    {
        return Ok(false);
    }
    let selected = if let Some(window) = certificate
        .ari_window
        .filter(|window| window.start_unix == start && window.end_unix == end)
    {
        window.selected_unix
    } else {
        let maximum = end - start - 1;
        let offset = random(maximum)?;
        if offset > maximum {
            return Err(StateError::InvalidData);
        }
        add(start, offset)?
    };
    certificate.renew_at_unix = selected;
    certificate.ari_window = Some(AriWindow {
        start_unix: start,
        end_unix: end,
        selected_unix: selected,
    });
    Ok(true)
}

#[cfg(test)]
mod tests;
