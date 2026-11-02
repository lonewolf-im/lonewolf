// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::types::CertificateMaterial;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn certificate() -> StoredCertificate {
    StoredCertificate {
        replaces: None,
        material: CertificateMaterial {
            chain: vec![vec![1]],
            private_key_pkcs8: Zeroizing::new(vec![2]),
        },
        not_before_unix: 100,
        not_after_unix: 10000,
        renew_at_unix: 5000,
        ari_check_at_unix: 100,
        fallback_at_unix: 5000,
        ari_window: None,
        ari_failures: 0,
        profile: None,
    }
}

#[test]
fn fallback_uses_actual_lifetime_and_earlier_bounded_jitter() -> TestResult {
    for lifetime in [90 * 86400, 45 * 86400, 6 * 86400, 576_000, 120, 1] {
        let validity = CertificateValidity {
            not_before_unix: 100,
            not_after_unix: 100 + lifetime,
        };
        let base = 100
            + if lifetime >= 864000 {
                lifetime * 2 / 3
            } else {
                lifetime / 2
            };
        assert_eq!(fallback(validity, |_| Ok(0))?, base);
        assert_eq!(fallback(validity, Ok)?, base - lifetime / 20);
        assert!(fallback(validity, |max| Ok(max + 1)).is_err());
    }
    Ok(())
}

#[test]
fn windows_are_uniform_half_open_persisted_and_changed_only_when_needed() -> TestResult {
    let mut cert = certificate();
    assert!(apply_window(&mut cert, 200, 300, Ok)?);
    assert_eq!(cert.renew_at_unix, 299);
    assert!(apply_window(&mut cert, 200, 300, |_| panic!(
        "unchanged window resampled"
    ))?);
    assert!(apply_window(&mut cert, 100, 150, |_| Ok(0))?);
    assert_eq!(cert.renew_at_unix, 100);
    assert!(apply_window(&mut cert, 0, 1, Ok)?);
    assert_eq!(cert.renew_at_unix, 0);
    Ok(())
}

#[test]
fn malformed_overflow_and_beyond_expiry_windows_do_not_replace_schedule() -> TestResult {
    let mut cert = certificate();
    for (start, end) in [(3, 3), (4, 3), (100, 10001), (0, u64::MAX), (u64::MAX, 0)] {
        assert!(!apply_window(&mut cert, start, end, |_| panic!(
            "invalid window sampled"
        ))?);
        assert_eq!(cert.renew_at_unix, 5000);
    }
    assert!(apply_window(&mut cert, 200, 300, |_| Ok(100)).is_err());
    assert!(add(i64::MAX as u64, 1).is_err());
    assert!(add(u64::MAX, 1).is_err());
    assert!(
        fallback(
            CertificateValidity {
                not_before_unix: 1,
                not_after_unix: 1
            },
            Ok
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn retry_and_ari_backoff_have_distinct_caps_and_checked_jitter() -> TestResult {
    for (count, base, ari) in [
        (1, 60, 60),
        (2, 600, 600),
        (3, 6000, 6000),
        (4, 86400, 43200),
        (u32::MAX, 86400, 43200),
    ] {
        assert_eq!(retry_delay(count, None, |_| Ok(0))?, base);
        assert_eq!(retry_delay(count, None, Ok)?, base + base / 10);
        assert!(retry_delay(count, None, |max| Ok(max + 1)).is_err());
        assert_eq!(ari_delay(count, true), ari);
        assert_eq!(ari_delay(count, false), 43200);
    }
    assert_eq!(retry_delay(4, Some(576_000), Ok)?, 26_400);
    assert!(retry_delay(4, Some(576_000), |max| Ok(max + 1)).is_err());
    Ok(())
}

#[test]
fn retry_base_caps_later_tiers_by_certificate_lifetime() {
    for (failures, lifetime, expected) in [
        (1, None, 60),
        (2, None, 600),
        (3, Some(576_000), 6_000),
        (0, None, 86_400),
        (4, None, 86_400),
        (4, Some(100_000), 6_000),
        (4, Some(576_000), 24_000),
        (4, Some(864_000), 36_000),
        (4, Some(2_073_600), 86_400),
        (4, Some(7_776_000), 86_400),
        (u32::MAX, Some(576_000), 24_000),
    ] {
        assert_eq!(retry_base(failures, lifetime), expected);
    }
}

#[test]
fn short_lifetime_retries_fit_in_the_last_half_of_the_lifetime() -> TestResult {
    const LIFETIME: u64 = 576_000;
    for (lifetime, expected_attempts, maximum_delay) in
        [(Some(LIFETIME), 14, 26_400), (None, 6, 95_040)]
    {
        let mut time = LIFETIME / 2;
        let mut attempts = 0;
        while time < LIFETIME {
            attempts += 1;
            let delay = retry_delay(attempts, lifetime, Ok)?;
            assert!(delay <= maximum_delay);
            time += delay;
        }
        assert_eq!(attempts, expected_attempts);
    }
    Ok(())
}
