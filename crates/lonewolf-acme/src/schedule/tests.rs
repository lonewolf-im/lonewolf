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
    }
}

#[test]
fn fallback_uses_actual_lifetime_and_earlier_bounded_jitter() -> TestResult {
    for lifetime in [90 * 86400, 45 * 86400, 6 * 86400, 120, 1] {
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
        assert_eq!(retry_delay(count, |_| Ok(0))?, base);
        assert_eq!(retry_delay(count, Ok)?, base + base / 10);
        assert!(retry_delay(count, |max| Ok(max + 1)).is_err());
        assert_eq!(ari_delay(count, true), ari);
        assert_eq!(ari_delay(count, false), 43200);
    }
    Ok(())
}
