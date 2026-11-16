// SPDX-License-Identifier: Apache-2.0

use super::*;

const KNOWN_ANSWERS: [(&str, &str, &str); 2] = [
    (
        "3BF96D32",
        "s3cr3t-component-k3y",
        "361c7979c52d56db546b5cf2e34a305164dbea1a",
    ),
    (
        "d2f1b4e6a8c0e2f4a6b8c0d2e4f6a8b0",
        "mañana-component-secret",
        "b1face2bd9032272bc2d8b45d3b2cf62f362c4fa",
    ),
];

#[test]
fn known_handshakes_accept_case_and_surrounding_ascii_whitespace()
-> Result<(), ComponentSecretError> {
    for (stream_id, secret, digest) in KNOWN_ANSWERS {
        let secret = ComponentSecret::new(secret)?;
        assert!(handshake_matches(&secret, stream_id, digest));
        assert!(handshake_matches(
            &secret,
            stream_id,
            &digest.to_ascii_uppercase()
        ));
        assert!(handshake_matches(
            &secret,
            stream_id,
            &format!(" \t\r\n{digest} \t\r\n")
        ));
    }
    Ok(())
}

#[test]
fn malformed_or_mismatched_handshakes_are_rejected() -> Result<(), ComponentSecretError> {
    for (stream_id, secret, digest) in KNOWN_ANSWERS {
        let secret = ComponentSecret::new(secret)?;
        let changed_digest = format!("0{}", &digest[1..]);
        let extended_digest = format!("{digest}0");
        let non_hex_digest = format!("g{}", &digest[1..]);
        let inner_whitespace = format!("{} {}", &digest[..20], &digest[20..]);
        let changed_secret = ComponentSecret::new("different-component-secret")?;
        for (candidate_stream_id, candidate_secret, candidate_digest) in [
            (stream_id, &secret, changed_digest.as_str()),
            ("different-stream-id", &secret, digest),
            (stream_id, &changed_secret, digest),
            (stream_id, &secret, &digest[..39]),
            (stream_id, &secret, extended_digest.as_str()),
            (stream_id, &secret, non_hex_digest.as_str()),
            (stream_id, &secret, inner_whitespace.as_str()),
            (stream_id, &secret, ""),
        ] {
            assert!(
                !handshake_matches(candidate_secret, candidate_stream_id, candidate_digest),
                "accepted invalid handshake {candidate_digest:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn secrets_enforce_byte_length_limits() {
    assert!(matches!(
        ComponentSecret::new(&"x".repeat(MIN_SECRET_BYTES - 1)),
        Err(ComponentSecretError::Length)
    ));
    assert!(ComponentSecret::new(&"x".repeat(MIN_SECRET_BYTES)).is_ok());
    assert!(ComponentSecret::new(&"x".repeat(MAX_SECRET_BYTES)).is_ok());
    assert!(matches!(
        ComponentSecret::new(&"x".repeat(MAX_SECRET_BYTES + 1)),
        Err(ComponentSecretError::Length)
    ));
    let multibyte_minimum = "12345678901234ñ";
    assert_eq!(multibyte_minimum.chars().count(), 15);
    assert_eq!(multibyte_minimum.len(), MIN_SECRET_BYTES);
    assert!(ComponentSecret::new(multibyte_minimum).is_ok());
    assert_eq!(
        ComponentSecretError::Length.to_string(),
        "component secret must be 16 to 1024 bytes"
    );
}

#[test]
fn secret_debug_and_equality_do_not_expose_the_secret() -> Result<(), ComponentSecretError> {
    let secret = ComponentSecret::new("sensitive-component-secret")?;
    let equal = secret.clone();
    let different_byte = ComponentSecret::new("sensitive-component-secreu")?;
    let different_length = ComponentSecret::new("short-component-secret")?;
    let debug = format!("{secret:?}");
    assert_eq!(debug, "ComponentSecret(..)");
    assert!(!debug.contains("sensitive-component-secret"));
    assert_eq!(secret, equal);
    assert_ne!(secret, different_byte);
    assert_ne!(secret, different_length);
    Ok(())
}
