// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::Digest;

use super::super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn rfc5802_sha1_verifier_validates_the_published_exchange() -> TestResult {
    let salt = STANDARD.decode("QSXCR+Q6sek8bf92")?;
    let (stored_key, server_key) =
        derive_keys::<Sha1, 20>(b"pencil", &salt, ScramIterations::new(4096)?)?;
    let auth_message = b"n=user,r=fyko+d2lbbFgONRv9qkxdawL,\
        r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,\
        c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";

    let mut signature = Hmac::<Sha1>::new_from_slice(&stored_key)?;
    signature.update(auth_message);
    let signature = signature.finalize().into_bytes();
    let mut client_key = STANDARD.decode("v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")?;
    for (byte, signature) in client_key.iter_mut().zip(signature) {
        *byte ^= signature;
    }
    assert_eq!(Sha1::digest(client_key).as_slice(), stored_key);

    let mut signature = Hmac::<Sha1>::new_from_slice(&server_key)?;
    signature.update(auth_message);
    assert_eq!(
        STANDARD.encode(signature.finalize().into_bytes()),
        "rmF9pqV8S7suAoZWja4dJRkFsKQ="
    );
    Ok(())
}

#[test]
fn ascii_password_preparation_borrows_the_input() -> TestResult {
    let password = " pEncil! ";
    let prepared = PreparedPassword::new(password)?;
    assert!(matches!(prepared.0, Cow::Borrowed(_)));
    assert_eq!(prepared.0.as_ptr(), password.as_ptr());
    assert_eq!(prepared.0, password);
    Ok(())
}

#[test]
fn random_source_failure_never_returns_a_verifier() -> TestResult {
    for hash in [ScramHash::Sha1, ScramHash::Sha256, ScramHash::Sha512] {
        let result = ScramVerifier::generate_with_salt_source(
            hash,
            "pencil",
            ScramIterations::new(hash.minimum_iterations())?,
            |salt| {
                salt[0] = 42;
                Err(getrandom::Error::UNSUPPORTED)
            },
        );
        let error = result.expect_err("random failure must stop credential generation");
        assert!(matches!(error, ScramError::RandomUnavailable(_)));
        assert!(error.source().is_some());
        assert_eq!(error.to_string(), "secure random source is unavailable");
    }
    Ok(())
}

#[test]
fn invalid_password_is_rejected_before_requesting_randomness() -> TestResult {
    let result = ScramVerifier::generate_with_salt_source(
        ScramHash::Sha256,
        "\u{0007}",
        ScramIterations::new(4096)?,
        |_| panic!("randomness must not be requested for an invalid password"),
    );
    assert!(matches!(result, Err(ScramError::InvalidPassword)));
    Ok(())
}

#[test]
fn provisioning_rejects_prepared_weakness_before_randomness_or_derivation() -> TestResult {
    for password in [
        "a".into(),
        "password".into(),
        "123456".into(),
        format!("abc{}", "a".repeat(11)),
        "a".repeat(30),
        "ab".repeat(30),
        "é中aé中aé中".into(),
        format!("abc{}\u{ad}", "a".repeat(11)),
        "ａab".repeat(8),
    ] {
        assert!(matches!(
            ScramCredentials::provision_with_salt_source(
                &password,
                ScramIterations::new(4096)?,
                |_| panic!("weak input must not request salts"),
            ),
            Err(ProvisioningError::WeakPassword)
        ));
    }
    for password in ["", "\u{ad}", "\u{7}", "\u{221}"] {
        assert!(matches!(
            ScramCredentials::provision_with_salt_source(
                password,
                ScramIterations::new(4096)?,
                |_| panic!("invalid input must not request salts"),
            ),
            Err(ProvisioningError::Scram(ScramError::InvalidPassword))
        ));
    }
    Ok(())
}

#[test]
fn provisioning_derives_all_hashes_from_prepared_scalars_with_independent_salts() -> TestResult {
    let iterations = ScramIterations::new(10_000)?;
    for (raw, prepared) in [
        (
            format!("abc{}", "a".repeat(12)),
            format!("abc{}", "a".repeat(12)),
        ),
        ("你好世".repeat(5), "你好世".repeat(5)),
        (
            format!("{}Ⅸ", "a".repeat(13)),
            format!("{}IX", "a".repeat(13)),
        ),
        (
            format!("ab{}\u{a0}", "a".repeat(12)),
            format!("ab{} ", "a".repeat(12)),
        ),
        (
            "ocean copper lantern meadow".into(),
            "ocean copper lantern meadow".into(),
        ),
    ] {
        let mut calls = 0;
        let credentials = ScramCredentials::provision_with_salt_source(&raw, iterations, |salt| {
            calls += 1;
            salt.fill(calls);
            Ok(())
        })?;
        assert_eq!(calls, 3);
        let sha1 = credentials.sha1().ok_or("missing SHA-1 verifier")?;
        let sha256 = credentials.sha256().ok_or("missing SHA-256 verifier")?;
        assert_eq!(sha1.salt(), &[1; 16]);
        assert_eq!(sha256.salt(), &[2; 16]);
        let ScramVerifier::Sha1(expected) =
            ScramVerifier::derive(ScramHash::Sha1, &prepared, [1; 16], iterations)?
        else {
            return Err("wrong hash".into());
        };
        assert_eq!(sha1.stored_key(), expected.stored_key());
        assert_eq!(sha1.server_key(), expected.server_key());
        let ScramVerifier::Sha256(expected) =
            ScramVerifier::derive(ScramHash::Sha256, &prepared, [2; 16], iterations)?
        else {
            return Err("wrong hash".into());
        };
        assert_eq!(sha256.stored_key(), expected.stored_key());
        assert_eq!(sha256.server_key(), expected.server_key());
        let sha512 = credentials.sha512().ok_or("missing SHA-512 verifier")?;
        assert_eq!(sha512.salt(), &[3; 16]);
        let ScramVerifier::Sha512(expected) =
            ScramVerifier::derive(ScramHash::Sha512, &prepared, [3; 16], iterations)?
        else {
            return Err("wrong hash".into());
        };
        assert_eq!(sha512.stored_key(), expected.stored_key());
        assert_eq!(sha512.server_key(), expected.server_key());
    }
    Ok(())
}

#[test]
fn provisioning_random_failure_stops_without_returning_credentials() -> TestResult {
    for fail_at in [1, 2, 3] {
        let mut calls = 0;
        let result = ScramCredentials::provision_with_salt_source(
            "ocean copper lantern meadow",
            ScramIterations::new(10_000)?,
            |salt| {
                calls += 1;
                salt.fill(calls);
                if calls == fail_at {
                    Err(getrandom::Error::UNSUPPORTED)
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(calls, fail_at);
        let Err(error) = result else {
            return Err("random failure returned credentials".into());
        };
        assert!(matches!(
            error,
            ProvisioningError::Scram(ScramError::RandomUnavailable(_))
        ));
        assert!(error.source().is_some());
        assert_eq!(error.to_string(), "secure random source is unavailable");
    }
    Ok(())
}

#[test]
fn sha512_and_provisioning_reject_low_cost_before_requesting_salts() -> TestResult {
    for count in [4096, 9_999] {
        let iterations = ScramIterations::new(count)?;
        assert!(matches!(
            ScramVerifier::generate_with_salt_source(
                ScramHash::Sha512,
                "pencil",
                iterations,
                |_| panic!("invalid cost must not request a salt")
            ),
            Err(ScramError::InvalidIterations)
        ));
        assert!(matches!(
            ScramCredentials::provision_with_salt_source(
                "ocean copper lantern meadow",
                iterations,
                |_| panic!("invalid cost must not request a salt")
            ),
            Err(ProvisioningError::Scram(ScramError::InvalidIterations))
        ));
    }
    Ok(())
}
