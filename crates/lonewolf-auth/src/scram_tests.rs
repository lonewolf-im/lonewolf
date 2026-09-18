// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::Digest;

use super::*;

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
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        let result = ScramVerifier::generate_with_salt_source(
            hash,
            "pencil",
            ScramIterations::new(4096)?,
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
