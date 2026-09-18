// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use lonewolf_auth::scram::{
    ScramCredentials, ScramError, ScramHash, ScramIterations, ScramSha1Verifier,
    ScramSha256Verifier, ScramVerifier, ScramVerifierData,
};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

const SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn sha1() -> ScramSha1Verifier {
    ScramSha1Verifier::new([11; 16], NonZeroU32::MIN, [12; 20], [13; 20])
}

fn sha256() -> ScramSha256Verifier {
    ScramSha256Verifier::new([21; 16], NonZeroU32::MIN, [22; 32], [23; 32])
}

#[test]
fn credential_sets_preserve_independent_verifiers() {
    let credentials = ScramCredentials::both(sha1(), sha256());
    let Some(sha1) = credentials.sha1() else {
        panic!("SHA-1 verifier missing");
    };
    let Some(sha256) = credentials.sha256() else {
        panic!("SHA-256 verifier missing");
    };

    assert_eq!(sha1.salt(), &[11; 16]);
    assert_eq!(sha1.iterations(), NonZeroU32::MIN);
    assert_eq!(sha1.stored_key(), &[12; 20]);
    assert_eq!(sha1.server_key(), &[13; 20]);
    assert_eq!(sha256.salt(), &[21; 16]);
    assert_eq!(sha256.iterations(), NonZeroU32::MIN);
    assert_eq!(sha256.stored_key(), &[22; 32]);
    assert_eq!(sha256.server_key(), &[23; 32]);
}

#[test]
fn single_hash_credential_sets_do_not_supply_the_other_hash() {
    let verifier = ScramVerifier::Sha1(sha1());
    assert_eq!(verifier.hash(), ScramHash::Sha1);
    let credentials = ScramCredentials::new(verifier);
    assert!(credentials.sha1().is_some());
    assert!(credentials.sha256().is_none());

    let verifier = ScramVerifier::Sha256(sha256());
    assert_eq!(verifier.hash(), ScramHash::Sha256);
    let credentials = ScramCredentials::new(verifier);
    assert!(credentials.sha1().is_none());
    assert!(credentials.sha256().is_some());
}

#[test]
fn rfc7677_sha256_verifier_validates_the_published_exchange() -> TestResult {
    let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==")?;
    let salt = salt.try_into().map_err(|_| "invalid fixture salt length")?;
    let ScramVerifier::Sha256(verifier) = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        salt,
        ScramIterations::new(4096)?,
    )?
    else {
        return Err("wrong verifier hash".into());
    };
    assert_eq!(verifier.salt(), &salt);
    assert_eq!(verifier.iterations().get(), 4096);
    let auth_message = b"n=user,r=rOprNGfwEbeRWgbNEkqO,\
        r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,\
        c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";

    let mut signature = Hmac::<Sha256>::new_from_slice(verifier.stored_key())?;
    signature.update(auth_message);
    let signature = signature.finalize().into_bytes();
    let mut client_key = STANDARD.decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")?;
    for (byte, signature) in client_key.iter_mut().zip(signature) {
        *byte ^= signature;
    }
    assert_eq!(Sha256::digest(client_key).as_slice(), verifier.stored_key());

    let mut signature = Hmac::<Sha256>::new_from_slice(verifier.server_key())?;
    signature.update(auth_message);
    assert_eq!(
        STANDARD.encode(signature.finalize().into_bytes()),
        "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    );
    Ok(())
}

#[test]
fn sha1_derivation_matches_an_independent_known_answer_with_a_sixteen_byte_salt() -> TestResult {
    let ScramVerifier::Sha1(verifier) =
        ScramVerifier::derive(ScramHash::Sha1, "pencil", SALT, ScramIterations::new(4096)?)?
    else {
        return Err("wrong verifier hash".into());
    };
    assert_eq!(verifier.salt(), &SALT);
    assert_eq!(verifier.iterations().get(), 4096);
    assert_eq!(
        STANDARD.encode(verifier.stored_key()),
        "VDlbg2hiPs7Sz96xRXoDeVxwMPk="
    );
    assert_eq!(
        STANDARD.encode(verifier.server_key()),
        "4q9hLjotvo0hqzEIvTJY/oC5Boo="
    );
    Ok(())
}

#[test]
fn generation_requires_an_explicit_iteration_count_at_or_above_the_minimum() -> TestResult {
    for value in [0, 1, ScramIterations::MIN - 1] {
        assert!(matches!(
            ScramIterations::new(value),
            Err(ScramError::InvalidIterations)
        ));
    }
    for value in [ScramIterations::MIN, 100_000] {
        assert_eq!(ScramIterations::new(value)?.get(), value);
    }
    Ok(())
}

#[test]
fn saslprep_equivalent_passwords_produce_the_same_verifier() -> TestResult {
    for (input, expected) in [
        ("I\u{00ad}X", "IX"),
        ("\u{00aa}", "a"),
        ("\u{2168}", "IX"),
        ("a\u{00a0}b", "a b"),
        ("e\u{0301}", "é"),
        ("\u{00bd}", "1\u{2044}2"),
        ("\u{00b4}", " \u{0301}"),
        ("\u{0627}1\u{0628}", "\u{0627}1\u{0628}"),
    ] {
        let input = derive_sha256(input, 4096)?;
        let expected = derive_sha256(expected, 4096)?;
        assert_same_verifier(&input, &expected);
    }
    Ok(())
}

#[test]
fn passwords_preserve_case_and_ascii_spaces() -> TestResult {
    let baseline = derive_sha256("pencil", 4096)?;
    for password in ["PENCIL", " pencil", "pencil "] {
        let verifier = derive_sha256(password, 4096)?;
        assert_ne!(verifier.stored_key(), baseline.stored_key());
        assert_ne!(verifier.server_key(), baseline.server_key());
    }
    Ok(())
}

#[test]
fn invalid_or_empty_prepared_passwords_are_rejected_without_exposing_input() -> TestResult {
    for password in [
        "",
        "\u{00ad}",
        "private\u{0007}value",
        "private\u{0000}value",
        "\u{e000}",
        "\u{fdd0}",
        "\u{0627}1",
        "\u{0627}a\u{0628}",
        "\u{0221}",
        "\u{1d2c}",
    ] {
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            let result = ScramVerifier::derive(hash, password, SALT, ScramIterations::new(4096)?);
            let error = result.expect_err("invalid password must be rejected");
            assert!(matches!(error, ScramError::InvalidPassword));
            assert_eq!(format!("{error:?}"), "InvalidPassword");
            assert_eq!(error.to_string(), "password is not valid for SCRAM");
            assert!(error.source().is_none());
        }
    }
    Ok(())
}

#[test]
fn changing_salt_or_iteration_count_changes_both_keys() -> TestResult {
    let baseline = derive_sha256("pencil", 4096)?;
    let higher_cost = derive_sha256("pencil", 8192)?;
    assert_eq!(higher_cost.iterations().get(), 8192);
    assert_ne!(baseline.stored_key(), higher_cost.stored_key());
    assert_ne!(baseline.server_key(), higher_cost.server_key());
    let ScramVerifier::Sha256(different_salt) = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [42; 16],
        ScramIterations::new(4096)?,
    )?
    else {
        return Err("wrong verifier hash".into());
    };
    assert_ne!(baseline.stored_key(), different_salt.stored_key());
    assert_ne!(baseline.server_key(), different_salt.server_key());
    Ok(())
}

#[test]
fn generated_verifiers_use_fresh_salts_and_can_be_rederived() -> TestResult {
    let iterations = ScramIterations::new(4096)?;
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        let first = ScramVerifier::generate(hash, "pencil", iterations)?;
        let second = ScramVerifier::generate(hash, "pencil", iterations)?;
        match (first, second) {
            (ScramVerifier::Sha1(first), ScramVerifier::Sha1(second)) => {
                assert_ne!(first.salt(), second.salt());
                let ScramVerifier::Sha1(rederived) =
                    ScramVerifier::derive(hash, "pencil", *first.salt(), iterations)?
                else {
                    return Err("wrong verifier hash".into());
                };
                assert_same_verifier(&first, &rederived);
            }
            (ScramVerifier::Sha256(first), ScramVerifier::Sha256(second)) => {
                assert_ne!(first.salt(), second.salt());
                let ScramVerifier::Sha256(rederived) =
                    ScramVerifier::derive(hash, "pencil", *first.salt(), iterations)?
                else {
                    return Err("wrong verifier hash".into());
                };
                assert_same_verifier(&first, &rederived);
            }
            _ => return Err("wrong verifier hash".into()),
        }
    }
    Ok(())
}

fn derive_sha256(password: &str, iterations: u32) -> Result<ScramSha256Verifier, Box<dyn Error>> {
    match ScramVerifier::derive(
        ScramHash::Sha256,
        password,
        SALT,
        ScramIterations::new(iterations)?,
    )? {
        ScramVerifier::Sha256(verifier) => Ok(verifier),
        _ => Err("wrong verifier hash".into()),
    }
}

fn assert_same_verifier<const N: usize>(
    actual: &ScramVerifierData<N>,
    expected: &ScramVerifierData<N>,
) {
    assert_eq!(actual.salt(), expected.salt());
    assert_eq!(actual.iterations(), expected.iterations());
    assert_eq!(actual.stored_key(), expected.stored_key());
    assert_eq!(actual.server_key(), expected.server_key());
}
