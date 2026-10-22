// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use crate::scram::{ScramHash, ScramIterations, ScramVerifier};
use crate::server::{ClientFirst, Mechanism, ScramDecoy, ScramServer, ServerError};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn sha256_server_matches_rfc7677_exchange() -> TestResult {
    let salt: [u8; 16] = STANDARD
        .decode("W22ZaJ0SNY7soEsUEjb6gQ==")?
        .try_into()
        .map_err(|_| "invalid salt")?;
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        salt,
        ScramIterations::new(4096)?,
    )?;
    let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO", true)
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    assert_eq!(first.username(), "user");
    assert_eq!(first.authzid(), None);
    let (server, challenge) = first
        .start(verifier, "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
        .map_err(|error| format!("cannot start: {error:?}"))?;
    assert_eq!(
        challenge,
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
    );
    assert_eq!(
        server.finish(
            b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
            &[],
        ),
        Ok("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=".into())
    );
    Ok(())
}

#[test]
fn optional_extensions_are_authenticated() -> TestResult {
    let extension = "x=é=\u{1}\t\u{7f},z=漢";
    let first_bare = format!("n=user,r=nonce,{extension}");
    let first_message = format!("n,,{first_bare}");
    let (server, challenge) = sha256_server(first_message.as_bytes())?;
    let without_proof = format!("c=biws,r=nonceserver,{extension}");
    let (final_message, _) = sha256_client_final(&first_bare, &challenge, &without_proof)?;
    assert_eq!(
        server.finish(final_message.as_bytes(), &[]),
        Ok("v=RG19dyA1jckZOSGXo7bCOZUGh5b89DwjMVbSPg2++LU=".into())
    );
    Ok(())
}

#[test]
fn tampered_first_extension_invalidates_proof() -> TestResult {
    let (server, challenge) = sha256_server(b"n,,n=user,r=nonce,x=changed")?;
    let (final_message, _) = sha256_client_final(
        "n=user,r=nonce,x=original",
        &challenge,
        "c=biws,r=nonceserver",
    )?;
    assert_eq!(
        server.finish(final_message.as_bytes(), &[]),
        Err(ServerError::InvalidProof)
    );
    Ok(())
}

#[test]
fn tampered_final_extension_invalidates_proof() -> TestResult {
    let (server, challenge) = sha256_server(b"n,,n=user,r=nonce")?;
    let (final_message, _) = sha256_client_final(
        "n=user,r=nonce",
        &challenge,
        "c=biws,r=nonceserver,x=original",
    )?;
    let tampered = final_message.replacen("x=original", "x=changed", 1);
    assert_eq!(
        server.finish(tampered.as_bytes(), &[]),
        Err(ServerError::InvalidProof)
    );
    Ok(())
}

#[test]
fn incorrect_proof_and_channel_binding_fail() -> TestResult {
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let first = ClientFirst::parse(
        Mechanism::Sha256Plus,
        b"p=tls-exporter,,n=user,r=nonce",
        true,
    )
    .map_err(|error| format!("invalid client first: {error:?}"))?;
    let (server, _) = first
        .start(verifier, "server")
        .map_err(|error| format!("cannot start: {error:?}"))?;
    let wrong_channel = format!(
        "c={},r=nonceserver,p={}",
        STANDARD.encode(b"p=tls-exporter,,wrong"),
        STANDARD.encode([0; 32])
    );
    assert_eq!(
        server.finish(wrong_channel.as_bytes(), b"actual"),
        Err(ServerError::ChannelBindingMismatch)
    );
    let wrong_proof = format!(
        "c={},r=nonceserver,p={}",
        STANDARD.encode(b"p=tls-exporter,,actual"),
        STANDARD.encode([0; 32])
    );
    assert_eq!(
        server.finish(wrong_proof.as_bytes(), b"actual"),
        Err(ServerError::InvalidProof)
    );
    Ok(())
}

#[test]
fn credential_recheck_rejects_rotation() -> TestResult {
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce", true)
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    let (server, _) = first
        .start(verifier, "server")
        .map_err(|error| format!("cannot start: {error:?}"))?;
    let unchanged = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let rotated = ScramVerifier::derive(
        ScramHash::Sha256,
        "different",
        [8; 16],
        ScramIterations::new(4096)?,
    )?;
    assert!(server.credential_is_current(&unchanged));
    assert!(!server.credential_is_current(&rotated));
    Ok(())
}

#[test]
fn decoy_verifier_is_stable_per_account() -> TestResult {
    let decoy = ScramDecoy::new().map_err(|error| format!("no randomness: {error:?}"))?;
    let a = decoy
        .verifier(ScramHash::Sha1, "alice@example.com")
        .map_err(|error| format!("no decoy: {error:?}"))?;
    let b = decoy
        .verifier(ScramHash::Sha1, "alice@example.com")
        .map_err(|error| format!("no decoy: {error:?}"))?;
    let c = decoy
        .verifier(ScramHash::Sha1, "bob@example.com")
        .map_err(|error| format!("no decoy: {error:?}"))?;
    let ScramVerifier::Sha1(a) = a else {
        return Err("wrong hash".into());
    };
    let ScramVerifier::Sha1(b) = b else {
        return Err("wrong hash".into());
    };
    let ScramVerifier::Sha1(c) = c else {
        return Err("wrong hash".into());
    };
    assert_eq!(a.salt(), b.salt());
    assert_ne!(a.salt(), c.salt());
    Ok(())
}

#[test]
fn malformed_first_messages_are_rejected() {
    for input in [
        "n,,n=user",
        "n,,n=user,r=",
        "n,,n=user,r=bad,nonce",
        "n,,n=user,r=nonce,m=required",
        "n,,n=user,r=nonce,n=other",
        "n,,n=user,r=nonce,x=",
        "n,,n=user,r=nonce,x=a\0",
        "n,,n=user,r=nonce,x=a,b",
        "n,,n=bad=XX,r=nonce",
    ] {
        assert_eq!(
            ClientFirst::parse(Mechanism::Sha256, input.as_bytes(), true).map(|_| ()),
            Err(ServerError::Malformed),
            "{input:?}"
        );
    }
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha256, b"p=tls-exporter,,n=user,r=nonce", true).map(|_| ()),
        Err(ServerError::UnsupportedBinding)
    );
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha256Plus, b"n,,n=user,r=nonce", true).map(|_| ()),
        Err(ServerError::Malformed)
    );
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce,x=\xff", true).map(|_| ()),
        Err(ServerError::Malformed)
    );
}

#[test]
fn first_message_accepts_4096_bytes_and_rejects_4097_bytes() -> TestResult {
    let prefix = "n,,n=user,r=nonce,x=";
    let mut input = format!("{prefix}{}", "a".repeat(4_096 - prefix.len()));
    assert_eq!(input.len(), 4_096);
    let first = ClientFirst::parse(Mechanism::Sha256, input.as_bytes(), true)
        .map_err(|error| format!("invalid maximum-length client first: {error:?}"))?;
    assert_eq!(first.username(), "user");
    assert_eq!(first.authzid(), None);
    input.push('a');
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha256, input.as_bytes(), true).map(|_| ()),
        Err(ServerError::Malformed)
    );
    Ok(())
}

#[test]
fn final_message_accepts_4096_bytes_and_rejects_4097_bytes() -> TestResult {
    let (server, challenge) = sha256_server(b"n,,n=user,r=nonce")?;
    let prefix = "c=biws,r=nonceserver,x=";
    let proof_suffix_len = ",p=".len() + 44;
    for (length, accepted) in [(4_096, true), (4_097, false)] {
        let without_proof = format!(
            "{prefix}{}",
            "a".repeat(length - prefix.len() - proof_suffix_len)
        );
        let (input, signature) = sha256_client_final("n=user,r=nonce", &challenge, &without_proof)?;
        assert_eq!(input.len(), length);
        let expected = if accepted {
            Ok(signature)
        } else {
            Err(ServerError::Malformed)
        };
        assert_eq!(
            server.finish(input.as_bytes(), &[]),
            expected,
            "{length} bytes"
        );
    }
    Ok(())
}

#[test]
fn channel_binding_flag_depends_on_listener_offer() -> TestResult {
    let input = b"y,,n=user,r=nonce";
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha256, input, true).map(|_| ()),
        Err(ServerError::ChannelBindingMismatch)
    );
    let first = ClientFirst::parse(Mechanism::Sha256, input, false)
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    assert_eq!(first.binding(), None);
    Ok(())
}

#[test]
fn mechanism_names_match_protocol_literals() {
    for (mechanism, name, hash, plus) in [
        (Mechanism::Sha1, "SCRAM-SHA-1", ScramHash::Sha1, false),
        (
            Mechanism::Sha1Plus,
            "SCRAM-SHA-1-PLUS",
            ScramHash::Sha1,
            true,
        ),
        (Mechanism::Sha256, "SCRAM-SHA-256", ScramHash::Sha256, false),
        (
            Mechanism::Sha256Plus,
            "SCRAM-SHA-256-PLUS",
            ScramHash::Sha256,
            true,
        ),
    ] {
        assert_eq!(mechanism.name(), name);
        assert_eq!(Mechanism::from_name(name), Some(mechanism));
        assert_eq!(mechanism.hash(), hash);
        assert_eq!(mechanism.is_plus(), plus);
    }
    for name in [
        "",
        "scram-sha-256",
        "SCRAM-SHA-256 ",
        "SCRAM-SHA-512",
        "PLAIN",
    ] {
        assert_eq!(Mechanism::from_name(name), None, "{name:?}");
    }
}

#[test]
fn malformed_final_extensions_are_rejected() -> TestResult {
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce", true)
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    let (server, _) = first
        .start(verifier, "server")
        .map_err(|error| format!("cannot start: {error:?}"))?;
    let proof = STANDARD.encode([0; 32]);
    for extension in ["x=", "x=a\0", "x=a,b", "m=required", "n=other"] {
        let input = format!("c=biws,r=nonceserver,{extension},p={proof}");
        assert_eq!(
            server.finish(input.as_bytes(), &[]),
            Err(ServerError::Malformed),
            "{extension:?}"
        );
    }
    let mut invalid_utf8 = b"c=biws,r=nonceserver,x=".to_vec();
    invalid_utf8.push(0xff);
    invalid_utf8.extend_from_slice(format!(",p={proof}").as_bytes());
    assert_eq!(
        server.finish(&invalid_utf8, &[]),
        Err(ServerError::Malformed)
    );
    Ok(())
}

#[test]
fn verifier_hash_must_match_selected_mechanism() -> TestResult {
    for (mechanism, hash) in [
        (Mechanism::Sha1, ScramHash::Sha256),
        (Mechanism::Sha256, ScramHash::Sha1),
    ] {
        let first = ClientFirst::parse(mechanism, b"n,,n=user,r=nonce", true)
            .map_err(|error| format!("invalid client first: {error:?}"))?;
        let verifier = ScramVerifier::derive(hash, "pencil", [7; 16], ScramIterations::new(4096)?)?;
        assert_eq!(
            first.start(verifier, "server").map(|_| ()),
            Err(ServerError::HashMismatch),
            "{mechanism:?}"
        );
    }
    Ok(())
}

#[test]
fn malformed_server_nonces_are_rejected() -> TestResult {
    for nonce in ["", "with space", "with,comma", "with\0nul", "non-ascii-é"] {
        let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce", true)
            .map_err(|error| format!("invalid client first: {error:?}"))?;
        let verifier = ScramVerifier::derive(
            ScramHash::Sha256,
            "pencil",
            [7; 16],
            ScramIterations::new(4096)?,
        )?;
        assert_eq!(
            first.start(verifier, nonce).map(|_| ()),
            Err(ServerError::Malformed),
            "{nonce:?}"
        );
    }
    Ok(())
}

#[test]
fn final_nonce_must_match_the_combined_challenge_nonce() -> TestResult {
    let (server, challenge) = sha256_server(b"n,,n=user,r=nonce")?;
    for nonce in ["", "nonce", "server", "nonceserverextra", "other"] {
        let without_proof = format!("c=biws,r={nonce}");
        let (input, _) = sha256_client_final("n=user,r=nonce", &challenge, &without_proof)?;
        assert_eq!(
            server.finish(input.as_bytes(), &[]),
            Err(ServerError::Malformed),
            "{nonce:?}"
        );
    }
    Ok(())
}

#[test]
fn proof_length_must_match_the_selected_hash() -> TestResult {
    for (mechanism, hash, proof_len) in [
        (Mechanism::Sha1, ScramHash::Sha1, 20),
        (Mechanism::Sha256, ScramHash::Sha256, 32),
    ] {
        let first = ClientFirst::parse(mechanism, b"n,,n=user,r=nonce", true)
            .map_err(|error| format!("invalid client first: {error:?}"))?;
        let verifier = ScramVerifier::derive(hash, "pencil", [7; 16], ScramIterations::new(4096)?)?;
        let (server, _) = first
            .start(verifier, "server")
            .map_err(|error| format!("cannot start: {error:?}"))?;
        for length in [0, proof_len - 1, proof_len + 1] {
            let input = format!(
                "c=biws,r=nonceserver,p={}",
                STANDARD.encode(&[0; 33][..length])
            );
            assert_eq!(
                server.finish(input.as_bytes(), &[]),
                Err(ServerError::Malformed),
                "{mechanism:?}, {length} proof bytes"
            );
        }
        let input = format!(
            "c=biws,r=nonceserver,p={}",
            STANDARD.encode(&[0; 32][..proof_len])
        );
        assert_eq!(
            server.finish(input.as_bytes(), &[]),
            Err(ServerError::InvalidProof),
            "{mechanism:?}, correctly sized invalid proof"
        );
    }
    Ok(())
}

fn sha256_server(first_message: &[u8]) -> Result<(ScramServer, String), Box<dyn Error>> {
    let first = ClientFirst::parse(Mechanism::Sha256, first_message, true)
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    first
        .start(verifier, "server")
        .map_err(|error| format!("cannot start: {error:?}").into())
}

fn sha256_client_final(
    first_bare: &str,
    challenge: &str,
    without_proof: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let auth_message = format!("{first_bare},{challenge},{without_proof}");
    let mut salted = [0; 32];
    pbkdf2_hmac::<Sha256>(b"pencil", &[7; 16], 4096, &mut salted);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&salted)?;
    mac.update(b"Client Key");
    let client_key = mac.finalize().into_bytes();
    let stored_key = Sha256::digest(client_key);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&stored_key)?;
    mac.update(auth_message.as_bytes());
    let signature = mac.finalize().into_bytes();
    let mut proof = [0; 32];
    for (output, (key, signature)) in proof
        .iter_mut()
        .zip(client_key.iter().zip(signature.iter()))
    {
        *output = key ^ signature;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&salted)?;
    mac.update(b"Server Key");
    let server_key = mac.finalize().into_bytes();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&server_key)?;
    mac.update(auth_message.as_bytes());
    Ok((
        format!("{without_proof},p={}", STANDARD.encode(proof)),
        format!("v={}", STANDARD.encode(mac.finalize().into_bytes())),
    ))
}
