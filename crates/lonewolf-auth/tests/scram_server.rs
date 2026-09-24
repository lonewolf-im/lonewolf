// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lonewolf_auth::scram::{ScramHash, ScramIterations, ScramVerifier};
use lonewolf_auth::server::{ClientFirst, Mechanism, ScramDecoy, ServerError};

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
    let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
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
fn incorrect_proof_and_channel_binding_fail() -> TestResult {
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let first = ClientFirst::parse(Mechanism::Sha256Plus, b"p=tls-exporter,,n=user,r=nonce")
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
    let first = ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce")
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
        "n,,n=bad=XX,r=nonce",
        "y,,n=user,r=nonce",
    ] {
        assert!(
            ClientFirst::parse(Mechanism::Sha256, input.as_bytes()).is_err(),
            "{input}"
        );
    }
    assert!(ClientFirst::parse(Mechanism::Sha256, b"p=tls-exporter,,n=user,r=nonce").is_err());
    assert!(ClientFirst::parse(Mechanism::Sha256Plus, b"n,,n=user,r=nonce").is_err());
    assert!(ClientFirst::parse(Mechanism::Sha256, &[b'a'; 4_097]).is_err());
}
