// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use lonewolf_auth::scram::{ScramHash, ScramIterations, ScramVerifier};
use lonewolf_auth::server::{ClientFirst, Mechanism, ScramDecoy, ServerError};
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
fn optional_extensions_are_authenticated() -> TestResult {
    let extension = "x=é=\u{1}\t\u{7f},z=漢";
    let first_bare = format!("n=user,r=nonce,{extension}");
    let first_message = format!("n,,{first_bare}");
    let first = ClientFirst::parse(Mechanism::Sha256, first_message.as_bytes())
        .map_err(|error| format!("invalid client first: {error:?}"))?;
    let verifier = ScramVerifier::derive(
        ScramHash::Sha256,
        "pencil",
        [7; 16],
        ScramIterations::new(4096)?,
    )?;
    let (server, challenge) = first
        .start(verifier, "server")
        .map_err(|error| format!("cannot start: {error:?}"))?;
    let without_proof = format!("c=biws,r=nonceserver,{extension}");
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
    let final_message = format!("{without_proof},p={}", STANDARD.encode(proof));
    assert!(server.finish(final_message.as_bytes(), &[]).is_ok());
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
        "n,,n=user,r=nonce,x=",
        "n,,n=user,r=nonce,x=a\0",
        "n,,n=user,r=nonce,x=a,b",
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
    assert!(ClientFirst::parse(Mechanism::Sha256, b"n,,n=user,r=nonce,x=\xff").is_err());
}

#[test]
fn malformed_final_extensions_are_rejected() -> TestResult {
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
