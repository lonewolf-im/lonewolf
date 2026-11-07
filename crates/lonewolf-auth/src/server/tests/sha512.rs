// SPDX-License-Identifier: Apache-2.0

use super::*;
use sha2::Sha512;

#[test]
fn sha512_matches_independently_generated_exchange() -> TestResult {
    // Fixture provenance: https://github.com/lonewolf-im/lonewolf/issues/708.
    let salt = STANDARD
        .decode("W22ZaJ0SNY7soEsUEjb6gQ==")?
        .try_into()
        .map_err(|_| "invalid salt")?;
    let verifier = ScramVerifier::derive(
        ScramHash::Sha512,
        "pencil",
        salt,
        ScramIterations::new(100_000)?,
    )?;
    let ScramVerifier::Sha512(keys) = &verifier else {
        return Err("wrong hash".into());
    };
    assert_eq!(
        STANDARD.encode(keys.stored_key()),
        "QDhQjOg5u4BDQcZldAEaGkJf9W5wCTj5QKybkhejOrFuQ5Msgj/+q9zujJSft5U4ub0SvsPl9nEm6r1YiDdjYQ=="
    );
    assert_eq!(
        STANDARD.encode(keys.server_key()),
        "TlGBh6KrVRHF+QOiGxm4odxDcriMuG2pgDY/FebWjY1agGk6qUQMFjL5Aj6jtZbFRdaRxQ9ncz8qlGBsbTXy4Q=="
    );
    let first = ClientFirst::parse(Mechanism::Sha512, b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO", true)
        .map_err(|e| format!("{e:?}"))?;
    let (server, challenge) = first
        .start(verifier, "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        challenge,
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=100000"
    );
    let response = server.finish(b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=Gp/stGqGAAIOcUO3wf4QyWwbi0dGSOHf5kxtNmHNaJiWoSSF58bxM37XDtpVOQA6A7KLVpm7WZOA/hsrJ1dI4w==", &[]);
    assert_eq!(response, Ok("v=oUXTlNe3S4/fneEH2KfX5croWGoSyn/eKEJEYJiQza6HYqWhfNF4xb2T3ALbNYCU54z21i8BFFrudyCsGRBWcg==".into()));
    Ok(())
}

fn server(mechanism: Mechanism, input: &[u8]) -> Result<(ScramServer, String), Box<dyn Error>> {
    let first = ClientFirst::parse(mechanism, input, true).map_err(|e| format!("{e:?}"))?;
    first
        .start(
            ScramVerifier::derive(
                ScramHash::Sha512,
                "pencil",
                [7; 16],
                ScramIterations::new(10_000)?,
            )?,
            "server",
        )
        .map_err(|e| format!("{e:?}").into())
}

fn final_message(
    first: &str,
    challenge: &str,
    final_bare: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let mut salted = [0; 64];
    pbkdf2_hmac::<Sha512>(b"pencil", &[7; 16], 10_000, &mut salted);
    let mac = |key: &[u8], input: &[u8]| -> Result<[u8; 64], Box<dyn Error>> {
        let mut hmac = <Hmac<Sha512> as KeyInit>::new_from_slice(key)?;
        hmac.update(input);
        Ok(hmac.finalize().into_bytes().into())
    };
    let client_key = mac(&salted, b"Client Key")?;
    let auth = format!("{first},{challenge},{final_bare}");
    let signature = mac(&Sha512::digest(client_key), auth.as_bytes())?;
    let mut proof = client_key;
    for (out, signature) in proof.iter_mut().zip(signature) {
        *out ^= signature;
    }
    let server_signature = mac(&mac(&salted, b"Server Key")?, auth.as_bytes())?;
    Ok((
        format!("{final_bare},p={}", STANDARD.encode(proof)),
        format!("v={}", STANDARD.encode(server_signature)),
    ))
}

#[test]
fn sha512_plus_authenticates_bindings_and_rejects_mismatch() -> TestResult {
    for binding in ["tls-exporter", "tls-server-end-point"] {
        let header = format!("p={binding},,");
        let (server, challenge) = server(
            Mechanism::Sha512Plus,
            format!("{header}n=user,r=nonce").as_bytes(),
        )?;
        let channel = STANDARD.encode(format!("{header}actual"));
        let (message, signature) = final_message(
            "n=user,r=nonce",
            &challenge,
            &format!("c={channel},r=nonceserver"),
        )?;
        assert_eq!(server.finish(message.as_bytes(), b"actual"), Ok(signature));
        assert_eq!(
            server.finish(message.as_bytes(), b"wrong"),
            Err(ServerError::ChannelBindingMismatch)
        );
    }
    for (mechanism, input, expected) in [
        (
            Mechanism::Sha512,
            "y,,n=user,r=nonce",
            ServerError::ChannelBindingMismatch,
        ),
        (
            Mechanism::Sha512,
            "p=tls-exporter,,n=user,r=nonce",
            ServerError::UnsupportedBinding,
        ),
        (
            Mechanism::Sha512Plus,
            "n,,n=user,r=nonce",
            ServerError::Malformed,
        ),
        (
            Mechanism::Sha512Plus,
            "p=tls-unique,,n=user,r=nonce",
            ServerError::UnsupportedBinding,
        ),
    ] {
        assert_eq!(
            ClientFirst::parse(mechanism, input.as_bytes(), true).map(|_| ()),
            Err(expected)
        );
    }
    assert!(ClientFirst::parse(Mechanism::Sha512, b"y,,n=user,r=nonce", false).is_ok());
    Ok(())
}

#[test]
fn sha512_authenticates_transcript_extensions_and_enforces_message_bounds() -> TestResult {
    let first_bare = "n=user,r=nonce,x=original";
    let (server, challenge) = server(Mechanism::Sha512, format!("n,,{first_bare}").as_bytes())?;
    let final_bare = "c=biws,r=nonceserver,x=original";
    let (message, signature) = final_message(first_bare, &challenge, final_bare)?;
    assert_eq!(server.finish(message.as_bytes(), &[]), Ok(signature));
    assert_eq!(
        server.finish(message.replacen("original", "tampered", 1).as_bytes(), &[]),
        Err(ServerError::InvalidProof)
    );
    let (message, _) = final_message("n=user,r=nonce,x=tampered", &challenge, final_bare)?;
    assert_eq!(
        server.finish(message.as_bytes(), &[]),
        Err(ServerError::InvalidProof)
    );
    for malformed in [
        "c=biws,r=nonceserver,p=!",
        "c=!,r=nonceserver,p=AAAA",
        "c=biws,r=nonceserver,p=AAAA,p=AAAA",
        "c=biws,r=nonceserver,x=,p=AAAA",
        "c=biws,r=nonceserver,m=required,p=AAAA",
        "c=biws,r=nonceserver",
    ] {
        assert_eq!(
            server.finish(malformed.as_bytes(), &[]),
            Err(ServerError::Malformed)
        );
    }
    for length in [20, 32, 63, 65] {
        let message = format!("{final_bare},p={}", STANDARD.encode(&[0; 65][..length]));
        assert_eq!(
            server.finish(message.as_bytes(), &[]),
            Err(ServerError::Malformed)
        );
    }
    let (message, _) = final_message(first_bare, &challenge, "c=biws,r=wrong")?;
    assert_eq!(
        server.finish(message.as_bytes(), &[]),
        Err(ServerError::Malformed)
    );
    let prefix = "c=biws,r=nonceserver,x=";
    let final_bare = format!("{prefix}{}", "a".repeat(4096 - prefix.len() - 3 - 88));
    let (mut message, signature) = final_message(first_bare, &challenge, &final_bare)?;
    assert_eq!(message.len(), 4096);
    assert_eq!(server.finish(message.as_bytes(), &[]), Ok(signature));
    message.push('a');
    assert_eq!(
        server.finish(message.as_bytes(), &[]),
        Err(ServerError::Malformed)
    );
    let prefix = "n,,n=user,r=nonce,x=";
    let mut first = format!("{prefix}{}", "a".repeat(4096 - prefix.len()));
    assert!(ClientFirst::parse(Mechanism::Sha512, first.as_bytes(), true).is_ok());
    first.push('a');
    assert_eq!(
        ClientFirst::parse(Mechanism::Sha512, first.as_bytes(), true).map(|_| ()),
        Err(ServerError::Malformed)
    );
    for input in [
        "n,,n=user,r=nonce,m=required",
        "n,,n=user,r=nonce,x=",
        "n,,n=user,r=nonce,n=other",
    ] {
        assert_eq!(
            ClientFirst::parse(Mechanism::Sha512, input.as_bytes(), true).map(|_| ()),
            Err(ServerError::Malformed)
        );
    }
    for (salt, password, current) in [
        ([7; 16], "pencil", true),
        ([8; 16], "pencil", false),
        ([7; 16], "changed", false),
    ] {
        let verifier = ScramVerifier::derive(
            ScramHash::Sha512,
            password,
            salt,
            ScramIterations::new(10_000)?,
        )?;
        assert_eq!(server.credential_is_current(&verifier), current);
    }
    Ok(())
}

#[test]
fn sha512_decoys_are_stable_and_separate_every_input() -> TestResult {
    let decoy = ScramDecoy::from_secret([0; 32]);
    let derive = |decoy: &ScramDecoy, account| -> Result<_, Box<dyn Error>> {
        let ScramVerifier::Sha512(verifier) = decoy
            .verifier(ScramHash::Sha512, account)
            .map_err(|e| format!("{e:?}"))?
        else {
            return Err("wrong hash".into());
        };
        Ok(verifier)
    };
    for (hash, salt, stored, server) in [
        (
            ScramHash::Sha1,
            "tXEAVTRmM16Vn+V7d39eNA==",
            "C0Arn1vzd2HGrQ2ZiPXt9cb1kyc=",
            "QbVdiiNLp0kG++TPoa7ra3QUJlk=",
        ),
        (
            ScramHash::Sha256,
            "SC5gpL4+N+urXs552KXUPw==",
            "m1i6/+OoEa4+tm9x6QhDf2w5Yj4IwZLL29R5vEjDYw4=",
            "W6O5E6ycNwBbPArNLFuyE3rDHEOSyFgVnnUSceyJkeg=",
        ),
        (
            ScramHash::Sha512,
            "evkm1/1xvgo/jKTedfIt6A==",
            "l8lTPUOzHwqO/E39lc+ygPDpC0qqFwAGthAnDr3+7AQgp6ZA1ffcsIlpUFIQT0KrilmneWf55tOMYYS2AUl82A==",
            "V2VZiTwF0BNFHGcxXD1sGDDh5c7H/GmZj8JWZbDm+CsULbprK8oEXfuXyzJK9FDItVhmM0bgPSGbmcYRS8nO3A==",
        ),
    ] {
        let verifier = decoy
            .verifier(hash, "alice@example.com")
            .map_err(|e| format!("{e:?}"))?;
        let (actual_salt, actual_stored, actual_server): (&[u8], &[u8], &[u8]) = match &verifier {
            ScramVerifier::Sha1(v) => (v.salt(), v.stored_key(), v.server_key()),
            ScramVerifier::Sha256(v) => (v.salt(), v.stored_key(), v.server_key()),
            ScramVerifier::Sha512(v) => (v.salt(), v.stored_key(), v.server_key()),
        };
        assert_eq!(STANDARD.encode(actual_salt), salt);
        assert_eq!(STANDARD.encode(actual_stored), stored);
        assert_eq!(STANDARD.encode(actual_server), server);
    }
    let actual = derive(&decoy, "alice@example.com")?;
    let repeated = derive(&decoy, "alice@example.com")?;
    assert_eq!(actual.salt(), repeated.salt());
    assert_eq!(actual.stored_key(), repeated.stored_key());
    assert_eq!(actual.server_key(), repeated.server_key());
    for other in [
        derive(&decoy, "bob@example.com")?,
        derive(&ScramDecoy::from_secret([1; 32]), "alice@example.com")?,
    ] {
        assert_ne!(actual.salt(), other.salt());
        assert_ne!(actual.stored_key(), other.stored_key());
        assert_ne!(actual.server_key(), other.server_key());
    }
    assert_eq!(actual.iterations().get(), 100_000);
    assert_ne!(actual.stored_key(), actual.server_key());
    assert_ne!(&actual.stored_key()[..32], &actual.stored_key()[32..]);
    assert_ne!(&actual.server_key()[..32], &actual.server_key()[32..]);
    for hash in [ScramHash::Sha1, ScramHash::Sha256] {
        let verifier = decoy
            .verifier(hash, "alice@example.com")
            .map_err(|e| format!("{e:?}"))?;
        let (salt, key): (&[u8], &[u8]) = match &verifier {
            ScramVerifier::Sha1(v) => (v.salt(), v.stored_key()),
            ScramVerifier::Sha256(v) => (v.salt(), v.stored_key()),
            ScramVerifier::Sha512(_) => return Err("wrong hash".into()),
        };
        assert_ne!(actual.salt(), salt);
        assert_ne!(&actual.stored_key()[..key.len()], key);
    }
    Ok(())
}
