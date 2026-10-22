// SPDX-License-Identifier: Apache-2.0

use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use x509_cert::der::{Decode, Encode};

#[test]
fn generator_jwk_thumbprint_and_rfc4231_hmac() {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let secret = p256::SecretKey::from_slice(&scalar).unwrap();
    let der = secret.to_pkcs8_der().unwrap();
    let key = crypto_provider()
        .key_provider
        .load_key(PrivatePkcs8KeyDer::from(der.as_bytes().to_vec()))
        .unwrap();
    let jwk = key.as_jwk();
    let value = serde_json::to_value(&jwk).unwrap();
    assert_eq!(value["x"], "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY");
    assert_eq!(value["y"], "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU");
    let canonical = serde_json::to_vec(&jwk.key).unwrap();
    assert_eq!(canonical, br#"{"crv":"P-256","kty":"EC","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(crypto_provider().sha256.hash(&canonical)),
        "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
    );
    let hmac = crypto_provider().hmac.load_key(&[0x0b; 20]);
    assert_eq!(
        hmac.sign(b"Hi There"),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    assert!(matches!(hmac.algorithm(), SigningAlgorithm::Hs256));
    assert_eq!(
        crypto_provider().sha256.hash(b"abc").as_slice(),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn account_keys_roundtrip_and_verify_with_independent_rustcrypto() {
    let (key, der) = crypto_provider().key_provider.generate_key().unwrap();
    let loaded = crypto_provider()
        .key_provider
        .load_key(der.clone_key())
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&key.as_jwk()).unwrap(),
        serde_json::to_vec(&loaded.as_jwk()).unwrap()
    );
    let secret = p256::SecretKey::from_pkcs8_der(der.secret_pkcs8_der()).unwrap();
    let verifier = VerifyingKey::from(secret.public_key());
    for signer in [key, loaded] {
        assert!(matches!(signer.algorithm(), SigningAlgorithm::Es256));
        let signature = signer.sign(b"independent ES256 check").unwrap();
        assert_eq!(signature.len(), 64);
        verifier
            .verify(
                b"independent ES256 check",
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        assert!(
            verifier
                .verify(
                    b"wrong message",
                    &Signature::from_slice(&signature).unwrap()
                )
                .is_err()
        );
    }
    assert!(
        crypto_provider()
            .key_provider
            .load_key(PrivatePkcs8KeyDer::from(vec![0; 64]))
            .is_err()
    );
    let wrong = SigningKey::<graviola::signing::ecdsa::P384> {
        private_key: graviola::key_agreement::p384::StaticPrivateKey::new_random().unwrap(),
    };
    let mut buffer = Zeroizing::new([0; 512]);
    let wrong = wrong.to_pkcs8_der(&mut buffer[..]).unwrap();
    assert!(
        crypto_provider()
            .key_provider
            .load_key(PrivatePkcs8KeyDer::from(wrong.to_vec()))
            .is_err()
    );
    let mut wrong_curve = der.secret_pkcs8_der().to_vec();
    let oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let index = wrong_curve
        .windows(oid.len())
        .position(|bytes| bytes == oid)
        .unwrap();
    wrong_curve[index + oid.len() - 1] = 8;
    assert!(
        crypto_provider()
            .key_provider
            .load_key(PrivatePkcs8KeyDer::from(wrong_curve))
            .is_err()
    );
}

#[test]
fn csr_has_one_dns_san_and_independent_signature_and_key() {
    let (account, _) = crypto_provider().key_provider.generate_key().unwrap();
    let (key, csr) = new_certificate_request("xmpp.example.com").unwrap();
    let csr = x509_cert::request::CertReq::from_der(&csr).unwrap();
    let secret = p256::SecretKey::from_pkcs8_der(&key).unwrap();
    let verifier = VerifyingKey::from(secret.public_key());
    assert_eq!(
        verifier.to_sec1_point(false).as_bytes(),
        csr.info.public_key.subject_public_key.as_bytes().unwrap()
    );
    verifier
        .verify(
            &csr.info.to_der().unwrap(),
            &Signature::from_der(csr.signature.as_bytes().unwrap()).unwrap(),
        )
        .unwrap();
    let attribute = csr.info.attributes.iter().next().unwrap();
    let extensions = x509_cert::request::ExtensionReq::from_der(
        &attribute.values.iter().next().unwrap().to_der().unwrap(),
    )
    .unwrap();
    let san = extensions
        .0
        .iter()
        .find(|extension| extension.extn_id.to_string() == "2.5.29.17")
        .unwrap();
    let names = x509_cert::ext::pkix::SubjectAltName::from_der(san.extn_value.as_bytes()).unwrap();
    assert_eq!(names.0.len(), 1);
    assert!(
        matches!(&names.0[0], x509_cert::ext::pkix::name::GeneralName::DnsName(name) if name.as_str() == "xmpp.example.com")
    );
    let certificate_key = crypto_provider()
        .key_provider
        .load_key(PrivatePkcs8KeyDer::from(key.to_vec()))
        .unwrap();
    assert_ne!(
        serde_json::to_vec(&account.as_jwk()).unwrap(),
        serde_json::to_vec(&certificate_key.as_jwk()).unwrap()
    );
    for invalid in ["*.example.com", "127.0.0.1", "", "bad name"] {
        assert!(new_certificate_request(invalid).is_err());
    }
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
