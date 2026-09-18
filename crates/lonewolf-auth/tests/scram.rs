// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroU32;

use lonewolf_auth::scram::{
    ScramCredentials, ScramHash, ScramSha1Verifier, ScramSha256Verifier, ScramVerifier,
};

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
