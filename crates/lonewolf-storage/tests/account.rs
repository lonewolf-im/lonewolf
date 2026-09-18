// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::error::Error;
use std::num::NonZeroU32;

use lonewolf_auth::scram::{ScramCredentials, ScramSha1Verifier, ScramSha256Verifier};
use lonewolf_storage::account::{Account, AccountError, AccountKey, AccountKeyError, NewAccount};
use lonewolf_storage::{StorageError, StorageErrorKind};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

type TestResult = Result<(), Box<dyn Error>>;

fn key(input: &str) -> Result<AccountKey, Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn sha1() -> ScramSha1Verifier {
    ScramSha1Verifier::new([11; 16], NonZeroU32::MIN, [12; 20], [13; 20])
}

fn sha256() -> ScramSha256Verifier {
    ScramSha256Verifier::new([21; 16], NonZeroU32::MIN, [22; 32], [23; 32])
}

#[test]
fn equivalent_jids_produce_equal_account_keys_across_arenas() -> TestResult {
    let mut keys = HashSet::new();
    for input in [
        "É@BÜCHER.EXAMPLE",
        "E\u{301}@xn--bcher-kva.example",
        "é@bücher.example.",
    ] {
        let account = key(input)?;
        assert_eq!(account.username(), "é");
        assert_eq!(account.domain(), "bücher.example");
        assert_eq!(account.as_str(), "é@bücher.example");
        keys.insert(account);
    }
    assert_eq!(keys.len(), 1);
    Ok(())
}

#[test]
fn account_identity_includes_both_username_and_domain() -> TestResult {
    let alice = key("alice@example.com")?;
    assert_ne!(alice, key("bob@example.com")?);
    assert_ne!(alice, key("alice@example.org")?);
    Ok(())
}

#[test]
fn account_key_rejects_domain_only_and_resource_jids() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    for (input, expected) in [
        ("example.com", AccountKeyError::MissingUsername),
        (
            "alice@example.com/desktop",
            AccountKeyError::ResourceNotAllowed,
        ),
        ("example.com/service", AccountKeyError::ResourceNotAllowed),
    ] {
        let jid = Jid::parse_in(input, &mut arena)?;
        assert_eq!(AccountKey::try_from(jid.resolve(&arena)?), Err(expected));
    }
    Ok(())
}

#[test]
fn account_key_remains_valid_after_its_source_arena_is_dropped() -> TestResult {
    let account = key("ALICE@EXAMPLE.COM")?;
    assert_eq!(account.as_str(), "alice@example.com");
    assert_eq!(account.username(), "alice");
    assert_eq!(account.domain(), "example.com");
    Ok(())
}

#[test]
fn diagnostics_omit_account_identity_and_credential_material() -> TestResult {
    let account = NewAccount {
        key: key("alice@example.com")?,
        credentials: ScramCredentials::both(sha1(), sha256()),
    };
    assert_eq!(format!("{:?}", account.key), "AccountKey { .. }");
    assert_eq!(
        format!("{account:?}"),
        "NewAccount { key: AccountKey { .. }, credentials: ScramCredentials { sha1: Some(ScramVerifierData { .. }), sha256: Some(ScramVerifierData { .. }) } }"
    );
    let public = Account { key: account.key };
    assert_eq!(format!("{public:?}"), "Account { key: AccountKey { .. } }");
    Ok(())
}

#[test]
fn storage_errors_preserve_the_cause_without_formatting_it() -> TestResult {
    let detail = "backend error contains alice@example.com and secret material";
    let error: AccountError =
        StorageError::with_source(StorageErrorKind::Unavailable, std::io::Error::other(detail))
            .into();

    assert_eq!(
        error.to_string(),
        "account storage failed: storage unavailable"
    );
    assert_eq!(
        format!("{error:?}"),
        "Storage(StorageError { kind: Unavailable, .. })"
    );
    let storage = error.source().ok_or("missing storage error")?;
    let cause = storage.source().ok_or("missing backend error")?;
    assert_eq!(cause.to_string(), detail);
    Ok(())
}

#[test]
fn indeterminate_commit_is_distinct_from_unavailable_storage() {
    let error = StorageError::new(StorageErrorKind::CommitUnknown);
    assert_eq!(error.kind(), StorageErrorKind::CommitUnknown);
    assert_eq!(error.to_string(), "storage commit outcome is unknown");
    assert!(error.source().is_none());
}
