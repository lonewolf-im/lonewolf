// SPDX-License-Identifier: Apache-2.0

//! Storage contract tests, written once over the storage traits and run by each backend.

pub(crate) mod account;
pub(crate) mod roster;
pub(crate) mod transaction;

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramVerifier, ScramVerifierData,
};
use lonewolf_auth::server::ScramDecoy;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use crate::account::{AccountKey, NewAccount};
use crate::roster::{PendingSubscription, RosterItemUpdate, RosterJid};
use crate::{Storage, StorageError, StorageErrorKind, WriteTransaction};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn key(input: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

pub(crate) fn jid(input: &str) -> TestResult<RosterJid> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(input, &mut arena)?;
    Ok(RosterJid::from(jid.resolve(&arena)?))
}

pub(crate) fn verifier<const N: usize>(marker: u8) -> ScramVerifierData<N> {
    ScramVerifierData::new(
        [marker; 16],
        SCRAM_POLICY_ITERATIONS,
        [marker + 1; N],
        [marker + 2; N],
    )
}

pub(crate) fn credentials(marker: u8) -> ScramCredentials {
    ScramCredentials::both(verifier(marker), verifier(marker + 3))
}

pub(crate) fn new_account(input: &str, marker: u8) -> TestResult<NewAccount> {
    Ok(NewAccount {
        key: key(input)?,
        credentials: credentials(marker),
    })
}

pub(crate) fn item(
    contact: &str,
    name: Option<&str>,
    groups: &[&str],
) -> TestResult<RosterItemUpdate> {
    Ok(RosterItemUpdate {
        jid: jid(contact)?,
        name: name.map(Box::from),
        groups: groups.iter().copied().map(Box::from).collect(),
    })
}

pub(crate) fn pending(sender: &str, stanza: &[u8]) -> TestResult<PendingSubscription> {
    Ok(PendingSubscription {
        sender: jid(sender)?,
        stanza: Box::from(stanza),
    })
}

pub(crate) fn assert_verifier<const N: usize>(actual: &ScramVerifierData<N>, marker: u8) {
    assert_eq!(actual.salt(), &[marker; 16]);
    assert_eq!(actual.iterations(), SCRAM_POLICY_ITERATIONS);
    assert_eq!(actual.stored_key(), &[marker + 1; N]);
    assert_eq!(actual.server_key(), &[marker + 2; N]);
}

pub(crate) fn assert_scram(actual: Option<ScramVerifier>, marker: u8) -> TestResult {
    match actual.ok_or("missing verifier")? {
        ScramVerifier::Sha1(value) => assert_verifier(&value, marker),
        ScramVerifier::Sha256(value) => assert_verifier(&value, marker),
    }
    Ok(())
}

/// Finds the storage error anywhere in the source chain of `result`'s error.
pub(crate) fn assert_storage_error<T, E: Into<Box<dyn Error>>>(
    result: Result<T, E>,
    expected: StorageErrorKind,
) {
    let Err(error) = result else {
        panic!("expected a {expected:?} storage error");
    };
    let error: Box<dyn Error> = error.into();
    let mut current: &(dyn Error + 'static) = error.as_ref();
    loop {
        if let Some(storage) = current.downcast_ref::<StorageError>() {
            assert_eq!(storage.kind(), expected);
            return;
        }
        current = current
            .source()
            .unwrap_or_else(|| panic!("expected a {expected:?} storage error"));
    }
}

pub(crate) fn decoy_salt(decoy: &ScramDecoy) -> TestResult<[u8; 16]> {
    let verifier = decoy
        .verifier(ScramHash::Sha256, "alice@example.com")
        .map_err(|error| format!("cannot build decoy: {error:?}"))?;
    match verifier {
        ScramVerifier::Sha256(verifier) => Ok(*verifier.salt()),
        ScramVerifier::Sha1(_) => Err("wrong hash".into()),
    }
}

pub(crate) fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

/// Runs `operation` in a new write transaction and commits it.
pub(crate) async fn write<S, T, E>(
    storage: &S,
    operation: impl AsyncFnOnce(&mut S::Write) -> Result<T, E>,
) -> TestResult<T>
where
    S: Storage,
    E: Into<Box<dyn Error>>,
{
    let mut transaction = storage.begin_write().await?;
    let value = operation(&mut transaction).await.map_err(Into::into)?;
    transaction.commit().await?;
    Ok(value)
}

pub(crate) async fn read<S, T, E>(
    storage: &S,
    operation: impl AsyncFnOnce(&S::Read) -> Result<T, E>,
) -> TestResult<T>
where
    S: Storage,
    E: Into<Box<dyn Error>>,
{
    let transaction = storage.begin_read().await?;
    operation(&transaction).await.map_err(Into::into)
}

/// Generates one `#[test]` per contract function, each over a store from `$storage()`.
macro_rules! storage_contract_tests {
    ($storage:path) => {
        $crate::tests::storage_contract_tests!(@generate $storage;
            account::created_account_exposes_every_verifier_field,
            account::absent_accounts_and_absent_hashes_return_none,
            account::non_policy_iterations_are_rejected_without_changing_accounts,
            account::normalized_duplicate_does_not_replace_existing_credentials,
            account::usernames_and_domains_are_independent_storage_keys,
            account::replacement_removes_omitted_hashes,
            account::replacement_does_not_create_an_account,
            account::deletion_removes_the_account_and_all_its_credentials,
            account::deleted_accounts_can_be_recreated_with_new_credentials,
            account::concurrent_creation_has_one_winner_without_overwriting_credentials,
            account::concurrent_deletion_has_one_successful_removal,
            account::accounts_after_returns_pages_in_canonical_key_order,
            account::accounts_after_returns_at_most_limit_accounts,
            account::accounts_after_returns_an_empty_page_for_empty_and_exhausted_stores,
            account::accounts_after_resumes_after_deleted_and_absent_cursor_keys,
            account::accounts_after_reads_the_snapshot_of_its_transaction,
            roster::new_roster_is_empty_at_version_zero,
            roster::upsert_stores_editable_fields_and_advances_version,
            roster::editable_and_subscription_updates_preserve_each_other,
            roster::remove_roster_item_returns_the_old_item_and_only_advances_an_existing_roster,
            roster::pending_request_is_deduplicated_by_sender_and_can_be_removed,
            roster::resolving_a_pending_request_removes_it_and_applies_the_transition,
            roster::subscription_request_updates_the_sender_and_recipient_in_one_transaction,
            roster::established_subscription_requests_are_automatically_approved_without_changes,
            roster::automatic_approval_resolves_an_outstanding_request,
            roster::denying_a_pending_request_clears_both_sides_without_changing_the_grantor_roster,
            roster::revoking_a_mutual_subscription_keeps_the_reverse_grant,
            roster::denying_a_crossed_request_keeps_the_reverse_subscription,
            roster::clearing_preapproval_does_not_notify_the_contact,
            roster::cancellation_clears_the_grantor_when_the_subscriber_is_missing,
            roster::self_subscription_cancellation_writes_one_final_roster_version,
            roster::unsubscribe_keeps_the_reverse_grant_and_does_not_advance_versions_twice,
            roster::unsubscribe_from_self_writes_one_roster_version,
            roster::unsubscribe_clears_a_stale_subscription_after_the_contact_is_deleted,
            roster::clear_roster_removes_one_owners_items_version_and_pending_requests,
            roster::rosters_are_isolated_by_owner_and_sorted_by_contact,
            roster::subscription_update_reads_and_changes_state_in_one_write,
            roster::item_removal_clears_the_contact_and_both_pending_requests,
            roster::item_removal_without_a_local_contact_changes_only_the_owner,
            roster::removing_a_missing_item_writes_nothing,
            transaction::uncommitted_writes_are_visible_only_inside_their_transaction,
            transaction::dropping_a_write_transaction_aborts_every_write,
            transaction::commit_persists_account_and_roster_writes_together,
            transaction::a_read_transaction_keeps_its_snapshot_across_commits,
            transaction::a_second_write_transaction_waits_for_the_first_while_reads_proceed,
            transaction::cancelling_a_waiting_write_transaction_does_not_block_later_writers,
            transaction::transactions_can_be_driven_from_other_threads,
            transaction::clones_share_committed_state_and_the_scram_decoy,
        );
    };
    (@generate $storage:path; $($module:ident :: $name:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() -> $crate::tests::TestResult {
                $crate::tests::$module::$name($storage()?)
            }
        )*
    };
}

pub(crate) use storage_contract_tests;
