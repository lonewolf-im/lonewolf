// SPDX-License-Identifier: Apache-2.0

pub(crate) mod account;
pub(crate) mod offline;
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
use crate::roster::{PendingSubscription, RosterItem, RosterJid, RosterSubscription};
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

pub(crate) fn item(contact: &str, name: Option<&str>, groups: &[&str]) -> TestResult<RosterItem> {
    item_with_subscription(contact, name, groups, RosterSubscription::default())
}

pub(crate) fn item_with_subscription(
    contact: &str,
    name: Option<&str>,
    groups: &[&str],
    subscription: RosterSubscription,
) -> TestResult<RosterItem> {
    Ok(RosterItem {
        jid: jid(contact)?,
        name: name.map(Box::from),
        groups: groups.iter().copied().map(Box::from).collect(),
        subscription,
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
            roster::put_roster_item_stores_every_field_and_advances_the_version,
            roster::put_roster_item_replaces_the_item_for_the_same_jid_and_advances_again,
            roster::rosters_are_isolated_by_owner_and_sorted_by_contact,
            roster::roster_item_returns_exactly_the_stored_item_or_none,
            roster::remove_roster_item_returns_the_old_item_and_only_advances_an_existing_roster,
            roster::removing_a_missing_item_writes_nothing,
            roster::pending_requests_are_deduplicated_by_sender_and_returned_in_sender_order,
            roster::remove_pending_request_reports_existence_and_leaves_items_and_versions_untouched,
            roster::clear_roster_removes_one_owners_items_version_and_pending_requests,
            roster::put_roster_item_is_rejected_for_an_owner_without_an_account_record,
            roster::put_pending_request_is_rejected_for_an_owner_without_an_account_record,
            roster::roster_removals_and_clearing_succeed_for_a_deleted_owner,
            offline::offline_reads_of_an_empty_or_absent_account_return_no_messages,
            offline::offline_messages_keep_every_field_in_sequence_order,
            offline::removing_offline_messages_through_preserves_later_messages_and_the_counter,
            offline::removing_one_offline_message_preserves_other_messages_and_the_counter,
            offline::clearing_offline_messages_during_deletion_resets_a_recreated_accounts_counter,
            offline::offline_operations_isolate_accounts_with_shared_prefixes,
            offline::offline_push_for_an_absent_or_deleted_account_writes_nothing,
            offline::offline_removals_and_clear_succeed_without_messages,
            offline::dropping_offline_writes_preserves_messages_and_the_counter,
            offline::offline_reads_keep_their_snapshot_across_commits,
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
