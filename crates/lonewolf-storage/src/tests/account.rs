// SPDX-License-Identifier: Apache-2.0

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Barrier;
use std::thread;

use futures_executor::block_on;
use lonewolf_auth::scram::{ScramCredentials, ScramHash, ScramVerifier, ScramVerifierData};

use super::{TestResult, assert_scram, credentials, key, new_account, read, verifier, write};
use crate::account::{AccountError, AccountReads, AccountWrites, NewAccount};
use crate::{Storage, WriteTransaction};

const TWO: NonZeroUsize = const { NonZeroUsize::new(2).unwrap() };
const THREE: NonZeroUsize = const { NonZeroUsize::new(3).unwrap() };

pub(crate) fn created_account_exposes_every_verifier_field<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        write(&storage, async |tx| tx.create_account(account).await).await?;
        let reader = storage.begin_read().await?;
        assert_eq!(
            reader.account(&alice).await?.ok_or("missing account")?.key,
            alice
        );
        assert_scram(reader.scram(&alice, ScramHash::Sha1).await?, 10)?;
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 13)?;
        Ok(())
    })
}

pub(crate) fn absent_accounts_and_absent_hashes_return_none<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_none());
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            assert!(reader.scram(&alice, hash).await?.is_none());
        }
        drop(reader);

        for (present, absent) in [
            (ScramVerifier::Sha1(verifier(10)), ScramHash::Sha256),
            (ScramVerifier::Sha256(verifier(20)), ScramHash::Sha1),
        ] {
            let account = key(match absent {
                ScramHash::Sha1 => "sha256@example.com",
                ScramHash::Sha256 => "sha1@example.com",
            })?;
            let hash = present.hash();
            let new = NewAccount {
                key: account.clone(),
                credentials: ScramCredentials::new(present),
            };
            write(&storage, async |tx| tx.create_account(new).await).await?;
            let reader = storage.begin_read().await?;
            assert!(reader.account(&account).await?.is_some());
            assert!(reader.scram(&account, absent).await?.is_none());
            assert_eq!(
                reader
                    .scram(&account, hash)
                    .await?
                    .ok_or("missing verifier")?
                    .hash(),
                hash
            );
        }
        Ok(())
    })
}

pub(crate) fn non_policy_iterations_are_rejected_without_changing_accounts<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let legacy_sha256 = ScramVerifierData::new(
        [7; 16],
        NonZeroU32::MIN.saturating_add(4095),
        [8; 32],
        [9; 32],
    );
    let legacy_sha1 = ScramVerifierData::new(
        [7; 16],
        NonZeroU32::MIN.saturating_add(4095),
        [8; 20],
        [9; 20],
    );
    let legacy = ScramCredentials::new(ScramVerifier::Sha256(legacy_sha256.clone()));
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer
                .create_account(NewAccount {
                    key: alice.clone(),
                    credentials: legacy.clone(),
                })
                .await,
            Err(AccountError::UnsupportedIterations)
        ));
        assert!(writer.account(&alice).await?.is_none());
        writer.commit().await?;
        assert!(
            read(&storage, async |tx| tx.account(&alice).await)
                .await?
                .is_none()
        );

        write(&storage, async |tx| tx.create_account(account).await).await?;
        let mut writer = storage.begin_write().await?;
        for invalid in [
            legacy,
            ScramCredentials::new(ScramVerifier::Sha1(legacy_sha1)),
            ScramCredentials::both(verifier(10), legacy_sha256),
        ] {
            assert!(matches!(
                writer.replace_credentials(&alice, invalid).await,
                Err(AccountError::UnsupportedIterations)
            ));
        }
        assert_scram(writer.scram(&alice, ScramHash::Sha256).await?, 13)?;
        writer.commit().await?;
        assert_scram(
            read(&storage, async |tx| {
                tx.scram(&alice, ScramHash::Sha256).await
            })
            .await?,
            13,
        )?;
        Ok(())
    })
}

pub(crate) fn normalized_duplicate_does_not_replace_existing_credentials<S: Storage>(
    storage: S,
) -> TestResult {
    let original = new_account("É@BÜCHER.EXAMPLE", 10)?;
    let duplicate = new_account("E\u{301}@xn--bcher-kva.example", 20)?;
    let account = duplicate.key.clone();
    block_on(async {
        write(&storage, async |tx| tx.create_account(original).await).await?;
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer.create_account(duplicate).await,
            Err(AccountError::AlreadyExists)
        ));
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert_scram(reader.scram(&account, ScramHash::Sha1).await?, 10)?;
        assert_scram(reader.scram(&account, ScramHash::Sha256).await?, 13)?;
        Ok(())
    })
}

pub(crate) fn usernames_and_domains_are_independent_storage_keys<S: Storage>(
    storage: S,
) -> TestResult {
    let accounts = [
        ("alice@example.com", 10),
        ("bob@example.com", 20),
        ("alice@example.org", 30),
    ];
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for (input, marker) in accounts {
            writer.create_account(new_account(input, marker)?).await?;
        }
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        for (input, marker) in accounts {
            assert_scram(
                reader.scram(&key(input)?, ScramHash::Sha256).await?,
                marker + 3,
            )?;
        }
        Ok(())
    })
}

pub(crate) fn replacement_removes_omitted_hashes<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        write(&storage, async |tx| tx.create_account(account).await).await?;
        write(&storage, async |tx| {
            tx.replace_credentials(
                &alice,
                ScramCredentials::new(ScramVerifier::Sha256(verifier(20))),
            )
            .await
        })
        .await?;
        let reader = storage.begin_read().await?;
        assert!(reader.scram(&alice, ScramHash::Sha1).await?.is_none());
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 20)?;
        Ok(())
    })
}

pub(crate) fn replacement_does_not_create_an_account<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        assert!(matches!(
            writer.replace_credentials(&alice, credentials(10)).await,
            Err(AccountError::NotFound)
        ));
        writer.commit().await?;
        assert!(
            read(&storage, async |tx| tx.account(&alice).await)
                .await?
                .is_none()
        );
        Ok(())
    })
}

pub(crate) fn deletion_removes_the_account_and_all_its_credentials<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let other = key("alice@example.org")?;
    let normalized = key("ALICE@EXAMPLE.COM")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        writer
            .create_account(new_account("alice@example.com", 10)?)
            .await?;
        writer
            .create_account(new_account("alice@example.org", 10)?)
            .await?;
        writer.commit().await?;

        let mut writer = storage.begin_write().await?;
        writer.delete_account(&normalized).await?;
        assert!(matches!(
            writer.delete_account(&alice).await,
            Err(AccountError::NotFound)
        ));
        assert!(matches!(
            writer.replace_credentials(&alice, credentials(20)).await,
            Err(AccountError::NotFound)
        ));
        assert!(writer.account(&alice).await?.is_none());
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        assert!(reader.account(&alice).await?.is_none());
        for hash in [ScramHash::Sha1, ScramHash::Sha256] {
            assert!(reader.scram(&alice, hash).await?.is_none());
            assert!(reader.scram(&other, hash).await?.is_some());
        }
        Ok(())
    })
}

pub(crate) fn deleted_accounts_can_be_recreated_with_new_credentials<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    let recreated = new_account("alice@example.com", 20)?;
    block_on(async {
        write(&storage, async |tx| tx.create_account(account).await).await?;
        let mut writer = storage.begin_write().await?;
        writer.delete_account(&alice).await?;
        writer.create_account(recreated).await?;
        writer.commit().await?;
        let reader = storage.begin_read().await?;
        assert_scram(reader.scram(&alice, ScramHash::Sha1).await?, 20)?;
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, 23)?;
        Ok(())
    })
}

pub(crate) fn concurrent_creation_has_one_winner_without_overwriting_credentials<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let barrier = Barrier::new(2);
    let create = |marker: u8| -> Result<(), AccountError> {
        barrier.wait();
        block_on(async {
            let mut writer = storage.begin_write().await?;
            writer
                .create_account(NewAccount {
                    key: alice.clone(),
                    credentials: credentials(marker),
                })
                .await?;
            writer.commit().await?;
            Ok(())
        })
    };
    let (first, second) = thread::scope(|scope| {
        let first = scope.spawn(|| create(10));
        let second = create(20);
        (first.join(), second)
    });
    let first = first.map_err(|_| "account creation thread panicked")?;
    let marker = match (first, second) {
        (Ok(()), Err(AccountError::AlreadyExists)) => 10,
        (Err(AccountError::AlreadyExists), Ok(())) => 20,
        _ => return Err("expected exactly one successful create".into()),
    };
    block_on(async {
        let reader = storage.begin_read().await?;
        assert_scram(reader.scram(&alice, ScramHash::Sha1).await?, marker)?;
        assert_scram(reader.scram(&alice, ScramHash::Sha256).await?, marker + 3)?;
        Ok(())
    })
}

pub(crate) fn concurrent_deletion_has_one_successful_removal<S: Storage>(storage: S) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(write(&storage, async |tx| tx.create_account(account).await))?;
    let barrier = Barrier::new(2);
    let delete = || -> Result<(), AccountError> {
        barrier.wait();
        block_on(async {
            let mut writer = storage.begin_write().await?;
            writer.delete_account(&alice).await?;
            writer.commit().await?;
            Ok(())
        })
    };
    let (first, second) = thread::scope(|scope| {
        let first = scope.spawn(delete);
        let second = delete();
        (first.join(), second)
    });
    let first = first.map_err(|_| "account deletion thread panicked")?;
    assert!(matches!(
        (first, second),
        (Ok(()), Err(AccountError::NotFound)) | (Err(AccountError::NotFound), Ok(()))
    ));
    assert!(block_on(read(&storage, async |tx| tx.account(&alice).await))?.is_none());
    Ok(())
}

pub(crate) fn accounts_after_returns_pages_in_canonical_key_order<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for input in [
            "bob@example.com",
            "É@BÜCHER.EXAMPLE",
            "alice@example.org",
            "ALICE@EXAMPLE.COM",
        ] {
            writer.create_account(new_account(input, 10)?).await?;
        }
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let first = reader.accounts_after(None, THREE).await?;
        assert_eq!(first.len(), 3);
        assert_eq!(first[0].key, key("alice@example.com")?);
        assert_eq!(first[1].key, key("alice@example.org")?);
        assert_eq!(first[2].key, key("bob@example.com")?);
        let second = reader.accounts_after(Some(&first[1].key), THREE).await?;
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].key, first[2].key);
        assert_eq!(second[1].key, key("é@bücher.example")?);
        assert!(
            reader
                .accounts_after(Some(&second[1].key), THREE)
                .await?
                .is_empty()
        );
        Ok(())
    })
}

pub(crate) fn accounts_after_returns_at_most_limit_accounts<S: Storage>(storage: S) -> TestResult {
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for input in [
            "a@example.com",
            "b@example.com",
            "c@example.com",
            "d@example.com",
            "e@example.com",
        ] {
            writer.create_account(new_account(input, 10)?).await?;
        }
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let one = reader.accounts_after(None, NonZeroUsize::MIN).await?;
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].key, key("a@example.com")?);
        assert_eq!(reader.accounts_after(None, TWO).await?.len(), 2);
        assert_eq!(
            reader.accounts_after(None, NonZeroUsize::MAX).await?.len(),
            5
        );
        let middle = reader
            .accounts_after(Some(&key("b@example.com")?), TWO)
            .await?;
        assert_eq!(middle.len(), 2);
        assert_eq!(middle[0].key, key("c@example.com")?);
        assert_eq!(middle[1].key, key("d@example.com")?);
        assert_eq!(
            reader
                .accounts_after(Some(&key("d@example.com")?), TWO)
                .await?
                .len(),
            1
        );
        Ok(())
    })
}

pub(crate) fn accounts_after_returns_an_empty_page_for_empty_and_exhausted_stores<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let account = new_account("alice@example.com", 10)?;
    block_on(async {
        let reader = storage.begin_read().await?;
        assert!(
            reader
                .accounts_after(None, NonZeroUsize::MAX)
                .await?
                .is_empty()
        );
        assert!(
            reader
                .accounts_after(Some(&alice), NonZeroUsize::MAX)
                .await?
                .is_empty()
        );
        drop(reader);

        write(&storage, async |tx| tx.create_account(account).await).await?;
        let reader = storage.begin_read().await?;
        let page = reader.accounts_after(None, NonZeroUsize::MAX).await?;
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].key, alice);
        assert!(
            reader
                .accounts_after(Some(&alice), NonZeroUsize::MAX)
                .await?
                .is_empty()
        );
        Ok(())
    })
}

pub(crate) fn accounts_after_resumes_after_deleted_and_absent_cursor_keys<S: Storage>(
    storage: S,
) -> TestResult {
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for input in ["alice@example.com", "carol@example.com", "erin@example.com"] {
            writer.create_account(new_account(input, 10)?).await?;
        }
        writer.commit().await?;
        let first = read(&storage, async |tx| {
            tx.accounts_after(None, NonZeroUsize::MIN).await
        })
        .await?;
        assert_eq!(first.len(), 1);
        let cursor = &first[0].key;

        let mut writer = storage.begin_write().await?;
        writer.delete_account(cursor).await?;
        for input in ["aaron@example.com", "bob@example.com"] {
            writer.create_account(new_account(input, 10)?).await?;
        }
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let second = reader
            .accounts_after(Some(cursor), NonZeroUsize::MAX)
            .await?;
        assert_eq!(second.len(), 3);
        assert_eq!(second[0].key, key("bob@example.com")?);
        assert_eq!(second[1].key, key("carol@example.com")?);
        assert_eq!(second[2].key, key("erin@example.com")?);
        let between = reader
            .accounts_after(Some(&key("dan@example.com")?), NonZeroUsize::MAX)
            .await?;
        assert_eq!(between.len(), 1);
        assert_eq!(between[0].key, key("erin@example.com")?);
        Ok(())
    })
}

pub(crate) fn accounts_after_reads_the_snapshot_of_its_transaction<S: Storage>(
    storage: S,
) -> TestResult {
    let alice = key("alice@example.com")?;
    let bob = key("bob@example.com")?;
    let carol = key("carol@example.com")?;
    let dave = key("dave@example.com")?;
    block_on(async {
        let mut writer = storage.begin_write().await?;
        for input in ["alice@example.com", "bob@example.com", "dave@example.com"] {
            writer.create_account(new_account(input, 10)?).await?;
        }
        writer.commit().await?;

        let reader = storage.begin_read().await?;
        let mut writer = storage.begin_write().await?;
        writer.delete_account(&bob).await?;
        writer.delete_account(&dave).await?;
        writer
            .create_account(new_account("carol@example.com", 10)?)
            .await?;
        let own = writer
            .accounts_after(Some(&alice), NonZeroUsize::MAX)
            .await?;
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].key, carol);
        writer.commit().await?;

        let stale = reader
            .accounts_after(Some(&alice), NonZeroUsize::MAX)
            .await?;
        assert_eq!(stale.len(), 2);
        assert_eq!(stale[0].key, bob);
        assert_eq!(stale[1].key, dave);
        let current = read(&storage, async |tx| {
            tx.accounts_after(Some(&alice), NonZeroUsize::MAX).await
        })
        .await?;
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].key, carol);
        Ok(())
    })
}
