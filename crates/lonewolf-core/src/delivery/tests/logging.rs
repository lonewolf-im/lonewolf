// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::iq::{IqHandler, IqRequest};
use lonewolf_extension::presence::{PresenceHandler, PresenceRequest, PresenceRequestType};
use lonewolf_extension::roster::Roster;
use lonewolf_storage::roster::{
    PendingSubscription, RosterItem, RosterJid, RosterReads, RosterSubscription, RosterWrites,
    SubscriptionState,
};

use super::*;
use crate::logging::tests::Capture;

#[test]
fn staged_and_aborted_roster_changes_emit_no_commit_and_committed_effects_emit_once() -> TestResult
{
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let owner = account("private-alice@example.com")?;
        let mut transaction = storage.begin_write().await?;
        transaction.create_account(NewAccount {
            key: owner,
            credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                [11; 16], SCRAM_POLICY_ITERATIONS, [12; 20], [13; 20],
            ))),
        }).await?;
        transaction.commit().await?;
        let input = b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq from='private-alice@example.com/private-device' type='set' id='PRIVATE-ID'><query xmlns='jabber:iq:roster'><item jid='private-contact@example.com' name='PRIVATE-NAME'><group>PRIVATE-GROUP</group></item></query></iq>";
        let mut parser = XmppParser::new(input.as_slice(), ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("invalid stanza limit")?,
            arena: ArenaConfig::default(),
        }, GlobalChunkAllocator);
        assert!(matches!(parser.next_event().await?, Some(StreamEvent::StreamStart { .. })));
        let Some(StreamEvent::Stanza(stanza)) = parser.next_event().await? else { return Err("missing IQ".into()); };
        let view = stanza.value().resolve(stanza.arena())?;
        let sender = view.from()?.ok_or("missing sender")?;
        for commit in [false, true] {
            let mut transaction = storage.begin_write().await?;
            let mut response = Arena::try_new(ArenaConfig::default())?;
            let reply = <Roster as IqHandler<GlobalChunkAllocator, RedbStorage>>::set(
                &Roster,
                IqRequest {
                    sender,
                    target: sender.bare(),
                    payload: view.child("query", "jabber:iq:roster")?.ok_or("missing payload")?,
                },
                &mut transaction,
                &NoDelivery,
                &mut response,
            ).await.map_err(|error| format!("{error:?}"))?;
            assert_eq!(capture.count("roster operation committed")?, 0);
            if commit {
                let pending = commit_and_deliver(Order::new(), transaction, reply.effects, NoDelivery, None);
                assert!(matches!(pending.finished().await, Some(Ok(_))));
            } else {
                drop(transaction);
                drop(reply);
            }
        }
        assert_eq!(capture.count("roster operation committed")?, 1);
        let logs = capture.read()?;
        assert!(logs.contains("operation=\"upsert\" outcome=\"upserted\" item_count=1"));
        for private in ["private-alice", "private-contact", "private-device", "PRIVATE-ID", "PRIVATE-NAME", "PRIVATE-GROUP", "version="] {
            assert!(!logs.contains(private), "leaked {private}");
        }
        Ok(())
    })
}

#[test]
fn orphan_pending_cancellation_reports_a_change_without_item_mutations() -> TestResult {
    pending_only_transition(
        PresenceRequestType::Unsubscribed,
        "cancel",
        "cancelled",
        true,
        false,
    )
}

#[test]
fn pending_only_withdrawal_reports_a_change_without_item_mutations() -> TestResult {
    pending_only_transition(
        PresenceRequestType::Unsubscribe,
        "unsubscribe",
        "withdrawn",
        false,
        false,
    )
}

#[test]
fn approval_of_existing_grants_reports_the_removed_request_as_a_change() -> TestResult {
    pending_only_transition(
        PresenceRequestType::Subscribed,
        "approve",
        "approved",
        false,
        true,
    )
}

fn pending_only_transition(
    kind: PresenceRequestType,
    operation: &str,
    changed: &str,
    orphan: bool,
    matching_grants: bool,
) -> TestResult {
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let alice = account("alice@example.com")?;
        let bob = account("bob@example.com")?;
        let mut transaction = storage.begin_write().await?;
        for owner in [&alice, &bob]
            .into_iter()
            .filter(|owner| !orphan || *owner == &bob)
        {
            transaction
                .create_account(NewAccount {
                    key: owner.clone(),
                    credentials: ScramCredentials::new(ScramVerifier::Sha1(
                        ScramSha1Verifier::new(
                            [11; 16],
                            SCRAM_POLICY_ITERATIONS,
                            [12; 20],
                            [13; 20],
                        ),
                    )),
                })
                .await?;
        }
        if matching_grants {
            for (owner, contact, state) in [
                (&alice, &bob, SubscriptionState::To),
                (&bob, &alice, SubscriptionState::From),
            ] {
                transaction
                    .put_roster_item(
                        owner,
                        &RosterItem {
                            jid: RosterJid::from(contact),
                            name: None,
                            groups: Vec::new(),
                            subscription: RosterSubscription {
                                state,
                                ..Default::default()
                            },
                        },
                    )
                    .await?;
            }
        }
        transaction
            .put_pending_request(
                &bob,
                PendingSubscription {
                    sender: RosterJid::from(&alice),
                    stanza: b"<presence type='subscribe' id='PRIVATE-PENDING'/>"
                        .as_slice()
                        .into(),
                },
            )
            .await?;
        transaction.commit().await?;
        let snapshot = storage.begin_read().await?;
        let before_alice = snapshot.roster(&alice).await?;
        let before_bob = snapshot.roster(&bob).await?;
        drop(snapshot);
        let (sender, target, stanza_type) = match kind {
            PresenceRequestType::Unsubscribe => (&alice, &bob, "unsubscribe"),
            PresenceRequestType::Unsubscribed => (&bob, &alice, "unsubscribed"),
            PresenceRequestType::Subscribed => (&bob, &alice, "subscribed"),
            _ => return Err("unsupported test transition".into()),
        };
        let stanza = parsed(&format!(
            "<presence from='{}' to='{}' type='{stanza_type}' id='PRIVATE-TRANSITION'/>",
            sender.as_str(),
            target.as_str()
        ))
        .await?;
        let view = stanza.resolve()?;
        for (commit, expected_pending) in [(false, 1), (true, 0), (true, 0)] {
            let previous_events = capture.count("roster operation committed")?;
            let mut transaction = storage.begin_write().await?;
            let effects = <Roster as PresenceHandler<GlobalChunkAllocator, RedbStorage>>::receive(
                &Roster,
                PresenceRequest {
                    kind,
                    sender: view.from()?.ok_or("missing sender")?,
                    target: view.to()?.ok_or("missing target")?,
                    stanza: &stanza,
                },
                &mut transaction,
                &NoDelivery,
            )
            .await
            .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                capture.count("roster operation committed")?,
                previous_events
            );
            if commit {
                let pending =
                    commit_and_deliver(Order::new(), transaction, effects, NoDelivery, None);
                assert!(matches!(pending.finished().await, Some(Ok(_))));
            } else {
                drop(transaction);
                drop(effects);
            }
            let snapshot = storage.begin_read().await?;
            assert_eq!(
                snapshot.pending_requests(&bob).await?.len(),
                expected_pending
            );
            assert_eq!(snapshot.roster(&alice).await?, before_alice);
            assert_eq!(snapshot.roster(&bob).await?, before_bob);
        }
        let changed_fields = format!(
            "operation=\"{operation}\" outcome=\"{changed}\" item_count=0 requests_removed=1"
        );
        let unchanged_fields = format!(
            "operation=\"{operation}\" outcome=\"no_change\" item_count=0 requests_removed=0"
        );
        assert_eq!(capture.count(&changed_fields)?, 1);
        assert_eq!(capture.count(&unchanged_fields)?, 1);
        assert_eq!(capture.count("roster operation committed")?, 2);
        let logs = capture.read()?;
        for private in ["alice@example.com", "bob@example.com", "PRIVATE-"] {
            assert!(!logs.contains(private), "leaked {private}");
        }
        Ok(())
    })
}

#[test]
fn automatic_approval_and_no_change_have_distinct_committed_outcomes() -> TestResult {
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let alice = account("alice@example.com")?;
        let bob = account("bob@example.com")?;
        let mut transaction = storage.begin_write().await?;
        for owner in [&alice, &bob] {
            transaction.create_account(NewAccount {
                key: owner.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [11; 16], SCRAM_POLICY_ITERATIONS, [12; 20], [13; 20],
                ))),
            }).await?;
        }
        for (owner, contact, state, pending_out) in [
            (&alice, &bob, SubscriptionState::None, true),
            (&bob, &alice, SubscriptionState::From, false),
        ] {
            transaction.put_roster_item(owner, &RosterItem {
                jid: RosterJid::from(contact),
                name: None,
                groups: Vec::new(),
                subscription: RosterSubscription { state, pending_out, approved: false },
            }).await?;
        }
        transaction.commit().await?;
        let stanza = parsed("<presence from='alice@example.com' to='bob@example.com' type='subscribe' id='PRIVATE-SUBSCRIBE'/>").await?;
        let view = stanza.resolve()?;
        for previous_count in 0..2 {
            let mut transaction = storage.begin_write().await?;
            let effects = <Roster as PresenceHandler<GlobalChunkAllocator, RedbStorage>>::receive(
                &Roster,
                PresenceRequest {
                    kind: PresenceRequestType::Subscribe,
                    sender: view.from()?.ok_or("missing sender")?,
                    target: view.to()?.ok_or("missing recipient")?,
                    stanza: &stanza,
                },
                &mut transaction,
                &NoDelivery,
            ).await.map_err(|error| format!("{error:?}"))?;
            assert_eq!(capture.count("roster operation committed")?, previous_count);
            let pending = commit_and_deliver(Order::new(), transaction, effects, NoDelivery, None);
            assert!(matches!(pending.finished().await, Some(Ok(_))));
        }
        assert_eq!(capture.count("operation=\"subscribe\" outcome=\"auto_approved\" item_count=1")?, 1);
        assert_eq!(capture.count("operation=\"subscribe\" outcome=\"no_change\" item_count=0")?, 1);
        let logs = capture.read()?;
        assert!(!logs.contains("alice@example.com"));
        assert!(!logs.contains("bob@example.com"));
        assert!(!logs.contains("PRIVATE-SUBSCRIBE"));
        Ok(())
    })
}
