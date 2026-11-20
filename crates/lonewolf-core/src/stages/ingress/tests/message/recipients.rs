// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::router::Registration;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::delivery::SessionTag;
use lonewolf_storage::account::{AccountWrites, NewAccount};
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};
use lonewolf_storage::offline::OfflineReads;
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{Storage, WriteTransaction};
use lonewolf_xmpp::stanza::RoutedStanza;

async fn fixture() -> TestResult<Fixture> {
    let fixture = Fixture::with_extensions(
        Verdict::Allow,
        false,
        false,
        &[BLOCKING, "pipeline-recorder", "carbons", "offline"],
    )?;
    let mut writer = fixture.storage.begin_write().await?;
    for name in ["alice@localhost", "bob@localhost"] {
        writer
            .create_account(NewAccount {
                key: account(name)?,
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [1; 16],
                    SCRAM_POLICY_ITERATIONS,
                    [2; 20],
                    [3; 20],
                ))),
            })
            .await?;
    }
    writer.commit().await?;
    Ok(fixture)
}

async fn block(fixture: &Fixture, owner: &str, items: &[&str]) -> TestResult {
    let mut arena = Arena::try_new(Default::default())?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        entries.push(RosterJid::from(
            Jid::parse_in(item, &mut arena)?.resolve(&arena)?,
        ));
    }
    let mut writer = fixture.storage.begin_write().await?;
    writer
        .change_blocklist(&account(owner)?, BlockChange::Block(&entries))
        .await?;
    writer.commit().await?;
    Ok(())
}

async fn bind(
    fixture: &Fixture,
    owner: &str,
    resource: &str,
) -> TestResult<Registration<GlobalChunkAllocator>> {
    Ok(fixture
        .handle
        .register(
            &account(owner)?,
            Some(resource),
            NonZeroUsize::new(8).ok_or("zero limit")?,
        )
        .await?)
}

async fn chat(
    fixture: &Fixture,
    source: &Registration<GlobalChunkAllocator>,
    to: &str,
) -> TestResult<MessageDisposition<GlobalChunkAllocator>> {
    handle(
        &fixture.stage(),
        &Origin::Session(source),
        stanza(&source.full_jid(), to)?,
        MessageType::Chat,
    )
    .await
    .map_err(|_| "message stage".into())
}

async fn recipient(
    fixture: &Fixture,
    resource: &str,
    priority: i8,
) -> TestResult<Registration<GlobalChunkAllocator>> {
    let session = bind(fixture, "bob@localhost", resource).await?;
    let mut arena = Arena::try_new(Default::default())?;
    let from = Jid::parse_in(&session.full_jid(), &mut arena)?;
    let available = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Available),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .build()?;
    session
        .handle()
        .set_presence(
            Some(priority),
            RoutedStanza::from_parts(available, arena),
            None,
        )
        .await?;
    session.handle().tag(SessionTag::Carbons).await?;
    Ok(session)
}

fn one_message(
    session: &Registration<GlobalChunkAllocator>,
    target: &str,
    copy: bool,
) -> TestResult {
    let messages = session.take_queued();
    assert_eq!(messages.len(), 1, "mailbox for {}", session.full_jid());
    let message = messages[0].stanza.resolve()?;
    assert_eq!(message.to()?.ok_or("missing destination")?.as_str(), target);
    let received = message.child("received", "urn:xmpp:carbons:2")?;
    if copy {
        let forwarded = received
            .ok_or("missing received carbon")?
            .child("forwarded", "urn:xmpp:forward:0")?
            .ok_or("missing forwarded carbon")?;
        let original = forwarded
            .child("message", "jabber:client")?
            .ok_or("missing original")?;
        assert_eq!(
            original.attribute("from", "")?,
            Some("alice@localhost/desk")
        );
        assert_eq!(original.attribute("to", "")?, Some("bob@localhost"));
    } else {
        assert!(received.is_none());
        assert_eq!(
            message.from()?.ok_or("missing sender")?.as_str(),
            "alice@localhost/desk"
        );
    }
    Ok(())
}

#[test]
fn bare_delivery_skips_exact_blocked_resource_and_its_carbons() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = fixture().await?;
        let source = bind(&fixture, "alice@localhost", "desk").await?;
        let desk = recipient(&fixture, "desk", 5).await?;
        let phone = recipient(&fixture, "phone", 5).await?;
        let watch = recipient(&fixture, "watch", -1).await?;
        let tablet = recipient(&fixture, "tablet", -1).await?;
        for session in [&desk, &phone, &watch, &tablet] {
            session.take_queued();
        }
        block(
            &fixture,
            "alice@localhost",
            &["bob@localhost/phone", "bob@localhost/watch"],
        )
        .await?;
        let outcome = chat(&fixture, &source, "bob@localhost").await?;
        assert!(matches!(outcome, MessageDisposition::Done));
        one_message(&desk, "bob@localhost", false)?;
        one_message(&tablet, "bob@localhost/tablet", true)?;
        assert!(phone.take_queued().is_empty());
        assert!(watch.take_queued().is_empty());
        drop((source, desk, phone, watch, tablet));
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn full_address_does_not_fall_back_around_a_block() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = fixture().await?;
        let source = bind(&fixture, "alice@localhost", "desk").await?;
        let sibling = bind(&fixture, "alice@localhost", "phone").await?;
        sibling.handle().tag(SessionTag::Carbons).await?;
        let receiver = recipient(&fixture, "desk", 0).await?;
        for (rule, target) in [
            ("bob@localhost/missing", "bob@localhost/missing"),
            ("bob@localhost/desk", "bob@localhost"),
            ("bob@localhost/desk", "bob@localhost/unknown"),
            ("bob@localhost", "bob@localhost/other"),
        ] {
            block(&fixture, "alice@localhost", &[rule]).await?;
            fixture.recorder.calls.lock().clear();
            let outcome = chat(&fixture, &source, target).await?;
            let reply = match outcome {
                MessageDisposition::Reply(Reply::Built(stanza)) => stanza,
                MessageDisposition::Reply(Reply::Error {
                    stanza,
                    condition,
                    application,
                    text,
                }) => crate::stages::ingress::rejection_reply(
                    &GlobalChunkAllocator,
                    &stanza,
                    condition,
                    application,
                    text,
                )
                .map_err(|_| "invalid rejection")?,
                MessageDisposition::Done => {
                    return Err(format!("expected owner rejection for {target}").into());
                }
            };
            let reply = reply.resolve()?;
            assert_eq!(reply.stanza_type(), StanzaType::Message(MessageType::Error));
            assert_eq!(reply.from()?.ok_or("missing source")?.as_str(), target);
            assert_eq!(
                reply.to()?.ok_or("missing destination")?.as_str(),
                source.full_jid()
            );
            let error = reply
                .child("error", "jabber:client")?
                .ok_or("missing error")?;
            assert_eq!(error.attribute("type", "")?, Some("cancel"));
            assert!(
                error
                    .child("not-acceptable", "urn:ietf:params:xml:ns:xmpp-stanzas")?
                    .is_some()
            );
            assert!(
                error
                    .child("blocked", "urn:xmpp:blocking:errors")?
                    .is_some()
            );
            assert!(receiver.take_queued().is_empty());
            assert!(sibling.take_queued().is_empty());
            assert!(
                fixture
                    .recorder
                    .calls
                    .lock()
                    .iter()
                    .all(|call| matches!(call, Call::Policy(_, _)))
            );
            assert_eq!(
                fixture
                    .storage
                    .begin_read()
                    .await?
                    .offline_count(&account("bob@localhost")?)
                    .await?,
                0
            );
        }
        drop((source, sibling, receiver));
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn missing_full_address_selects_highest_remaining_priority() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = fixture().await?;
        let source = bind(&fixture, "alice@localhost", "desk").await?;
        let high = recipient(&fixture, "high", 20).await?;
        let desk = recipient(&fixture, "desk", 10).await?;
        let low = recipient(&fixture, "low", 5).await?;
        for session in [&high, &desk, &low] {
            session.take_queued();
        }
        block(&fixture, "alice@localhost", &["bob@localhost/high"]).await?;
        let target = "bob@localhost/missing";
        let outcome = chat(&fixture, &source, target).await?;
        assert!(matches!(outcome, MessageDisposition::Done));
        one_message(&desk, target, false)?;
        let expected = desk.session_id();
        assert!(fixture.recorder.calls.lock().iter().any(|call| {
            matches!(call, Call::Observe {
                role: MessageRole::Received,
                holders,
                outcome: MessageOutcome::Routed,
                ..
            } if holders == &[expected])
        }));
        drop((source, desk, high, low));
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn bare_message_without_eligible_sessions_uses_offline_storage() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = fixture().await?;
        let source = bind(&fixture, "alice@localhost", "desk").await?;
        let sink = account("bob@localhost")?;
        block(&fixture, "alice@localhost", &["bob@localhost/absent"]).await?;
        let outcome = chat(&fixture, &source, "bob@localhost").await?;
        assert!(matches!(outcome, MessageDisposition::Done));
        assert_eq!(
            fixture
                .storage
                .begin_read()
                .await?
                .offline_count(&sink)
                .await?,
            1
        );
        assert!(fixture.recorder.calls.lock().iter().any(|call| {
            matches!(call, Call::Observe {
                role: MessageRole::Received,
                holders,
                outcome: MessageOutcome::Stored,
                ..
            } if holders.is_empty())
        }));
        drop(source);
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn own_resource_rule_preserves_local_sibling_delivery() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = fixture().await?;
        let source = bind(&fixture, "bob@localhost", "desk").await?;
        let phone = recipient(&fixture, "phone", 1).await?;
        block(&fixture, "bob@localhost", &["bob@localhost/phone"]).await?;
        let outcome = chat(&fixture, &source, "bob@localhost").await?;
        assert!(matches!(outcome, MessageDisposition::Done));
        let messages = phone.take_queued();
        assert_eq!(messages.len(), 1);
        let message = messages[0].stanza.resolve()?;
        assert_eq!(
            message.from()?.ok_or("missing source")?.as_str(),
            "bob@localhost/desk"
        );
        assert_eq!(
            message.to()?.ok_or("missing target")?.as_str(),
            "bob@localhost"
        );
        assert!(message.child("received", "urn:xmpp:carbons:2")?.is_none());
        drop((source, phone));
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn bare_original_honors_replacement_presence_at_admission() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = fixture().await?;
        let sender = account("alice@localhost")?;
        let owner = account("bob@localhost")?;
        let origin = fixture
            .handle
            .register(&sender, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let old = recipient(&fixture, "phone", 1).await?;
        let ((), mut ticket) = fixture
            .handle
            .order()
            .fix(vec![owner.clone()], async {
                Ok::<_, crate::stages::StageFailure>(())
            })
            .await
            .map_err(|_| "missing order ticket")?;
        ticket.turn().await;
        let (checking, checked) = oneshot::channel();
        *fixture.recorder.checking.lock() = Some(checking);
        let stage = fixture.stage();
        let source = Origin::Session(&origin);
        let message = stanza("alice@localhost/desk", "bob@localhost")?;
        let mut pending = Box::pin(handle(&stage, &source, message, MessageType::Chat));
        match select(checked, pending.as_mut()).await {
            Either::Left((signal, _)) => signal?,
            Either::Right(_) => return Err("message completed before admission".into()),
        }
        fixture.handle.retire_account(&owner).await?;
        old.wait_retired().await?;
        let new = fixture
            .handle
            .register(&owner, Some("phone"), NonZeroUsize::MIN)
            .await?;
        assert_eq!(old.full_jid(), new.full_jid());
        assert_ne!(old.session_id(), new.session_id());
        drop(ticket);
        pending.await.map_err(|_| "message stage")?;
        assert!(old.take_queued().is_empty());
        assert!(new.take_queued().is_empty());
        assert!(fixture.recorder.calls.lock().iter().all(|call| !matches!(
            call,
            Call::Observe {
                role: MessageRole::Received,
                outcome: MessageOutcome::Routed,
                ..
            }
        )));
        drop((origin, old, new));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}
