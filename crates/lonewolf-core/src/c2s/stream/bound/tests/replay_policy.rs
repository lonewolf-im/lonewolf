// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_extension::Extensions;
use lonewolf_extension::blocking::Blocking;
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};

use super::*;

fn record(sender: &str, id: &str) -> String {
    let mut xml = format!(
        "<message xmlns='jabber:client' from='{sender}' to='bob@localhost' type='chat' id='{id}'><body>"
    );
    let end = "</body></message>";
    let bytes = REPLAY_PAGE_BYTES.get() / 2;
    xml.extend(std::iter::repeat_n('x', bytes - xml.len() - end.len()));
    xml.push_str(end);
    xml
}

async fn fixture(records: &[&[u8]]) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(records).await?;
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Blocking))?;
    extensions.register(Arc::new(Offline::new(Default::default())))?;
    fixture.router = fixture.router.with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", ["blocking", "offline"])?,
    )]));
    Ok(fixture)
}

async fn bind<'a>(
    fixture: &'a Fixture,
    resource: &str,
) -> TestResult<BoundSession<'a, GlobalChunkAllocator, ControlledWriter>> {
    let router = fixture.router.handle();
    let registration = router
        .register(
            fixture.registration.account(),
            Some(resource),
            NonZeroUsize::new(4).ok_or("resource limit")?,
        )
        .await?;
    let (_, incoming) = async_channel::bounded(1);
    fixture.bound_session(GlobalChunkAllocator, registration, router, incoming)
}

async fn available(
    session: &mut BoundSession<'_, GlobalChunkAllocator, ControlledWriter>,
) -> TestResult {
    session
        .handle_availability(parsed("<presence/>").await?, true)
        .await
        .map_err(|error| format!("{error:?}").into())
}

fn assert_messages(writer: &ControlledWriter, ids: &[&str]) {
    let mut messages = writer
        .written
        .iter()
        .filter(|xml| xml.starts_with("<message "));
    for id in ids {
        assert!(
            messages
                .next()
                .is_some_and(|xml| xml.contains(&format!(r#"id="{id}""#))),
            "missing {id}"
        );
    }
    assert!(messages.next().is_none());
}

async fn await_empty(fixture: &Fixture) -> TestResult {
    compio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture.count().await? == 0 {
                return Ok(());
            }
        }
    })
    .await?
}

#[test]
fn replay_preserves_deferred_sequence_for_unblocked_sibling() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let records = [
            record("alice@localhost/sender", "deferred"),
            record("alice@localhost/sender", "also-deferred"),
            record("carol@remote.test/sender", "flushed"),
            record("erin@remote.test/sender", "discarded"),
            record("alice@localhost/sender", "later-deferred"),
            record("carol@remote.test/sender", "later"),
            record("carol@remote.test/sender", "retry"),
        ];
        let fixture = fixture(&records.each_ref().map(String::as_bytes)).await?;
        let mut arena = Arena::try_new(Default::default())?;
        let alice =
            AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
        let desk_jid =
            RosterJid::from(Jid::parse_in("bob@localhost/desk", &mut arena)?.resolve(&arena)?);
        let erin = RosterJid::from(Jid::parse_in("erin@remote.test", &mut arena)?.resolve(&arena)?);
        let mut tx = fixture.storage.begin_write().await?;
        tx.create_account(NewAccount {
            key: alice.clone(),
            credentials: credentials(),
        })
        .await?;
        tx.change_blocklist(&alice, BlockChange::Block(&[desk_jid]))
            .await?;
        tx.change_blocklist(fixture.registration.account(), BlockChange::Block(&[erin]))
            .await?;
        tx.commit().await?;
        let mut desk = bind(&fixture, "desk").await?;
        desk.outbox.writer.fail_write_id = Some("retry");
        available(&mut desk).await?;
        assert_eq!(desk.outbox.flush().await, Err(CloseOutcome::TransportError));
        assert_eq!(stored_sequences(&fixture).await?, [1, 2, 5, 7]);
        assert_messages(&desk.outbox.writer, &["flushed", "later"]);
        drop(desk);

        let mut sibling = bind(&fixture, "tablet").await?;
        available(&mut sibling).await?;
        sibling
            .outbox
            .flush()
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_messages(
            &sibling.outbox.writer,
            &["deferred", "also-deferred", "later-deferred", "retry"],
        );
        await_empty(&fixture).await?;
        drop(sibling);
        fixture.finish().await
    }))?
}

#[test]
fn later_replay_page_observes_a_block_committed_during_previous_page_output() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let records = [
            record("alice@remote.test/desk", "first"),
            record("alice@remote.test/phone", "second"),
            record("alice@remote.test/desk", "third"),
            record("alice@remote.test/phone", "fourth"),
        ];
        let fixture = fixture(&records.each_ref().map(String::as_bytes)).await?;
        let mut session = bind(&fixture, "desk").await?;
        let (entered, writing) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        session.outbox.writer.partial_after = 2;
        session.outbox.writer.partial_entered = Some(entered);
        session.outbox.writer.partial_release = Some(resume);
        available(&mut session).await?;
        let change = async {
            writing.await?;
            let mut arena = Arena::try_new(Default::default())?;
            let rule = RosterJid::from(
                Jid::parse_in("alice@remote.test/desk", &mut arena)?.resolve(&arena)?,
            );
            let mut tx = fixture.storage.begin_write().await?;
            tx.change_blocklist(fixture.registration.account(), BlockChange::Block(&[rule]))
                .await?;
            tx.commit().await?;
            release.send(()).map_err(|_| "pending write closed")?;
            Ok::<_, Box<dyn Error>>(())
        };
        let (flushed, committed) = join(session.outbox.flush(), change).await;
        committed?;
        flushed.map_err(|error| format!("{error:?}"))?;
        assert_messages(&session.outbox.writer, &["first", "second", "fourth"]);
        await_empty(&fixture).await?;
        drop(session);
        fixture.finish().await
    }))?
}
