// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_extension::Extensions;
use lonewolf_extension::blocking::{Blocking, NAME, NAMESPACE};
use lonewolf_extension::delivery::SessionTag;
use lonewolf_extension::iq::IqErrorPayload;
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};
use lonewolf_storage::roster::RosterJid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::STANZA_ERROR_NAMESPACE;

use super::*;

fn router() -> TestResult<Router<GlobalChunkAllocator>> {
    let mut extensions = Extensions::default();
    extensions.register(Arc::new(Blocking))?;
    Ok(Router::new(
        Hosts::new(&Config::default().hosts, Some("localhost"))?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", [NAME])?,
    )])))
}

async fn blocklist_get(
    target: Option<&str>,
    contents: &str,
) -> TestResult<Parsed<Stanza, GlobalChunkAllocator>> {
    let to = target.map(|to| format!(" to='{to}'")).unwrap_or_default();
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq type='get' id='list'{to}><blocklist xmlns='{NAMESPACE}'>{contents}</blocklist></iq>"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("stanza limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
        return Err("missing GET".into());
    };
    Ok(parsed)
}

async fn route_tagged(router: &RouterHandle<GlobalChunkAllocator>, tag: SessionTag) -> TestResult {
    router
        .route_presence_to_tagged(
            tag,
            routed_presence("localhost", Some("bob@localhost"), PresenceType::Available)?,
        )
        .await?;
    Ok(())
}

#[test]
fn get_lists_prepared_items_and_tags_only_fetcher() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let limit = NonZeroUsize::new(4).ok_or("resource limit")?;
        let desk = handle.register(owner, Some("desk"), limit).await?;
        let phone = handle.register(owner, Some("phone"), limit).await?;
        let laptop = handle.register(owner, Some("laptop"), limit).await?;
        desk.handle().tag(SessionTag::Interested).await?;
        phone.handle().tag(SessionTag::Carbons).await?;
        let (_input, incoming) = async_channel::bounded(1);
        let mut session =
            fixture.bound_session(GlobalChunkAllocator, desk, handle.clone(), incoming)?;

        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let john = Jid::parse_in("John@EXAMPLE.TEST/Desk", &mut arena)?;
        let domain = Jid::parse_in("ABUSE.example", &mut arena)?;
        let rules = [
            RosterJid::from(john.resolve(&arena)?),
            RosterJid::from(domain.resolve(&arena)?),
        ];
        for expected in [&[][..], &["abuse.example", "john@example.test/Desk"][..]] {
            if !expected.is_empty() {
                let mut tx = fixture.storage.begin_write().await?;
                tx.change_blocklist(owner, BlockChange::Block(&rules))
                    .await?;
                tx.commit().await?;
            }
            session
                .handle_stanza(blocklist_get(None, "").await?)
                .await
                .map_err(|error| format!("{error:?}"))?;
            session
                .outbox
                .flush()
                .await
                .map_err(|error| format!("{error:?}"))?;
            let reply = session
                .outbox
                .writer
                .written
                .pop()
                .ok_or("missing result")?;
            let expected = if expected.is_empty() {
                format!("<blocklist xmlns=\"{NAMESPACE}\"/>")
            } else {
                let items = expected
                    .iter()
                    .map(|item| format!("<item jid=\"{item}\"/>"))
                    .collect::<String>();
                format!("<blocklist xmlns=\"{NAMESPACE}\">{items}</blocklist>")
            };
            assert!(reply.contains("type=\"result\""), "{reply}");
            assert!(reply.contains(&expected), "{reply}");
            route_tagged(&handle, SessionTag::Blocklist).await?;
            assert_eq!(session.registration.take_queued().len(), 1);
            assert!(phone.take_queued().is_empty());
            assert!(laptop.take_queued().is_empty());
        }

        route_tagged(&handle, SessionTag::Interested).await?;
        assert_eq!(session.registration.take_queued().len(), 1);
        assert!(phone.take_queued().is_empty());
        assert!(laptop.take_queued().is_empty());
        route_tagged(&handle, SessionTag::Carbons).await?;
        assert!(session.registration.take_queued().is_empty());
        assert_eq!(phone.take_queued().len(), 1);
        assert!(laptop.take_queued().is_empty());

        let replacement = handle.register(owner, Some("desk"), limit).await?;
        route_tagged(&handle, SessionTag::Blocklist).await?;
        assert!(replacement.take_queued().is_empty());
        assert!(phone.take_queued().is_empty());
        assert!(laptop.take_queued().is_empty());
        drop((session, replacement, phone, laptop));
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

#[test]
fn failed_or_foreign_get_never_marks_interest() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new(&[]).await?;
        let router = router()?;
        let handle = router.handle();
        let owner = fixture.registration.account();
        let desk = handle
            .register(owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let (_input, incoming) = async_channel::bounded(1);
        let mut session =
            fixture.bound_session(GlobalChunkAllocator, desk, handle.clone(), incoming)?;
        session
            .handle_stanza(blocklist_get(None, "<item jid='peer.example'/>").await?)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_blocklist_error(&mut session, StanzaErrorCondition::BadRequest)?;

        let (_value, mut ticket) = handle
            .order()
            .fix(vec![owner.clone()], async { Ok::<_, RouterError>(()) })
            .await?;
        ticket.turn().await;
        for target in ["bob@localhost/desk", "other@localhost"] {
            let request = blocklist_get(Some(target), "").await?;
            session
                .handle_stanza(request)
                .now_or_never()
                .ok_or("invalid destination started asynchronous target work")?
                .map_err(|error| format!("{error:?}"))?;
            assert_blocklist_error(&mut session, StanzaErrorCondition::Forbidden)?;
        }
        for kind in [StanzaNamespace::Server, StanzaNamespace::ComponentAccept] {
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let payload = Element::builder_in("blocklist", NAMESPACE, &mut arena)?.build()?;
            let target = Jid::parse_in(owner.as_str(), &mut arena)?;
            let sender = Jid::parse_in("reader@external.test/desk", &mut arena)?;
            let stanza = Stanza::builder_in(StanzaType::Iq(IqType::Get), kind, &mut arena)
                .id(Some("list"))?
                .from(Some(sender))?
                .to(Some(target))?
                .child(payload)?
                .build()?;
            let view = stanza.resolve(&arena)?;
            let error = crate::stages::iq::destination_error(&handle, None, &view)
                .map_err(|_| "destination check failed")?
                .ok_or("external origin reached account lookup")?;
            assert_eq!(error.condition(), StanzaErrorCondition::Forbidden);
            assert_eq!(error.payload(), IqErrorPayload::Omit);
        }
        drop(ticket);
        route_tagged(&handle, SessionTag::Blocklist).await?;
        assert!(session.registration.take_queued().is_empty());
        drop(session);
        router.shutdown().await?;
        fixture.finish().await
    }))?
}

fn assert_blocklist_error(
    session: &mut BoundSession<'_, GlobalChunkAllocator, ControlledWriter>,
    condition: StanzaErrorCondition,
) -> TestResult {
    let Some(Output::Owned { stanza, arena }) = session.outbox.queue.pop_front() else {
        return Err("missing blocklist error".into());
    };
    let reply = stanza.resolve(&arena)?;
    assert_eq!(reply.stanza_type(), StanzaType::Iq(IqType::Error));
    let mut children = reply.children()?;
    let error = children.next().transpose()?.ok_or("missing stanza error")?;
    assert_eq!(error.name(), "error");
    assert!(
        error
            .child(condition.as_str(), STANZA_ERROR_NAMESPACE)?
            .is_some()
    );
    assert!(children.next().is_none());
    assert!(session.outbox.queue.is_empty());
    Ok(())
}
