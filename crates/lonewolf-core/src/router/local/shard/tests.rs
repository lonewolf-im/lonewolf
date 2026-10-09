// SPDX-License-Identifier: Apache-2.0

fn test_router() -> LocalRouterHandle<GlobalChunkAllocator> {
    LocalRouter::new(GlobalChunkAllocator).handle()
}

use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind};

use compio::runtime::Runtime;
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{PresenceType, StanzaType};

use super::super::registration::release_deferred;
use super::super::shards::LocalRouter;
use super::*;

fn account() -> Result<AccountKey, Box<dyn Error>> {
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in("alice@localhost", &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn routed(xml: &str) -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
    let xml = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>{xml}"
    );
    let mut parser = XmppParser::new(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("zero stanza size")?,
            arena: Default::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(parsed)) => Ok(RoutedStanza::from_parsed(parsed)),
        _ => Err("expected a stanza".into()),
    }
}

#[test]
fn invalid_target_forms_fail_without_touching_a_shard() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {

        let router = test_router();
        for target in [
            "",
            " to='localhost'",
            " to='localhost/desk'",
            " to='alice@localhost'",
        ] {
            let xml = format!("<presence type='error'{target}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>");
            assert_eq!(
                router
                    .deliver_full_or_chat_fallback(routed(&xml).await?, false, None, None)
                    .now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
            assert_eq!(
                router
                    .deliver_iq_request(routed(&xml).await?, false, None)
                    .now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
        }
        for target in [
            "",
            " to='localhost'",
            " to='localhost/desk'",
            " to='alice@localhost/desk'",
        ] {
            let xml = format!("<presence type='error'{target}><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>");
            assert_eq!(
                router.deliver_bare(routed(&xml).await?, None).now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
            assert_eq!(
                router.deliver_presence(routed(&xml).await?).now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
            assert_eq!(
                router
                    .deliver_presence_error(routed(&xml).await?)
                    .now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
            assert_eq!(
                router
                    .deliver_presence_to_tagged(SessionTag::Interested, routed(&xml).await?)
                    .now_or_never(),
                Some(Err(RouterError::InvalidTarget))
            );
        }
        assert_eq!(
            router
                .deliver_presence_error(routed("<presence to='alice@localhost'/>").await?)
                .now_or_never(),
            Some(Err(RouterError::InvalidTarget))
        );
        Ok(())
    })
}

#[test]
fn closing_selected_bare_recipient_rechecks_eligibility_without_retrying_a_sibling()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for kind in ["normal", "chat"] {
            for eligible_sibling in [false, true] {
                let mut sessions = HashMap::new();
                let mut receivers = Vec::new();
                for (token, resource, priority) in [
                    (1, "selected", Some(1)),
                    (2, "sibling", eligible_sibling.then_some(0)),
                ] {
                    let (outbound, inbound) = async_channel::bounded(1);
                    let (retired, _) = oneshot::channel();
                    sessions.insert(
                        resource.into(),
                        Session {
                            token,
                            alive: Arc::new(AtomicBool::new(true)),
                            outbound,
                            inbound: inbound.clone(),
                            priority,
                            tags: SessionTags::default(),
                            presence: None,
                            unavailable: None,
                            directed: Vec::new(),
                            retired,
                        },
                    );
                    receivers.push(inbound);
                }
                let selected = &sessions["selected"];
                assert!(selected.accepts_bare_message());
                receivers[0].close();
                let stanza =
                    routed(&format!("<message to='alice@localhost' type='{kind}'/>")).await?;
                assert_eq!(
                    enqueue_bare_message(&sessions, selected, stanza, None),
                    Err(if eligible_sibling {
                        RouterError::NotFound
                    } else {
                        RouterError::Offline
                    })
                );
                assert!(receivers[1].is_empty());
            }
        }
        Ok(())
    })
}

#[test]
fn headline_prefers_success_then_busy_and_keeps_closed_sessions() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let account = account()?;
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let mut sessions = HashMap::new();
        let mut receivers = Vec::new();
        for (token, resource) in [(1, "ready"), (2, "full"), (3, "closed")] {
            let (outbound, inbound) = async_channel::bounded(1);
            let (retired, _) = oneshot::channel();
            sessions.insert(
                resource.into(),
                Session {
                    token,
                    alive: Arc::new(AtomicBool::new(true)),
                    outbound,
                    inbound: inbound.clone(),
                    priority: Some(0),
                    tags: SessionTags::default(),
                    presence: None,
                    unavailable: None,
                    directed: Vec::new(),
                    retired,
                },
            );
            receivers.push(inbound);
        }
        let stanza = routed("<message to='alice@localhost' type='headline'/>").await?;
        assert!(
            sessions["full"]
                .outbound
                .try_send(MailboxEntry::new(stanza.clone()))
                .is_ok()
        );
        receivers[2].close();
        shard.accounts.insert(account.as_str().into(), sessions);

        assert_eq!(shard.deliver_bare(stanza.clone(), false, None), Ok(()));
        let delivery = receivers[0].try_recv()?;
        assert_eq!(
            delivery.stanza.resolve()?.stanza_type(),
            StanzaType::Message(MessageType::Headline)
        );
        assert_eq!(receivers[1].len(), 1);
        receivers[0].close();
        assert_eq!(
            shard.deliver_bare(stanza.clone(), false, None),
            Err(RouterError::Busy)
        );
        receivers[1].close();
        assert_eq!(
            shard.deliver_bare(stanza, false, None),
            Err(RouterError::Offline)
        );
        let sessions = &shard.accounts[account.as_str()];
        assert_eq!(sessions.len(), 3);
        assert!(
            sessions
                .values()
                .all(|session| session.alive.load(Ordering::Acquire))
        );
        Ok(())
    })
}

#[test]
fn full_normal_delivery_linearizes_at_exact_resource_binding_and_disconnect()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for sibling_priority in [None, Some(-1), Some(0)] {
            for closed in [false, true] {
                let account = account()?;
                let mut shard = Shard::<GlobalChunkAllocator>::new();

                let limit = NonZeroUsize::new(2).ok_or("zero resource limit")?;
                let (outbound, inbound) = async_channel::bounded(64);
                let sibling = shard.register(
                    account.clone(),
                    Some("phone".into()),
                    limit,
                    outbound,
                    inbound,
                    test_router(),
                )?;
                shard
                    .accounts
                    .get_mut(account.as_str())
                    .ok_or("missing account")?
                    .get_mut("phone")
                    .ok_or("missing sibling")?
                    .priority = sibling_priority;
                let stanza = routed("<message to='alice@localhost/desk' type='normal'/>").await?;
                assert_eq!(
                    shard.deliver(stanza.clone(), true, None),
                    Err(RouterError::NotFound)
                );
                let (outbound, inbound) = async_channel::bounded(64);
                let desk = shard.register(
                    account.clone(),
                    Some("desk".into()),
                    limit,
                    outbound,
                    inbound,
                    test_router(),
                )?;
                for priority in [None, Some(-1)] {
                    shard
                        .accounts
                        .get_mut(account.as_str())
                        .ok_or("missing account")?
                        .get_mut("desk")
                        .ok_or("missing resource")?
                        .priority = priority;
                    assert_eq!(shard.deliver(stanza.clone(), true, None), Ok(()));
                    let delivered = desk.links.inbound.try_recv()?;
                    assert_eq!(
                        delivered
                            .stanza
                            .resolve()?
                            .to()?
                            .ok_or("missing target")?
                            .as_str(),
                        "alice@localhost/desk"
                    );
                }
                if closed {
                    desk.links.inbound.close();
                } else {
                    desk.alive.store(false, Ordering::Release);
                }
                assert_eq!(
                    shard.deliver(stanza.clone(), true, None),
                    Err(RouterError::NotFound)
                );
                assert_eq!(
                    shard.deliver(stanza, true, None),
                    Err(RouterError::NotFound)
                );
                assert!(sibling.take_queued().is_empty());
                assert!(!shard.accounts[account.as_str()].contains_key("desk"));
            }
        }
        Ok(())
    })
}

#[test]
fn resource_match_ignores_dead_and_closed_sessions() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for closed in [false, true] {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();

            let (outbound, inbound) = async_channel::bounded(64);
            let registration = shard.register(
                account.clone(),
                Some("desk".into()),
                NonZeroUsize::MIN,
                outbound,
                inbound,
                test_router(),
            )?;
            if closed {
                registration.links.inbound.close();
            } else {
                registration.alive.store(false, Ordering::Release);
            }
            assert_eq!(shard.resource_match(&account, "desk"), None);
        }
        Ok(())
    })
}

#[test]
fn a_registration_dropped_by_a_panic_is_released_afterwards() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let account = account()?;
        let router = test_router();
        let desk = router
            .register(&account, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let caught = catch_unwind(AssertUnwindSafe(move || {
            let _held = desk;
            panic!("deliberate");
        }));
        assert!(caught.is_err());
        let index = router.shard_index(account.as_str());
        assert!(
            router
                .with_shard(index, |shard| shard
                    .accounts
                    .get(account.as_str())
                    .is_some_and(|sessions| sessions.contains_key("desk")))
                .await?
        );
        release_deferred();
        assert!(
            !router
                .with_shard(index, |shard| shard
                    .accounts
                    .get(account.as_str())
                    .is_some_and(|sessions| sessions.contains_key("desk")))
                .await?
        );
        Ok(())
    })
}

#[test]
fn a_busy_shard_defers_registration_cleanup_to_its_next_operation() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let account = account()?;
        let router = test_router();
        let desk = router
            .register(&account, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let index = router.shard_index(account.as_str());
        let guard = router.inner.slots[index].shard.lock().await;
        drop(desk);
        assert_eq!(router.inner.slots[index].pending.lock().len(), 1);
        drop(guard);
        assert_eq!(router.resource_match(&account, "desk").await?, None);
        assert!(router.inner.slots[index].pending.lock().is_empty());
        assert!(
            !router
                .with_shard(index, |shard| shard.accounts.contains_key(account.as_str()))
                .await?
        );
        Ok(())
    })
}

#[test]
fn full_delivery_removes_stale_session_and_broadcasts_unavailable() -> Result<(), Box<dyn Error>> {
    for xml in [
        "<message to='alice@localhost/desk'/>",
        "<presence from='bob@localhost/desk' to='alice@localhost/desk' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
    ] {
        Runtime::new()?.block_on(async {
            let account = account()?;
            let mut shard = Shard::<GlobalChunkAllocator>::new();

            let (desk_outbound, desk_inbound) = async_channel::bounded(64);
            let desk = shard.register(
                account.clone(),
                Some("desk".into()),
                NonZeroUsize::new(2).ok_or("zero resource limit")?,
                desk_outbound,
                desk_inbound,
                test_router(),
            )?;
            let (phone_outbound, phone_inbound) = async_channel::bounded(64);
            let phone = shard.register(
                account.clone(),
                Some("phone".into()),
                NonZeroUsize::new(2).ok_or("zero resource limit")?,
                phone_outbound,
                phone_inbound,
                test_router(),
            )?;
            let became_available = shard.presence(
                &account,
                "desk",
                desk.token,
                Some(0),
                routed("<presence from='alice@localhost/desk'/>").await?,
                Some(routed("<presence from='alice@localhost/desk' type='unavailable'/>").await?),
            )?;
            assert!(became_available.became_available);
            assert!(became_available.siblings.is_empty());
            let became_available = shard.presence(
                &account,
                "phone",
                phone.token,
                Some(0),
                routed("<presence from='alice@localhost/phone'/>").await?,
                None,
            )?;
            assert!(became_available.became_available);
            assert_eq!(became_available.siblings.len(), 1);
            if desk.recv().await.is_none() {
                return Err("missing peer presence".into());
            }

            drop(desk);
            assert_eq!(
                shard.deliver(routed(xml).await?, false, None),
                Err(RouterError::NotFound)
            );
            let Some(unavailable) = phone.recv().await else {
                return Err("missing unavailable".into());
            };
            assert_eq!(
                unavailable.stanza.resolve()?.stanza_type(),
                StanzaType::Presence(PresenceType::Unavailable)
            );
            assert!(!shard.accounts[account.as_str()].contains_key("desk"));
            assert!(phone.take_queued().is_empty());
            Ok::<_, Box<dyn Error>>(())
        })?;
    }
    Ok(())
}

fn directed_recipient(text: &str) -> Result<DirectedRecipient, Box<dyn Error>> {
    let mut arena = Arena::try_new(Default::default())?;
    Ok(DirectedRecipient::new(
        Jid::parse_in(text, &mut arena)?.resolve(&arena)?,
    ))
}

#[test]
fn directed_presence_limit_counts_exact_recipients_per_resource() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let alice = account()?;
        let mut shard =
            Shard::with_directed_presence_limit(NonZeroUsize::new(2).ok_or("zero limit")?);

        let router = test_router();
        let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
        let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
        for target in ["bob@localhost", "bob@localhost/desk"] {
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient(target)?,
                true,
            )?;
        }
        shard.record_directed_presence(
            &alice,
            "desk",
            desk.token,
            directed_recipient("bob@localhost")?,
            true,
        )?;
        assert_eq!(
            shard.accounts[alice.as_str()]["desk"].directed[0].as_str(),
            "bob@localhost"
        );
        assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
        assert_eq!(
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("carol@localhost")?,
                true
            ),
            Err(RouterError::DirectedPresenceLimit)
        );
        assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
        shard.record_directed_presence(
            &alice,
            "phone",
            phone.token,
            directed_recipient("carol@localhost")?,
            true,
        )?;
        assert_eq!(shard.accounts[alice.as_str()]["phone"].directed.len(), 1);
        shard.record_directed_presence(
            &alice,
            "desk",
            desk.token,
            directed_recipient("alice@localhost/phone")?,
            true,
        )?;
        shard.record_directed_presence(
            &alice,
            "desk",
            desk.token,
            directed_recipient("unknown@localhost")?,
            false,
        )?;
        assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
        shard.record_directed_presence(
            &alice,
            "desk",
            desk.token,
            directed_recipient("bob@localhost")?,
            false,
        )?;
        assert!(
            shard.accounts[alice.as_str()]["desk"]
                .directed
                .iter()
                .all(|grant| grant.as_str() != "bob@localhost")
        );
        shard.record_directed_presence(
            &alice,
            "desk",
            desk.token,
            directed_recipient("bob@localhost")?,
            true,
        )?;
        assert_eq!(
            shard.accounts[alice.as_str()]["desk"].directed[1].as_str(),
            "bob@localhost"
        );
        assert_eq!(shard.accounts[alice.as_str()]["desk"].directed.len(), 2);
        Ok(())
    })
}

#[test]
fn recipient_unavailable_releases_directed_presence_limit() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for sender in ["bob@localhost/desk", "bob@localhost"] {
            let alice = account()?;
            let mut shard =
                Shard::with_directed_presence_limit(NonZeroUsize::new(2).ok_or("zero limit")?);

            let router = test_router();
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            for target in ["bob@localhost", "bob@localhost/desk"] {
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    desk.token,
                    directed_recipient(target)?,
                    true,
                )?;
            }
            shard.prune_directed(
                &routed(&format!(
                    "<presence from='{sender}' to='alice@localhost/desk' type='unavailable'/>"
                ))
                .await?,
                None,
            )?;
            assert_eq!(
                shard.accounts[alice.as_str()]["desk"].directed.len(),
                usize::from(sender.contains('/'))
            );
            if sender.contains('/') {
                assert_eq!(
                    shard.accounts[alice.as_str()]["desk"].directed[0].as_str(),
                    "bob@localhost"
                );
            }
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("bob@localhost/desk")?,
                true,
            )?;
            assert_eq!(
                shard.accounts[alice.as_str()]["desk"]
                    .directed
                    .last()
                    .ok_or("missing grant")?
                    .as_str(),
                "bob@localhost/desk"
            );
        }
        Ok(())
    })
}

#[test]
fn directed_presence_limit_resets_on_withdrawal_and_retirement_without_touching_replacements()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for action in ["unavailable", "disconnect", "evict", "delete", "drop"] {
            let alice = account()?;
            let mut shard = Shard::with_directed_presence_limit(NonZeroUsize::MIN);

            let router = test_router();
            let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
            let token = desk.token;
            shard.record_directed_presence(
                &alice,
                "desk",
                token,
                directed_recipient("bob@localhost")?,
                true,
            )?;
            let mut held = Some(desk);
            match action {
                "unavailable" => {
                    let change = shard.presence(
                        &alice,
                        "desk",
                        token,
                        None,
                        routed("<presence from='alice@localhost/desk' type='unavailable'/>")
                            .await?,
                        None,
                    )?;
                    assert_eq!(change.directed.recipients.len(), 1);
                    assert_eq!(change.directed.recipients[0].as_str(), "bob@localhost");
                    assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
                }
                "disconnect" => {
                    let withdrawal = shard.end_presence(&alice, "desk", token)?;
                    assert_eq!(withdrawal.directed.recipients.len(), 1);
                    assert_eq!(withdrawal.directed.recipients[0].as_str(), "bob@localhost");
                    assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
                }
                "delete" => shard.retire_account(&alice),
                "drop" => {
                    drop(held.take());
                    shard.cleanup(&alice, "desk", token);
                }
                _ => shard.remove(alice.as_str(), "desk", token, RetireCause::Evicted),
            }
            if !matches!(action, "unavailable" | "disconnect") {
                assert!(
                    shard
                        .accounts
                        .get(alice.as_str())
                        .is_none_or(|sessions| !sessions.contains_key("desk")),
                    "{action}"
                );
            }
            let replacement = if action == "unavailable" {
                held.take().ok_or("missing registration")?
            } else {
                register_probe_session(&mut shard, &router, &alice, "desk")?
            };
            assert!(shard.accounts[alice.as_str()]["desk"].directed.is_empty());
            shard.record_directed_presence(
                &alice,
                "desk",
                replacement.token,
                directed_recipient("carol@localhost")?,
                true,
            )?;
            if action != "unavailable" {
                assert_ne!(token, replacement.token);
                assert_eq!(
                    shard.record_directed_presence(
                        &alice,
                        "desk",
                        token,
                        directed_recipient("carol@localhost")?,
                        false
                    ),
                    Err(RouterError::NotFound)
                );
                assert!(matches!(
                    shard.end_presence(&alice, "desk", token),
                    Err(RouterError::NotFound)
                ));
                shard.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                shard.finish_presence(&alice, token);
            }
            let grants = &shard.accounts[alice.as_str()]["desk"].directed;
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].as_str(), "carol@localhost");
            assert_eq!(
                shard.record_directed_presence(
                    &alice,
                    "desk",
                    replacement.token,
                    directed_recipient("dave@localhost")?,
                    true
                ),
                Err(RouterError::DirectedPresenceLimit)
            );
        }
        Ok(())
    })
}

#[test]
fn committed_directed_unavailable_survives_source_retirement_and_replacement()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for evict in [false, true] {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob_jid = Jid::parse_in("bob@localhost/desk", &mut arena)?.resolve(&arena)?;
            let bob = AccountKey::try_from(bob_jid.bare())?;
            let mut source = Shard::<GlobalChunkAllocator>::new();
            let mut destination = Shard::<GlobalChunkAllocator>::new();

            let router = test_router();
            let (outbound, inbound) = async_channel::bounded(64);
            let desk = source.register(alice.clone(), Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
            let (outbound, inbound) = async_channel::bounded(64);
            let observer = destination.register(bob, Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
            source.record_directed_presence(&alice, "desk", desk.token, DirectedRecipient::new(bob_jid), true)?;
            let unavailable = routed("<presence from='alice@localhost/desk' to='bob@localhost/desk' type='unavailable'/>").await?;
            source.record_directed_presence(&alice, "desk", desk.token, DirectedRecipient::new(bob_jid), false)?;
            assert!(source.accounts[alice.as_str()]["desk"].directed.is_empty());
            if evict {
                source.remove(alice.as_str(), "desk", desk.token, RetireCause::Evicted);
                let retired = desk.wait_retired().await?;
                assert!(retired.unavailable.is_none());
                assert!(retired.directed.take().ok_or("missing retired withdrawal")?.recipients.is_empty());
            } else {
                let withdrawal = source.end_presence(&alice, "desk", desk.token)?;
                assert!(withdrawal.unavailable.is_none());
                assert!(withdrawal.directed.recipients.is_empty());
            }
            let (outbound, inbound) = async_channel::bounded(64);
            let replacement = source.register(alice.clone(), Some("desk".into()), NonZeroUsize::MIN, outbound, inbound, router.clone())?;
            assert_ne!(replacement.token, desk.token);
            source.record_directed_presence(&alice, "desk", replacement.token, DirectedRecipient::new(bob_jid), true)?;
            destination.deliver(unavailable, false, None)?;
            let delivered = observer.take_queued();
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0].stanza.resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
            source.finish_presence(&alice, desk.token);
            let replacement_state = &source.accounts[alice.as_str()]["desk"];
            assert_eq!(replacement_state.token, replacement.token);
            assert_eq!(replacement_state.directed.len(), 1);
            assert_eq!(replacement_state.directed[0].as_str(), "bob@localhost/desk");
        }
        Ok(())
    })
}
fn register_probe_session(
    shard: &mut Shard<GlobalChunkAllocator>,
    router: &LocalRouterHandle<GlobalChunkAllocator>,
    owner: &AccountKey,
    resource: &str,
) -> Result<Registration<GlobalChunkAllocator>, Box<dyn Error>> {
    let (outbound, inbound) = async_channel::bounded(64);
    Ok(shard.register(
        owner.clone(),
        Some(resource.into()),
        NonZeroUsize::new(4).ok_or("zero limit")?,
        outbound,
        inbound,
        router.clone(),
    )?)
}

#[test]
fn iq_admission_checks_source_liveness_at_delivery() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for kind in ["get", "set", "result", "error"] {
            for action in ["unchanged", "drop", "evict", "replace"] {
                let alice = account()?;
                let mut arena = Arena::try_new(Default::default())?;
                let bob = AccountKey::try_from(
                    Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?
                )?;
                let mut source = Shard::<GlobalChunkAllocator>::new();
                let mut destination = Shard::<GlobalChunkAllocator>::new();

                let router = test_router();
                let origin = register_probe_session(&mut source, &router, &alice, "desk")?;
                let target = register_probe_session(&mut destination, &router, &bob, "phone")?;
                let token = origin.token;
                let liveness = origin.liveness();
                let error = if kind == "error" {
                    "<error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
                } else {
                    ""
                };
                let stanza = routed(&format!(
                    "<iq type='{kind}' from='alice@localhost/desk' to='bob@localhost/phone' id='queued'><query xmlns='urn:test:iq'/>{error}</iq>"
                )).await?;
                let mut replacement = None;
                match action {
                    "drop" => drop(origin),
                    "evict" => {
                        source.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                    }
                    "replace" => {
                        source.remove(alice.as_str(), "desk", token, RetireCause::Evicted);
                        replacement = Some(register_probe_session(&mut source, &router, &alice, "desk")?);
                        assert_ne!(replacement.as_ref().ok_or("missing replacement")?.token, token);
                    }
                    _ => {}
                }
                if matches!(kind, "get" | "set") {
                    destination.deliver_iq_request(stanza, true, Some(liveness))?;
                } else {
                    destination.deliver_with_guard(stanza, false, || liveness.is_alive(), None)?;
                }
                assert_eq!(target.take_queued().len(), usize::from(action == "unchanged"), "{kind} {action}");
                drop(replacement);
            }
        }
        Ok(())
    })
}

#[test]
fn probe_replies_enter_the_requester_mailbox() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let alice = account()?;
        let mut arena = Arena::try_new(Default::default())?;
        let bob = AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

        let router = test_router();
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
        let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='none'/>").await?;
        let unavailable = shard.probe(&observer.handle(), &request, true)?.ok_or("missing unavailable")?;
        assert_eq!(unavailable.resolve()?.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
        let replies = observer.take_queued();
        assert_eq!(replies.len(), 1);
        let view = replies[0].stanza.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unavailable));
        assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost");
        assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
        assert_eq!(view.id()?, Some("none"));
        assert!(view.child("delay", "urn:xmpp:delay")?.is_none());

        let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
        shard.presence(&alice, "desk", desk.token, Some(0), routed("<presence from='alice@localhost/desk' id='p'><status>here</status></presence>").await?, None)?;
        let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='bare'/>").await?;
        assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
        let replies = observer.take_queued();
        assert_eq!(replies.len(), 1);
        let view = replies[0].stanza.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
        assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost/desk");
        assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
        assert_eq!(view.child("status", "jabber:client")?.ok_or("missing status")?.text()?, Some("here"));

        let request = routed("<presence from='bob@localhost/desk' to='alice@localhost/desk' type='probe' id='full'/>").await?;
        assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
        let replies = observer.take_queued();
        assert_eq!(replies.len(), 1);
        let view = replies[0].stanza.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Available));
        assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost/desk");
        assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
        assert_eq!(view.id()?, Some("full"));
        assert!(view.children()?.next().is_none());

        let request = routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='denied'/>").await?;
        assert!(shard.probe(&observer.handle(), &request, false)?.is_none());
        let replies = observer.take_queued();
        assert_eq!(replies.len(), 1);
        let view = replies[0].stanza.resolve()?;
        assert_eq!(view.stanza_type(), StanzaType::Presence(PresenceType::Unsubscribed));
        assert_eq!(view.from()?.ok_or("missing source")?.as_str(), "alice@localhost");
        assert_eq!(view.to()?.ok_or("missing target")?.as_str(), "bob@localhost/desk");
        assert_eq!(view.id()?, Some("denied"));
        Ok(())
    })
}

#[test]
fn probe_reply_never_reaches_an_ended_requester_or_its_replacement() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        for action in ["end", "evict", "drop", "closed_only"] {
            let alice = account()?;
            let mut arena = Arena::try_new(Default::default())?;
            let bob =
                AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

            let router = test_router();
            let mut source = Shard::<GlobalChunkAllocator>::new();
            let mut destination = Shard::<GlobalChunkAllocator>::new();
            let desk = register_probe_session(&mut source, &router, &alice, "desk")?;
            source.presence(
                &alice,
                "desk",
                desk.token,
                Some(0),
                routed("<presence from='alice@localhost/desk'/>").await?,
                None,
            )?;
            let observer = register_probe_session(&mut destination, &router, &bob, "desk")?;
            let old = observer.handle();
            let old_mailbox = observer.mailbox();
            let replacement = match action {
                "end" => {
                    destination.end_presence(&bob, "desk", old.token)?;
                    Some(register_probe_session(
                        &mut destination,
                        &router,
                        &bob,
                        "desk",
                    )?)
                }
                "evict" => {
                    destination.remove(bob.as_str(), "desk", old.token, RetireCause::Evicted);
                    Some(register_probe_session(
                        &mut destination,
                        &router,
                        &bob,
                        "desk",
                    )?)
                }
                "drop" => {
                    drop(observer);
                    None
                }
                _ => {
                    observer.links.inbound.close();
                    None
                }
            };
            assert_eq!(old.liveness.is_alive(), action == "closed_only");
            let request =
                routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe'/>")
                    .await?;
            assert!(source.probe(&old, &request, true)?.is_none());
            assert!(old_mailbox.take_queued().is_empty());
            if let Some(replacement) = replacement {
                assert_eq!(replacement.resource(), "desk");
                assert_ne!(replacement.token, old.token);
                assert!(replacement.take_queued().is_empty());
            }
        }
        Ok(())
    })
}

#[test]
fn probe_reads_grants_when_it_runs() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let alice = account()?;
        let mut arena = Arena::try_new(Default::default())?;
        let bob =
            AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

        let router = test_router();
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
        let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
        let request = routed(
            "<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='directed'/>",
        )
        .await?;
        for available in [true, false] {
            shard.record_directed_presence(
                &alice,
                "desk",
                desk.token,
                directed_recipient("bob@localhost/desk")?,
                available,
            )?;
            assert!(shard.probe(&observer.handle(), &request, false)?.is_none());
            let replies = observer.take_queued();
            assert_eq!(replies.len(), 1);
            let view = replies[0].stanza.resolve()?;
            let (kind, from) = if available {
                (PresenceType::Available, "alice@localhost/desk")
            } else {
                (PresenceType::Unsubscribed, "alice@localhost")
            };
            assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
            assert_eq!(view.from()?.ok_or("missing source")?.as_str(), from);
            assert_eq!(
                view.to()?.ok_or("missing target")?.as_str(),
                "bob@localhost/desk"
            );
            assert_eq!(view.id()?, Some("directed"));
            assert!(view.children()?.next().is_none());
        }
        Ok(())
    })
}

#[test]
fn requester_prune_is_limited_to_its_generation() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let mut arena = Arena::try_new(Default::default())?;
        let bob =
            AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

        let router = test_router();
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
        shard.record_directed_presence(
            &bob,
            "desk",
            observer.token,
            directed_recipient("alice@localhost")?,
            true,
        )?;
        let stanza =
            routed("<presence from='alice@localhost' to='bob@localhost/desk' type='unavailable'/>")
                .await?;
        shard.prune_directed(&stanza, Some(observer.token + 1))?;
        assert_eq!(shard.accounts[bob.as_str()]["desk"].directed.len(), 1);
        shard.prune_directed(&stanza, Some(observer.token))?;
        assert!(shard.accounts[bob.as_str()]["desk"].directed.is_empty());
        Ok(())
    })
}

#[test]
fn full_probe_mailbox_preserves_the_requester_and_unavailable_prune() -> Result<(), Box<dyn Error>>
{
    Runtime::new()?.block_on(async {
        let alice = account()?;
        let mut arena = Arena::try_new(Default::default())?;
        let bob =
            AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

        let router = test_router();
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let (outbound, inbound) = async_channel::bounded(1);
        let observer = shard.register(
            bob.clone(),
            Some("desk".into()),
            NonZeroUsize::MIN,
            outbound,
            inbound,
            router.clone(),
        )?;
        let queued =
            routed("<presence from='carol@localhost/desk' to='bob@localhost/desk' id='queued'/>")
                .await?;
        shard.accounts[bob.as_str()]["desk"]
            .outbound
            .try_send(MailboxEntry::new(queued))?;
        shard.record_directed_presence(
            &bob,
            "desk",
            observer.token,
            directed_recipient("alice@localhost")?,
            true,
        )?;
        let request =
            routed("<presence from='bob@localhost/desk' to='alice@localhost' type='probe'/>")
                .await?;
        let unavailable = shard
            .probe(&observer.handle(), &request, true)?
            .ok_or("missing unavailable prune")?;
        shard.prune_directed(&unavailable, Some(observer.token + 1))?;
        assert_eq!(shard.accounts[bob.as_str()]["desk"].directed.len(), 1);
        shard.prune_directed(&unavailable, Some(observer.token))?;
        assert!(shard.accounts[bob.as_str()]["desk"].directed.is_empty());
        let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
        let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
        for session in [&desk, &phone] {
            shard.presence(
                &alice,
                session.resource(),
                session.token,
                Some(0),
                routed(&format!("<presence from='{}'/>", session.full_jid())).await?,
                None,
            )?;
        }
        assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
        assert!(observer.liveness().is_alive());
        assert!(!observer.links.inbound.is_closed());
        let queued = observer.take_queued();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].stanza.resolve()?.id()?, Some("queued"));
        assert!(shard.probe(&observer.handle(), &request, true)?.is_none());
        assert_eq!(observer.take_queued().len(), 1);
        Ok(())
    })
}

#[test]
fn probe_unavailable_cache_is_bounded_and_does_not_invent_history() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        let alice = account()?;
        let mut arena = Arena::try_new(Default::default())?;
        let bob =
            AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;

        let router = test_router();
        let mut shard = Shard::<GlobalChunkAllocator>::new();
        let observer = register_probe_session(&mut shard, &router, &bob, "desk")?;
        let request = routed(
            "<presence from='bob@localhost/desk' to='alice@localhost' type='probe' id='offline'/>",
        )
        .await?;
        shard.probe(&observer.handle(), &request, true)?;
        let first = observer.take_queued().pop().ok_or("missing reply")?;
        assert!(first.stanza.resolve()?.children()?.next().is_none());
        let desk = register_probe_session(&mut shard, &router, &alice, "desk")?;
        let phone = register_probe_session(&mut shard, &router, &alice, "phone")?;
        let available = routed("<presence from='alice@localhost/desk'/>").await?;
        let unavailable =
            routed("<presence from='alice@localhost/desk' type='unavailable'/>").await?;
        shard.presence(
            &alice,
            "desk",
            desk.token,
            Some(0),
            available.clone(),
            Some(unavailable.clone()),
        )?;
        shard.presence(
            &alice,
            "phone",
            phone.token,
            Some(0),
            available.clone(),
            Some(unavailable.clone()),
        )?;
        shard.end_presence(&alice, "desk", desk.token)?;
        assert!(shard.last_unavailable.is_empty());
        shard.end_presence(&alice, "phone", phone.token)?;
        let at = shard.last_unavailable[0].1.at;
        shard.probe(&observer.handle(), &request, true)?;
        let offline = observer.take_queued().pop().ok_or("missing reply")?;
        assert!(
            offline
                .stanza
                .resolve()?
                .child("delay", "urn:xmpp:delay")?
                .is_some()
        );
        shard.record_last_unavailable(alice.as_str());
        assert_eq!(shard.last_unavailable[0].1.at, at);
        for index in 0..LAST_UNAVAILABLE_PER_SHARD {
            shard.record_last_unavailable(&format!("user{index}@localhost"));
        }
        assert_eq!(shard.last_unavailable.len(), LAST_UNAVAILABLE_PER_SHARD);
        shard.probe(&observer.handle(), &request, true)?;
        let evicted = observer.take_queued().pop().ok_or("missing reply")?;
        assert!(
            evicted
                .stanza
                .resolve()?
                .child("delay", "urn:xmpp:delay")?
                .is_none()
        );
        shard.record_last_unavailable(alice.as_str());
        let replacement = register_probe_session(&mut shard, &router, &alice, "desk")?;
        shard.presence(
            &alice,
            "desk",
            replacement.token,
            Some(0),
            available.clone(),
            Some(unavailable),
        )?;
        assert!(
            !shard
                .last_unavailable
                .iter()
                .any(|(known, _)| known.as_ref() == alice.as_str())
        );
        drop(replacement);
        shard.remove(
            alice.as_str(),
            "desk",
            shard.accounts[alice.as_str()]["desk"].token,
            RetireCause::Evicted,
        );
        assert!(
            shard
                .last_unavailable
                .iter()
                .any(|(known, _)| known.as_ref() == alice.as_str())
        );
        shard.retire_account(&alice);
        assert!(
            !shard
                .last_unavailable
                .iter()
                .any(|(known, _)| known.as_ref() == alice.as_str())
        );
        Ok(())
    })
}
