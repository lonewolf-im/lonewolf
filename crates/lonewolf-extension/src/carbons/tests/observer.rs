// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};

use lonewolf_storage::RedbStorage;
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, MAX_ELEMENT_DEPTH, MessageType, StanzaType};

use super::*;
use crate::archive::ArchiveId;
use crate::carbons::{FORWARD_NAMESPACE, NAMESPACE};
use crate::delivery::{
    CopyFactory, Delivery, DeliveryError, DeliveryFuture, HostLookup, SessionId, SessionTag,
    StanzaFactory,
};
use crate::observer::{MessageEvent, MessageOutcome, MessageRole};

const TARGETS: [&str; 2] = ["alice@localhost/phone", "alice@localhost/tablet"];
const HOLDERS: [SessionId; 2] = [SessionId::new(17), SessionId::new(29)];
const CHAT: &str = "<message from='alice@localhost/desk' to='bob@localhost' type='chat' id='original'><body>hello</body></message>";
const ERROR: &str = "<message from='bob@localhost' to='alice@localhost/desk' type='error' id='original'><body>hello</body><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>";

struct Call {
    account: String,
    tag: SessionTag,
    holders: Vec<SessionId>,
    copies: Vec<String>,
}

#[derive(Default)]
struct RecordingDelivery {
    calls: RefCell<Vec<Call>>,
    fail_call: Cell<Option<usize>>,
}

impl HostLookup for RecordingDelivery {
    fn is_local_host(&self, domain: &str) -> bool {
        domain == "localhost"
    }
}

impl Delivery<GlobalChunkAllocator> for RecordingDelivery {
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Ok(Arena::try_new(ArenaConfig::default())?)
    }

    fn copy_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        tag: SessionTag,
        holders: &'a [SessionId],
        build: CopyFactory<'a, GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let mut calls = self.calls.borrow_mut();
            calls.push(Call {
                account: account.as_str().into(),
                tag,
                holders: holders.into(),
                copies: Vec::new(),
            });
            if self.fail_call.get() == Some(calls.len()) {
                return Err(DeliveryError);
            }
            let copies = build(&TARGETS)?
                .iter()
                .map(|copy| {
                    let mut xml = String::new();
                    copy.resolve()?.write_xml(&mut xml)?;
                    Ok(xml)
                })
                .collect::<Result<Vec<_>, DeliveryError>>()?;
            calls.last_mut().ok_or(DeliveryError)?.copies = copies;
            Ok(())
        })
    }

    fn tag_session<'a>(&'a self, _: SessionTag) -> DeliveryFuture<'a> {
        panic!("observer must not tag a session")
    }

    fn to_available<'a>(&'a self, _: Message) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }

    fn to_tagged<'a>(&'a self, _: SessionTag, _: Message) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }

    fn push_to_tagged<'a>(
        &'a self,
        _: &'a AccountKey,
        _: SessionTag,
        _: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }

    fn retire_tagged<'a>(&'a self, _: &'a AccountKey, _: SessionTag) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        panic!("observer must use copy delivery")
    }
}

fn observe(
    event: MessageEvent<'_, GlobalChunkAllocator>,
    delivery: &RecordingDelivery,
) -> TestResult<Result<(), DeliveryError>> {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let registry = super::extension::registry()?;
    let [(name, observer)] = registry.message_observers() else {
        return Err("expected one observer".into());
    };
    assert_eq!(*name, "carbons");
    Ok(block_on(observer.observe(event, &storage, delivery)))
}

fn event<'a>(
    account: &'a AccountKey,
    stanza: &'a Message,
    role: MessageRole,
    outcome: MessageOutcome,
) -> MessageEvent<'a, GlobalChunkAllocator> {
    MessageEvent {
        account,
        stanza,
        role,
        outcome,
        archived: None,
        holders: &HOLDERS,
        rejection: None,
    }
}

fn expected_copy(original: &Message, container: &str, target: &str) -> TestResult<String> {
    Ok(format!(
        r#"<message xmlns="jabber:client" from="alice@localhost" to="{target}"{}><{container} xmlns="urn:xmpp:carbons:2"><forwarded xmlns="urn:xmpp:forward:0">{}</forwarded></{container}></message>"#,
        if original.resolve()?.stanza_type() == StanzaType::Message(MessageType::Chat) {
            " type=\"chat\""
        } else {
            ""
        },
        serialize(original)?
    ))
}

fn assert_call(call: &Call, original: &Message, container: &str) -> TestResult {
    assert_eq!(call.account, "alice@localhost");
    assert_eq!(call.tag, SessionTag::Carbons);
    assert_eq!(call.holders, HOLDERS);
    assert_eq!(call.copies.len(), TARGETS.len());
    for (copy, target) in call.copies.iter().zip(TARGETS) {
        assert_eq!(*copy, expected_copy(original, container, target)?);
    }
    Ok(())
}

#[test]
fn observer_copies_eligible_sent_messages_once() -> TestResult {
    let account = owner()?;
    let original = parse(CHAT)?;
    for outcome in [
        MessageOutcome::Routed,
        MessageOutcome::Stored,
        MessageOutcome::Forwarded,
        MessageOutcome::Rejected,
        MessageOutcome::Discarded,
    ] {
        let delivery = RecordingDelivery::default();
        observe(
            event(&account, &original, MessageRole::Sent, outcome),
            &delivery,
        )??;
        let calls = delivery.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_call(&calls[0], &original, "sent")?;
    }
    Ok(())
}

#[test]
fn observer_copies_received_messages_for_routed_and_stored_outcomes() -> TestResult {
    let account = owner()?;
    let original = parse(CHAT)?;
    for outcome in [
        MessageOutcome::Routed,
        MessageOutcome::Stored,
        MessageOutcome::Forwarded,
        MessageOutcome::Rejected,
        MessageOutcome::Discarded,
    ] {
        let delivery = RecordingDelivery::default();
        observe(
            event(&account, &original, MessageRole::Received, outcome),
            &delivery,
        )??;
        let calls = delivery.calls.borrow();
        if matches!(outcome, MessageOutcome::Routed | MessageOutcome::Stored) {
            assert_eq!(calls.len(), 1);
            assert_call(&calls[0], &original, "received")?;
        } else {
            assert!(calls.is_empty());
        }
    }
    Ok(())
}

#[test]
fn observer_ignores_ineligible_messages() -> TestResult {
    let account = owner()?;
    for xml in [
        "<message type='groupchat'><body>hello</body></message>",
        "<message type='chat'><private xmlns='urn:xmpp:carbons:2'/><body>hello</body></message>",
        "<message type='chat' xmlns='jabber:server' from='alice@localhost/desk' to='bob@remote'><body>hello</body></message>",
    ] {
        let original = parse(xml)?;
        for role in [MessageRole::Sent, MessageRole::Received] {
            let delivery = RecordingDelivery::default();
            observe(
                event(&account, &original, role, MessageOutcome::Routed),
                &delivery,
            )??;
            assert!(delivery.calls.borrow().is_empty());
        }
    }
    Ok(())
}

#[test]
fn observer_copies_rejected_errors_after_the_sent_copy() -> TestResult {
    let account = owner()?;
    let rejection = parse(ERROR)?;
    for xml in [
        CHAT,
        "<message type='groupchat'><body>hello</body></message>",
        "<message type='chat'><private xmlns='urn:xmpp:carbons:2'/></message>",
    ] {
        let original = parse(xml)?;
        let delivery = RecordingDelivery::default();
        let mut event = event(
            &account,
            &original,
            MessageRole::Sent,
            MessageOutcome::Rejected,
        );
        event.rejection = Some(&rejection);
        observe(event, &delivery)??;
        let calls = delivery.calls.borrow();
        if xml == CHAT {
            assert_eq!(calls.len(), 2);
            assert_call(&calls[0], &original, "sent")?;
            assert_call(&calls[1], &rejection, "received")?;
        } else {
            assert!(calls.is_empty());
        }
    }
    Ok(())
}

#[test]
fn observer_adds_the_senders_archive_id_only_to_sent_copies() -> TestResult {
    let account = owner()?;
    let original = parse(CHAT)?;
    let rejection = parse(ERROR)?;
    for role in [MessageRole::Sent, MessageRole::Received] {
        let delivery = RecordingDelivery::default();
        let mut event = event(
            &account,
            &original,
            role,
            if role == MessageRole::Sent {
                MessageOutcome::Rejected
            } else {
                MessageOutcome::Routed
            },
        );
        event.archived = Some(ArchiveId::new(73));
        event.rejection = Some(&rejection);
        observe(event, &delivery)??;
        let calls = delivery.calls.borrow();
        assert_eq!(calls.len(), if role == MessageRole::Sent { 2 } else { 1 });
        for (index, call) in calls.iter().enumerate() {
            for xml in &call.copies {
                let copy = parse(xml)?;
                let view = copy.resolve()?;
                let container = view
                    .child(
                        if role == MessageRole::Sent && index == 0 {
                            "sent"
                        } else {
                            "received"
                        },
                        NAMESPACE,
                    )?
                    .ok_or("container")?;
                let forwarded = container
                    .child("forwarded", FORWARD_NAMESPACE)?
                    .ok_or("forwarded")?;
                let inner = forwarded
                    .child("message", CLIENT_NAMESPACE)?
                    .ok_or("message")?;
                let id = inner.child("stanza-id", "urn:xmpp:sid:0")?;
                if role == MessageRole::Sent && index == 0 {
                    let id = id.ok_or("missing archive ID")?;
                    assert_eq!(id.attribute("by", "")?, Some(account.as_str()));
                    assert_eq!(id.attribute("id", "")?, Some("73"));
                } else {
                    assert!(id.is_none());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn observer_reports_delivery_failures() -> TestResult {
    let account = owner()?;
    let original = parse(CHAT)?;
    let rejection = parse(ERROR)?;
    for failing_call in [1, 2] {
        let delivery = RecordingDelivery::default();
        delivery.fail_call.set(Some(failing_call));
        let mut event = event(
            &account,
            &original,
            MessageRole::Sent,
            MessageOutcome::Rejected,
        );
        event.rejection = Some(&rejection);
        assert!(observe(event, &delivery)?.is_err());
        let calls = delivery.calls.borrow();
        assert_eq!(calls.len(), failing_call);
        assert!(calls[failing_call - 1].copies.is_empty());
        if failing_call == 2 {
            assert_call(&calls[0], &original, "sent")?;
        }
    }
    Ok(())
}

#[test]
fn observer_skips_copies_above_tree_limits_and_preserves_the_original() -> TestResult {
    let account = owner()?;
    for depth in [MAX_ELEMENT_DEPTH - 3, MAX_ELEMENT_DEPTH - 2] {
        let original = parse(&format!(
            "<message type='chat'>{}{}</message>",
            "<x>".repeat(depth - 1),
            "</x>".repeat(depth - 1)
        ))?;
        let before = serialize(&original)?;
        for role in [MessageRole::Sent, MessageRole::Received] {
            let delivery = RecordingDelivery::default();
            observe(
                event(&account, &original, role, MessageOutcome::Routed),
                &delivery,
            )??;
            let calls = delivery.calls.borrow();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0].copies.len(),
                if depth == MAX_ELEMENT_DEPTH - 3 { 2 } else { 0 }
            );
            assert_eq!(serialize(&original)?, before);
        }
    }
    Ok(())
}
