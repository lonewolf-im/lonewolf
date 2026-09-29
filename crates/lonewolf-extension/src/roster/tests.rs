// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::hash::BuildHasher;
use std::sync::Arc;

use futures_executor::block_on;
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::roster::redb::RedbRosterRepository;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{Element, RoutedStanza};

use super::{NAMESPACE, Roster, RosterSequencer};
use crate::delivery::{Delivery, DeliveryError, DeliveryFuture, SessionTag, StanzaFactory};
use crate::iq::{IqHandler, IqRequest, IqRequestType};
use crate::presence::{PresenceHandler, PresenceUpdate};

type TestRoster = Roster<RedbRosterRepository, RedbAccountRepository>;

#[derive(Default)]
struct RecordingDelivery {
    tags: RefCell<Vec<SessionTag>>,
    pushes: RefCell<Vec<String>>,
}

impl Delivery<GlobalChunkAllocator> for RecordingDelivery {
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Arena::try_new(ArenaConfig::default()).map_err(|_| DeliveryError)
    }

    fn tag_session<'a>(&'a self, tag: SessionTag) -> DeliveryFuture<'a> {
        self.tags.borrow_mut().push(tag);
        Box::pin(async { Ok(()) })
    }

    fn to_available<'a>(&'a self, _: RoutedStanza<GlobalChunkAllocator>) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_tagged<'a>(
        &'a self,
        _: SessionTag,
        _: RoutedStanza<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        _: SessionTag,
        mut build: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        let full_jid = format!("{}/desk", account.as_str());
        let mut arena =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let to = Jid::parse_in(&full_jid, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let push = build(to, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let mut xml = String::new();
        push.resolve(&arena)
            .and_then(|push| {
                push.write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write push"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        self.pushes.borrow_mut().push(xml);
        Box::pin(async { Ok(()) })
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn roster() -> (tempfile::TempDir, TestRoster) {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
    let database = RedbDatabase::open(directory.path().join("lonewolf.dat"))
        .unwrap_or_else(|error| panic!("{error}"));
    let repository = RedbRosterRepository::from_database(database.clone())
        .unwrap_or_else(|error| panic!("{error}"));
    let accounts =
        RedbAccountRepository::from_database(database).unwrap_or_else(|error| panic!("{error}"));
    let roster = Roster {
        repository,
        accounts,
        order: RosterSequencer::new(),
    };
    (directory, roster)
}

fn handle_iq(
    roster: &TestRoster,
    kind: IqRequestType,
    payload: &str,
    delivery: &RecordingDelivery,
) {
    let mut request =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let mut response =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let sender = Jid::parse_in("alice@example.com/desk", &mut request)
        .unwrap_or_else(|error| panic!("{error}"));
    let item = (!payload.is_empty()).then(|| {
        Element::builder_in("item", NAMESPACE, &mut request)
            .and_then(|item| item.attribute("jid", "", payload))
            .and_then(|item| item.build())
            .unwrap_or_else(|error| panic!("{error:?}"))
    });
    let mut query = Element::builder_in("query", NAMESPACE, &mut request)
        .unwrap_or_else(|error| panic!("{error:?}"));
    if let Some(item) = item {
        query = query
            .child(item)
            .unwrap_or_else(|error| panic!("{error:?}"));
    }
    let query = query.build().unwrap_or_else(|error| panic!("{error:?}"));
    let sender = sender
        .resolve(&request)
        .unwrap_or_else(|error| panic!("{error}"));
    let payload = query
        .resolve(&request)
        .unwrap_or_else(|error| panic!("{error}"));
    block_on(IqHandler::<GlobalChunkAllocator>::handle(
        roster,
        IqRequest {
            sender,
            target: sender.bare(),
            kind,
            payload,
        },
        &mut response,
        delivery,
    ))
    .unwrap_or_else(|error| panic!("{error:?}"));
}

#[test]
fn roster_retrieval_tags_the_requesting_session_as_interested() {
    let (_directory, roster) = roster();
    let delivery = RecordingDelivery::default();
    handle_iq(&roster, IqRequestType::Get, "", &delivery);
    assert_eq!(*delivery.tags.borrow(), [SessionTag::Interested]);
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn roster_update_pushes_the_item_to_interested_resources() {
    let (_directory, roster) = roster();
    let delivery = RecordingDelivery::default();
    handle_iq(&roster, IqRequestType::Set, "bob@example.com", &delivery);
    assert!(delivery.tags.borrow().is_empty());
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert!(
        pushes[0].contains(r#"to="alice@example.com/desk""#),
        "{pushes:?}"
    );
    assert!(pushes[0].contains(r#"id="roster-1""#), "{pushes:?}");
    assert!(
        pushes[0].contains(r#"<item jid="bob@example.com" subscription="none"/>"#),
        "{pushes:?}"
    );
}

#[test]
fn availability_audience_holds_the_owner_order_until_dropped() {
    let (_directory, roster) = roster();
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let sender = Jid::parse_in("bob@example.com/phone", &mut arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let sender = sender
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let owner = AccountKey::try_from(sender.bare()).unwrap_or_else(|error| panic!("{error}"));
    let audience = block_on(PresenceHandler::<GlobalChunkAllocator>::audience(
        &roster,
        PresenceUpdate {
            sender,
            available: true,
        },
    ))
    .unwrap_or_else(|error| panic!("{error:?}"))
    .unwrap_or_else(|| panic!("expected an audience"));
    assert!(audience.pending.is_empty());
    assert!(audience.subscribers.is_empty());
    let index = (roster.order.hash_state.hash_one(&owner) as usize) % roster.order.shards.len();
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_none()
    );
    drop(audience);
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_some()
    );
}
