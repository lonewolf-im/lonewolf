// SPDX-License-Identifier: Apache-2.0

use std::hash::BuildHasher;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use async_lock::Mutex;
use futures_executor::block_on;
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::roster::redb::RedbRosterRepository;
use lonewolf_storage::roster::{
    RosterItem, RosterJid, RosterSnapshot, RosterSubscription, RosterVersion,
};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{PresenceType, Stanza, StanzaNamespace, StanzaType};

use super::{Roster, RosterOrder, RosterPush, RosterSequencer, build_response};
use crate::iq::IqEffect;
use crate::presence::{
    PresenceDirection, PresenceEffect, PresenceHandler, PresenceRequest, PresenceRequestType,
};

#[test]
fn successful_response_marks_the_session_as_roster_interested() {
    let Ok(mut arena) = Arena::try_new(ArenaConfig::default()) else {
        panic!("cannot create response arena");
    };
    let lock = Arc::new(Mutex::new(()));
    let Some(guard) = Arc::clone(&lock).try_lock_arc() else {
        panic!("cannot lock roster order");
    };
    let order = RosterOrder::new(guard);
    let Ok(response) = build_response(
        RosterSnapshot {
            version: RosterVersion::new(0),
            items: Vec::new(),
        },
        order,
        &mut arena,
    ) else {
        panic!("cannot build roster response");
    };

    assert!(Arc::clone(&lock).try_lock_arc().is_none());
    let effect = response.into_parts().1;
    assert!(matches!(effect, IqEffect::MarkRosterInterested(_)));
    drop(effect);
    assert!(Arc::clone(&lock).try_lock_arc().is_some());
}

#[test]
fn availability_replay_holds_recipient_order_until_the_transition_finishes() {
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
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let sender = Jid::parse_in("bob@example.com/phone", &mut arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let target = sender.bare();
    let stanza = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Available),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(sender))
    .and_then(|builder| builder.to(Some(target)))
    .and_then(|builder| builder.build())
    .unwrap_or_else(|error| panic!("{error:?}"));
    let sender = sender
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let owner = AccountKey::try_from(sender.bare()).unwrap_or_else(|error| panic!("{error}"));
    let stanza = stanza
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let target = target
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let effect = block_on(roster.handle(PresenceRequest {
        direction: PresenceDirection::Outbound,
        kind: PresenceRequestType::Available,
        sender,
        target,
        stanza,
    }))
    .unwrap_or_else(|error| panic!("{error:?}"));
    let PresenceEffect::Replay { order, pending } = effect else {
        panic!("expected pending replay");
    };
    assert!(pending.is_empty());
    let index = (roster.order.hash_state.hash_one(&owner) as usize) % roster.order.shards.len();
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_none()
    );
    drop(order);
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_some()
    );
}

#[test]
fn approval_push_holds_order_through_followup_delivery() {
    let lock = Arc::new(Mutex::new(()));
    let guard = Arc::clone(&lock)
        .try_lock_arc()
        .unwrap_or_else(|| panic!("cannot lock roster order"));
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let jid =
        Jid::parse_in("bob@example.com", &mut arena).unwrap_or_else(|error| panic!("{error}"));
    let jid = RosterJid::from(
        jid.resolve(&arena)
            .unwrap_or_else(|error| panic!("{error}")),
    );
    let push = RosterPush::new(
        RosterOrder::new(guard),
        RosterItem {
            jid,
            name: None,
            groups: Vec::new(),
            subscription: RosterSubscription::default(),
        },
        RosterVersion::new(1),
    );
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let (finish_tx, finish_rx) = mpsc::sync_channel(0);
    let work = thread::spawn(move || {
        block_on(push.with_mutation(|_| async move {
            started_tx
                .send(())
                .unwrap_or_else(|error| panic!("{error}"));
            finish_rx.recv().unwrap_or_else(|error| panic!("{error}"));
        }));
    });
    started_rx.recv().unwrap_or_else(|error| panic!("{error}"));
    assert!(Arc::clone(&lock).try_lock_arc().is_none());
    finish_tx.send(()).unwrap_or_else(|error| panic!("{error}"));
    work.join()
        .unwrap_or_else(|_| panic!("approval work panicked"));
    assert!(Arc::clone(&lock).try_lock_arc().is_some());
}
