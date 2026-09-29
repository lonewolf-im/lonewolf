// SPDX-License-Identifier: Apache-2.0

use std::hash::BuildHasher;
use std::sync::Arc;

use async_lock::Mutex;
use futures_executor::block_on;
use lonewolf_storage::RedbDatabase;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::account::redb::RedbAccountRepository;
use lonewolf_storage::roster::redb::RedbRosterRepository;
use lonewolf_storage::roster::{RosterSnapshot, RosterVersion};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use super::{Roster, RosterOrder, RosterSequencer, build_response};
use crate::iq::IqEffect;
use crate::presence::{PresenceHandler, PresenceUpdate};

#[test]
fn successful_response_marks_the_session_as_roster_interested() {
    let Ok(mut arena) = Arena::try_new(ArenaConfig::default()) else {
        panic!("cannot create response arena");
    };
    let lock = Arc::new(Mutex::new(()));
    let Some(guard) = Arc::clone(&lock).try_lock_arc() else {
        panic!("cannot lock roster order");
    };
    let order = RosterOrder {
        _first: guard,
        _second: None,
    };
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
fn availability_broadcast_holds_the_owner_order_until_dropped() {
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
    let sender = sender
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let owner = AccountKey::try_from(sender.bare()).unwrap_or_else(|error| panic!("{error}"));
    let broadcast = block_on(PresenceHandler::<GlobalChunkAllocator>::update(
        &roster,
        PresenceUpdate {
            sender,
            available: true,
        },
    ))
    .unwrap_or_else(|error| panic!("{error:?}"))
    .unwrap_or_else(|| panic!("expected a broadcast"));
    assert!(broadcast.pending.is_empty());
    assert!(broadcast.subscribers.is_empty());
    let index = (roster.order.hash_state.hash_one(&owner) as usize) % roster.order.shards.len();
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_none()
    );
    drop(broadcast);
    assert!(
        Arc::clone(&roster.order.shards[index])
            .try_lock_arc()
            .is_some()
    );
}
