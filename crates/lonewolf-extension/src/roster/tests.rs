// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use async_lock::Mutex;
use lonewolf_storage::roster::{RosterSnapshot, RosterVersion};
use lonewolf_util::arena::{Arena, ArenaConfig};

use super::{RosterOrder, build_response};
use crate::iq::IqEffect;

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
