// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::{RosterSnapshot, RosterVersion};
use lonewolf_util::arena::{Arena, ArenaConfig};

use super::build_response;
use crate::iq::IqEffect;

#[test]
fn successful_response_marks_the_session_as_roster_interested() {
    let Ok(mut arena) = Arena::try_new(ArenaConfig::default()) else {
        panic!("cannot create response arena");
    };
    let Ok(response) = build_response(
        RosterSnapshot {
            version: RosterVersion::new(0),
            items: Vec::new(),
        },
        &mut arena,
    ) else {
        panic!("cannot build roster response");
    };

    assert_eq!(response.into_parts().1, IqEffect::MarkRosterInterested);
}
