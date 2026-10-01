// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::{RosterItem, RosterMutation, RosterSnapshot, RosterVersion};

/// How a roster get is answered, given the version the client says it holds.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Answer {
    /// The whole roster; `stamped` when the client asked for versioning.
    Full { stamped: bool },
    /// Nothing, because the client already holds the current roster.
    Unchanged,
    /// Nothing, followed by one push per item changed after `since`.
    Changes { since: RosterVersion },
}

/// A removal cannot be expressed as a push without a record of what was removed, so a
/// client whose version predates the last removal receives the whole roster. A resource
/// that is already interested was pushed every change after `interested_since`, or was
/// evicted, so it is answered from that point: nothing when it holds that version or a
/// later one, and the whole roster when it fell behind it, since a replay would trail
/// pushes it already has.
pub(super) fn answer(
    known: Option<&str>,
    snapshot: &RosterSnapshot,
    interested_since: Option<RosterVersion>,
) -> Answer {
    let Some(known) = known else {
        return Answer::Full { stamped: false };
    };
    let Ok(known) = known.parse::<u64>().map(RosterVersion::new) else {
        return Answer::Full { stamped: true };
    };
    if known == snapshot.version {
        return Answer::Unchanged;
    }
    if known > snapshot.version {
        return Answer::Full { stamped: true };
    }
    match interested_since {
        Some(since) if known >= since => Answer::Unchanged,
        Some(_) => Answer::Full { stamped: true },
        None if known >= snapshot.last_removal => Answer::Changes { since: known },
        None => Answer::Full { stamped: true },
    }
}

/// The items changed after `since`, oldest change first, so the last push carries the
/// current version.
pub(super) fn changes_since(
    items: Vec<RosterMutation<RosterItem>>,
    since: RosterVersion,
) -> Vec<RosterMutation<RosterItem>> {
    let mut changed: Vec<_> = items
        .into_iter()
        .filter(|entry| entry.version > since)
        .collect();
    changed.sort_by_key(|entry| entry.version);
    changed
}
