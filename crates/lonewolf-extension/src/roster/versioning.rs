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
/// client whose version predates the last removal receives the whole roster instead. So
/// does a client with deliveries queued ahead of the reply: a replay would repeat what
/// those deliveries carry, or send older changes after them.
pub(super) fn answer(known: Option<&str>, snapshot: &RosterSnapshot, preceded: bool) -> Answer {
    let Some(known) = known else {
        return Answer::Full { stamped: false };
    };
    let Ok(known) = known.parse::<u64>().map(RosterVersion::new) else {
        return Answer::Full { stamped: true };
    };
    if known == snapshot.version {
        Answer::Unchanged
    } else if known < snapshot.version && known >= snapshot.last_removal && !preceded {
        Answer::Changes { since: known }
    } else {
        Answer::Full { stamped: true }
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
