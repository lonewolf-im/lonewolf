// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::{RosterSnapshot, RosterVersion};

/// How a roster get is answered, given the version the client says it holds.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Answer {
    /// The whole roster; `stamped` when the client asked for versioning.
    Full { stamped: bool },
    /// Nothing, because the client already holds the current roster.
    Unchanged,
}

/// Only an exact match with the current version is answered with nothing; any other
/// version receives the whole roster, so a client never depends on pushes it may have
/// missed.
pub(super) fn answer(known: Option<&str>, snapshot: &RosterSnapshot) -> Answer {
    match known {
        None => Answer::Full { stamped: false },
        Some(known) if known.parse::<u64>().map(RosterVersion::new) == Ok(snapshot.version) => {
            Answer::Unchanged
        }
        Some(_) => Answer::Full { stamped: true },
    }
}
