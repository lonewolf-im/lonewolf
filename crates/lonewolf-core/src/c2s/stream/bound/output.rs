// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::Stanza;

use crate::router::RoutedStanza;

/// Counts stanzas the session hands to its writer, starting at one.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct OutputSequence(u64);

impl OutputSequence {
    pub(super) fn next(self) -> Self {
        Self(self.0 + 1)
    }

    #[cfg(test)]
    pub(super) const fn new(value: u64) -> Self {
        Self(value)
    }
}

pub(super) enum Outgoing<A: ChunkAllocator> {
    Routed(RoutedStanza<A>),
    Owned { stanza: Stanza, arena: Arena<A> },
}
