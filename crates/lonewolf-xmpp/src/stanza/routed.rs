// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator, HandleError, SharedArena};

use super::{Stanza, StanzaRef};
use crate::parser::Parsed;

/// Retains a parsed stanza and its immutable arena across workers.
pub struct RoutedStanza<A: ChunkAllocator> {
    stanza: Stanza,
    arena: SharedArena<A>,
}

impl<A: ChunkAllocator> RoutedStanza<A> {
    pub fn from_parsed(parsed: Parsed<Stanza, A>) -> Self {
        let (stanza, arena) = parsed.into_parts();
        Self::from_parts(stanza, arena)
    }

    pub fn from_parts(stanza: Stanza, arena: Arena<A>) -> Self {
        Self {
            stanza,
            arena: arena.freeze(),
        }
    }

    /// Freezes one arena shared by both stanzas.
    pub fn from_parts_pair(first: Stanza, second: Stanza, arena: Arena<A>) -> (Self, Self) {
        let arena = arena.freeze();
        (
            Self {
                stanza: first,
                arena: arena.clone(),
            },
            Self {
                stanza: second,
                arena,
            },
        )
    }

    pub fn resolve(&self) -> Result<StanzaRef<'_, SharedArena<A>>, HandleError> {
        self.stanza.resolve(&self.arena)
    }
}

impl<A: ChunkAllocator> Clone for RoutedStanza<A> {
    fn clone(&self) -> Self {
        Self {
            stanza: self.stanza,
            arena: self.arena.clone(),
        }
    }
}
