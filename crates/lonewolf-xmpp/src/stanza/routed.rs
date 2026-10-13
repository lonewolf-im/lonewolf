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

    /// Freezes one arena shared by every stanza.
    pub fn from_parts_shared(stanzas: Vec<Stanza>, arena: Arena<A>) -> Vec<Self> {
        let mut stanzas = stanzas.into_iter();
        let Some(last) = stanzas.next_back() else {
            return Vec::new();
        };
        let arena = arena.freeze();
        let mut routed = Vec::with_capacity(stanzas.len() + 1);
        routed.extend(stanzas.map(|stanza| Self {
            stanza,
            arena: arena.clone(),
        }));
        routed.push(Self {
            stanza: last,
            arena,
        });
        routed
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stanza::{Element, MessageType, StanzaNamespace, StanzaType};

    #[test]
    fn from_parts_shared_resolves_three_stanzas_in_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut arena = Arena::try_new(Default::default())?;
        let mut stanzas = Vec::with_capacity(3);
        for index in ["0", "1", "2"] {
            let result = Element::builder_in("result", "urn:lonewolf:test:results", &mut arena)?
                .attribute("index", "", index)?
                .build()?;
            stanzas.push(
                Stanza::builder_in(
                    StanzaType::Message(MessageType::Normal),
                    StanzaNamespace::Client,
                    &mut arena,
                )
                .child(result)?
                .build()?,
            );
        }
        let routed = RoutedStanza::from_parts_shared(stanzas, arena);
        assert_eq!(routed.len(), 3);
        for (stanza, index) in routed.iter().zip(["0", "1", "2"]) {
            let view = stanza.resolve()?;
            assert_eq!(view.stanza_type(), StanzaType::Message(MessageType::Normal));
            let result = view
                .children()?
                .next()
                .transpose()?
                .ok_or("missing result")?;
            assert_eq!(result.namespace(), "urn:lonewolf:test:results");
            assert_eq!(result.name(), "result");
            assert_eq!(result.attribute("index", "")?, Some(index));
        }
        Ok(())
    }
}
