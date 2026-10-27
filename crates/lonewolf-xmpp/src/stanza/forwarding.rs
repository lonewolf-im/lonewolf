// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};

use super::{BuildError, Element};

pub const NAMESPACE: &str = "urn:xmpp:forward:0";

/// Shares prepared elements from `arena` without copying their content.
/// The caller must supply a stanza in its original namespace and, if present, a valid XEP-0203 delay.
pub fn build_in<A: ChunkAllocator>(
    stanza: Element,
    delay: Option<Element>,
    arena: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut builder = Element::builder_in("forwarded", NAMESPACE, arena)?;
    if let Some(delay) = delay {
        builder = builder.child(delay)?;
    }
    builder.child(stanza)?.build()
}

#[cfg(test)]
mod tests;
