// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{MAX_PART_LEN, normalize_domainpart};
use lonewolf_xmpp::stanza::{BuildError, ElementRef, Stanza, StanzaBuilder, StanzaKind, StanzaRef};

const DELAY_NAMESPACE: &str = "urn:xmpp:delay";

/// Removes delay notations whose sender claims a domain that `served` accepts.
///
/// Returns the stanza unchanged, without allocating, when it carries no such notation.
pub(crate) fn discard_forged<A: ChunkAllocator>(
    stanza: Stanza,
    arena: &mut Arena<A>,
    served: impl Fn(&str) -> bool + Copy,
) -> Result<Stanza, BuildError> {
    if !carries_forged(&stanza.resolve(arena)?, served)? {
        return Ok(stanza);
    }
    discard_forged_from(stanza.derive_in(arena)?, served)?.build()
}

pub(crate) fn carries_forged<R: ArenaRead>(
    stanza: &StanzaRef<'_, R>,
    served: impl Fn(&str) -> bool + Copy,
) -> Result<bool, HandleError> {
    if stanza.kind() == StanzaKind::Iq {
        return Ok(false);
    }
    for child in stanza.children()? {
        if is_forged(&child?, served)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn discard_forged_from<'a, A: ChunkAllocator>(
    builder: StanzaBuilder<'a, A>,
    served: impl Fn(&str) -> bool + Copy,
) -> Result<StanzaBuilder<'a, A>, BuildError> {
    builder.retain_children(|child| Ok(!is_forged(child, served)?))
}

fn is_forged<R: ArenaRead>(
    element: &ElementRef<'_, R>,
    served: impl Fn(&str) -> bool,
) -> Result<bool, HandleError> {
    if element.name() != "delay" || element.namespace() != DELAY_NAMESPACE {
        return Ok(false);
    }
    Ok(element
        .attribute("from", "")?
        .is_some_and(|from| names_served_domain(from, served)))
}

fn names_served_domain(from: &str, served: impl Fn(&str) -> bool) -> bool {
    if served(from) {
        return true;
    }
    if skips_normalization(from) {
        return false;
    }
    let mut ip_buffer = [0; MAX_PART_LEN];
    normalize_domainpart(from, &mut ip_buffer).is_ok_and(|domain| served(&domain))
}

// Lowercase ASCII is already canonical, and an address with a localpart or resource never names the server.
fn skips_normalization(address: &str) -> bool {
    !address.ends_with('.')
        && address.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.@/".contains(&byte)
        })
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::num::NonZeroUsize;

    use futures_util::FutureExt;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn served(domain: &str) -> bool {
        matches!(domain, "localhost" | "upload.localhost")
    }

    fn parsed(xml: &str) -> TestResult<(Stanza, Arena<GlobalChunkAllocator>)> {
        let input = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
        );
        let mut parser = XmppParser::new(
            input.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(4096).ok_or("invalid stanza limit")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().now_or_never().ok_or("pending")??,
            Some(StreamEvent::StreamStart { .. })
        ));
        match parser.next_event().now_or_never().ok_or("pending")?? {
            Some(StreamEvent::Stanza(stanza)) => Ok(stanza.into_parts()),
            _ => Err("expected stanza".into()),
        }
    }

    fn discarded(xml: &str) -> TestResult<String> {
        let (stanza, mut arena) = parsed(xml)?;
        let cleaned = discard_forged(stanza, &mut arena, served)?;
        let mut output = String::new();
        cleaned.resolve(&arena)?.write_xml(&mut output)?;
        Ok(output)
    }

    #[test]
    fn served_domain_delays_are_removed_and_other_children_keep_their_order() -> TestResult {
        let output = discarded(
            "<message to='bob@localhost'><delay xmlns='urn:xmpp:delay' from='localhost' stamp='2000-01-01T00:00:00Z'/><body>hi</body><delay xmlns='urn:xmpp:delay' from='muc.example' stamp='2001-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' stamp='2002-01-01T00:00:00Z'/><delay xmlns='urn:other' from='localhost'/><delay xmlns='urn:xmpp:delay' from='upload.localhost' stamp='2003-01-01T00:00:00Z'/></message>",
        )?;
        assert_eq!(
            output,
            "<message xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" to=\"bob@localhost\"><body>hi</body><delay xmlns=\"urn:xmpp:delay\" from=\"muc.example\" stamp=\"2001-01-01T00:00:00Z\"/><delay xmlns=\"urn:xmpp:delay\" stamp=\"2002-01-01T00:00:00Z\"/><delay xmlns=\"urn:other\" from=\"localhost\"/></message>"
        );
        Ok(())
    }

    #[test]
    fn non_canonical_spellings_of_a_served_domain_are_removed() -> TestResult {
        let output = discarded(
            "<presence><delay xmlns='urn:xmpp:delay' from='LocalHost.' stamp='2000-01-01T00:00:00Z'/></presence>",
        )?;
        assert_eq!(
            output,
            "<presence xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\"/>"
        );
        Ok(())
    }

    #[test]
    fn addresses_within_a_served_domain_are_not_the_server() -> TestResult {
        let xml = "<message><delay xmlns='urn:xmpp:delay' from='room@localhost' stamp='2000-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' from='localhost/admin' stamp='2000-01-01T00:00:00Z'/></message>";
        assert_eq!(
            discarded(xml)?,
            "<message xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\"><delay xmlns=\"urn:xmpp:delay\" from=\"room@localhost\" stamp=\"2000-01-01T00:00:00Z\"/><delay xmlns=\"urn:xmpp:delay\" from=\"localhost/admin\" stamp=\"2000-01-01T00:00:00Z\"/></message>"
        );
        Ok(())
    }

    #[test]
    fn stanzas_without_forged_delays_are_returned_unchanged() -> TestResult {
        let (stanza, mut arena) = parsed(
            "<message><body>hi</body><delay xmlns='urn:xmpp:delay' from='example.org' stamp='2000-01-01T00:00:00Z'/></message>",
        )?;
        let used = arena.stats().used_bytes;
        let cleaned = discard_forged(stanza, &mut arena, served)?;
        assert_eq!(arena.stats().used_bytes, used);
        assert_eq!(cleaned.resolve(&arena)?.children()?.count(), 2);
        Ok(())
    }

    #[test]
    fn iq_payloads_are_never_inspected() -> TestResult {
        let (stanza, mut arena) = parsed(
            "<iq type='set' id='1'><delay xmlns='urn:xmpp:delay' from='localhost' stamp='2000-01-01T00:00:00Z'/></iq>",
        )?;
        let cleaned = discard_forged(stanza, &mut arena, served)?;
        assert_eq!(cleaned.resolve(&arena)?.children()?.count(), 1);
        Ok(())
    }
}
