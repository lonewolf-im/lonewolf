// SPDX-License-Identifier: Apache-2.0

mod copy;
mod rules;

use std::error::Error;
use std::num::NonZeroUsize;

use futures_executor::block_on;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::RoutedStanza;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Message = RoutedStanza<GlobalChunkAllocator>;

fn arena() -> TestResult<Arena<GlobalChunkAllocator>> {
    Ok(Arena::try_new(ArenaConfig {
        max_reserved_bytes: NonZeroUsize::new(33_554_432).ok_or("zero arena budget")?,
        ..ArenaConfig::default()
    })?)
}

fn owner() -> TestResult<AccountKey> {
    let mut arena = arena()?;
    let jid = Jid::parse_in("alice@localhost", &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

fn parse(xml: &str) -> TestResult<Message> {
    block_on(async {
        let input = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}</stream:stream>"
        );
        let mut parser = XmppParser::new(
            input.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(2_097_152).ok_or("zero limit")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ));
        let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
            return Err("expected one stanza".into());
        };
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamEnd)
        ));
        assert!(parser.next_event().await?.is_none());
        Ok(RoutedStanza::from_parsed(parsed))
    })
}

fn serialize(stanza: &Message) -> TestResult<String> {
    let mut output = String::new();
    stanza.resolve()?.write_xml(&mut output)?;
    Ok(output)
}
