// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;

use compio::runtime::Runtime;
use futures_util::poll;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::parser::ParserConfig;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";

fn reader(
    input: &[u8],
    burst: usize,
) -> Result<Reader<GlobalChunkAllocator, &[u8]>, Box<dyn Error>> {
    Ok(Reader {
        parser: XmppParser::new(
            input,
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ),
        stanzas: StanzaLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(burst).ok_or("invalid burst")?,
        ),
    })
}

#[test]
fn only_complete_stanzas_consume_tokens_including_all_iq_types_and_server_namespace() -> TestResult
{
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER} \t\r\n<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/><response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><message/><presence/><iq type='get' id='get'><query xmlns='urn:test'/></iq><iq type='set' id='set'><query xmlns='urn:test'/></iq><iq type='result' id='result'/><iq type='error' id='error'><error type='cancel'/></iq><message xmlns='jabber:server' from='alice@localhost' to='localhost'/><message/></stream:stream>");
        let mut reader = reader(input.as_bytes(), 7)?;
        assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::StreamStart { .. }))));
        for _ in 0..3 {
            assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::Element(_)))));
        }
        for index in 0..7 {
            match reader.next_event().await {
                Ok(Some(StreamEvent::Stanza(_))) => {}
                Err(outcome) => panic!("stanza {index}: {outcome:?}"),
                _ => panic!("expected stanza {index}"),
            }
        }
        let mut depleted = pin!(reader.next_event());
        assert!(poll!(depleted.as_mut()).is_pending());
        Ok(())
    })
}

#[test]
fn stream_restart_preserves_depleted_allowance_and_does_not_charge_the_header() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER}<message/>{HEADER}<message/>");
        let mut reader = reader(input.as_bytes(), 1)?;
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::Stanza(_)))
        ));
        let mut reader = reader.restart().map_err(|error| format!("{error:?}"))?;
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        let mut depleted = pin!(reader.next_event());
        assert!(poll!(depleted.as_mut()).is_pending());
        Ok(())
    })
}

#[test]
fn stream_footer_does_not_wait_for_depleted_stanza_allowance() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER}<message/></stream:stream>");
        let mut reader = reader(input.as_bytes(), 1)?;
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::Stanza(_)))
        ));
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamEnd))
        ));
        Ok(())
    })
}

#[test]
fn cancelling_a_token_wait_releases_its_single_parsed_stanza() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER}<message/><message/><message/>");
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("invalid pool size")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let mut reader = Reader {
            parser: XmppParser::new(
                input.as_bytes(),
                ParserConfig {
                    max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                    arena: ArenaConfig::default(),
                },
                pool.clone(),
            ),
            stanzas: StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
        };
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::Stanza(_)))
        ));
        let live_chunks = || {
            pool.stats()
                .buckets
                .iter()
                .map(|bucket| bucket.total_chunks - bucket.available_chunks)
                .sum::<usize>()
        };
        assert_eq!(live_chunks(), 0);
        let mut waiting = Box::pin(reader.next_event());
        assert!(poll!(waiting.as_mut()).is_pending());
        assert!((1..=3).contains(&live_chunks()));
        assert_eq!(pool.stats().heap_allocation_count, 0);
        drop(waiting);
        assert_eq!(live_chunks(), 0);
        Ok(())
    })
}
