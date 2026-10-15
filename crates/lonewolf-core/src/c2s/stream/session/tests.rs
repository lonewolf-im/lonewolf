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

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestReader = Reader<GlobalChunkAllocator, std::io::Cursor<Vec<u8>>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";

fn reader(input: &[u8], burst: usize) -> TestResult<TestReader> {
    Ok(Reader::new(
        XmppParser::new(
            std::io::Cursor::new(input.to_vec()),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        ),
        StanzaLimiter::new(
            NonZeroUsize::MIN,
            NonZeroUsize::new(burst).ok_or("invalid burst")?,
        ),
    ))
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
fn rejected_reader_restart_keeps_transport_available_for_close() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER}<message/>");
        let mut reader = reader(input.as_bytes(), 1)?;
        assert!(matches!(reader.restart(), Err(ParseError::UnexpectedEvent)));
        assert!(reader.is_failed());
        let retained = reader
            .take_input()
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        assert_eq!(retained.get_ref().as_slice(), input.as_bytes());
        assert_eq!(retained.position(), 0);
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
        reader.restart().map_err(|error| format!("{error:?}"))?;
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
fn dropping_reader_releases_valid_and_rejected_stanzas_after_a_cancelled_token_wait() -> TestResult
{
    for waiting in ["<message/>", "<iq type='unknown'/>"] {
        Runtime::new()?.block_on(async {
            let input = format!("{HEADER}<message/>{waiting}<message/>");
            let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
                total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("invalid pool size")?,
                shards_per_bucket: NonZeroUsize::MIN,
            })?);
            let mut reader = Reader::new(
                XmppParser::new(
                    std::io::Cursor::new(input.into_bytes()),
                    ParserConfig {
                        max_stanza_bytes: NonZeroUsize::new(10_000).ok_or("invalid stanza size")?,
                        arena: ArenaConfig::default(),
                    },
                    pool.clone(),
                ),
                StanzaLimiter::new(NonZeroUsize::MIN, NonZeroUsize::MIN),
            );
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
            assert!((1..=3).contains(&live_chunks()));
            drop(reader);
            assert_eq!(live_chunks(), 0);
            Ok::<(), Box<dyn Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn rejected_requests_and_responses_each_consume_a_stanza_token() -> TestResult {
    Runtime::new()?.block_on(async {
        let input = format!("{HEADER}<iq type='unknown'/><iq type='result'/><message/>");
        let mut reader = reader(input.as_bytes(), 2)?;
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        for _ in 0..2 {
            assert!(matches!(
                reader.next_event().await,
                Ok(Some(StreamEvent::RejectedStanza(_)))
            ));
        }
        let mut depleted = pin!(reader.next_event());
        assert!(poll!(depleted.as_mut()).is_pending());
        Ok(())
    })
}

#[test]
fn peer_error_classifier_ignores_text_and_requires_exact_root_namespace() -> TestResult {
    Runtime::new()?.block_on(async {
        for (xml, expected) in [
            ("<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>private</text></stream:error>", Some(StreamErrorCondition::PolicyViolation)),
            ("<stream:error><unsupported-feature xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UnsupportedFeature)),
            ("<stream:error><unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<stream:error/>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<stream:error><bad-format xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>", Some(StreamErrorCondition::UndefinedCondition)),
            ("<error xmlns='urn:other'><bad-format xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></error>", None),
        ] {
            let mut input = reader(format!("{HEADER}{xml}").as_bytes(), 1)?;
            input.next_event().await.map_err(|outcome| format!("{outcome:?}"))?;
            let event = input.next_event().await.map_err(|outcome| format!("{outcome:?}"))?.ok_or("missing event")?;
            assert_eq!(peer_stream_error(&event).map_err(|outcome| format!("{outcome:?}"))?, expected);
        }
        Ok(())
    })
}

#[test]
fn closing_repolls_a_preserved_token_wait_without_a_timer_wakeup() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut reader = reader(
            format!("{HEADER}<message/><message/></stream:stream>").as_bytes(),
            1,
        )?;
        reader
            .next_event()
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        reader
            .next_event()
            .await
            .map_err(|outcome| format!("{outcome:?}"))?;
        let mut wait = Box::pin(reader.next_event());
        assert!(poll!(wait.as_mut()).is_pending());
        drop(wait);
        reader.closing();
        assert!(matches!(
            poll!(Box::pin(reader.next_event()).as_mut()),
            Poll::Ready(Ok(Some(StreamEvent::Stanza(_))))
        ));
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamEnd))
        ));
        Ok(())
    })
}

#[test]
fn closing_bypasses_a_depleted_byte_bucket() -> TestResult {
    Runtime::new()?.block_on(async {
        let closing = Rc::new(Cell::new(ReadMode::Open));
        let source = std::io::Cursor::new(format!("{HEADER}</stream:stream>").into_bytes());
        let mut input = ClosingInput::new(
            RateLimitedReader::new(source, NonZeroUsize::MIN, NonZeroUsize::MIN),
            Rc::clone(&closing),
        );
        let mut first = [0];
        tokio::io::AsyncReadExt::read_exact(&mut input, &mut first).await?;
        let mut rest = Vec::new();
        let mut pending = Box::pin(tokio::io::AsyncReadExt::read_to_end(&mut input, &mut rest));
        assert!(poll!(pending.as_mut()).is_pending());
        closing.set(ReadMode::Closing);
        assert!(poll!(pending.as_mut()).is_ready());
        drop(pending);
        assert_eq!(first[0], b'<');
        assert!(rest.ends_with(b"</stream:stream>"));
        Ok(())
    })
}

#[test]
fn parsed_and_written_stanzas_are_counted_by_kind() -> TestResult {
    Runtime::new()?.block_on(async {
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let input = format!("{HEADER}<message/><iq type='unknown'/>");
        let mut reader = reader(input.as_bytes(), 3)?;
        reader.ready.as_mut().ok_or("missing read state")?.metrics = metrics.worker(0, 0);
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::StreamStart { .. }))
        ));
        let Some(StreamEvent::Stanza(parsed)) =
            reader.next_event().await.map_err(|e| format!("{e:?}"))?
        else {
            return Err("missing message stanza".into());
        };
        let mut writer = Writer::new(Vec::new(), "localhost".into(), metrics.worker(0, 0));
        let stanza = parsed.value().resolve(parsed.arena())?;
        writer
            .write_stanza(&stanza)
            .await
            .map_err(|e| format!("{e:?}"))?;
        assert!(matches!(
            reader.next_event().await,
            Ok(Some(StreamEvent::RejectedStanza(_)))
        ));
        let body = metrics.render()?;
        for sample in [
            "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"} 1\n",
            "lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"iq\"} 1\n",
            "lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"message\"} 1\n",
        ] {
            assert!(body.contains(sample), "{body}");
        }
        Ok(())
    })
}

#[test]
fn resumed_stanza_waits_are_counted_once() -> TestResult {
    Runtime::new()?.block_on(async {
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let input = format!("{HEADER}<message/><message/>");
        let mut reader = reader(input.as_bytes(), 1)?;
        let state = reader.ready.as_mut().ok_or("missing read state")?;
        state.metrics = metrics.worker(0, 0);
        state.stanzas = StanzaLimiter::new(NonZeroUsize::new(20).ok_or("zero rate")?, NonZeroUsize::MIN);
        assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::StreamStart { .. }))));
        assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::Stanza(_)))));
        let mut waiting = Box::pin(reader.next_event());
        assert!(poll!(waiting.as_mut()).is_pending());
        assert!(metrics.render()?.contains("lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"} 2\n"));
        drop(waiting);
        assert!(matches!(reader.next_event().await, Ok(Some(StreamEvent::Stanza(_)))));
        let body = metrics.render()?;
        assert!(body.contains("lonewolf_c2s_stanzas_received_total{listener=\"0\",kind=\"message\"} 2\n"), "{body}");
        assert!(body.contains("lonewolf_c2s_rate_limited_total{listener=\"0\",limit=\"incoming_stanzas_per_connection\"} 1\n"), "{body}");
        Ok(())
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputMode {
    Ready,
    WriteFailure,
    FlushFailure,
    FlushPending,
}

struct OutputState {
    mode: Cell<OutputMode>,
    bytes: std::cell::RefCell<Vec<u8>>,
    flush_polled: Cell<bool>,
}

impl OutputState {
    fn new(mode: OutputMode) -> Rc<Self> {
        Rc::new(Self {
            mode: Cell::new(mode),
            bytes: std::cell::RefCell::new(Vec::new()),
            flush_polled: Cell::new(false),
        })
    }
}

struct ControlledOutput(Rc<OutputState>);

impl AsyncWrite for ControlledOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.0.mode.get() == OutputMode::WriteFailure {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.0.bytes.borrow_mut().extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.flush_polled.set(true);
        match self.0.mode.get() {
            OutputMode::FlushPending => Poll::Pending,
            OutputMode::FlushFailure => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("sending a stanza must not close the transport")
    }
}

#[test]
fn raw_stanza_is_counted_once_after_its_flush_completes() -> TestResult {
    Runtime::new()?.block_on(async {
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let output = OutputState::new(OutputMode::FlushPending);
        let mut writer = Writer::new(
            ControlledOutput(Rc::clone(&output)),
            "localhost".into(),
            metrics.worker(0, 0),
        );
        let xml = "<iq xmlns='jabber:client' type='result' id='bind'/>";
        let mut send = Box::pin(writer.send_stanza_xml(xml, StanzaKind::Iq));
        assert!(poll!(send.as_mut()).is_pending());
        assert!(output.flush_polled.get());
        assert!(
            metrics
                .render()?
                .contains("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 0\n")
        );
        assert_eq!(output.bytes.borrow().as_slice(), xml.as_bytes());
        output.mode.set(OutputMode::Ready);
        assert_eq!(send.await, Ok(()));
        assert!(
            metrics
                .render()?
                .contains("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 1\n")
        );
        assert_eq!(output.bytes.borrow().as_slice(), xml.as_bytes());
        Ok(())
    })
}

#[test]
fn raw_stanza_write_and_flush_failures_do_not_increment_sent_count() -> TestResult {
    Runtime::new()?.block_on(async {
        for mode in [OutputMode::WriteFailure, OutputMode::FlushFailure] {
            let metrics = crate::c2s::metrics::C2sMetrics::detached();
            let output = OutputState::new(mode);
            let mut writer = Writer::new(
                ControlledOutput(Rc::clone(&output)),
                "localhost".into(),
                metrics.worker(0, 0),
            );
            assert_eq!(
                writer
                    .send_stanza_xml("<iq type='error' id='bind'/>", StanzaKind::Iq)
                    .await,
                Err(CloseOutcome::TransportError)
            );
            assert_eq!(output.flush_polled.get(), mode == OutputMode::FlushFailure);
            assert!(
                metrics
                    .render()?
                    .contains("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 0\n")
            );
        }
        Ok(())
    })
}

#[test]
fn cancelled_raw_stanza_flush_does_not_increment_sent_count() -> TestResult {
    Runtime::new()?.block_on(async {
        let metrics = crate::c2s::metrics::C2sMetrics::detached();
        let output = OutputState::new(OutputMode::FlushPending);
        let mut writer = Writer::new(
            ControlledOutput(Rc::clone(&output)),
            "localhost".into(),
            metrics.worker(0, 0),
        );
        let mut send =
            Box::pin(writer.send_stanza_xml("<iq type='error' id='bind'/>", StanzaKind::Iq));
        assert!(poll!(send.as_mut()).is_pending());
        assert!(output.flush_polled.get());
        drop(send);
        assert!(
            metrics
                .render()?
                .contains("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 0\n")
        );
        Ok(())
    })
}
