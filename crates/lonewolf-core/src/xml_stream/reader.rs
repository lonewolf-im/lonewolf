// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::parser::{ParseError, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::StanzaKind;
use tokio::io::AsyncBufRead;

use super::limiter::StanzaLimiter;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReadMode {
    Open,
    Closing,
    AbandonParser,
}

pub(crate) trait ReadObserver: 'static {
    fn stanza_parsed(&self, _kind: StanzaKind) {}
    fn rate_limited(&self) {}
}

pub(crate) struct XmlReader<A: ChunkAllocator, R, O: ReadObserver> {
    ready: Option<ReadState<A, R, O>>,
    pending: Option<PendingRead<A, R, O>>,
    mode: Rc<Cell<ReadMode>>,
    failed: bool,
}

struct ReadState<A: ChunkAllocator, R, O> {
    parser: XmppParser<R, A>,
    limiter: StanzaLimiter,
    observer: O,
}

type ReadResult<A, R, O> = (
    ReadState<A, R, O>,
    Result<Option<StreamEvent<A>>, ParseError>,
);
type PendingRead<A, R, O> = Pin<Box<dyn Future<Output = ReadResult<A, R, O>>>>;

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static, O: ReadObserver>
    XmlReader<A, R, O>
{
    pub(crate) fn new(
        parser: XmppParser<R, A>,
        limiter: StanzaLimiter,
        mode: Rc<Cell<ReadMode>>,
        observer: O,
    ) -> Self {
        Self {
            ready: Some(ReadState {
                parser,
                limiter,
                observer,
            }),
            pending: None,
            mode,
            failed: false,
        }
    }

    pub(crate) fn restart(&mut self) -> Result<(), ParseError> {
        let Some(state) = self.ready.take() else {
            return Err(ParseError::ParserFailed);
        };
        let (parser, result) = match state.parser.try_restart() {
            Ok(parser) => (parser, Ok(())),
            Err((parser, error)) => (parser, Err(error)),
        };
        self.ready = Some(ReadState {
            parser,
            limiter: state.limiter,
            observer: state.observer,
        });
        self.failed |= result.is_err();
        result
    }

    /// Dropped calls resume the same read without losing parser state.
    pub(crate) async fn read_event(&mut self) -> Result<Option<StreamEvent<A>>, ParseError> {
        if self.pending.is_none() {
            let Some(mut state) = self.ready.take() else {
                return Err(ParseError::ParserFailed);
            };
            let mode = Rc::clone(&self.mode);
            self.pending = Some(Box::pin(async move {
                let event = {
                    let mut next = std::pin::pin!(state.parser.next_event());
                    poll_fn(|cx| {
                        if mode.get() == ReadMode::AbandonParser {
                            Poll::Ready(Err(ParseError::ParserFailed))
                        } else {
                            next.as_mut().poll(cx)
                        }
                    })
                    .await
                };
                let kind = match &event {
                    Ok(Some(StreamEvent::Stanza(parsed))) => parsed
                        .value()
                        .resolve(parsed.arena())
                        .ok()
                        .map(|stanza| stanza.kind()),
                    Ok(Some(StreamEvent::RejectedStanza(parsed))) => Some(parsed.value().kind()),
                    _ => None,
                };
                if let Some(kind) = kind {
                    state.observer.stanza_parsed(kind);
                    state.limiter.acquire(&mode, &state.observer).await;
                }
                (state, event)
            }));
        }
        let Some(pending) = &mut self.pending else {
            return Err(ParseError::ParserFailed);
        };
        let (state, result) = pending.await;
        self.pending = None;
        self.ready = Some(state);
        self.failed = result.is_err();
        result
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }
    pub(crate) fn has_ready_state(&self) -> bool {
        self.ready.is_some()
    }
    pub(crate) fn has_input(&self) -> bool {
        self.ready.is_some() || self.pending.is_some()
    }

    pub(crate) async fn take_parts(
        &mut self,
    ) -> Result<(XmppParser<R, A>, StanzaLimiter, O), ParseError> {
        if self.pending.is_some() {
            self.mode.set(ReadMode::AbandonParser);
            let _ = self.read_event().await;
        }
        self.ready
            .take()
            .map(|state| (state.parser, state.limiter, state.observer))
            .ok_or(ParseError::ParserFailed)
    }
}
