// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

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
    pump: Option<ReadPump<A, R, O>>,
    control: Rc<ReadControl<A>>,
    mode: Rc<Cell<ReadMode>>,
    in_flight: bool,
    terminal: bool,
    failed: bool,
}

struct ReadState<A: ChunkAllocator, R, O> {
    parser: XmppParser<R, A>,
    limiter: StanzaLimiter,
    observer: O,
}

#[derive(Clone, Copy)]
enum Command {
    Idle,
    Read,
    Stop,
}

struct ReadControl<A: ChunkAllocator> {
    command: Cell<Command>,
    result: RefCell<Option<Result<Option<StreamEvent<A>>, ParseError>>>,
}

type ReadPump<A, R, O> = Pin<Box<dyn Future<Output = ReadState<A, R, O>>>>;

impl<A: ChunkAllocator + Clone, R: AsyncBufRead + Unpin + 'static, O: ReadObserver>
    XmlReader<A, R, O>
{
    pub(crate) fn new(
        parser: XmppParser<R, A>,
        limiter: StanzaLimiter,
        mode: Rc<Cell<ReadMode>>,
        observer: O,
    ) -> Self {
        let control = Rc::new(ReadControl {
            command: Cell::new(Command::Idle),
            result: RefCell::new(None),
        });
        let pump = Self::pump(
            ReadState {
                parser,
                limiter,
                observer,
            },
            Rc::clone(&mode),
            Rc::clone(&control),
        );
        Self {
            ready: None,
            pump: Some(pump),
            control,
            mode,
            in_flight: false,
            terminal: false,
            failed: false,
        }
    }

    fn pump(
        mut state: ReadState<A, R, O>,
        mode: Rc<Cell<ReadMode>>,
        control: Rc<ReadControl<A>>,
    ) -> ReadPump<A, R, O> {
        Box::pin(async move {
            loop {
                let command = poll_fn(|_| match control.command.replace(Command::Idle) {
                    // Only the owning reader polls this pump, including idle stops; no producer runs independently.
                    Command::Idle => Poll::Pending,
                    command => Poll::Ready(command),
                })
                .await;
                if matches!(command, Command::Stop) {
                    return state;
                }
                let result = Self::read(&mut state, &mode).await;
                let terminal = matches!(result, Err(_) | Ok(None));
                *control.result.borrow_mut() = Some(result);
                if terminal {
                    return state;
                }
            }
        })
    }

    async fn read(
        state: &mut ReadState<A, R, O>,
        mode: &Cell<ReadMode>,
    ) -> Result<Option<StreamEvent<A>>, ParseError> {
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
            state.limiter.acquire(mode, &state.observer).await;
        }
        event
    }

    fn stop(&mut self) -> Result<ReadState<A, R, O>, ParseError> {
        if let Some(state) = self.ready.take() {
            return Ok(state);
        }
        let Some(pump) = self.pump.as_mut() else {
            return Err(ParseError::ParserFailed);
        };
        self.control.command.set(Command::Stop);
        match pump.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(state) => {
                self.pump = None;
                Ok(state)
            }
            Poll::Pending => Err(ParseError::ParserFailed),
        }
    }

    pub(crate) fn restart(&mut self) -> Result<(), ParseError> {
        if !self.has_ready_state() {
            return Err(ParseError::ParserFailed);
        }
        let state = self.stop()?;
        let (parser, result) = match state.parser.try_restart() {
            Ok(parser) => (parser, Ok(())),
            Err((parser, error)) => (parser, Err(error)),
        };
        let state = ReadState {
            parser,
            limiter: state.limiter,
            observer: state.observer,
        };
        if result.is_ok() {
            self.terminal = false;
            self.pump = Some(Self::pump(
                state,
                Rc::clone(&self.mode),
                Rc::clone(&self.control),
            ));
        } else {
            self.ready = Some(state);
        }
        self.failed |= result.is_err();
        result
    }

    /// Dropped calls resume the same read without losing parser state.
    pub(crate) async fn read_event(&mut self) -> Result<Option<StreamEvent<A>>, ParseError> {
        if self.terminal {
            let Some(state) = self.ready.as_mut() else {
                return Err(ParseError::ParserFailed);
            };
            let result = Self::read(state, &self.mode).await;
            self.failed = result.is_err();
            return result;
        }
        if self.pump.is_none() {
            let Some(state) = self.ready.take() else {
                return Err(ParseError::ParserFailed);
            };
            self.pump = Some(Self::pump(
                state,
                Rc::clone(&self.mode),
                Rc::clone(&self.control),
            ));
        }
        if !self.in_flight {
            self.in_flight = true;
            self.control.command.set(Command::Read);
        }
        let result = poll_fn(|cx| {
            if let Some(pump) = self.pump.as_mut()
                && let Poll::Ready(state) = pump.as_mut().poll(cx)
            {
                self.ready = Some(state);
                self.pump = None;
                self.terminal = true;
            }
            match self.control.result.borrow_mut().take() {
                Some(result) => Poll::Ready(result),
                None => Poll::Pending,
            }
        })
        .await;
        self.in_flight = false;
        self.failed = result.is_err();
        result
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.failed
    }
    pub(crate) fn has_ready_state(&self) -> bool {
        self.has_input() && !self.in_flight
    }
    pub(crate) fn has_input(&self) -> bool {
        self.ready.is_some() || self.pump.is_some()
    }

    pub(crate) async fn take_parts(
        &mut self,
    ) -> Result<(XmppParser<R, A>, StanzaLimiter, O), ParseError> {
        if self.in_flight {
            self.mode.set(ReadMode::AbandonParser);
            let _ = self.read_event().await;
        }
        let state = self.stop()?;
        Ok((state.parser, state.limiter, state.observer))
    }
}
