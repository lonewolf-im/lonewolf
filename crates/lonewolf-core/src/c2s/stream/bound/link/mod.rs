// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use futures_util::future::{Either, select};
use futures_util::task::AtomicWaker;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::{RejectedStanza, Stanza};
use parking_lot::Mutex;
use tokio::io::AsyncBufRead;

use super::super::certificate::CertificateMonitor;
use super::super::session::{Reader, namespace_error, peer_stream_error};
use super::{CloseOutcome, OutboxWriter, Outgoing, OutputSequence};

// Queued outputs already sit in memory, so this only limits how far the session runs ahead of socket writes.
const COMMAND_CAPACITY: usize = 16;

pub(super) enum Incoming<A: ChunkAllocator> {
    Stanza(Parsed<Stanza, A>),
    Rejected(Parsed<RejectedStanza, A>),
    /// The transport stopped reading; nothing follows.
    Ended(CloseOutcome),
}

pub(super) enum Command<A: ChunkAllocator> {
    Write(Outgoing<A>),
    Flush {
        through: OutputSequence,
        request: u64,
    },
    Close(CloseOutcome),
}

struct Progress {
    flushed: OutputSequence,
    completed_flush: u64,
    failure: Option<CloseOutcome>,
    stopped: bool,
    accepted: u64,
}

/// Each waker belongs to one half; only futures that run in that half may wait on it.
struct LinkState {
    progress: Mutex<Progress>,
    session: AtomicWaker,
    transport: AtomicWaker,
}

pub(super) struct LinkWriter<A: ChunkAllocator> {
    commands: async_channel::Sender<Command<A>>,
    state: Arc<LinkState>,
    requested_flush: u64,
}

pub(super) struct LinkTransport<A: ChunkAllocator> {
    commands: async_channel::Receiver<Command<A>>,
    incoming: async_channel::Sender<Incoming<A>>,
    state: Arc<LinkState>,
    _keepalive: async_channel::Sender<Command<A>>,
    _incoming_keepalive: async_channel::Receiver<Incoming<A>>,
}

/// Observes a link without borrowing the session's writer.
pub(super) struct LinkWatch {
    state: Arc<LinkState>,
}

pub(super) fn link<A: ChunkAllocator>() -> (
    LinkWriter<A>,
    async_channel::Receiver<Incoming<A>>,
    LinkTransport<A>,
) {
    let (sender, receiver) = async_channel::bounded(COMMAND_CAPACITY);
    let (incoming_sender, incoming_receiver) = async_channel::bounded(1);
    let state = Arc::new(LinkState {
        progress: Mutex::new(Progress {
            flushed: OutputSequence::default(),
            completed_flush: 0,
            failure: None,
            stopped: false,
            accepted: 0,
        }),
        session: AtomicWaker::new(),
        transport: AtomicWaker::new(),
    });
    let transport = LinkTransport {
        commands: receiver,
        incoming: incoming_sender,
        state: Arc::clone(&state),
        _keepalive: sender.clone(),
        _incoming_keepalive: incoming_receiver.clone(),
    };
    (
        LinkWriter {
            commands: sender,
            state,
            requested_flush: 0,
        },
        incoming_receiver,
        transport,
    )
}

impl<A: ChunkAllocator> LinkWriter<A> {
    pub(super) fn stop(&self) {
        self.state.progress.lock().stopped = true;
        self.state.transport.wake();
    }

    pub(super) fn accept(&self) {
        self.state.progress.lock().accepted += 1;
        self.state.transport.wake();
    }

    pub(super) fn watch(&self) -> LinkWatch {
        LinkWatch {
            state: Arc::clone(&self.state),
        }
    }

    pub(super) async fn close(&self, outcome: CloseOutcome) {
        let _ = self.commands.send(Command::Close(outcome)).await;
    }

    fn failure(&self) -> Option<CloseOutcome> {
        self.state.progress.lock().failure
    }
}

impl<A: ChunkAllocator> Drop for LinkWriter<A> {
    fn drop(&mut self) {
        // Waking another task while this thread unwinds aborts the process.
        if !std::thread::panicking() {
            self.stop();
            self.commands.close();
        }
    }
}

impl<A: ChunkAllocator> OutboxWriter<A> for LinkWriter<A> {
    async fn write(&mut self, output: Outgoing<A>) -> Result<(), CloseOutcome> {
        if let Some(outcome) = self.failure() {
            return Err(outcome);
        }
        self.commands
            .send(Command::Write(output))
            .await
            .map_err(|_| self.failure().unwrap_or(CloseOutcome::InternalError))
    }

    async fn flush(&mut self, through: OutputSequence) -> Result<(), CloseOutcome> {
        if let Some(outcome) = self.failure() {
            return Err(outcome);
        }
        let request = self
            .requested_flush
            .checked_add(1)
            .ok_or(CloseOutcome::InternalError)?;
        self.requested_flush = request;
        self.commands
            .send(Command::Flush { through, request })
            .await
            .map_err(|_| self.failure().unwrap_or(CloseOutcome::InternalError))?;
        poll_fn(|context| {
            self.state.session.register(context.waker());
            let progress = self.state.progress.lock();
            if let Some(outcome) = progress.failure {
                Poll::Ready(Err(outcome))
            } else if progress.completed_flush >= request {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

impl LinkWatch {
    pub(super) async fn failed(&self) -> CloseOutcome {
        poll_fn(|context| {
            self.state.session.register(context.waker());
            match self.state.progress.lock().failure {
                Some(outcome) => Poll::Ready(outcome),
                None => Poll::Pending,
            }
        })
        .await
    }
}

impl<A: ChunkAllocator> LinkTransport<A> {
    pub(super) async fn write<W: OutboxWriter<A>>(
        &self,
        writer: &mut W,
        certificate: Option<&CertificateMonitor>,
    ) -> CloseOutcome {
        while let Ok(command) = self.commands.recv().await {
            if let Command::Close(outcome) = command {
                return outcome;
            }
            {
                let progress = self.state.progress.lock();
                if progress.stopped || progress.failure.is_some() {
                    continue;
                }
            }
            if let Err(outcome) = certificate.map_or(Ok(()), CertificateMonitor::check) {
                self.fail(outcome);
                continue;
            }
            match command {
                Command::Write(output) => {
                    if let Some(Err(outcome)) = self.until_stopped(writer.write(output)).await {
                        self.fail(outcome);
                    }
                }
                Command::Flush { through, request } => {
                    match self.until_stopped(writer.flush(through)).await {
                        Some(Ok(())) => {
                            {
                                let mut progress = self.state.progress.lock();
                                progress.flushed = through;
                                progress.completed_flush = request;
                            }
                            self.state.session.wake();
                        }
                        Some(Err(outcome)) => self.fail(outcome),
                        None => {}
                    }
                }
                Command::Close(outcome) => return outcome,
            }
        }
        CloseOutcome::InternalError
    }

    pub(super) async fn read<R: AsyncBufRead + Unpin + 'static>(
        &self,
        reader: &mut Reader<A, R>,
        certificate: Option<&CertificateMonitor>,
    ) where
        A: Clone,
    {
        let mut forwarded = 0;
        loop {
            let stopped = poll_fn(|context| {
                self.state.transport.register(context.waker());
                let progress = self.state.progress.lock();
                if progress.stopped {
                    Poll::Ready(true)
                } else if progress.accepted >= forwarded {
                    Poll::Ready(false)
                } else {
                    Poll::Pending
                }
            })
            .await;
            if stopped {
                return;
            }
            let event = match select(pin!(reader.next_event()), pin!(self.stopped())).await {
                Either::Left((event, _)) => event,
                Either::Right(_) => return,
            };
            let incoming = match event {
                Ok(Some(StreamEvent::Stanza(parsed))) => {
                    if let Err(outcome) = certificate.map_or(Ok(()), CertificateMonitor::check) {
                        self.fail(outcome);
                        return;
                    }
                    Incoming::Stanza(parsed)
                }
                Ok(Some(StreamEvent::RejectedStanza(parsed))) => {
                    if let Err(outcome) = certificate.map_or(Ok(()), CertificateMonitor::check) {
                        self.fail(outcome);
                        return;
                    }
                    Incoming::Rejected(parsed)
                }
                Ok(Some(StreamEvent::StreamEnd) | None) => Incoming::Ended(CloseOutcome::StreamEnd),
                Ok(Some(event)) => Incoming::Ended(match peer_stream_error(&event) {
                    Ok(Some(condition)) => CloseOutcome::PeerError(condition),
                    Err(outcome) => outcome,
                    Ok(None) => {
                        namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedStanzaType)
                    }
                }),
                Err(outcome) => Incoming::Ended(outcome),
            };
            let ended = matches!(incoming, Incoming::Ended(_));
            if !ended {
                forwarded += 1;
            }
            if self.incoming.send(incoming).await.is_err() || ended {
                return;
            }
        }
    }

    pub(super) async fn stopped(&self) {
        poll_fn(|context| {
            self.state.transport.register(context.waker());
            if self.state.progress.lock().stopped {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    async fn until_stopped(
        &self,
        operation: impl Future<Output = Result<(), CloseOutcome>>,
    ) -> Option<Result<(), CloseOutcome>> {
        let mut operation = pin!(operation);
        poll_fn(|context| {
            self.state.transport.register(context.waker());
            let stopped = self.state.progress.lock().stopped;
            if stopped {
                Poll::Ready(None)
            } else {
                operation.as_mut().poll(context).map(Some)
            }
        })
        .await
    }

    pub(super) fn fail(&self, outcome: CloseOutcome) {
        {
            let mut progress = self.state.progress.lock();
            if progress.failure.is_none() {
                progress.failure = Some(outcome);
            }
        }
        self.state.session.wake();
    }
}

#[cfg(test)]
mod tests;
