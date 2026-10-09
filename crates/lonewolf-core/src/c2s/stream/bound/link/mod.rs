// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use futures_util::task::AtomicWaker;
use lonewolf_util::arena::ChunkAllocator;
use parking_lot::Mutex;

use super::{CertificateMonitor, CloseOutcome, OutboxWriter, Outgoing, OutputSequence};

// Queued outputs already sit in memory, so this only limits how far the session runs ahead of socket writes.
const COMMAND_CAPACITY: usize = 16;

pub(super) enum Command<A: ChunkAllocator> {
    Write(Outgoing<A>),
    Flush {
        through: OutputSequence,
        request: u64,
    },
}

struct Progress {
    flushed: OutputSequence,
    completed_flush: u64,
    failure: Option<CloseOutcome>,
    stopped: bool,
}

struct LinkState {
    progress: Mutex<Progress>,
    session: AtomicWaker,
}

/// The session's end of one transport attachment.
pub(super) struct LinkWriter<A: ChunkAllocator> {
    commands: async_channel::Sender<Command<A>>,
    state: Arc<LinkState>,
    requested_flush: u64,
}

/// The transport's end of one transport attachment.
pub(super) struct LinkTransport<A: ChunkAllocator> {
    commands: async_channel::Receiver<Command<A>>,
    state: Arc<LinkState>,
    _keepalive: async_channel::Sender<Command<A>>,
}

pub(super) fn link<A: ChunkAllocator>() -> (LinkWriter<A>, LinkTransport<A>) {
    let (sender, receiver) = async_channel::bounded(COMMAND_CAPACITY);
    let state = Arc::new(LinkState {
        progress: Mutex::new(Progress {
            flushed: OutputSequence::default(),
            completed_flush: 0,
            failure: None,
            stopped: false,
        }),
        session: AtomicWaker::new(),
    });
    let transport = LinkTransport {
        commands: receiver,
        state: Arc::clone(&state),
        _keepalive: sender.clone(),
    };
    (
        LinkWriter {
            commands: sender,
            state,
            requested_flush: 0,
        },
        transport,
    )
}

impl<A: ChunkAllocator> LinkWriter<A> {
    pub(super) fn stop(&self) {
        self.state.progress.lock().stopped = true;
    }

    fn failure(&self) -> Option<CloseOutcome> {
        self.state.progress.lock().failure
    }
}

impl<A: ChunkAllocator> Drop for LinkWriter<A> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
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

impl<A: ChunkAllocator> LinkTransport<A> {
    /// Writes commands until the session drops its writer.
    pub(super) async fn run<W: OutboxWriter<A>>(
        self,
        writer: &mut W,
        certificate: Option<&CertificateMonitor>,
    ) {
        while let Ok(command) = self.commands.recv().await {
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
            }
        }
    }

    async fn until_stopped(
        &self,
        operation: impl Future<Output = Result<(), CloseOutcome>>,
    ) -> Option<Result<(), CloseOutcome>> {
        let mut operation = pin!(operation);
        poll_fn(|context| {
            let stopped = self.state.progress.lock().stopped;
            if stopped {
                Poll::Ready(None)
            } else {
                operation.as_mut().poll(context).map(Some)
            }
        })
        .await
    }

    fn fail(&self, outcome: CloseOutcome) {
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
