// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::{Pin, pin};
use std::time::Duration;

use futures_util::future::{Either, join, select};
use lonewolf_util::arena::ChunkAllocator;

use super::super::certificate::CertificateMonitor;
use super::super::close::{self, CloseContext};
use super::super::session::{Reader, Writer};
use super::link::LinkTransport;
use super::{CloseOutcome, OutboxWriter, Outgoing, OutputSequence};
use crate::xml_stream::traffic::WriteProgress;

pub(super) struct Transport<A: ChunkAllocator> {
    pub(super) reader: Reader<A>,
    pub(super) writer: Writer,
    pub(super) close: CloseContext,
    pub(super) monitor: Option<CertificateMonitor>,
    pub(super) link: LinkTransport<A>,
    pub(super) stall: WriteStall,
}

/// Fails a pending write when the client accepts no outgoing bytes for the timeout.
pub(super) struct WriteStall {
    progress: WriteProgress,
    timeout: Duration,
}

impl WriteStall {
    pub(super) fn new(progress: WriteProgress, timeout: Duration) -> Self {
        Self { progress, timeout }
    }

    /// Takes the operation pinned so the write future is not stored twice.
    pub(super) async fn watch(
        &self,
        mut operation: Pin<&mut impl Future<Output = Result<(), CloseOutcome>>>,
    ) -> Result<(), CloseOutcome> {
        let started = crate::clock::now();
        loop {
            let Some(deadline) = started.max(self.progress.last()).checked_add(self.timeout) else {
                return operation.await;
            };
            if crate::clock::now() >= deadline {
                return Err(CloseOutcome::StalledWrite);
            }
            let sleep = pin!(crate::clock::sleep_until(deadline));
            if let Either::Left((result, _)) = select(operation.as_mut(), sleep).await {
                return result;
            }
        }
    }
}

struct Watched<'a, W> {
    writer: &'a mut W,
    stall: &'a WriteStall,
}

impl<A: ChunkAllocator, W: OutboxWriter<A>> OutboxWriter<A> for Watched<'_, W> {
    async fn write(&mut self, output: Outgoing<A>) -> Result<(), CloseOutcome> {
        self.stall.watch(pin!(self.writer.write(output))).await
    }

    async fn flush(&mut self, through: OutputSequence) -> Result<(), CloseOutcome> {
        self.stall.watch(pin!(self.writer.flush(through))).await
    }
}

impl<A: ChunkAllocator + Clone> Transport<A> {
    pub(super) async fn run(&mut self) -> CloseOutcome {
        let Self {
            reader,
            writer,
            close,
            monitor,
            link,
            stall,
        } = self;
        let link = &*link;
        let close = &*close;
        let monitor = monitor.as_ref();
        let reading = async {
            let read = pin!(async {
                link.read(reader, monitor).await;
                Ok(())
            });
            let result = match monitor {
                Some(monitor) => monitor.interrupt(read).await,
                None => read.await,
            };
            if let Err(outcome) = result {
                link.fail(outcome);
            }
        };
        let writing = async {
            let mut watched = Watched {
                writer: &mut *writer,
                stall,
            };
            let mut write = pin!(link.write(&mut watched, monitor));
            match select(write.as_mut(), pin!(link.stopped())).await {
                Either::Left((outcome, _)) => (outcome, close.deadline()),
                Either::Right(((), _)) => {
                    let deadline = close.deadline();
                    (close.cleanup(deadline, write).await, deadline)
                }
            }
        };
        let ((), (outcome, deadline)) = join(reading, writing).await;
        close::finish(reader, writer, outcome.into(), close, deadline).await
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::future::pending;
    use std::task::Poll;

    use compio::runtime::Runtime;
    use futures_util::poll;

    use super::*;
    use crate::clock::FrozenClock;

    const TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn a_write_without_progress_fails_once_the_timeout_elapses() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let clock = FrozenClock::start();
            let stall = WriteStall::new(WriteProgress::new(clock.now()), TIMEOUT);
            let operation = pin!(pending());
            let mut watch = pin!(stall.watch(operation));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(TIMEOUT - Duration::from_secs(1));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                poll!(watch.as_mut()),
                Poll::Ready(Err(CloseOutcome::StalledWrite))
            );
            Ok(())
        })
    }

    #[test]
    fn outgoing_progress_extends_the_write_deadline() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let clock = FrozenClock::start();
            let progress = WriteProgress::new(clock.now());
            let stall = WriteStall::new(progress.clone(), TIMEOUT);
            let operation = pin!(pending());
            let mut watch = pin!(stall.watch(operation));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(Duration::from_secs(50));
            progress.record(clock.now());
            clock.advance(Duration::from_secs(20));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(Duration::from_secs(39));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                poll!(watch.as_mut()),
                Poll::Ready(Err(CloseOutcome::StalledWrite))
            );
            Ok(())
        })
    }

    #[test]
    fn idle_time_before_a_write_does_not_count_as_a_stall() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let clock = FrozenClock::start();
            let stall = WriteStall::new(WriteProgress::new(clock.now()), TIMEOUT);
            clock.advance(TIMEOUT * 2);
            let operation = pin!(pending());
            let mut watch = pin!(stall.watch(operation));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(TIMEOUT - Duration::from_secs(1));
            assert!(poll!(watch.as_mut()).is_pending());
            clock.advance(Duration::from_secs(1));
            assert_eq!(
                poll!(watch.as_mut()),
                Poll::Ready(Err(CloseOutcome::StalledWrite))
            );
            Ok(())
        })
    }

    #[test]
    fn a_completed_write_returns_its_own_result() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let clock = FrozenClock::start();
            let stall = WriteStall::new(WriteProgress::new(clock.now()), TIMEOUT);
            assert_eq!(stall.watch(pin!(async { Ok(()) })).await, Ok(()));
            assert_eq!(
                stall
                    .watch(pin!(async { Err(CloseOutcome::TransportError) }))
                    .await,
                Err(CloseOutcome::TransportError)
            );
            Ok(())
        })
    }
}
