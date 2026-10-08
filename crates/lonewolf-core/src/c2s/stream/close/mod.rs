// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, poll_fn};
use std::io;
use std::net::Shutdown;
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use futures_util::future::{Either, LocalBoxFuture, Shared, select};
use futures_util::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::parser::StreamEvent;
use socket2::SockRef;
use tokio::io::AsyncBufRead;

use super::header::{STREAM_FOOTER, stream_error_xml};
use super::outcome::CloseOutcome;
use super::session::{Reader, Writer};

pub(super) const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) type ShutdownSignal = Shared<LocalBoxFuture<'static, Instant>>;

#[derive(Clone)]
pub(super) struct CloseContext {
    pub(super) socket: TcpStream,
    pub(super) shutdown: ShutdownSignal,
    pub(super) phase_deadline: Option<Instant>,
}

#[derive(Clone, Copy)]
pub(super) enum CloseReason {
    PeerFooter,
    PeerError(lonewolf_xmpp::stream::StreamErrorCondition),
    Local(CloseOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseState {
    Open,
    FooterSent,
    TlsClosing,
    Closed,
}

impl CloseReason {
    fn outcome(self) -> CloseOutcome {
        match self {
            Self::PeerFooter => CloseOutcome::StreamEnd,
            Self::PeerError(condition) => CloseOutcome::PeerError(condition),
            Self::Local(outcome) => outcome,
        }
    }
}

impl From<CloseOutcome> for CloseReason {
    fn from(outcome: CloseOutcome) -> Self {
        match outcome {
            CloseOutcome::StreamEnd => Self::PeerFooter,
            CloseOutcome::PeerError(condition) => Self::PeerError(condition),
            outcome => Self::Local(outcome),
        }
    }
}

impl CloseContext {
    pub(super) fn deadline(&self) -> Instant {
        let deadline = Instant::now() + CLOSE_TIMEOUT;
        self.phase_deadline
            .map_or(deadline, |phase| deadline.min(phase))
    }

    pub(super) fn abort(&self) {
        let _ = SockRef::from(&self.socket).shutdown(Shutdown::Both);
    }

    pub(super) async fn interrupt<T>(
        &self,
        future: impl Future<Output = Result<T, CloseOutcome>>,
    ) -> Result<T, CloseOutcome> {
        match select(pin!(self.shutdown.clone()), pin!(future)).await {
            Either::Left(_) => Err(CloseOutcome::SystemShutdown),
            Either::Right((result, _)) => result,
        }
    }

    pub(super) async fn until<T>(
        &self,
        deadline: Instant,
        future: impl Future<Output = T>,
    ) -> Result<T, ()> {
        let mut future = pin!(future);
        let first = {
            let wait = pin!(before_deadline(deadline, future.as_mut()));
            match select(pin!(self.shutdown.clone()), wait).await {
                Either::Right((result, _)) => Either::Right(result),
                Either::Left((shutdown, _)) => Either::Left(shutdown),
            }
        };
        let result = match first {
            Either::Right(result) => result,
            Either::Left(shutdown) => {
                before_deadline(deadline.min(shutdown), future.as_mut()).await
            }
        };
        if result.is_err() {
            self.abort();
        }
        result
    }

    /// Network expiry does not cancel committed work or presence retirement.
    pub(super) async fn cleanup<T>(
        &self,
        deadline: Instant,
        cleanup: impl Future<Output = T>,
    ) -> T {
        let mut cleanup = pin!(cleanup);
        if let Ok(result) = self.until(deadline, cleanup.as_mut()).await {
            return result;
        }
        cleanup.await
    }
}

pub(super) async fn finish<A: ChunkAllocator + Clone>(
    reader: &mut Reader<A>,
    writer: &mut Writer,
    reason: CloseReason,
    context: &CloseContext,
    deadline: Instant,
) -> CloseOutcome {
    let outcome = reason.outcome();
    let result = context
        .until(deadline, async {
            let mut state = CloseState::Open;
            if !xml(reader, writer, reason).await? {
                return Ok(outcome);
            }
            transition(&mut state, CloseState::FooterSent);
            let input = reader.take_input().await?;
            let read = input.into_inner().into_inner().into_inner();
            let write = writer.take_output()?;
            let mut transport = read
                .reunite(write)
                .map_err(|_| CloseOutcome::InternalError)?;
            transition(&mut state, CloseState::TlsClosing);
            transport.get_mut().1.send_close_notify();
            transport
                .flush()
                .await
                .map_err(|_| CloseOutcome::TransportError)?;
            let mut buffer = [0; 4096];
            loop {
                match transport.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(_) => yield_once().await,
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(_) => return Err(CloseOutcome::TransportError),
                }
            }
            transition(&mut state, CloseState::Closed);
            Ok(outcome)
        })
        .await;
    context.abort();
    completed(result, outcome)
}

pub(super) async fn finish_plain<A, R, W>(
    reader: &mut Reader<A, R>,
    writer: &mut Writer<W>,
    reason: CloseReason,
    context: &CloseContext,
) -> CloseOutcome
where
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let outcome = reason.outcome();
    let result = context
        .until(context.deadline(), async {
            xml(reader, writer, reason).await.map(|_| outcome)
        })
        .await;
    context.abort();
    completed(result, outcome)
}

pub(super) async fn before_deadline<T>(
    deadline: Instant,
    mut future: std::pin::Pin<&mut impl Future<Output = T>>,
) -> Result<T, ()> {
    compio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        poll_fn(|context| {
            if Instant::now() >= deadline {
                Poll::Ready(Err(()))
            } else {
                future.as_mut().poll(context).map(Ok)
            }
        }),
    )
    .await
    .map_err(|_| ())?
}

fn completed(
    result: Result<Result<CloseOutcome, CloseOutcome>, ()>,
    outcome: CloseOutcome,
) -> CloseOutcome {
    match result {
        Ok(Ok(result) | Err(result)) => result,
        Err(()) if matches!(outcome, CloseOutcome::StreamEnd | CloseOutcome::LocalClose) => {
            CloseOutcome::ClosingTimeout
        }
        Err(()) => outcome,
    }
}

fn transition(state: &mut CloseState, next: CloseState) {
    debug_assert!(matches!(
        (*state, next),
        (CloseState::Open, CloseState::FooterSent)
            | (CloseState::FooterSent, CloseState::TlsClosing)
            | (CloseState::TlsClosing, CloseState::Closed)
    ));
    *state = next;
}

async fn xml<A, R, W>(
    reader: &mut Reader<A, R>,
    writer: &mut Writer<W>,
    reason: CloseReason,
) -> Result<bool, CloseOutcome>
where
    A: ChunkAllocator + Clone,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    if matches!(
        reason.outcome(),
        CloseOutcome::Eof | CloseOutcome::TransportError | CloseOutcome::TlsFailure
    ) {
        return Ok(false);
    }
    reader.closing();
    if !writer.is_open() || !writer.is_intact() {
        return Ok(true);
    }
    if let CloseReason::Local(outcome) = reason
        && let Some(error) = stream_error_xml(outcome)
    {
        writer.send(&error).await?;
    } else {
        writer.send(STREAM_FOOTER).await?;
    }
    if !matches!(reason, CloseReason::PeerFooter) && !reader.is_failed() {
        loop {
            match reader.next_event().await {
                Ok(Some(StreamEvent::StreamEnd) | None) => break,
                Ok(Some(_)) => yield_once().await,
                Err(CloseOutcome::Eof | CloseOutcome::TransportError) => return Ok(false),
                Err(_) => break,
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;

async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}
