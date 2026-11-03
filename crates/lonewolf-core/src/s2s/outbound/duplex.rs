// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use futures_util::task::AtomicWaker;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::AsyncBufRead;

use super::*;
use crate::s2s::ingress::{InboundPeer, IngressContext, IngressFailure, receive};
use crate::s2s::metrics::StreamClose;
use crate::s2s::stream::S2sError;
use crate::s2s::validity::LinkValidity;

pub(in crate::s2s) struct DuplexEnd {
    pub(in crate::s2s) reason: StreamClose,
    pub(in crate::s2s) violation: Option<StreamErrorCondition>,
    pub(in crate::s2s) peer_closed: bool,
    /// A failed transport cannot carry a closing tag.
    pub(in crate::s2s) abort: bool,
}

impl DuplexEnd {
    fn new(reason: StreamClose) -> Self {
        Self {
            reason,
            violation: None,
            peer_closed: false,
            abort: false,
        }
    }

    async fn finish(self, stop: &StopRequest, sending: impl Future<Output = SendEnd>) -> Self {
        stop.request();
        let abort = matches!(sending.await, SendEnd::Failed { abort: true, .. });
        Self {
            abort: self.abort || abort,
            ..self
        }
    }
}

pub(in crate::s2s) struct DuplexParameters<'a, A: ChunkAllocator> {
    pub(in crate::s2s) peer: &'a InboundPeer,
    pub(in crate::s2s) context: &'a IngressContext<A>,
    pub(in crate::s2s) validity: &'a LinkValidity,
    pub(in crate::s2s) idle_timeout: Duration,
}

trait IdleClock {
    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}

struct SystemIdleClock;
impl IdleClock for SystemIdleClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    async fn sleep_until(&self, deadline: Instant) {
        compio::time::sleep_until(deadline).await;
    }
}

async fn cooperate() {
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

struct Activity {
    at: Cell<Instant>,
    receiving: Cell<bool>,
    sending: Cell<bool>,
    stop: StopRequest,
}

#[derive(Default)]
struct StopRequest {
    requested: Cell<bool>,
    waker: AtomicWaker,
}
impl StopRequest {
    fn request(&self) {
        self.requested.set(true);
        self.waker.wake();
    }
    async fn wait(&self) {
        poll_fn(|cx| {
            self.waker.register(cx.waker());
            if self.requested.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

enum QueueSource<'a, A: ChunkAllocator + Clone + 'static> {
    Owned(&'a mut LinkQueue<A>),
    Assigned(&'a BidiRegistration<A>, &'a mut Option<LinkQueue<A>>),
}
impl<A: ChunkAllocator + Clone + 'static> QueueSource<'_, A> {
    fn queue_mut(&mut self) -> Option<&mut LinkQueue<A>> {
        match self {
            Self::Owned(queue) => Some(queue),
            Self::Assigned(_, queue) => queue.as_mut(),
        }
    }
}

struct Session<'a, A: ChunkAllocator + Clone + 'static> {
    inner: &'a Inner<A>,
    source: QueueSource<'a, A>,
    outbound: bool,
}

enum SendEnd {
    Stopped,
    Failed { reason: StreamClose, abort: bool },
}

pub(in crate::s2s) async fn run_inbound<A, R, W, D>(
    registration: &BidiRegistration<A>,
    queue: &mut Option<LinkQueue<A>>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    parameters: DuplexParameters<'_, A>,
    shutdown: impl Future<Output = ()>,
    dispatch: D,
) -> DuplexEnd
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    run(
        Session {
            inner: registration.inner(),
            source: QueueSource::Assigned(registration, queue),
            outbound: false,
        },
        reader,
        writer,
        parameters,
        shutdown,
        dispatch,
        &SystemIdleClock,
    )
    .await
}

#[cfg_attr(not(test), expect(dead_code))]
pub(super) async fn run_outbound<A, R, W, D>(
    inner: &Inner<A>,
    queue: &mut LinkQueue<A>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    parameters: DuplexParameters<'_, A>,
    dispatch: D,
) -> DuplexEnd
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    run(
        Session {
            inner,
            source: QueueSource::Owned(queue),
            outbound: true,
        },
        reader,
        writer,
        parameters,
        inner.stopped.clone(),
        dispatch,
        &SystemIdleClock,
    )
    .await
}

async fn receiving<A, R, D>(
    reader: &mut S2sReader<A, R>,
    parameters: &DuplexParameters<'_, A>,
    metrics: &S2sMetrics,
    activity: &Activity,
    count_bidi: bool,
    mut dispatch: D,
    clock: &impl IdleClock,
) -> DuplexEnd
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    loop {
        let event = match reader.next_event().await {
            Ok(Some(StreamEvent::StreamEnd)) => {
                return DuplexEnd {
                    peer_closed: true,
                    ..DuplexEnd::new(StreamClose::StreamEnd)
                };
            }
            Ok(Some(event)) => event,
            Ok(None) | Err(S2sError::Eof | S2sError::Io | S2sError::Timeout) => {
                return DuplexEnd {
                    abort: true,
                    ..DuplexEnd::new(StreamClose::TransportError)
                };
            }
            Err(S2sError::PeerError(_)) => {
                return DuplexEnd {
                    abort: true,
                    ..DuplexEnd::new(StreamClose::PeerError)
                };
            }
            Err(S2sError::Stream(condition)) => {
                return DuplexEnd {
                    violation: Some(condition),
                    ..DuplexEnd::new(receive::reader_violation_close(condition))
                };
            }
            Err(S2sError::Internal) => {
                return DuplexEnd {
                    violation: Some(StreamErrorCondition::InternalServerError),
                    ..DuplexEnd::new(StreamClose::InternalError)
                };
            }
        };
        if matches!(
            event,
            StreamEvent::Stanza(_) | StreamEvent::RejectedStanza(_)
        ) {
            activity.at.set(clock.now());
        }
        activity.receiving.set(true);
        let result = receive::process(
            event,
            parameters.peer,
            metrics,
            parameters.context,
            count_bidi,
            async |stanza| {
                dispatch(parameters.context, parameters.peer, stanza)
                    .await
                    .map_err(|_| StreamErrorCondition::InternalServerError)
            },
        )
        .await;
        activity.receiving.set(false);
        if let Err(condition) = result {
            return DuplexEnd {
                violation: Some(condition),
                ..DuplexEnd::new(receive::violation_close(condition))
            };
        }
        cooperate().await;
    }
}

async fn sending<A, W>(
    source: &mut QueueSource<'_, A>,
    writer: &mut S2sWriter<W>,
    inner: &Inner<A>,
    validity: &LinkValidity,
    activity: &Activity,
    count_bidi: bool,
    clock: &impl IdleClock,
) -> SendEnd
where
    A: ChunkAllocator + Clone + 'static,
    W: AsyncWrite + Unpin,
{
    let queue = match source {
        QueueSource::Owned(queue) => &mut **queue,
        QueueSource::Assigned(registration, queue) => {
            if queue.is_none() {
                match select(pin!(activity.stop.wait()), pin!(registration.assigned())).await {
                    Either::Left(_) => return SendEnd::Stopped,
                    Either::Right((Some(assigned), _)) => **queue = Some(assigned),
                    Either::Right((None, _)) => {
                        activity.stop.wait().await;
                        return SendEnd::Stopped;
                    }
                }
            }
            let Some(queue) = queue.as_mut() else {
                return SendEnd::Failed {
                    reason: StreamClose::InternalError,
                    abort: true,
                };
            };
            queue.counters.ready.store(true, Ordering::Relaxed);
            queue
        }
    };
    let mut buffered = false;
    loop {
        if queue.current.is_none() {
            match select(pin!(activity.stop.wait()), pin!(queue.receiver.recv())).await {
                Either::Left(_) => return SendEnd::Stopped,
                Either::Right((Ok(head), _)) => queue.current = Some(head),
                Either::Right((Err(_), _)) => {
                    return SendEnd::Failed {
                        reason: StreamClose::TransportError,
                        abort: true,
                    };
                }
            }
        }
        if activity.stop.requested.get() {
            return SendEnd::Stopped;
        }
        let Some(head) = queue.current.as_mut() else {
            return SendEnd::Failed {
                reason: StreamClose::InternalError,
                abort: true,
            };
        };
        activity.sending.set(true);
        let result = link::write(
            writer,
            head,
            inner,
            validity,
            queue.receiver.is_empty(),
            &mut buffered,
        )
        .await;
        activity.sending.set(false);
        match result {
            Ok(link::WriteOutcome::Written { kind, .. }) => {
                activity.at.set(clock.now());
                queue.current = None;
                if count_bidi {
                    inner.metrics.bidi_stanza_sent(kind);
                }
            }
            Ok(link::WriteOutcome::Discarded) => queue.current = None,
            Err(reason) => {
                let started = head.reservation.is_none();
                if started {
                    queue.current = None;
                }
                return SendEnd::Failed {
                    reason,
                    abort: started
                        || !(matches!(reason, StreamClose::Shutdown)
                            || reason.certificate_invalid()),
                };
            }
        }
        cooperate().await;
    }
}

enum FirstEvent {
    Received(DuplexEnd),
    Sent(SendEnd),
    Invalid(StreamClose),
    Shutdown,
    Idle,
}

async fn run<A, R, W, D>(
    session: Session<'_, A>,
    reader: &mut S2sReader<A, R>,
    writer: &mut S2sWriter<W>,
    parameters: DuplexParameters<'_, A>,
    shutdown: impl Future<Output = ()>,
    dispatch: D,
    clock: &impl IdleClock,
) -> DuplexEnd
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(
        &'a IngressContext<A>,
        &'a InboundPeer,
        RoutedStanza<A>,
    ) -> Result<(), IngressFailure>,
{
    let Session {
        inner,
        mut source,
        outbound,
    } = session;
    let activity = Activity {
        at: Cell::new(clock.now()),
        receiving: Cell::new(false),
        sending: Cell::new(false),
        stop: StopRequest::default(),
    };
    let end = {
        let mut receiving = pin!(Some(receiving(
            reader,
            &parameters,
            &inner.metrics,
            &activity,
            outbound,
            dispatch,
            clock
        )));
        let mut sending = pin!(Some(sending(
            &mut source,
            writer,
            inner,
            parameters.validity,
            &activity,
            !outbound,
            clock
        )));
        let mut invalid = pin!(parameters.validity.wait());
        let mut shutdown = pin!(shutdown);
        let mut deadline = activity.at.get() + parameters.idle_timeout;
        loop {
            let Some(receiver) = receiving.as_mut().as_pin_mut() else {
                break DuplexEnd::new(StreamClose::InternalError);
            };
            let Some(sender) = sending.as_mut().as_pin_mut() else {
                break DuplexEnd::new(StreamClose::InternalError);
            };
            let first = async {
                let traffic = async {
                    let idle = clock.sleep_until(deadline);
                    match select(receiver, pin!(select(sender, pin!(idle)))).await {
                        Either::Left((end, _)) => FirstEvent::Received(end),
                        Either::Right((Either::Left((end, _)), _)) => FirstEvent::Sent(end),
                        Either::Right((Either::Right(_), _)) => FirstEvent::Idle,
                    }
                };
                let authenticated = async {
                    match select(invalid.as_mut(), pin!(traffic)).await {
                        Either::Left((reason, _)) => FirstEvent::Invalid(reason),
                        Either::Right((event, _)) => event,
                    }
                };
                match select(shutdown.as_mut(), pin!(authenticated)).await {
                    Either::Left(_) => FirstEvent::Shutdown,
                    Either::Right((event, _)) => event,
                }
            }
            .await;
            let end = match first {
                FirstEvent::Received(end) => end,
                FirstEvent::Sent(SendEnd::Failed { reason, abort }) => {
                    receiving.as_mut().set(None);
                    break DuplexEnd {
                        abort,
                        ..DuplexEnd::new(reason)
                    };
                }
                FirstEvent::Sent(SendEnd::Stopped) | FirstEvent::Shutdown => {
                    DuplexEnd::new(StreamClose::Shutdown)
                }
                FirstEvent::Invalid(reason) => DuplexEnd::new(reason),
                FirstEvent::Idle => {
                    let now = clock.now();
                    let idle_at = activity.at.get() + parameters.idle_timeout;
                    if now < idle_at {
                        deadline = idle_at;
                        continue;
                    }
                    if activity.receiving.get() || activity.sending.get() {
                        deadline = now + parameters.idle_timeout;
                        continue;
                    }
                    DuplexEnd::new(StreamClose::Idle)
                }
            };
            receiving.as_mut().set(None);
            if end.abort {
                sending.as_mut().set(None);
                break end;
            }
            let Some(sender) = sending.as_mut().as_pin_mut() else {
                break end;
            };
            break end.finish(&activity.stop, sender).await;
        }
    };
    if let Some(queue) = source.queue_mut()
        && queue
            .current
            .as_ref()
            .is_some_and(|head| head.reservation.is_none())
    {
        if queue
            .current
            .as_ref()
            .is_some_and(|head| !head.write_outcome_recorded)
        {
            inner.metrics.dropped(DropReason::ConnectionLost, 1);
        }
        queue.current = None;
    }
    end
}

#[cfg(test)]
#[path = "duplex_tests.rs"]
mod tests;
