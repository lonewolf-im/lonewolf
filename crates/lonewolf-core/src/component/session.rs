// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use compio::net::TcpStream;
use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use futures_util::task::AtomicWaker;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaNamespace};
use lonewolf_xmpp::stream::StreamErrorCondition;
use tokio::io::AsyncBufRead;

use super::bounce;
use super::ingress::{self, Context, IngressFailure};
use super::metrics::{ComponentMetrics, DropReason, StreamClose};
use super::negotiate::Authenticated;
use super::registry::ComponentLink;
use super::stream::{ComponentError, ComponentReader, ComponentWriter, WriteProgress};
use super::{ComponentServices, Settings};
use crate::connection::ShutdownSignal;
use crate::delivery::WorkGroup;

trait Clock {
    fn now(&self) -> Instant;
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}
struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    async fn sleep_until(&self, deadline: Instant) {
        compio::time::sleep_until(deadline).await;
    }
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

async fn watch<T>(
    operation: impl Future<Output = Result<T, ComponentError>>,
    progress: &WriteProgress,
    timeout: Duration,
    clock: &impl Clock,
    abort: &impl Fn(),
) -> Result<T, StreamClose> {
    let started = clock.now();
    let mut deadline = started + timeout;
    let mut operation = pin!(operation);
    loop {
        if clock.now() >= deadline {
            deadline = started.max(progress.last()) + timeout;
            if clock.now() >= deadline {
                abort();
                return Err(StreamClose::StalledWrite);
            }
        }
        match select(pin!(clock.sleep_until(deadline)), operation.as_mut()).await {
            Either::Right((result, _)) => {
                return result.map_err(|error| match error {
                    ComponentError::Internal => StreamClose::InternalError,
                    _ => StreamClose::TransportError,
                });
            }
            Either::Left(_) => {
                deadline = started.max(progress.last()) + timeout;
                if clock.now() >= deadline {
                    abort();
                    return Err(StreamClose::StalledWrite);
                }
            }
        }
    }
}

async fn sending<A: ChunkAllocator + Clone + 'static, W: AsyncWrite + Unpin>(
    link: &mut ComponentLink<A>,
    writer: &mut ComponentWriter<W>,
    stop: &StopRequest,
    metrics: &ComponentMetrics,
    timeout: Duration,
    clock: &impl Clock,
    abort: &impl Fn(),
) -> Result<(), StreamClose> {
    let progress = writer.progress();
    let mut buffered = false;
    loop {
        if stop.requested.get() {
            return Ok(());
        }
        let stanza = match link.try_next() {
            Some(stanza) => stanza,
            None => {
                if buffered {
                    watch(writer.flush(), &progress, timeout, clock, abort).await?;
                    buffered = false;
                }
                match select(pin!(stop.wait()), pin!(link.next())).await {
                    Either::Left(_) => return Ok(()),
                    Either::Right((Some(stanza), _)) => stanza,
                    Either::Right((None, _)) => return Err(StreamClose::TransportError),
                }
            }
        };
        let view = stanza.resolve().ok().filter(|view| {
            view.validate_rescope(StanzaNamespace::ComponentAccept)
                .is_ok()
        });
        if let Some(view) = view {
            watch(writer.write_stanza(&view), &progress, timeout, clock, abort).await?;
            buffered = true;
            metrics.stanza_sent(view.kind());
        } else {
            metrics.dropped(DropReason::Invalid, 1);
        }
        cooperate().await;
    }
}

struct End {
    outcome: StreamClose,
    condition: Option<StreamErrorCondition>,
    peer_footer: bool,
    abort: bool,
}
impl End {
    fn abort(outcome: StreamClose) -> Self {
        Self {
            outcome,
            condition: None,
            peer_footer: false,
            abort: true,
        }
    }
    fn error(condition: StreamErrorCondition) -> Self {
        Self {
            outcome: super::receive::violation_close(condition),
            condition: Some(condition),
            peer_footer: false,
            abort: false,
        }
    }
}
async fn receiving<A, R, D>(
    reader: &mut ComponentReader<A, R>,
    context: &Context<A>,
    domain: &str,
    metrics: &ComponentMetrics,
    mut dispatch: D,
) -> End
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    D: for<'a> AsyncFnMut(&'a Context<A>, &'a str, RoutedStanza<A>) -> Result<(), IngressFailure>,
{
    loop {
        let event = match reader.next_event().await {
            Ok(Some(StreamEvent::StreamEnd)) => {
                return End {
                    outcome: StreamClose::StreamEnd,
                    condition: None,
                    peer_footer: true,
                    abort: false,
                };
            }
            Ok(Some(event)) => event,
            Ok(None) | Err(ComponentError::Eof | ComponentError::Io | ComponentError::Timeout) => {
                return End::abort(StreamClose::TransportError);
            }
            Err(ComponentError::PeerError(_)) => return End::abort(StreamClose::PeerError),
            Err(ComponentError::Stream(condition)) => return End::error(condition),
            Err(ComponentError::Internal) => {
                return End::error(StreamErrorCondition::InternalServerError);
            }
        };
        if let Err(condition) =
            super::receive::process(event, domain, metrics, context, async |stanza| {
                dispatch(context, domain, stanza)
                    .await
                    .map_err(|_| StreamErrorCondition::InternalServerError)
            })
            .await
        {
            return End::error(condition);
        }
        cooperate().await;
    }
}

struct CloseDeadline {
    at: Cell<Instant>,
    shutdown_seen: Cell<bool>,
}
impl CloseDeadline {
    fn new(clock: &impl Clock, shutdown: &ShutdownSignal) -> Self {
        let deadline = clock.now() + Duration::from_secs(6);
        let known = shutdown.clone().now_or_never();
        Self {
            at: Cell::new(known.map_or(deadline, |known| known.min(deadline))),
            shutdown_seen: Cell::new(known.is_some()),
        }
    }
    async fn bound<T>(
        &self,
        operation: impl Future<Output = T>,
        shutdown: &ShutdownSignal,
        clock: &impl Clock,
        abort: &impl Fn(),
    ) -> Result<T, ()> {
        let mut operation = pin!(operation);
        loop {
            if clock.now() >= self.at.get() {
                abort();
                return Err(());
            }
            let timed = async {
                match select(pin!(clock.sleep_until(self.at.get())), operation.as_mut()).await {
                    Either::Right((result, _)) => Ok(result),
                    Either::Left(_) => {
                        abort();
                        Err(())
                    }
                }
            };
            if self.shutdown_seen.get() {
                return timed.await;
            }
            match select(pin!(shutdown.clone()), pin!(timed)).await {
                Either::Left((deadline, _)) => {
                    self.at.set(self.at.get().min(deadline));
                    self.shutdown_seen.set(true);
                }
                Either::Right((result, _)) => return result,
            }
        }
    }
}

async fn run<A, R, W, D>(
    authenticated: &mut Authenticated<A, R, W>,
    context: &Context<A>,
    settings: &Settings<A>,
    shutdown: ShutdownSignal,
    dispatch: D,
    clock: &impl Clock,
    abort: &impl Fn(),
) -> StreamClose
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(&'a Context<A>, &'a str, RoutedStanza<A>) -> Result<(), IngressFailure>,
{
    let stop = StopRequest::default();
    let timeout = Duration::from_secs(settings.limits.stalled_write_timeout_secs.get());
    let progress = authenticated.writer.progress();
    let (mut end, deadline) = {
        let mut receive = pin!(Some(receiving(
            &mut authenticated.reader,
            context,
            &authenticated.domain,
            &settings.metrics,
            dispatch
        )));
        let mut send = pin!(Some(sending(
            &mut authenticated.link,
            &mut authenticated.writer,
            &stop,
            &settings.metrics,
            timeout,
            clock,
            abort
        )));
        let receiver = receive.as_mut().as_pin_mut().ok_or(());
        let sender = send.as_mut().as_pin_mut().ok_or(());
        let event = match (receiver, sender) {
            (Ok(receiver), Ok(sender)) => {
                match select(pin!(shutdown.clone()), pin!(select(receiver, sender))).await {
                    Either::Left(_) => End {
                        outcome: StreamClose::Shutdown,
                        condition: Some(StreamErrorCondition::SystemShutdown),
                        peer_footer: false,
                        abort: false,
                    },
                    Either::Right((Either::Left((end, _)), _)) => end,
                    Either::Right((Either::Right((Err(outcome), _)), _)) => End::abort(outcome),
                    Either::Right((Either::Right((Ok(()), _)), _)) => {
                        End::error(StreamErrorCondition::InternalServerError)
                    }
                }
            }
            _ => End::error(StreamErrorCondition::InternalServerError),
        };
        let deadline = CloseDeadline::new(clock, &shutdown);
        authenticated.stream_accounting.set_outcome(event.outcome);
        if event.condition.is_some() && !matches!(event.outcome, StreamClose::Shutdown) {
            tracing::warn!(component_domain = %authenticated.domain, connection_id = authenticated.connection_id, outcome = event.outcome.as_str(), "component stream violation");
        }
        let mut end = event;
        receive.as_mut().set(None);
        if end.abort {
            abort();
        } else {
            stop.request();
            if let Some(sender) = send.as_mut().as_pin_mut() {
                match deadline.bound(sender, &shutdown, clock, abort).await {
                    Ok(Ok(())) => {}
                    _ => {
                        abort();
                        end.abort = true;
                    }
                }
            }
        }
        send.as_mut().set(None);
        (end, deadline)
    };
    if !end.abort {
        let closing = async {
            watch(
                authenticated.writer.flush(),
                &progress,
                timeout,
                clock,
                abort,
            )
            .await?;
            watch(
                authenticated.writer.close(end.condition),
                &progress,
                timeout,
                clock,
                abort,
            )
            .await?;
            let peer_until = clock.now() + Duration::from_secs(5);
            if end.peer_footer {
                let _ = select(
                    pin!(authenticated.reader.transport_end()),
                    pin!(clock.sleep_until(peer_until)),
                )
                .await;
            } else {
                let wait = async {
                    while let Ok(Some(event)) = authenticated.reader.next_event().await {
                        if matches!(event, StreamEvent::StreamEnd) {
                            break;
                        }
                    }
                };
                let _ = select(pin!(wait), pin!(clock.sleep_until(peer_until))).await;
            }
            watch(
                authenticated.writer.shutdown(),
                &progress,
                timeout,
                clock,
                abort,
            )
            .await
        };
        if !matches!(
            deadline.bound(closing, &shutdown, clock, abort).await,
            Ok(Ok(()))
        ) {
            end.abort = true;
        }
    }
    abort();
    end.outcome
}

pub(crate) async fn serve<A, R, W>(
    authenticated: Authenticated<A, R, W>,
    tcp: &TcpStream,
    settings: &Settings<A>,
    services: &ComponentServices<A>,
    shutdown: ShutdownSignal,
) -> StreamClose
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
{
    let aborted = Cell::new(false);
    let abort = || {
        if !aborted.replace(true) {
            let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both);
        }
    };
    serve_with(
        authenticated,
        settings,
        services,
        shutdown,
        ingress::dispatch,
        &SystemClock,
        &abort,
    )
    .await
}

async fn serve_with<A, R, W, D>(
    mut authenticated: Authenticated<A, R, W>,
    settings: &Settings<A>,
    services: &ComponentServices<A>,
    shutdown: ShutdownSignal,
    dispatch: D,
    clock: &impl Clock,
    abort: &impl Fn(),
) -> StreamClose
where
    A: ChunkAllocator + Clone + 'static,
    R: AsyncBufRead + Unpin + 'static,
    W: AsyncWrite + Unpin,
    D: for<'a> AsyncFnMut(&'a Context<A>, &'a str, RoutedStanza<A>) -> Result<(), IngressFailure>,
{
    let mut group = WorkGroup::new();
    let context = Context {
        router: services.router.clone(),
        storage: services.storage.clone(),
        allocator: services.allocator.clone(),
        work: group.handle(),
        registry: settings.registry.clone(),
        connection_id: authenticated.link.id(),
    };
    let outcome = run(
        &mut authenticated,
        &context,
        settings,
        shutdown.clone(),
        dispatch,
        clock,
        abort,
    )
    .await;
    if matches!(outcome, StreamClose::Shutdown) || shutdown.clone().now_or_never().is_some() {
        authenticated.link.discard();
    } else {
        let detached = authenticated.link.detach();
        bounce::undelivered(&context, &authenticated.domain, detached.stranded, async {
            shutdown.await;
        })
        .await;
    }
    drop(context);
    group.drain().await;
    drop(authenticated.stream_accounting);
    drop(authenticated.stream_gauge);
    outcome
}

#[cfg(test)]
mod tests;
