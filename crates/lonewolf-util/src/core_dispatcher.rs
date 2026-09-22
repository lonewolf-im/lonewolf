// SPDX-License-Identifier: Apache-2.0

//! Runs local futures on dedicated workers with bounded submission queues.
//!
//! Only dispatched tasks are tracked; they must join their own child tasks.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use compio::runtime::{JoinHandle, Runtime};
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Either, Shared, poll_fn, select};
use futures_util::stream::{FuturesUnordered, StreamExt};

type Job = Box<dyn FnOnce(WorkerContext) -> JoinHandle<bool> + Send>;
type Stop = Shared<BoxFuture<'static, Instant>>;

/// Owns runtime threads and requests cancellation on drop without waiting.
///
/// [`Self::shutdown`] waits for cleanup and reports worker failures.
pub struct CoreDispatcher {
    handle: DispatchHandle,
    workers: Vec<Worker>,
}

/// Clones share bounded submission queues without owning workers.
#[derive(Clone)]
pub struct DispatchHandle {
    senders: Arc<[async_channel::Sender<Job>]>,
}

struct Worker {
    stop: Option<oneshot::Sender<Instant>>,
    thread: thread::JoinHandle<io::Result<()>>,
}

struct Inbox(async_channel::Receiver<Job>);

impl Drop for Inbox {
    fn drop(&mut self) {
        self.0.close();
        while self.0.try_recv().is_ok() {}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerInfo {
    /// Zero-based index accepted by [`DispatchHandle::dispatch_at`].
    pub index: usize,
    /// Pinned logical CPU on Linux; `None` on other Unix targets.
    pub cpu_id: Option<usize>,
}

/// Shares the worker identity and shutdown signal with a dispatched task.
///
/// Tasks must join their local child tasks before completing.
#[derive(Clone)]
pub struct WorkerContext {
    pub worker: WorkerInfo,
    stop: Stop,
}

impl WorkerContext {
    /// Completes on shutdown with the deadline shared by all workers.
    ///
    /// Repeated calls return the same deadline, which may already have passed.
    pub async fn shutdown_requested(&self) -> Instant {
        self.stop.clone().await
    }
}

/// Reports task completion; dropping the handle leaves the task running.
///
/// Awaiting it returns [`TaskError::Panicked`] for a panic in the factory or
/// future, or [`TaskError::Cancelled`] if the worker drops the task.
#[must_use = "Await the task to observe its result and any panic."]
pub struct Task<T> {
    result: oneshot::Receiver<Result<T, TaskError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskError {
    Panicked,
    Cancelled,
}

impl fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Panicked => "dispatched task panicked",
            Self::Cancelled => "dispatched task was cancelled",
        })
    }
}

impl Error for TaskError {}

impl<T> Future for Task<T> {
    type Output = Result<T, TaskError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.result)
            .poll(context)
            .map(|result| result.unwrap_or(Err(TaskError::Cancelled)))
    }
}

impl CoreDispatcher {
    /// Blocks until all workers start and joins started workers on failure.
    ///
    /// Each worker has a queue of `queue_capacity` waiting jobs. Running tasks
    /// do not consume queue capacity. Linux workers pin to distinct allowed
    /// CPUs; other Unix targets do not pin workers.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the worker count exceeds the
    /// allowed CPU count on Linux, or [`io::ErrorKind::Other`] if a worker exits
    /// before reporting startup. Also returns CPU affinity, thread creation,
    /// or runtime initialization errors.
    pub fn new(workers: NonZeroUsize, queue_capacity: NonZeroUsize) -> io::Result<Self> {
        Self::start(worker_assignment(workers)?, queue_capacity, create_runtime)
    }

    fn start(
        assignments: Vec<WorkerInfo>,
        queue_capacity: NonZeroUsize,
        initialize: fn(WorkerInfo) -> io::Result<Runtime>,
    ) -> io::Result<Self> {
        let mut senders = Vec::with_capacity(assignments.len());
        let mut workers = Vec::with_capacity(assignments.len());
        for worker in assignments {
            match start_worker(worker, queue_capacity, initialize) {
                Ok((sender, handle)) => {
                    senders.push(sender);
                    workers.push(handle);
                }
                Err(error) => {
                    request_stop(&mut workers, Instant::now());
                    let _ = join_workers(workers);
                    return Err(error);
                }
            }
        }
        Ok(Self {
            handle: DispatchHandle {
                senders: senders.into(),
            },
            workers,
        })
    }

    pub fn handle(&self) -> DispatchHandle {
        self.handle.clone()
    }

    /// Closes queues, drops queued jobs, and waits for started tasks to finish.
    ///
    /// Signals the shared deadline, then joins every worker. Unfinished tasks
    /// are cancelled at the deadline. Tasks must yield for the deadline to
    /// take effect. Dropping this future after it starts does not stop worker
    /// cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if the deadline overflows,
    /// [`io::ErrorKind::TimedOut`] if a worker exceeds it, or
    /// [`io::ErrorKind::Other`] if a task or worker panicked. When several
    /// workers fail, reports the first failure in worker order.
    pub async fn shutdown(mut self, grace_period: Duration) -> io::Result<()> {
        let deadline = Instant::now().checked_add(grace_period).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "shutdown deadline overflows")
        })?;
        self.stop(deadline);
        let workers = std::mem::take(&mut self.workers);
        ::blocking::unblock(move || join_workers(workers)).await
    }

    fn stop(&mut self, deadline: Instant) {
        request_stop(&mut self.workers, deadline);
        for sender in self.handle.senders.iter() {
            sender.close();
        }
    }
}

impl Drop for CoreDispatcher {
    fn drop(&mut self) {
        self.stop(Instant::now());
    }
}

impl DispatchHandle {
    pub fn worker_count(&self) -> usize {
        self.senders.len()
    }

    /// Waits for queue space and creates the future on the selected worker.
    ///
    /// The future stays on that worker and need not implement [`Send`]. The
    /// factory must not block, and the future must yield to the runtime.
    /// Dropping a pending submission does not enqueue it; a returned [`Task`]
    /// can be dropped without cancelling the submitted work.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] for an out-of-range worker index
    /// or [`io::ErrorKind::BrokenPipe`] if that worker's queue has closed.
    pub async fn dispatch_at<F, Fut, T>(&self, worker: usize, factory: F) -> io::Result<Task<T>>
    where
        F: FnOnce(WorkerContext) -> Fut + Send + 'static,
        Fut: Future<Output = T> + 'static,
        T: Send + 'static,
    {
        let sender = self.senders.get(worker).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid dispatcher worker index",
            )
        })?;
        let (result, receiver) = oneshot::channel();
        let job: Job = Box::new(move |context| {
            compio::runtime::spawn(async move {
                let outcome = AssertUnwindSafe(async move { factory(context).await })
                    .catch_unwind()
                    .await
                    .map_err(|_| TaskError::Panicked);
                let panicked = outcome.is_err();
                let _ = result.send(outcome);
                panicked
            })
        });
        sender.send(job).await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "dispatcher worker has stopped")
        })?;
        Ok(Task { result: receiver })
    }
}

fn start_worker(
    worker: WorkerInfo,
    capacity: NonZeroUsize,
    initialize: fn(WorkerInfo) -> io::Result<Runtime>,
) -> io::Result<(async_channel::Sender<Job>, Worker)> {
    let (sender, jobs) = async_channel::bounded(capacity.get());
    let jobs = Inbox(jobs);
    let (stop, stopped) = oneshot::channel();
    let (ready, readiness) = mpsc::sync_channel(1);
    let thread = thread::Builder::new()
        .name(format!("lonewolf-core-{}", worker.index))
        .spawn(move || {
            let runtime = match initialize(worker) {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return Ok(());
                }
            };
            let stop = async move { stopped.await.unwrap_or_else(|_| Instant::now()) }
                .boxed()
                .shared();
            runtime.block_on(async move {
                if ready.send(Ok(())).is_err() {
                    return Ok(());
                }
                run_worker(WorkerContext { worker, stop }, jobs).await
            })
        })?;
    match readiness.recv() {
        Ok(Ok(())) => Ok((
            sender,
            Worker {
                stop: Some(stop),
                thread,
            },
        )),
        result => {
            drop(stop);
            let _ = thread.join();
            Err(match result {
                Ok(Err(error)) => error,
                Err(_) => io::Error::other("dispatcher worker stopped during startup"),
                Ok(Ok(())) => unreachable!(),
            })
        }
    }
}

async fn run_worker(context: WorkerContext, jobs: Inbox) -> io::Result<()> {
    let mut tasks = FuturesUnordered::new();
    let mut panicked = false;
    let deadline = {
        let mut stop = pin!(context.stop.clone());
        loop {
            let event = {
                let progress = async {
                    if tasks.is_empty() {
                        return jobs.0.recv().await.map(Some);
                    }
                    match select(pin!(tasks.next()), pin!(jobs.0.recv())).await {
                        Either::Left((result, _)) => {
                            panicked |= task_panicked(result);
                            Ok(None)
                        }
                        Either::Right((result, _)) => result.map(Some),
                    }
                };
                match select(stop.as_mut(), pin!(progress)).await {
                    Either::Left((deadline, _)) => Either::Left(deadline),
                    Either::Right((result, _)) => Either::Right(result),
                }
            };
            match event {
                Either::Left(deadline) => break deadline,
                Either::Right(Ok(Some(job))) => {
                    tasks.push(job(context.clone()));
                    // A ready queue must not starve spawned tasks or timers.
                    yield_to_runtime().await;
                }
                Either::Right(Ok(None)) => {}
                // Queue closure alone must not shorten the shared grace period.
                Either::Right(Err(_)) => break stop.await,
            }
        }
    };
    drop(jobs);
    let drain = async {
        while let Some(result) = tasks.next().await {
            panicked |= !matches!(result, Ok(false));
        }
    };
    if compio::time::timeout_at(deadline, drain).await.is_err() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "dispatcher worker exceeded shutdown deadline",
        ));
    }
    if panicked {
        return Err(io::Error::other("a dispatched task panicked"));
    }
    Ok(())
}

fn task_panicked(result: Option<Result<bool, compio::runtime::JoinError>>) -> bool {
    !matches!(result, None | Some(Ok(false)))
}

async fn yield_to_runtime() {
    let mut yielded = false;
    poll_fn(|context| {
        if std::mem::replace(&mut yielded, true) {
            Poll::Ready(())
        } else {
            context.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

fn request_stop(workers: &mut [Worker], deadline: Instant) {
    for worker in workers {
        if let Some(stop) = worker.stop.take() {
            let _ = stop.send(deadline);
        }
    }
}

fn join_workers(workers: Vec<Worker>) -> io::Result<()> {
    let mut outcome = Ok(());
    for worker in workers {
        let result = worker
            .thread
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("dispatcher worker panicked")));
        if outcome.is_ok() {
            outcome = result;
        }
    }
    outcome
}

#[cfg(target_os = "linux")]
fn worker_assignment(count: NonZeroUsize) -> io::Result<Vec<WorkerInfo>> {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;

    let allowed = sched_getaffinity(Pid::from_raw(0))?;
    let mut workers = Vec::with_capacity(count.get().min(CpuSet::count()));
    for cpu in 0..CpuSet::count() {
        if allowed.is_set(cpu)? {
            workers.push(WorkerInfo {
                index: workers.len(),
                cpu_id: Some(cpu),
            });
            if workers.len() == count.get() {
                return Ok(workers);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "worker count exceeds the allowed CPU set",
    ))
}

#[cfg(not(target_os = "linux"))]
fn worker_assignment(count: NonZeroUsize) -> io::Result<Vec<WorkerInfo>> {
    Ok((0..count.get())
        .map(|index| WorkerInfo {
            index,
            cpu_id: None,
        })
        .collect())
}

fn create_runtime(worker: WorkerInfo) -> io::Result<Runtime> {
    #[cfg(target_os = "linux")]
    if let Some(cpu) = worker.cpu_id {
        use nix::sched::{CpuSet, sched_setaffinity};
        use nix::unistd::Pid;

        let mut affinity = CpuSet::new();
        affinity.set(cpu)?;
        sched_setaffinity(Pid::from_raw(0), &affinity)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = worker;
    Runtime::new()
}

#[cfg(test)]
#[path = "../tests/core_dispatcher/lifecycle.rs"]
mod tests;
