// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::error::Error;
use std::future::{Future, pending, ready};
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::mpsc;
use std::task::{Context, Waker};
use std::thread;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWriteExt};
use compio::net::TcpListener;
use compio::time::{sleep, timeout};

use compio::runtime::Runtime;
use futures_channel::oneshot;
use lonewolf_util::core_dispatcher::{CoreDispatcher, TaskError};

type TestResult = Result<(), Box<dyn Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);
const TWO: NonZeroUsize = NonZeroUsize::MIN.saturating_add(1);

fn run_test(test: impl Future<Output = TestResult>) -> TestResult {
    Runtime::new()?.block_on(timeout(TIMEOUT, test))?
}

fn dispatcher() -> io::Result<CoreDispatcher> {
    CoreDispatcher::new(NonZeroUsize::MIN, NonZeroUsize::MIN)
}

fn multiple_workers() -> io::Result<CoreDispatcher> {
    match CoreDispatcher::new(TWO, TWO) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => dispatcher(),
        result => result,
    }
}

struct DropNotice(Option<oneshot::Sender<thread::ThreadId>>);

impl Drop for DropNotice {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(thread::current().id());
        }
    }
}

#[test]
fn local_futures_and_child_tasks_stay_on_the_selected_worker() -> TestResult {
    run_test(async {
        let dispatcher = multiple_workers()?;
        let handle = dispatcher.handle();
        let mut threads = Vec::new();
        for index in 0..handle.worker_count() {
            let task = handle
                .dispatch_at(index, move |context| {
                    let local = Rc::new(Cell::new(0));
                    async move {
                        assert_eq!(context.worker.index, index);
                        let worker_thread = thread::current().id();
                        let child_local = Rc::clone(&local);
                        let child = compio::runtime::spawn(async move {
                            sleep(Duration::from_millis(1)).await;
                            child_local.set(42);
                            thread::current().id()
                        });
                        assert_eq!(child.await.ok(), Some(worker_thread));
                        assert_eq!(local.get(), 42);
                        assert_eq!(thread::current().id(), worker_thread);
                        #[cfg(target_os = "linux")]
                        {
                            use nix::sched::{CpuSet, sched_getaffinity};
                            use nix::unistd::Pid;

                            let mask = sched_getaffinity(Pid::from_raw(0))?;
                            let cpu = context
                                .worker
                                .cpu_id
                                .ok_or_else(|| io::Error::other("missing CPU"))?;
                            assert!(mask.is_set(cpu)?);
                            assert_eq!(
                                (0..CpuSet::count())
                                    .filter(|&cpu| mask.is_set(cpu) == Ok(true))
                                    .count(),
                                1
                            );
                        }
                        Ok::<_, io::Error>(worker_thread)
                    }
                })
                .await?;
            let worker_thread = task.await??;
            assert_ne!(worker_thread, thread::current().id());
            assert!(!threads.contains(&worker_thread));
            threads.push(worker_thread);
            let again = handle
                .dispatch_at(index, |_| ready(thread::current().id()))
                .await?;
            assert_eq!(again.await?, worker_thread);
        }
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn listener_connection_and_local_state_share_a_worker() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (ready, address) = oneshot::channel();
        let server = handle
            .dispatch_at(0, move |context| async move {
                let owner = Rc::new(thread::current().id());
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let _ = ready.send(address);
                let (mut connection, _) = listener.accept().await?;
                let BufResult(result, buffer) = connection.read_exact([0; 1]).await;
                result?;
                assert_eq!(thread::current().id(), *owner);
                sleep(Duration::from_millis(1)).await;
                connection.write_all(buffer).await.0?;
                assert_eq!(thread::current().id(), *owner);
                context.shutdown_requested().await;
                Ok::<_, io::Error>(())
            })
            .await?;
        let address = match address.await {
            Ok(address) => address,
            Err(_) => {
                server.await??;
                return Err("listener stopped before binding".into());
            }
        };
        ::blocking::unblock(move || -> io::Result<()> {
            let mut client = std::net::TcpStream::connect_timeout(&address, TIMEOUT)?;
            client.set_read_timeout(Some(TIMEOUT))?;
            client.set_write_timeout(Some(TIMEOUT))?;
            client.write_all(&[42])?;
            let mut response = [0; 1];
            client.read_exact(&mut response)?;
            assert_eq!(response, [42]);
            Ok(())
        })
        .await?;
        dispatcher.shutdown(TIMEOUT).await?;
        server.await??;
        Ok(())
    })
}

#[test]
fn shutdown_notifies_tasks_and_waits_for_their_cleanup() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (started, running) = oneshot::channel();
        let (dropped, cleanup) = oneshot::channel();
        let task = handle
            .dispatch_at(0, move |context| async move {
                let _notice = DropNotice(Some(dropped));
                let _ = started.send(());
                let deadline = context.shutdown_requested().await;
                assert!(deadline > Instant::now());
                sleep(Duration::from_millis(1)).await;
                thread::current().id()
            })
            .await?;
        running.await?;
        dispatcher.shutdown(TIMEOUT).await?;
        assert_eq!(task.await?, cleanup.await?);
        let error = handle
            .dispatch_at(0, |_| ready(()))
            .await
            .err()
            .ok_or("submission succeeded after shutdown")?;
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        Ok(())
    })
}

#[test]
fn deadline_cancels_unfinished_tasks_and_drops_them_on_the_worker() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (started, running) = oneshot::channel();
        let (dropped, cleanup) = oneshot::channel();
        let task = handle
            .dispatch_at(0, move |_| async move {
                let _notice = DropNotice(Some(dropped));
                let _ = started.send(thread::current().id());
                pending::<()>().await;
            })
            .await?;
        let worker = running.await?;
        let error = dispatcher
            .shutdown(Duration::from_millis(10))
            .await
            .err()
            .ok_or("shutdown did not time out")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(task.await, Err(TaskError::Cancelled));
        assert_eq!(cleanup.await?, worker);
        Ok(())
    })
}

#[test]
fn task_panics_are_reported_without_stopping_the_worker() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let factory_panic = handle
            .dispatch_at(0, |_| -> std::future::Ready<()> { panic!("factory panic") })
            .await?;
        assert_eq!(factory_panic.await, Err(TaskError::Panicked));
        let future_panic = handle
            .dispatch_at(0, |_| async {
                sleep(Duration::from_millis(1)).await;
                panic!("future panic");
            })
            .await?;
        assert_eq!(future_panic.await, Err(TaskError::Panicked));
        assert_eq!(handle.dispatch_at(0, |_| ready(42)).await?.await?, 42);
        assert!(dispatcher.shutdown(TIMEOUT).await.is_err());
        Ok(())
    })
}

#[test]
fn invalid_worker_index_returns_an_error() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let error = handle
            .dispatch_at(1, |_| ready(()))
            .await
            .err()
            .ok_or("invalid index accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn shutdown_joins_every_worker_when_one_reports_a_panic() -> TestResult {
    run_test(async {
        let dispatcher = multiple_workers()?;
        let handle = dispatcher.handle();
        let failed = handle
            .dispatch_at(0, |_| async { panic!("task panic") })
            .await?;
        assert_eq!(failed.await, Err(TaskError::Panicked));
        let (started, running) = oneshot::channel();
        let (dropped, cleanup) = oneshot::channel();
        let task = handle
            .dispatch_at(handle.worker_count() - 1, move |context| async move {
                let _notice = DropNotice(Some(dropped));
                let _ = started.send(());
                context.shutdown_requested().await;
                thread::current().id()
            })
            .await?;
        running.await?;
        assert!(dispatcher.shutdown(TIMEOUT).await.is_err());
        assert_eq!(task.await?, cleanup.await?);
        Ok(())
    })
}

#[test]
fn dropping_the_owner_cancels_tasks_even_while_handles_survive() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (started, running) = oneshot::channel();
        let task = handle
            .dispatch_at(0, move |_| async move {
                let _ = started.send(());
                pending::<()>().await;
            })
            .await?;
        running.await?;
        drop(dispatcher);
        assert_eq!(task.await, Err(TaskError::Cancelled));
        assert!(handle.dispatch_at(0, |_| ready(())).await.is_err());
        Ok(())
    })
}

#[test]
fn full_queue_applies_backpressure_and_cancelled_submissions_do_not_run() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (started, running) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let blocked = handle
            .dispatch_at(0, move |_| async move {
                let _ = started.send(());
                gate.recv_timeout(TIMEOUT)
            })
            .await?;
        running.recv_timeout(TIMEOUT)?;
        let queued = handle.dispatch_at(0, |_| ready(42)).await?;
        let (entered, executed) = oneshot::channel();
        let mut waiting = Box::pin(handle.dispatch_at(0, move |_| async move {
            let _ = entered.send(());
        }));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(waiting);
        release.send(())?;
        blocked.await??;
        assert_eq!(queued.await?, 42);
        assert!(executed.await.is_err());
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    })
}

#[test]
fn shutdown_rejects_waiting_submissions_and_cancels_queued_work() -> TestResult {
    run_test(async {
        let dispatcher = dispatcher()?;
        let handle = dispatcher.handle();
        let (started, running) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let blocked = handle
            .dispatch_at(0, move |_| async move {
                let _ = started.send(());
                gate.recv_timeout(TIMEOUT)
            })
            .await?;
        running.recv_timeout(TIMEOUT)?;
        let queued = handle.dispatch_at(0, |_| ready(42)).await?;
        let mut waiting = Box::pin(handle.dispatch_at(0, |_| ready(())));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(dispatcher);
        let error = waiting.await.err().ok_or("waiting submission succeeded")?;
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        release.send(())?;
        blocked.await??;
        assert_eq!(queued.await, Err(TaskError::Cancelled));
        Ok(())
    })
}

#[cfg(target_os = "linux")]
#[test]
fn worker_count_cannot_exceed_allowed_cpus() {
    assert_eq!(
        CoreDispatcher::new(NonZeroUsize::MAX, NonZeroUsize::MIN)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
}
