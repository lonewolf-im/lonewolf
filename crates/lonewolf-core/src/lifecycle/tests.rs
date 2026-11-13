// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::io;
use std::pin::pin;
use std::time::Duration;

use compio::runtime::Runtime;
use futures_channel::oneshot;
use futures_util::poll;
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::core_dispatcher::CoreDispatcher;

use super::*;
use crate::connection::{ListenerKind, ListenerOutcome};
use crate::router::local::LocalRouter;

const TIMEOUT: Duration = Duration::from_secs(5);
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn service_join() -> ServiceJoin {
    ServiceJoin {
        primary: Ok(()),
        admin: Ok(()),
        metrics: Ok(()),
        acme: Ok(()),
        drain: Ok(()),
        router_failure: None,
    }
}
fn listener(result: Result<(), RunError>, deadline: bool) -> ListenerJoin {
    ListenerJoin {
        result,
        drain_deadline_exceeded: deadline,
    }
}
fn joined() -> ServingJoin {
    ServingJoin {
        s2s: listener(Ok(()), false),
        c2s: listener(Ok(()), false),
        remote: Ok(()),
        router: Ok(()),
        acme_drain: Ok(()),
    }
}

#[test]
fn partial_startup_owned_components_stop_once_and_join_before_returning_primary() -> TestResult {
    Runtime::new()?.block_on(async {
        for count in 0_usize..4 {
            let config = crate::Config::default();
            let hosts = crate::Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
            let mut serving = Serving::<GlobalChunkAllocator>::new();
            if count>0 { serving.router = Some(Router::new(hosts, LocalRouter::new(GlobalChunkAllocator))); }
            let mut stopped = Vec::new();
            for slot in 0..count.saturating_sub(1) {
                let (stop, until) = oneshot::channel();
                let listeners = ListenerSet::with_test_channels(if slot==0 { ListenerKind::C2s } else { ListenerKind::S2s }, stop, async_channel::bounded(1).1, 1);
                if slot==0 { serving.c2s = Some(listeners); } else { serving.s2s = Some(listeners); }
                stopped.push(until);
            }
            let deadline = Instant::now() + TIMEOUT;
            serving.stop(deadline);
            serving.stop(deadline + TIMEOUT);
            assert_eq!(serving.deadline, Some(deadline));
            for stopped in stopped { assert_eq!(stopped.await?, deadline); }
            if let Some(router) = &serving.router { assert!(matches!(router.state(), RouterState::Stopping)); }
            let drained = Cell::new(false);
            let result = serving.join(deadline, async { drained.set(true); Ok(()) }).await;
            assert!(drained.get());
            assert!(serving.router.is_none());
            assert!(matches!(result.startup(Err(RunError::C2s(io::Error::other("startup"))), Ok(())), Err(RunError::C2s(error)) if error.to_string()=="startup"));
        }
        Ok(())
    })
}

#[test]
fn join_retains_acme_interleave_and_runs_every_cleanup_after_errors() -> TestResult {
    Runtime::new()?.block_on(async {
        let events = RefCell::new(Vec::new());
        let (release_s2s, s2s_ready) = oneshot::channel();
        let (release_acme, acme_ready) = oneshot::channel();
        let c2s_started = Cell::new(false);
        let mut join = pin!(collect_join(
            async {
                events.borrow_mut().push("s2s");
                let _ = s2s_ready.await;
                listener(Err(RunError::S2s(io::Error::other("s2s"))), false)
            },
            async {
                events.borrow_mut().push("acme");
                let _ = acme_ready.await;
                Err(RunError::Acme {
                    phase: "drain",
                    source: Box::new(io::Error::other("acme")),
                })
            },
            async {
                c2s_started.set(true);
                events.borrow_mut().push("c2s");
                listener(Err(RunError::C2s(io::Error::other("c2s"))), false)
            },
            async {
                events.borrow_mut().push("remote");
                Err(RunError::S2s(io::Error::other("remote")))
            },
            async {
                events.borrow_mut().push("router");
                Err(RunError::RouterShutdown(io::Error::other("router")))
            },
        ));
        assert!(poll!(join.as_mut()).is_pending());
        assert_eq!(events.borrow().as_slice(), &["s2s"]);
        release_s2s.send(()).map_err(|_| "s2s gate dropped")?;
        assert!(poll!(join.as_mut()).is_pending());
        assert_eq!(events.borrow().as_slice(), &["s2s", "acme"]);
        assert!(!c2s_started.get());
        release_acme.send(()).map_err(|_| "ACME gate dropped")?;
        let result = join.await;
        assert_eq!(
            events.borrow().as_slice(),
            &["s2s", "acme", "c2s", "remote", "router"]
        );
        assert!(matches!(result.s2s.result, Err(RunError::S2s(_))));
        assert!(matches!(result.c2s.result, Err(RunError::C2s(_))));
        assert!(matches!(result.remote, Err(RunError::S2s(_))));
        assert!(matches!(result.router, Err(RunError::RouterShutdown(_))));
        assert!(matches!(result.acme_drain, Err(RunError::Acme { .. })));
        Ok(())
    })
}

fn stage(index: usize, first: usize) -> Result<(), RunError> {
    if index < first {
        return Ok(());
    }
    let error = io::Error::other(index.to_string());
    Err(match index {
        0 => RunError::Signal(error),
        1 => RunError::Admin(error),
        2 => RunError::S2s(error),
        3 => RunError::Metrics(error),
        4 => RunError::Acme {
            phase: "service",
            source: Box::new(error),
        },
        5 => RunError::C2s(error),
        6 => RunError::S2s(error),
        7 => RunError::DispatcherShutdown(error),
        8 => RunError::RouterShutdown(error),
        _ => RunError::Acme {
            phase: "drain",
            source: Box::new(error),
        },
    })
}
fn selected(error: RunError) -> (std::mem::Discriminant<RunError>, String) {
    use std::error::Error;
    (
        std::mem::discriminant(&error),
        error.source().map(ToString::to_string).unwrap_or_default(),
    )
}

#[test]
fn normal_results_follow_component_priority_without_execution_order_bias() {
    for first in 0..10 {
        let services = ServiceJoin {
            primary: stage(0, first),
            admin: stage(1, first),
            metrics: stage(3, first),
            acme: stage(4, first),
            drain: Ok(()),
            router_failure: None,
        };
        let result = ServingJoin {
            remote: stage(2, first),
            c2s: listener(stage(5, first), false),
            s2s: listener(stage(6, first), false),
            router: stage(8, first),
            acme_drain: stage(9, first),
        }
        .normal(services, stage(7, first));
        assert_eq!(
            selected(result.unwrap_err()),
            selected(stage(first, 0).unwrap_err())
        );
    }
}

#[test]
fn startup_results_keep_the_existing_fallback_priority() {
    for (position, expected) in [0, 7, 5, 6, 2, 8, 9].into_iter().enumerate() {
        let order = [0, 7, 5, 6, 2, 8, 9];
        let fail = |index| {
            if order
                .iter()
                .position(|value| *value == index)
                .is_some_and(|candidate| candidate < position)
            {
                Ok(())
            } else {
                stage(index, 0)
            }
        };
        let result = ServingJoin {
            remote: fail(2),
            c2s: listener(fail(5), true),
            s2s: listener(fail(6), true),
            router: fail(8),
            acme_drain: fail(9),
        }
        .startup(fail(0), fail(7));
        assert_eq!(
            selected(result.unwrap_err()),
            selected(stage(expected, 0).unwrap_err())
        );
    }
}

#[test]
fn ready_listener_deadline_overrides_cleanup_errors_but_preserves_primary() {
    for failure in [None, Some(RouterFailure { shard_id: 2 })] {
        for primary in [false, true] {
            let mut services = service_join();
            services.router_failure = failure;
            services.admin = Err(RunError::Admin(io::Error::other("cleanup")));
            if primary {
                services.primary = Err(RunError::C2s(io::Error::other("fatal accept")));
            }
            let mut result = joined();
            result.c2s = listener(
                Err(RunError::C2s(io::Error::other("masked deadline"))),
                true,
            );
            match result.normal(services, Ok(())) {
                Err(RunError::C2s(error)) if primary => {
                    assert_eq!(error.to_string(), "fatal accept")
                }
                Err(RunError::RouterFailed(actual)) if failure.is_some() => {
                    assert_eq!(Some(actual), failure)
                }
                Err(RunError::DispatcherShutdown(error)) if failure.is_none() => {
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut)
                }
                other => panic!("wrong deadline result: {other:?}"),
            }
        }
    }
    let mut result = joined();
    result.s2s = listener(
        Err(RunError::S2s(io::Error::new(
            io::ErrorKind::TimedOut,
            "s2s listener shutdown timed out",
        ))),
        false,
    );
    assert!(matches!(
        result.normal(service_join(), Ok(())),
        Err(RunError::S2s(_))
    ));
}

#[test]
fn listener_only_outer_deadline_maps_global_drain_after_backgrounds_finish() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let dispatcher =
            CoreDispatcher::new(std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN)?;
        for kind in [ListenerKind::C2s, ListenerKind::S2s] {
            let error: fn(io::Error) -> RunError = match kind {
                ListenerKind::C2s => RunError::C2s,
                ListenerKind::S2s => RunError::S2s,
            };
            for failure in [None, Some(RouterFailure { shard_id: 4 })] {
                let (stop, _stopped) = oneshot::channel();
                let mut listeners =
                    ListenerSet::with_test_channels(kind, stop, async_channel::bounded(1).1, 1);
                let (release, gate) = oneshot::channel();
                listeners.test_tasks().push(
                    dispatcher.handle().dispatch_at(0, move |_| async move {
                        let _ = gate.await;
                        ListenerOutcome::from(Ok(()))
                    }).await?,
                );
                let late = join_listeners(Some(&mut listeners), Instant::now(), error).await;
                assert!(late.drain_deadline_exceeded);
                assert!(matches!(&late.result, Err(RunError::C2s(error) | RunError::S2s(error)) if error.kind() == io::ErrorKind::TimedOut));
                let mut cleanup = joined();
                match kind {
                    ListenerKind::C2s => cleanup.c2s = late,
                    ListenerKind::S2s => cleanup.s2s = late,
                }
                let mut services = service_join();
                services.router_failure = failure;
                let result = cleanup.normal(services, Ok(()));
                if let Some(failure) = failure {
                    assert!(matches!(result, Err(RunError::RouterFailed(actual)) if actual == failure));
                } else {
                    assert!(matches!(result, Err(RunError::DispatcherShutdown(error)) if error.kind() == io::ErrorKind::TimedOut));
                }
                release.send(()).map_err(|_| "listener gate dropped")?;
                listeners.join().await?;
            }
        }
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    }))?
}

#[test]
fn ready_listener_join_does_not_infer_exhaustion_from_the_clock() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let dispatcher =
            CoreDispatcher::new(std::num::NonZeroUsize::MIN, std::num::NonZeroUsize::MIN)?;
        for kind in [ListenerKind::C2s, ListenerKind::S2s] {
            let error: fn(io::Error) -> RunError = match kind {
                ListenerKind::C2s => RunError::C2s,
                ListenerKind::S2s => RunError::S2s,
            };
            for outcome in [
                None,
                Some(ListenerOutcome::from(Ok(()))),
                Some(ListenerOutcome::from(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ordinary timeout",
                )))),
                Some(ListenerOutcome {
                    result: Err(io::Error::new(io::ErrorKind::TimedOut, "marked deadline")),
                    drain_deadline_exceeded: true,
                }),
            ] {
                let expected_error = outcome.as_ref().and_then(|outcome| {
                    outcome.result.as_ref().err().map(|error| error.to_string())
                });
                let expected_deadline = outcome
                    .as_ref()
                    .is_some_and(|outcome| outcome.drain_deadline_exceeded);
                let (stop, _stopped) = oneshot::channel();
                let mut listeners =
                    ListenerSet::with_test_channels(kind, stop, async_channel::bounded(1).1, 1);
                if let Some(outcome) = outcome {
                    let (completed, ready) = oneshot::channel();
                    listeners.test_tasks().push(
                        dispatcher
                            .handle()
                            .dispatch_at(0, move |_| async move {
                                // This task runs after the dispatcher publishes the listener result.
                                compio::runtime::spawn(async move {
                                    let _ = completed.send(());
                                })
                                .detach();
                                outcome
                            })
                            .await?,
                    );
                    ready.await?;
                }
                let result = join_listeners(Some(&mut listeners), Instant::now(), error).await;
                match expected_error {
                    None => assert!(result.result.is_ok()),
                    Some(expected) => match result.result {
                        Err(RunError::C2s(error) | RunError::S2s(error)) => {
                            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                            assert_eq!(error.to_string(), expected);
                        }
                        other => panic!("wrong ready listener result: {other:?}"),
                    },
                }
                assert_eq!(result.drain_deadline_exceeded, expected_deadline);
                let repeated = join_listeners(Some(&mut listeners), Instant::now(), error).await;
                assert!(repeated.result.is_ok());
                assert_eq!(repeated.drain_deadline_exceeded, expected_deadline);
            }
        }
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    }))?
}

#[test]
fn acme_service_diagnostic_follows_selected_service_error_without_logging_final_drain() {
    for earlier in 0..6 {
        let mut services = service_join();
        services.acme = Err(RunError::Acme {
            phase: "manager",
            source: Box::new(io::Error::other("service")),
        });
        let mut cleanup = joined();
        match earlier {
            0 => services.primary = Err(RunError::Signal(io::Error::other("primary"))),
            1 => services.drain = Err(RunError::DispatcherShutdown(shutdown_timeout())),
            2 => services.admin = Err(RunError::Admin(io::Error::other("admin"))),
            3 => cleanup.remote = Err(RunError::S2s(io::Error::other("remote"))),
            4 => services.metrics = Err(RunError::Metrics(io::Error::other("metrics"))),
            _ => cleanup.c2s.drain_deadline_exceeded = true,
        }
        assert_eq!(cleanup.acme_service_failure_phase(&services), None);
    }
    let mut services = service_join();
    services.acme = Err(RunError::Acme {
        phase: "manager",
        source: Box::new(io::Error::other("service")),
    });
    assert_eq!(
        joined().acme_service_failure_phase(&services),
        Some("manager")
    );
    let mut cleanup = joined();
    cleanup.acme_drain = Err(RunError::Acme {
        phase: "drain",
        source: Box::new(io::Error::other("final")),
    });
    assert_eq!(cleanup.acme_service_failure_phase(&service_join()), None);
}
