// SPDX-License-Identifier: Apache-2.0

use std::future::{Future, pending, ready};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::task::{ArcWake, waker};

use super::{ProbeError, StreamProbeEvent, install_stream_probe, observe_write, stream_event};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn complete_without_waiting(future: impl Future<Output = TestResult>) -> TestResult {
    future
        .now_or_never()
        .ok_or("probe test unexpectedly remained pending")?
}

#[test]
fn released_pending_writes_complete_without_cancellation() -> TestResult {
    complete_without_waiting(async {
        let target = "release@localhost/desk";
        let probe = install_stream_probe(target)?;
        probe.hold_next_pending_write()?;
        let (release, blocked) = oneshot::channel();
        let mut write = pin!(observe_write(Some(target), async {
            blocked.await.map(|()| 42)
        }));
        assert!(write.as_mut().now_or_never().is_none());
        assert_eq!(probe.next_event().await?, StreamProbeEvent::WriteHeld);
        release.send(()).map_err(|_| "write receiver dropped")?;
        assert!(write.as_mut().now_or_never().is_none());
        probe.release_write()?;
        assert_eq!(write.await?, 42);
        assert!(probe.next_event().now_or_never().is_none());
        Ok(())
    })
}

#[test]
fn dropping_a_held_write_reports_cancellation() -> TestResult {
    complete_without_waiting(async {
        let target = "cancel@localhost/desk";
        let probe = install_stream_probe(target)?;
        probe.hold_next_pending_write()?;
        {
            let mut write = pin!(observe_write(Some(target), pending::<()>()));
            assert!(write.as_mut().now_or_never().is_none());
            assert_eq!(probe.next_event().await?, StreamProbeEvent::WriteHeld);
        }
        assert_eq!(probe.next_event().await?, StreamProbeEvent::WriteCancelled);
        probe.hold_next_pending_write()?;
        Ok(())
    })
}

struct WakeCount(AtomicUsize);

impl ArcWake for WakeCount {
    fn wake_by_ref(value: &Arc<Self>) {
        value.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn dropping_the_owner_wakes_and_releases_its_held_write() -> TestResult {
    complete_without_waiting(async {
        let target = "owner-drop@localhost/desk";
        let probe = install_stream_probe(target)?;
        probe.hold_next_pending_write()?;
        let (release, blocked) = oneshot::channel();
        let mut write = pin!(observe_write(Some(target), blocked));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = waker(wakes.clone());
        let mut context = Context::from_waker(&waker);
        assert!(matches!(write.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(probe.next_event().await?, StreamProbeEvent::WriteHeld);
        release.send(()).map_err(|_| "write receiver dropped")?;
        assert!(matches!(write.as_mut().poll(&mut context), Poll::Pending));
        let before = wakes.0.load(Ordering::Relaxed);
        drop(probe);
        assert!(wakes.0.load(Ordering::Relaxed) > before);
        assert_eq!(write.await, Ok(()));
        let replacement = install_stream_probe(target)?;
        assert!(replacement.next_event().now_or_never().is_none());
        Ok(())
    })
}

#[test]
fn duplicate_targets_are_rejected_until_the_owner_drops() -> TestResult {
    let target = "duplicate@localhost/desk";
    let probe = install_stream_probe(target)?;
    assert_eq!(
        install_stream_probe(target).map(|_| ()),
        Err(ProbeError::DuplicateTarget)
    );
    drop(probe);
    let replacement = install_stream_probe(target)?;
    replacement.hold_next_pending_write()?;
    assert_eq!(
        replacement.hold_next_pending_write(),
        Err(ProbeError::WriteAlreadyArmed)
    );
    assert_eq!(replacement.release_write(), Err(ProbeError::WriteNotHeld));
    Ok(())
}

#[test]
fn probes_reject_targets_without_a_full_account_jid() {
    for target in [
        "",
        "localhost",
        "alice@localhost",
        "localhost/desk",
        "bad@@localhost/desk",
    ] {
        assert_eq!(
            install_stream_probe(target).map(|_| ()),
            Err(ProbeError::InvalidTarget),
            "{target:?}"
        );
    }
}

#[test]
fn ready_writes_leave_the_arm_for_the_next_pending_write() -> TestResult {
    complete_without_waiting(async {
        let target = "ready@localhost/desk";
        let probe = install_stream_probe(target)?;
        probe.hold_next_pending_write()?;
        assert_eq!(observe_write(Some(target), ready(42)).await, 42);
        assert!(probe.next_event().now_or_never().is_none());
        let mut write = pin!(observe_write(Some(target), pending::<()>()));
        assert!(write.as_mut().now_or_never().is_none());
        assert_eq!(probe.next_event().await?, StreamProbeEvent::WriteHeld);
        Ok(())
    })
}

#[test]
fn dropping_the_owner_closes_waits_that_do_not_retain_it() -> TestResult {
    complete_without_waiting(async {
        let probe = install_stream_probe("event-close@localhost/desk")?;
        let waiting = probe.next_event();
        drop(probe);
        assert_eq!(waiting.await, Err(ProbeError::Closed));
        Ok(())
    })
}

#[test]
fn admission_events_reach_only_the_installed_target() -> TestResult {
    complete_without_waiting(async {
        let target = "admission@localhost/desk";
        let probe = install_stream_probe(target)?;
        stream_event("admission@localhost/other", StreamProbeEvent::IqGetAdmitted);
        assert!(probe.next_event().now_or_never().is_none());
        stream_event(target, StreamProbeEvent::IqGetAdmitted);
        stream_event(target, StreamProbeEvent::UnavailablePresenceAdmitted);
        assert_eq!(probe.next_event().await?, StreamProbeEvent::IqGetAdmitted);
        assert_eq!(
            probe.next_event().await?,
            StreamProbeEvent::UnavailablePresenceAdmitted
        );
        Ok(())
    })
}
