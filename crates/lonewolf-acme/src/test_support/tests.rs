// SPDX-License-Identifier: Apache-2.0

use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

use compio::runtime::Runtime;
use futures_util::FutureExt;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn poll_timer(timer: Pin<&mut impl Future<Output = ()>>) -> Poll<()> {
    timer.poll(&mut Context::from_waker(Waker::noop()))
}

struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn clock() -> io::Result<TestClock> {
    TestClock::new(UNIX_EPOCH + Duration::from_secs(1_000), ClockMode::Frozen)
}

#[test]
fn advance_before_and_after_registration_reaches_original_deadlines() -> TestResult {
    let clock = clock()?;
    let start = clock.now();
    let mut timer = pin!(clock.sleep(Duration::from_secs(30), false));
    clock.advance_to(start + Duration::from_secs(10))?;
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    assert!(timer.as_mut().poll(&mut context).is_pending());
    clock.advance_to(start + Duration::from_secs(29))?;
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(timer.as_mut().poll(&mut context).is_pending());
    clock.advance_to(start + Duration::from_secs(30))?;
    assert_eq!(timer.as_mut().poll(&mut context), Poll::Ready(()));
    assert!(clock.shared.state.lock().timers.is_empty());
    Ok(())
}

#[test]
fn advance_wakes_multiple_sleepers_and_drop_unregisters() -> TestResult {
    let clock = clock()?;
    let now = clock.now();
    let mut first = Box::pin(clock.sleep(Duration::from_secs(5), false));
    let mut second = Box::pin(clock.sleep(Duration::from_secs(10), false));
    let mut cancelled = Box::pin(clock.sleep(Duration::from_secs(15), true));
    assert!(poll_timer(first.as_mut()).is_pending());
    assert!(poll_timer(second.as_mut()).is_pending());
    assert!(poll_timer(cancelled.as_mut()).is_pending());
    assert_eq!(clock.shared.state.lock().timers.len(), 3);
    drop(cancelled);
    assert_eq!(clock.shared.state.lock().timers.len(), 2);
    clock.advance_to(now + Duration::from_secs(5))?;
    assert_eq!(poll_timer(first.as_mut()), Poll::Ready(()));
    assert!(poll_timer(second.as_mut()).is_pending());
    clock.advance_to(now + Duration::from_secs(10))?;
    assert_eq!(poll_timer(second.as_mut()), Poll::Ready(()));
    assert!(clock.shared.state.lock().timers.is_empty());
    Ok(())
}

#[test]
fn idle_barrier_requires_live_pending_timer_for_current_generation() -> TestResult {
    let clock = clock()?;
    let now = clock.now();
    let generation = clock.freeze()?.generation;
    let mut ordinary = pin!(clock.sleep(Duration::from_secs(30), false));
    assert!(poll_timer(ordinary.as_mut()).is_pending());
    assert_eq!(
        clock
            .wait_parked(generation, Instant::now() + Duration::from_millis(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let mut idle = Box::pin(clock.sleep(Duration::from_secs(10), true));
    assert!(poll_timer(idle.as_mut()).is_pending());
    let parked = clock.wait_parked(generation, Instant::now() + Duration::from_secs(1))?;
    assert_eq!(parked.now, now);
    assert_eq!(parked.deadline, now + Duration::from_secs(10));
    let next = clock.advance_to(now + Duration::from_secs(5))?;
    assert_eq!(
        clock
            .wait_parked(next, Instant::now() + Duration::from_millis(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(poll_timer(idle.as_mut()).is_pending());
    assert_eq!(
        clock
            .wait_parked(next, Instant::now() + Duration::from_secs(1))?
            .generation,
        next
    );
    drop(idle);
    assert_eq!(
        clock
            .wait_parked(next, Instant::now() + Duration::from_millis(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let mut completed = pin!(clock.sleep(Duration::from_secs(1), true));
    assert!(poll_timer(completed.as_mut()).is_pending());
    let next = clock.advance_to(now + Duration::from_secs(6))?;
    assert_eq!(poll_timer(completed.as_mut()), Poll::Ready(()));
    assert_eq!(
        clock
            .wait_parked(next, Instant::now() + Duration::from_millis(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    Ok(())
}

#[test]
fn running_timer_retains_deadline_across_freeze_advance_and_resume() -> TestResult {
    Runtime::new()?.block_on(async {
        let clock = clock()?;
        let start = clock.now();
        let mut timer = pin!(clock.sleep(Duration::from_secs(60), true));
        assert!(poll_timer(timer.as_mut()).is_pending());
        clock.resume()?;
        assert!(poll_timer(timer.as_mut()).is_pending());
        let frozen = clock.freeze()?;
        assert!(frozen.now >= start);
        clock.advance_to(start + Duration::from_secs(60) - Duration::from_millis(5))?;
        assert!(poll_timer(timer.as_mut()).is_pending());
        clock.resume()?;
        timer.await;
        assert!(clock.now() >= start + Duration::from_secs(60));
        assert!(clock.shared.state.lock().timers.is_empty());
        Ok(())
    })
}

#[test]
fn backward_overflow_and_generation_errors_leave_state_unchanged() -> TestResult {
    let clock = clock()?;
    let before = clock.freeze()?;
    assert_eq!(
        clock
            .advance_to(before.now - Duration::from_secs(1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(clock.now(), before.now);
    assert_eq!(clock.shared.state.lock().generation, before.generation);
    assert!(TestClock::new(UNIX_EPOCH - Duration::from_secs(1), ClockMode::Running).is_err());
    if let Some(huge) = UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64)) {
        assert!(clock.advance_to(huge).is_err());
        assert_eq!(clock.now(), before.now);
    }
    clock.shared.state.lock().generation = u64::MAX;
    assert_eq!(clock.freeze().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(clock.resume().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(
        clock
            .advance_to(before.now + Duration::from_secs(1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(clock.now(), before.now);
    Ok(())
}

#[test]
fn parked_wait_is_bounded_and_cancellation_wakes_waiters() -> TestResult {
    let clock = clock()?;
    assert_eq!(
        clock
            .wait_parked(0, Instant::now() + Duration::from_millis(2))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let waiting = clock.clone();
    let thread =
        std::thread::spawn(move || waiting.wait_parked(0, Instant::now() + Duration::from_secs(1)));
    clock.cancel_waits();
    assert_eq!(
        thread
            .join()
            .map_err(|_| "waiter panicked")?
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    clock.cancel_waits();
    assert!(
        clock
            .sleep(Duration::from_secs(20), true)
            .now_or_never()
            .is_some()
    );
    assert!(clock.shared.state.lock().timers.is_empty());
    Ok(())
}
