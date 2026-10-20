// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::future::{Future, poll_fn, ready};
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{RawWaker, RawWakerVTable, Wake};

use futures_channel::oneshot;
use futures_util::FutureExt;

use super::*;
use crate::test_allocator::traced;

#[derive(Default)]
struct Parent(AtomicUsize);

impl Wake for Parent {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
}

#[test]
fn initially_ready_and_local_futures_complete() {
    let value = Rc::new(Cell::new(7));
    let mut future = WakeDriven::new(poll_fn(|_| Poll::Ready(value.get())));
    assert_eq!(poll(&mut future, Waker::noop()), Poll::Ready(7));
    assert!(future.parent.is_none());
    assert!(future.state.parent.lock().is_none());
    let mut ready = WakeDriven::new(ready(11));
    assert_eq!(poll(&mut ready, Waker::noop()), Poll::Ready(11));
}

#[test]
fn idle_polls_do_not_poll_inner_or_clone_the_parent_or_allocate() {
    let polls = Cell::new(0);
    let mut future = WakeDriven::new(poll_fn(|_| {
        polls.set(polls.get() + 1);
        Poll::<()>::Pending
    }));
    let parent = Arc::new(Probe::default());
    let waker = probe_waker(parent.clone());
    assert!(poll(&mut future, &waker).is_pending());
    let clones = parent.clones.load(Ordering::SeqCst);
    assert_eq!(clones, 1);
    let ((), trace) = traced(None, || {
        for _ in 0..10_000 {
            assert!(poll(&mut future, &waker).is_pending());
        }
    });
    assert_eq!(polls.get(), 1);
    assert_eq!(trace.allocations, 0);
    assert_eq!(trace.deallocations, 0);
    assert_eq!(parent.clones.load(Ordering::SeqCst), clones);
}

#[test]
fn explicit_wakes_and_parent_replacement_preserve_progress() {
    let polls = Cell::new(0);
    let proxy = std::cell::RefCell::new(None);
    let mut future = WakeDriven::new(poll_fn(|cx| {
        polls.set(polls.get() + 1);
        *proxy.borrow_mut() = Some(cx.waker().clone());
        Poll::<()>::Pending
    }));
    let first = Arc::new(Parent::default());
    let second = Arc::new(Parent::default());
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    assert!(poll(&mut future, &first_waker).is_pending());
    assert!(poll(&mut future, &second_waker).is_pending());
    assert_eq!(polls.get(), 1);
    proxy.borrow().as_ref().unwrap().wake_by_ref();
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
    assert!(poll(&mut future, &second_waker).is_pending());
    proxy.borrow().as_ref().unwrap().clone().wake();
    assert!(poll(&mut future, &second_waker).is_pending());
    assert_eq!(polls.get(), 3);
}

#[test]
fn a_synchronous_wake_during_poll_is_not_lost() {
    let mut first = true;
    let mut future = WakeDriven::new(poll_fn(|cx| {
        if std::mem::take(&mut first) {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(19)
        }
    }));
    assert!(poll(&mut future, Waker::noop()).is_pending());
    assert_eq!(poll(&mut future, Waker::noop()), Poll::Ready(19));
}

#[test]
fn a_concurrent_wake_during_poll_is_not_lost() {
    let barrier = Arc::new(Barrier::new(2));
    let (send, receive) = std::sync::mpsc::channel::<Waker>();
    let waking = {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let proxy = receive.recv().unwrap();
            barrier.wait();
            proxy.wake();
            barrier.wait();
        })
    };
    let mut first = true;
    let mut future = WakeDriven::new(poll_fn(|cx| {
        if std::mem::take(&mut first) {
            send.send(cx.waker().clone()).unwrap();
            barrier.wait();
            barrier.wait();
            Poll::Pending
        } else {
            Poll::Ready(23)
        }
    }));
    assert!(poll(&mut future, Waker::noop()).is_pending());
    assert_eq!(poll(&mut future, Waker::noop()), Poll::Ready(23));
    waking.join().unwrap();
}

#[test]
fn shared_waiters_survive_cancellation_and_replay_completion() {
    let (send, receive) = oneshot::channel::<usize>();
    let shared = receive.shared();
    let mut cancelled = WakeDriven::new(shared.clone());
    let mut first = WakeDriven::new(shared.clone());
    let mut second = WakeDriven::new(shared.clone());
    for future in [&mut cancelled, &mut first, &mut second] {
        assert!(poll(future, Waker::noop()).is_pending());
    }
    drop(cancelled);
    send.send(31).unwrap();
    for future in [&mut first, &mut second] {
        assert_eq!(poll(future, Waker::noop()), Poll::Ready(Ok(31)));
    }
    let mut replay = WakeDriven::new(shared);
    assert_eq!(poll(&mut replay, Waker::noop()), Poll::Ready(Ok(31)));
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut first, Waker::noop()))).is_err());
}

#[test]
fn shared_sender_drop_is_observed_by_every_waiter() {
    let (send, receive) = oneshot::channel::<()>();
    let shared = receive.shared();
    let mut first = WakeDriven::new(shared.clone());
    let mut second = WakeDriven::new(shared.clone());
    assert!(poll(&mut first, Waker::noop()).is_pending());
    assert!(poll(&mut second, Waker::noop()).is_pending());
    drop(send);
    assert!(matches!(
        poll(&mut first, Waker::noop()),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        poll(&mut second, Waker::noop()),
        Poll::Ready(Err(_))
    ));
    let mut replay = WakeDriven::new(shared);
    assert!(matches!(
        poll(&mut replay, Waker::noop()),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn retained_proxy_does_not_retain_a_cancelled_parent() {
    let proxy = std::cell::RefCell::new(None);
    let mut future = WakeDriven::new(poll_fn(|cx| {
        *proxy.borrow_mut() = Some(cx.waker().clone());
        Poll::<()>::Pending
    }));
    let parent = Arc::new(Parent::default());
    let weak = Arc::downgrade(&parent);
    let waker = Waker::from(parent);
    assert!(poll(&mut future, &waker).is_pending());
    drop(waker);
    assert!(weak.upgrade().is_some());
    drop(future);
    assert!(weak.upgrade().is_none());
    proxy.borrow().as_ref().unwrap().wake_by_ref();
}

#[test]
fn inner_panic_and_drop_release_the_parent_even_with_a_retained_proxy() {
    let proxy = std::cell::RefCell::new(None);
    let mut future = WakeDriven::new(poll_fn(|cx| -> Poll<()> {
        *proxy.borrow_mut() = Some(cx.waker().clone());
        panic!("injected inner poll panic");
    }));
    let parent = Arc::new(Parent::default());
    let weak = Arc::downgrade(&parent);
    let waker = Waker::from(parent);
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut future, &waker))).is_err());
    drop(waker);
    drop(future);
    assert!(weak.upgrade().is_none());
    proxy.borrow().as_ref().unwrap().wake_by_ref();
}

#[test]
fn adapter_is_send_for_send_futures() {
    fn assert_send<T: Send>(_: T) {}
    assert_send(WakeDriven::new(ready(())));
}

type Callback = Box<dyn FnOnce() + Send>;

#[derive(Default)]
struct Probe {
    clones: AtomicUsize,
    drops: AtomicUsize,
    wakes: AtomicUsize,
    on_clone: PlMutex<Option<Callback>>,
    on_drop: PlMutex<Option<Callback>>,
    on_wake: PlMutex<Option<Callback>>,
}

fn callback(slot: &PlMutex<Option<Callback>>) {
    let callback = slot.lock().take();
    if let Some(callback) = callback {
        callback();
    }
}

fn probe_waker(probe: Arc<Probe>) -> Waker {
    // Each raw waker owns the strong reference transferred by Arc::into_raw.
    unsafe { Waker::from_raw(probe_raw(probe)) }
}

fn probe_raw(probe: Arc<Probe>) -> RawWaker {
    RawWaker::new(Arc::into_raw(probe).cast(), &PROBE_VTABLE)
}

const PROBE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_probe, wake_probe, wake_probe_by_ref, drop_probe);

unsafe fn clone_probe(pointer: *const ()) -> RawWaker {
    // The source waker keeps this borrowed strong reference alive.
    let borrowed = ManuallyDrop::new(unsafe { Arc::from_raw(pointer.cast::<Probe>()) });
    let owned = Arc::clone(&borrowed);
    owned.clones.fetch_add(1, Ordering::SeqCst);
    callback(&owned.on_clone);
    probe_raw(owned)
}

unsafe fn wake_probe(pointer: *const ()) {
    // Consuming wake transfers the raw waker's reference to this RAII owner.
    let owned = unsafe { Arc::from_raw(pointer.cast::<Probe>()) };
    owned.wakes.fetch_add(1, Ordering::SeqCst);
    callback(&owned.on_wake);
}

unsafe fn wake_probe_by_ref(pointer: *const ()) {
    // The caller keeps the borrowed reference alive and retains ownership.
    let borrowed = ManuallyDrop::new(unsafe { Arc::from_raw(pointer.cast::<Probe>()) });
    borrowed.wakes.fetch_add(1, Ordering::SeqCst);
    callback(&borrowed.on_wake);
}

unsafe fn drop_probe(pointer: *const ()) {
    // Drop transfers the raw waker's reference to this RAII owner.
    let owned = unsafe { Arc::from_raw(pointer.cast::<Probe>()) };
    owned.drops.fetch_add(1, Ordering::SeqCst);
    callback(&owned.on_drop);
}

fn reenter(state: Arc<WakeState>) -> Callback {
    Box::new(move || {
        assert!(state.parent.try_lock().is_some());
        WakeState::wake_by_ref(&state);
    })
}

#[test]
fn clone_replace_wake_and_drop_callbacks_can_reenter() {
    let mut future = WakeDriven::new(std::future::pending::<()>());
    let first = Arc::new(Probe::default());
    let second = Arc::new(Probe::default());
    let first_waker = probe_waker(first.clone());
    let second_waker = probe_waker(second.clone());
    *first.on_clone.lock() = Some(reenter(future.state.clone()));
    assert!(poll(&mut future, &first_waker).is_pending());
    *second.on_clone.lock() = Some(reenter(future.state.clone()));
    *first.on_drop.lock() = Some(reenter(future.state.clone()));
    assert!(poll(&mut future, &second_waker).is_pending());
    *second.on_wake.lock() = Some(reenter(future.state.clone()));
    WakeState::wake_by_ref(&future.state);
    *second.on_drop.lock() = Some(reenter(future.state.clone()));
    drop(future);
    assert_eq!(first.clones.load(Ordering::SeqCst), 1);
    assert_eq!(second.clones.load(Ordering::SeqCst), 1);
    assert_eq!(first.drops.load(Ordering::SeqCst), 1);
    assert_eq!(second.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn panicking_raw_callbacks_do_not_leak_owned_references() {
    let probe = Arc::new(Probe::default());
    let waker = probe_waker(probe.clone());
    *probe.on_clone.lock() = Some(Box::new(|| panic!("injected clone panic")));
    assert!(catch_unwind(AssertUnwindSafe(|| waker.clone())).is_err());
    assert_eq!(Arc::strong_count(&probe), 2);
    *probe.on_wake.lock() = Some(Box::new(|| panic!("injected wake panic")));
    assert!(catch_unwind(AssertUnwindSafe(|| waker.clone().wake())).is_err());
    assert_eq!(Arc::strong_count(&probe), 2);
    *probe.on_drop.lock() = Some(Box::new(|| panic!("injected drop panic")));
    assert!(catch_unwind(AssertUnwindSafe(|| drop(waker))).is_err());
    assert_eq!(Arc::strong_count(&probe), 1);
}
