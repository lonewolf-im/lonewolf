// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use futures_util::task::{ArcWake, waker_ref};
use parking_lot::Mutex as PlMutex;

/// Polls the inner future only initially or after its waker receives a notification.
/// The inner future must notify its waker whenever readiness can change.
pub struct WakeDriven<F: Future + Unpin> {
    future: F,
    state: Arc<WakeState>,
    parent: Option<Arc<Waker>>,
    completed: bool,
}

struct WakeState {
    ready: AtomicBool,
    parent: PlMutex<Option<Arc<Waker>>>,
}

impl ArcWake for WakeState {
    fn wake_by_ref(state: &Arc<Self>) {
        state.ready.store(true, Ordering::Release);
        let parent = state.parent.lock().clone();
        if let Some(parent) = parent {
            parent.wake_by_ref();
        }
    }
}

impl<F: Future + Unpin> WakeDriven<F> {
    pub fn new(future: F) -> Self {
        Self {
            future,
            state: Arc::new(WakeState {
                ready: AtomicBool::new(true),
                parent: PlMutex::new(None),
            }),
            parent: None,
            completed: false,
        }
    }

    fn clear_parent(&mut self) {
        let registered = self.state.parent.lock().take();
        drop(registered);
        self.parent = None;
    }
}

impl<F: Future + Unpin> Future for WakeDriven<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Pin::new(&mut this.future).poll(cx);
        }
        if !this
            .parent
            .as_ref()
            .is_some_and(|parent| parent.will_wake(cx.waker()))
        {
            let parent = Arc::new(cx.waker().clone());
            let registered = this.state.parent.lock().replace(parent.clone());
            drop(registered);
            this.parent = Some(parent);
        }
        if !this.state.ready.load(Ordering::Acquire)
            || !this.state.ready.swap(false, Ordering::AcqRel)
        {
            return Poll::Pending;
        }
        let proxy = waker_ref(&this.state);
        let result = Pin::new(&mut this.future).poll(&mut Context::from_waker(&proxy));
        if result.is_ready() {
            this.completed = true;
            this.clear_parent();
        }
        result
    }
}

impl<F: Future + Unpin> Drop for WakeDriven<F> {
    fn drop(&mut self) {
        self.clear_parent();
    }
}

#[cfg(test)]
mod tests;
