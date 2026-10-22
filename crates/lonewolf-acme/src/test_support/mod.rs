// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Condvar as PlCondvar, Mutex as PlMutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockMode {
    Running,
    Frozen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSnapshot {
    pub generation: u64,
    pub now: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parked {
    pub generation: u64,
    pub now: SystemTime,
    pub deadline: SystemTime,
}

#[derive(Clone)]
pub struct TestClock {
    shared: Arc<Shared>,
}

struct Shared {
    state: PlMutex<State>,
    changed: PlCondvar,
}

struct State {
    now: SystemTime,
    monotonic: Instant,
    observed: Instant,
    mode: ClockMode,
    generation: u64,
    next_timer: u64,
    timers: Vec<Registration>,
    cancelled: bool,
}

struct Registration {
    id: u64,
    parked: Option<u64>,
    deadline: SystemTime,
    waker: Waker,
}

impl State {
    fn current(&self) -> (SystemTime, Instant) {
        let elapsed = match self.mode {
            ClockMode::Running => self.observed.elapsed(),
            ClockMode::Frozen => Duration::ZERO,
        };
        (self.now + elapsed, self.monotonic + elapsed)
    }

    fn next_generation(&self) -> io::Result<u64> {
        self.generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("clock generation exhausted"))
    }
}

fn validate(now: SystemTime) -> io::Result<()> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "clock precedes Unix epoch"))?;
    if elapsed.as_secs() > i64::MAX as u64 || now.checked_add(Duration::from_secs(900)).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "clock time is unrepresentable",
        ));
    }
    Ok(())
}

impl TestClock {
    pub fn new(now: SystemTime, mode: ClockMode) -> io::Result<Self> {
        validate(now)?;
        let real = Instant::now();
        Ok(Self {
            shared: Arc::new(Shared {
                state: PlMutex::new(State {
                    now,
                    monotonic: real,
                    observed: real,
                    mode,
                    generation: 0,
                    next_timer: 0,
                    timers: Vec::new(),
                    cancelled: false,
                }),
                changed: PlCondvar::new(),
            }),
        })
    }

    pub fn freeze(&self) -> io::Result<ClockSnapshot> {
        let mut state = self.shared.state.lock();
        let generation = state.next_generation()?;
        let (now, monotonic) = state.current();
        validate(now)?;
        state.now = now;
        state.monotonic = monotonic;
        state.observed = Instant::now();
        state.mode = ClockMode::Frozen;
        state.generation = generation;
        let wakers = invalidate(&mut state);
        drop(state);
        self.wake(wakers);
        Ok(ClockSnapshot { generation, now })
    }

    pub fn advance_to(&self, now: SystemTime) -> io::Result<u64> {
        validate(now)?;
        let mut state = self.shared.state.lock();
        let generation = state.next_generation()?;
        let (current, monotonic) = state.current();
        let elapsed = now.duration_since(current).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "clock cannot move backwards")
        })?;
        let monotonic = monotonic.checked_add(elapsed).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "monotonic clock is unrepresentable",
            )
        })?;
        state.now = now;
        state.monotonic = monotonic;
        state.observed = Instant::now();
        state.generation = generation;
        let wakers = invalidate(&mut state);
        drop(state);
        self.wake(wakers);
        Ok(generation)
    }

    pub fn resume(&self) -> io::Result<u64> {
        let mut state = self.shared.state.lock();
        let generation = state.next_generation()?;
        let (now, monotonic) = state.current();
        validate(now)?;
        state.now = now;
        state.monotonic = monotonic;
        state.observed = Instant::now();
        state.mode = ClockMode::Running;
        state.generation = generation;
        let wakers = invalidate(&mut state);
        drop(state);
        self.wake(wakers);
        Ok(generation)
    }

    /// A pending idle timer proves that the manager has no active issuer jobs.
    pub fn wait_parked(&self, generation: u64, deadline: Instant) -> io::Result<Parked> {
        let mut state = self.shared.state.lock();
        loop {
            if state.cancelled {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let now = state.current().0;
            if state.generation == generation
                && let Some(timer) = state
                    .timers
                    .iter()
                    .find(|timer| timer.parked == Some(generation) && timer.deadline > now)
            {
                return Ok(Parked {
                    generation,
                    now,
                    deadline: timer.deadline,
                });
            }
            self.shared.changed.wait_until(&mut state, deadline);
        }
    }

    pub fn cancel_waits(&self) {
        let mut state = self.shared.state.lock();
        state.cancelled = true;
        let wakers = invalidate(&mut state);
        drop(state);
        self.wake(wakers);
    }

    pub(crate) fn now(&self) -> SystemTime {
        self.shared.state.lock().current().0
    }

    pub(crate) fn monotonic(&self) -> Instant {
        self.shared.state.lock().current().1
    }

    pub(crate) fn sleep(&self, delay: Duration, idle: bool) -> impl Future<Output = ()> + '_ {
        Timer {
            clock: self,
            deadline: self.now() + delay,
            id: None,
            generation: None,
            real: None,
            idle,
        }
    }

    fn wake(&self, wakers: Vec<Waker>) {
        self.shared.changed.notify_all();
        for waker in wakers {
            waker.wake();
        }
    }
}

fn invalidate(state: &mut State) -> Vec<Waker> {
    state
        .timers
        .iter_mut()
        .map(|timer| {
            timer.parked = None;
            timer.waker.clone()
        })
        .collect()
}

struct Timer<'a> {
    clock: &'a TestClock,
    deadline: SystemTime,
    id: Option<u64>,
    generation: Option<u64>,
    real: Option<Pin<Box<dyn Future<Output = ()>>>>,
    idle: bool,
}

impl Future for Timer<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        loop {
            let mut state = this.clock.shared.state.lock();
            let now = state.current().0;
            if state.cancelled || now >= this.deadline {
                if let Some(id) = this.id.take() {
                    state.timers.retain(|timer| timer.id != id);
                }
                this.clock.shared.changed.notify_all();
                return Poll::Ready(());
            }
            let generation = state.generation;
            let mode = state.mode;
            let remaining = this.deadline.duration_since(now).unwrap_or_default();
            if let Some(id) = this.id {
                if let Some(timer) = state.timers.iter_mut().find(|timer| timer.id == id) {
                    timer.waker.clone_from(context.waker());
                    timer.parked = None;
                }
            } else {
                let id = state.next_timer;
                state.next_timer = state.next_timer.wrapping_add(1);
                state.timers.push(Registration {
                    id,
                    parked: None,
                    deadline: this.deadline,
                    waker: context.waker().clone(),
                });
                this.id = Some(id);
            }
            drop(state);
            if this.generation != Some(generation) {
                this.real = None;
                this.generation = Some(generation);
            }
            if mode == ClockMode::Running {
                let timer = this
                    .real
                    .get_or_insert_with(|| Box::pin(compio::time::sleep(remaining)));
                if timer.as_mut().poll(context).is_ready() {
                    this.real = None;
                    continue;
                }
            }
            let mut state = this.clock.shared.state.lock();
            if state.generation != generation
                || state.cancelled
                || state.current().0 >= this.deadline
            {
                continue;
            }
            if this.idle
                && let Some(timer) = state
                    .timers
                    .iter_mut()
                    .find(|timer| Some(timer.id) == this.id)
            {
                timer.parked = Some(generation);
                this.clock.shared.changed.notify_all();
            }
            return Poll::Pending;
        }
    }
}

impl Drop for Timer<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            let mut state = self.clock.shared.state.lock();
            state.timers.retain(|timer| timer.id != id);
            self.clock.shared.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests;
