// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::{Condvar as PlCondvar, Mutex as PlMutex};
use tokio::sync::watch;

static CLOCK: OnceLock<ManualClock> = OnceLock::new();

pub struct ManualClock {
    origin: Instant,
    wall_origin: PlMutex<SystemTime>,
    time: watch::Sender<Instant>,
    timers: PlMutex<BTreeMap<Instant, usize>>,
    registered: PlCondvar,
    protected_headers: PlMutex<u32>,
    header_read: PlCondvar,
}

impl ManualClock {
    /// Install once in an isolated fixture process before starting its workers.
    pub fn install() -> &'static Self {
        CLOCK.get_or_init(|| {
            let origin = Instant::now();
            Self {
                origin,
                wall_origin: PlMutex::new(SystemTime::now()),
                time: watch::channel(origin).0,
                timers: PlMutex::default(),
                registered: PlCondvar::new(),
                protected_headers: PlMutex::default(),
                header_read: PlCondvar::new(),
            }
        })
    }

    pub(crate) fn current() -> Option<&'static Self> {
        CLOCK.get()
    }

    pub(crate) fn now(&self) -> Instant {
        *self.time.borrow()
    }

    pub(crate) fn wall_now(&self) -> SystemTime {
        *self.wall_origin.lock() + self.now().duration_since(self.origin)
    }

    pub fn set_wall_before_handshake(&self, time: SystemTime) {
        *self.wall_origin.lock() = time - self.now().duration_since(self.origin);
    }

    pub(crate) fn reading_protected_header() {
        if let Some(clock) = Self::current() {
            *clock.protected_headers.lock() += 1;
            clock.header_read.notify_all();
        }
    }

    pub fn wait_for_protected_headers(&self, count: u32, timeout: Duration) -> io::Result<()> {
        let mut headers = self.protected_headers.lock();
        self.header_read
            .wait_while_for(&mut headers, |seen| *seen < count, timeout);
        if *headers < count {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    pub fn advance(&self, duration: Duration) {
        self.time.send_modify(|now| *now += duration);
    }

    pub fn wait_for_timers(
        &self,
        remaining: Duration,
        count: u32,
        timeout: Duration,
    ) -> io::Result<()> {
        let target = self.now() + remaining;
        let mut timers = self.timers.lock();
        let wait = self.registered.wait_while_for(
            &mut timers,
            |timers| timers.get(&target).copied().unwrap_or_default() < count as usize,
            timeout,
        );
        if wait.timed_out() && timers.get(&target).copied().unwrap_or_default() < count as usize {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("missing timer with {remaining:?} remaining: {timers:?}"),
            ));
        }
        Ok(())
    }

    pub(crate) async fn sleep_until(&self, target: Instant) {
        struct Registration<'a>(&'a ManualClock, Instant);
        impl Drop for Registration<'_> {
            fn drop(&mut self) {
                let mut timers = self.0.timers.lock();
                if let Some(count) = timers.get_mut(&self.1) {
                    *count -= 1;
                    if *count == 0 {
                        timers.remove(&self.1);
                    }
                }
            }
        }
        let mut time = self.time.subscribe();
        if *time.borrow() >= target {
            return;
        }
        *self.timers.lock().entry(target).or_default() += 1;
        let _registration = Registration(self, target);
        self.registered.notify_all();
        let _ = time.wait_for(|now| *now >= target).await;
    }
}
