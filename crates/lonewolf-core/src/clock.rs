// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

#[cfg(not(test))]
pub(crate) fn now() -> Instant {
    Instant::now()
}

#[cfg(test)]
pub(crate) fn now() -> Instant {
    FROZEN_NOW.get().unwrap_or_else(Instant::now)
}

#[cfg(test)]
thread_local! {
    static FROZEN_NOW: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// Holds [`now`] at a fixed instant on this thread until dropped, so a test decides when time passes.
#[cfg(test)]
pub(crate) struct FrozenClock;

#[cfg(test)]
impl FrozenClock {
    pub(crate) fn start() -> Self {
        FROZEN_NOW.set(Some(Instant::now()));
        Self
    }

    pub(crate) fn now(&self) -> Instant {
        now()
    }

    pub(crate) fn advance(&self, duration: std::time::Duration) {
        FROZEN_NOW.set(Some(now() + duration));
    }
}

#[cfg(test)]
impl Drop for FrozenClock {
    fn drop(&mut self) {
        FROZEN_NOW.set(None);
    }
}
