// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Default)]
pub(crate) struct Time {
    #[cfg(feature = "test-support")]
    clock: Option<crate::test_support::TestClock>,
}

impl Time {
    #[cfg(feature = "test-support")]
    pub(crate) fn controlled(clock: crate::test_support::TestClock) -> Self {
        Self { clock: Some(clock) }
    }

    pub(crate) fn now(&self) -> SystemTime {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.clock {
            return clock.now();
        }
        SystemTime::now()
    }

    pub(crate) fn unix(&self) -> Result<u64, crate::StateError> {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.clock {
            return crate::schedule::timestamp(
                clock
                    .now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| crate::StateError::InvalidData)?
                    .as_secs(),
            );
        }
        crate::schedule::now()
    }

    pub(crate) fn monotonic(&self) -> Instant {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.clock {
            return clock.monotonic();
        }
        Instant::now()
    }

    pub(crate) async fn sleep(&self, delay: Duration) {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.clock {
            return clock.sleep(delay, false).await;
        }
        compio::time::sleep(delay).await
    }

    pub(crate) async fn idle_sleep(&self, delay: Duration) {
        #[cfg(feature = "test-support")]
        if let Some(clock) = &self.clock {
            return clock.sleep(delay, true).await;
        }
        compio::time::sleep(delay).await
    }
}
