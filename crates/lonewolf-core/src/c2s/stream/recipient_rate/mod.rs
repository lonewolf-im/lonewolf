// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::num::NonZeroUsize;
use std::time::Instant;

use lonewolf_util::token_bucket::TokenBucket;

use crate::c2s::metrics::{C2sWorkerMetrics, RateLimit};

pub(super) struct RecipientLimiter {
    per_second: NonZeroUsize,
    burst: NonZeroUsize,
    bucket: TokenBucket,
    hasher: RandomState,
    recent: [u64; 64],
    len: usize,
    next: usize,
    metrics: C2sWorkerMetrics,
    #[cfg(test)]
    admission_calls: usize,
}

impl RecipientLimiter {
    pub(super) fn new(
        per_second: NonZeroUsize,
        burst: NonZeroUsize,
        now: Instant,
        metrics: C2sWorkerMetrics,
    ) -> Self {
        Self {
            per_second,
            burst,
            bucket: TokenBucket::new(burst, now),
            hasher: RandomState::new(),
            recent: [0; 64],
            len: 0,
            next: 0,
            metrics,
            #[cfg(test)]
            admission_calls: 0,
        }
    }

    #[cfg(test)]
    pub(super) fn admission_calls(&self) -> usize {
        self.admission_calls
    }

    pub(super) fn admit(&mut self, recipient: &str, now: Instant) -> bool {
        #[cfg(test)]
        {
            self.admission_calls += 1;
        }
        let hash = self.hasher.hash_one(recipient);
        if self.recent[..self.len].contains(&hash) {
            return true;
        }
        self.bucket.replenish(self.per_second, self.burst, now);
        if self.bucket.available() == 0 {
            self.metrics
                .rate_limited(RateLimit::NewRecipientsPerConnection);
            return false;
        }
        self.bucket.consume(1);
        self.recent[self.next] = hash;
        self.next = (self.next + 1) % self.recent.len();
        self.len = (self.len + 1).min(self.recent.len());
        true
    }
}

#[cfg(test)]
mod tests;
