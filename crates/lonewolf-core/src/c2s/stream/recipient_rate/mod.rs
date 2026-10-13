// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::num::NonZeroUsize;
use std::time::Instant;

use lonewolf_util::token_bucket::TokenBucket;

pub(super) struct RecipientLimiter {
    per_second: NonZeroUsize,
    burst: NonZeroUsize,
    bucket: TokenBucket,
    hasher: RandomState,
    recent: [u64; 64],
    len: usize,
    next: usize,
}

impl RecipientLimiter {
    pub(super) fn new(per_second: NonZeroUsize, burst: NonZeroUsize, now: Instant) -> Self {
        Self {
            per_second,
            burst,
            bucket: TokenBucket::new(burst, now),
            hasher: RandomState::new(),
            recent: [0; 64],
            len: 0,
            next: 0,
        }
    }

    pub(super) fn admit(&mut self, recipient: &str, now: Instant) -> bool {
        let hash = self.hasher.hash_one(recipient);
        if self.recent[..self.len].contains(&hash) {
            return true;
        }
        self.bucket.replenish(self.per_second, self.burst, now);
        if self.bucket.available() == 0 {
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
