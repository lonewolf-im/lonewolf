// SPDX-License-Identifier: Apache-2.0

use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use async_lock::{Mutex, MutexGuardArc};
use lonewolf_storage::account::AccountKey;

const SHARDS: usize = 64;

/// Serializes an extension's state changes and deliveries for the locked accounts while alive.
pub struct OrderGuard {
    _first: Option<MutexGuardArc<()>>,
    _second: Option<MutexGuardArc<()>>,
    _rest: Vec<MutexGuardArc<()>>,
}

impl OrderGuard {
    /// A guard that orders nothing, for extensions without state to serialize.
    pub fn none() -> Self {
        Self {
            _first: None,
            _second: None,
            _rest: Vec::new(),
        }
    }
}

/// Hands out per-account ordering guards.
/// Accounts that hash to the same shard also serialize with each other.
pub struct Sequencer {
    hash_state: RandomState,
    shards: [Arc<Mutex<()>>; SHARDS],
}

impl Default for Sequencer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sequencer {
    pub fn new() -> Self {
        Self {
            hash_state: RandomState::new(),
            shards: std::array::from_fn(|_| Arc::new(Mutex::new(()))),
        }
    }

    pub async fn lock(&self, owner: &AccountKey) -> OrderGuard {
        OrderGuard {
            _first: Some(self.lock_shard(self.shard_index(owner)).await),
            _second: None,
            _rest: Vec::new(),
        }
    }

    /// Locks every shard in index order, so it cannot deadlock with the other lock
    /// methods, and serializes with every account until the guard drops.
    pub async fn lock_all(&self) -> OrderGuard {
        let first = self.lock_shard(0).await;
        let second = self.lock_shard(1).await;
        let mut rest = Vec::with_capacity(SHARDS - 2);
        for index in 2..SHARDS {
            rest.push(self.lock_shard(index).await);
        }
        OrderGuard {
            _first: Some(first),
            _second: Some(second),
            _rest: rest,
        }
    }

    /// Locks both shards in index order so concurrent pairs cannot deadlock.
    pub async fn lock_pair(&self, first: &AccountKey, second: &AccountKey) -> OrderGuard {
        let first_index = self.shard_index(first);
        let second_index = self.shard_index(second);
        if first_index == second_index {
            return self.lock(first).await;
        }
        let (first_index, second_index) = if first_index < second_index {
            (first_index, second_index)
        } else {
            (second_index, first_index)
        };
        OrderGuard {
            _first: Some(self.lock_shard(first_index).await),
            _second: Some(self.lock_shard(second_index).await),
            _rest: Vec::new(),
        }
    }

    async fn lock_shard(&self, index: usize) -> MutexGuardArc<()> {
        Arc::clone(&self.shards[index]).lock_arc().await
    }

    fn shard_index(&self, owner: &AccountKey) -> usize {
        (self.hash_state.hash_one(owner) as usize) % self.shards.len()
    }

    #[cfg(test)]
    pub(crate) fn is_locked(&self, owner: &AccountKey) -> bool {
        Arc::clone(&self.shards[self.shard_index(owner)])
            .try_lock_arc()
            .is_none()
    }
}
