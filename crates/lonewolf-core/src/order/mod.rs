// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use futures_channel::oneshot;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::capacity::{Capacity, Histogram, Observation};

/// Orders deliveries per account by the moment each unit of work fixed its view of
/// storage, so a client never learns of an older change after a newer one.
///
/// Work takes a numbered ticket for the accounts it addresses, under the same lock
/// that commits its transaction or opens its snapshot. Deliveries run once the ticket
/// is at the head of every account's line. A ticket waits only for smaller tickets, so
/// waiting can never cycle.
pub(crate) struct Order {
    lines: Mutex<Lines>,
    /// Fixing a view and taking its ticket happen under this lock, so ticket order is
    /// commit order even when the store lets writers commit concurrently.
    fixing: async_lock::Mutex<()>,
    capacity: Option<Arc<Capacity>>,
}

#[derive(Default)]
struct Lines {
    next: u64,
    queues: HashMap<AccountKey, VecDeque<u64>>,
    waiting: HashMap<u64, Waiting>,
}

struct Waiting {
    accounts: Vec<AccountKey>,
    ready: Option<oneshot::Sender<()>>,
    observation: Option<Observation>,
}

/// A place in the delivery order for a set of accounts; dropping it releases the place.
pub(crate) struct Ticket {
    order: Arc<Order>,
    id: u64,
    ready: Option<oneshot::Receiver<()>>,
}

impl Order {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_capacity(None)
    }

    pub(crate) fn with_capacity(capacity: Option<Arc<Capacity>>) -> Arc<Self> {
        Arc::new(Self {
            lines: Mutex::new(Lines::default()),
            fixing: async_lock::Mutex::new(()),
            capacity,
        })
    }

    /// Runs `fix`, which commits a transaction or opens a snapshot, and takes the
    /// ticket for `accounts` in the same step.
    pub(crate) async fn fix<T, E>(
        self: &Arc<Self>,
        accounts: Vec<AccountKey>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        let wait = self
            .capacity
            .as_ref()
            .map(|capacity| capacity.observe(Histogram::OrderFixWait));
        let _fixing = self.fixing.lock().await;
        if let Some(wait) = wait {
            wait.complete();
        }
        let value = fix.await?;
        Ok((value, self.admit(accounts)))
    }

    fn admit(self: &Arc<Self>, accounts: Vec<AccountKey>) -> Ticket {
        let (ready, readiness) = oneshot::channel();
        let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        let id = lines.next;
        lines.next += 1;
        for account in &accounts {
            lines
                .queues
                .entry(account.clone())
                .or_default()
                .push_back(id);
        }
        lines.waiting.insert(
            id,
            Waiting {
                accounts,
                ready: Some(ready),
                observation: self
                    .capacity
                    .as_ref()
                    .map(|capacity| capacity.observe(Histogram::OrderTicketWait)),
            },
        );
        lines.wake_if_first(id);
        Ticket {
            order: Arc::clone(self),
            id,
            ready: Some(readiness),
        }
    }

    fn release(&self, id: u64) {
        let mut lines = self.lines.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(waiting) = lines.waiting.remove(&id) else {
            return;
        };
        let mut heads = Vec::with_capacity(waiting.accounts.len());
        for account in &waiting.accounts {
            let Some(queue) = lines.queues.get_mut(account) else {
                continue;
            };
            queue.retain(|ticket| *ticket != id);
            match queue.front() {
                Some(head) => heads.push(*head),
                None => {
                    lines.queues.remove(account);
                }
            }
        }
        for head in heads {
            lines.wake_if_first(head);
        }
    }
}

impl Lines {
    fn wake_if_first(&mut self, id: u64) {
        let Some(waiting) = self.waiting.get(&id) else {
            return;
        };
        let first_everywhere = waiting
            .accounts
            .iter()
            .all(|account| self.queues.get(account).and_then(VecDeque::front) == Some(&id));
        if !first_everywhere {
            return;
        }
        if let Some(waiting) = self.waiting.get_mut(&id)
            && let Some(ready) = waiting.ready.take()
        {
            if let Some(wait) = waiting.observation.take() {
                wait.complete();
            }
            let _ = ready.send(());
        }
    }
}

impl Ticket {
    /// Resolves once every earlier ticket for the same accounts has been released.
    /// A dropped `turn` future keeps the place, so the wait can resume later.
    pub(crate) async fn turn(&mut self) {
        if let Some(ready) = self.ready.as_mut() {
            let _ = ready.await;
            self.ready = None;
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.order.release(self.id);
    }
}

#[cfg(test)]
mod tests;
