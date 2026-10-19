// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;

use futures_channel::oneshot;
use lonewolf_storage::account::AccountKey;
use parking_lot::Mutex as PlMutex;

/// Orders deliveries by fixed storage view; deletion barriers also order unrelated accounts.
pub(crate) struct Order {
    lines: PlMutex<Lines>,
    /// Prevents a later commit from taking an earlier delivery ticket.
    fixing: async_lock::Mutex<()>,
}

#[derive(Default)]
struct Lines {
    next: u64,
    queues: HashMap<AccountKey, VecDeque<u64>>,
    waiting: BTreeMap<u64, Waiting>,
    globals: BTreeSet<u64>,
}

struct Waiting {
    accounts: Vec<AccountKey>,
    ready: Option<oneshot::Sender<()>>,
}

/// Dropping a ticket releases its place without delivering its effects.
pub(crate) struct Ticket {
    order: Arc<Order>,
    id: u64,
    ready: Option<oneshot::Receiver<()>>,
}

impl Order {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            lines: PlMutex::new(Lines::default()),
            fixing: async_lock::Mutex::new(()),
        })
    }

    /// Fixes a storage view and its account ticket under one ordering lock.
    pub(crate) async fn fix<T, E>(
        self: &Arc<Self>,
        accounts: Vec<AccountKey>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        let _fixing = self.fixing.lock().await;
        let value = fix.await?;
        Ok((value, self.admit(accounts, false)))
    }

    /// A deletion barrier waits for all older tickets and blocks all later deliveries.
    pub(crate) async fn fix_all<T, E>(
        self: &Arc<Self>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        let _fixing = self.fixing.lock().await;
        let value = fix.await?;
        Ok((value, self.admit(Vec::new(), true)))
    }

    fn admit(self: &Arc<Self>, accounts: Vec<AccountKey>, global: bool) -> Ticket {
        let (ready, readiness) = oneshot::channel();
        let mut lines = self.lines.lock();
        let id = lines.next;
        lines.next += 1;
        if global {
            lines.globals.insert(id);
        }
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
        let mut lines = self.lines.lock();
        let Some(waiting) = lines.waiting.remove(&id) else {
            return;
        };
        let global = lines.globals.remove(&id);
        for account in &waiting.accounts {
            let Some(queue) = lines.queues.get_mut(account) else {
                continue;
            };
            queue.retain(|ticket| *ticket != id);
            let head = queue.front().copied();
            if head.is_none() {
                lines.queues.remove(account);
            }
            if let Some(head) = head {
                lines.wake_if_first(head);
            }
        }
        if !global {
            if let Some(next) = lines.globals.first().copied() {
                lines.wake_if_first(next);
            }
            return;
        }
        let mut after = None;
        loop {
            let next = match after {
                None => lines.waiting.keys().next().copied(),
                Some(last) => lines
                    .waiting
                    .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(&id, _)| id),
            };
            let Some(next) = next else { break };
            lines.wake_if_first(next);
            after = Some(next);
        }
    }
}

impl Lines {
    fn wake_if_first(&mut self, id: u64) {
        let Some(waiting) = self.waiting.get(&id) else {
            return;
        };
        if self.globals.range(..id).next().is_some() {
            return;
        }
        if self.globals.contains(&id) && self.waiting.keys().next().copied() != Some(id) {
            return;
        }
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
            let _ = ready.send(());
        }
    }
}

impl Ticket {
    /// Cancellation keeps the ticket in order so this wait can resume.
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
