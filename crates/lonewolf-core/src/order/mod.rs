// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use futures_channel::oneshot;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::metrics::DURATION_BUCKETS;
use parking_lot::Mutex as PlMutex;
use prometheus_client::metrics::histogram::Histogram;

/// Orders deliveries by fixed storage view.
pub(crate) struct Order {
    lines: PlMutex<Lines>,
    /// Prevents a later commit from taking an earlier delivery ticket.
    fixing: async_lock::Mutex<()>,
    wait_duration: Histogram,
    hold_duration: Histogram,
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
    kind: TicketKind,
    ready: Option<oneshot::Sender<()>>,
}

enum TicketKind {
    Accounts,
    DirectedGrant(Option<Box<str>>),
    Global,
}

pub(crate) struct PendingDirectedGrant {
    pub(crate) account: AccountKey,
    pub(crate) full: Option<Box<str>>,
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
            wait_duration: Histogram::new(DURATION_BUCKETS),
            hold_duration: Histogram::new(DURATION_BUCKETS),
        })
    }

    pub(crate) fn wait_duration(&self) -> &Histogram {
        &self.wait_duration
    }

    pub(crate) fn hold_duration(&self) -> &Histogram {
        &self.hold_duration
    }

    /// Fixes a storage view and its account ticket under one ordering lock.
    pub(crate) async fn fix<T, E>(
        self: &Arc<Self>,
        accounts: Vec<AccountKey>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        self.fixing(async { Ok((fix.await?, self.admit(accounts, TicketKind::Accounts))) })
            .await
    }

    pub(crate) async fn fix_directed_grant<T, E>(
        self: &Arc<Self>,
        source: AccountKey,
        target: AccountKey,
        full: Option<Box<str>>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        self.fixing(async {
            let fixed = fix.await?;
            Ok((
                fixed,
                self.admit(vec![source, target], TicketKind::DirectedGrant(full)),
            ))
        })
        .await
    }

    /// A global turn waits for all older tickets and blocks later deliveries.
    pub(crate) async fn fix_all<T, E>(
        self: &Arc<Self>,
        fix: impl Future<Output = Result<T, E>>,
    ) -> Result<(T, Ticket), E> {
        self.fixing(async { Ok((fix.await?, self.admit(Vec::new(), TicketKind::Global))) })
            .await
    }

    pub(crate) async fn fix_block<E>(
        self: &Arc<Self>,
        owner: &AccountKey,
        mut accounts: Vec<AccountKey>,
        commit: impl Future<Output = Result<(), E>>,
        extend_scope: impl AsyncFnOnce(Vec<PendingDirectedGrant>, &mut Vec<AccountKey>),
    ) -> Result<Ticket, E> {
        self.fixing(async {
            commit.await?;
            // A completing grant must be in this list or already visible in the shard.
            let pending = self.lines.lock().pending_directed_grants(owner);
            extend_scope(pending, &mut accounts).await;
            accounts.sort_unstable();
            accounts.dedup();
            Ok(self.admit(accounts, TicketKind::Accounts))
        })
        .await
    }

    /// A fix cancelled before it releases the lock records no durations.
    async fn fixing<T>(&self, fix: impl Future<Output = T>) -> T {
        let started = Instant::now();
        let fixing = self.fixing.lock().await;
        let acquired = Instant::now();
        let fixed = fix.await;
        drop(fixing);
        let released = Instant::now();
        self.wait_duration
            .observe(acquired.duration_since(started).as_secs_f64());
        self.hold_duration
            .observe(released.duration_since(acquired).as_secs_f64());
        fixed
    }

    fn admit(self: &Arc<Self>, accounts: Vec<AccountKey>, kind: TicketKind) -> Ticket {
        let (ready, readiness) = oneshot::channel();
        let mut lines = self.lines.lock();
        let id = lines.next;
        lines.next += 1;
        if matches!(kind, TicketKind::Global) {
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
                kind,
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
        lines.wake_after_global();
    }
}

impl Lines {
    fn pending_directed_grants(&self, owner: &AccountKey) -> Vec<PendingDirectedGrant> {
        self.queues
            .get(owner)
            .into_iter()
            .flatten()
            .filter_map(|id| {
                let waiting = self.waiting.get(id)?;
                match (&waiting.kind, waiting.accounts.as_slice()) {
                    (TicketKind::DirectedGrant(full), [source, target]) if source == owner => {
                        Some(PendingDirectedGrant {
                            account: target.clone(),
                            full: full.clone(),
                        })
                    }
                    _ => None,
                }
            })
            .collect()
    }

    fn wake_after_global(&mut self) {
        let mut after = None;
        loop {
            let next = match after {
                None => self.waiting.keys().next().copied(),
                Some(last) => self
                    .waiting
                    .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(&id, _)| id),
            };
            let Some(next) = next else { break };
            self.wake_if_first(next);
            after = Some(next);
        }
    }
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
