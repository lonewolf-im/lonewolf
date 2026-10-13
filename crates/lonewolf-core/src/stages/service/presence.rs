// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Weak};

#[derive(Default)]
pub(crate) struct ServicePresenceGates {
    entries: parking_lot::Mutex<HashMap<Box<str>, Weak<ServicePresenceGate>>>,
}

pub(crate) struct ServicePresenceGate {
    registry: Weak<ServicePresenceGates>,
    source: Box<str>,
    mutex: Arc<async_lock::Mutex<()>>,
}

pub(crate) struct ServicePresenceLease {
    // Unlock before dropping the gate so replacement sessions reuse the same lock.
    _guard: async_lock::MutexGuardArc<()>,
    _gate: Arc<ServicePresenceGate>,
}

impl ServicePresenceGates {
    pub(crate) fn gate(self: &Arc<Self>, source: &str) -> Arc<ServicePresenceGate> {
        let mut entries = self.entries.lock();
        if let Some(gate) = entries.get(source).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(ServicePresenceGate {
            registry: Arc::downgrade(self),
            source: source.into(),
            mutex: Arc::new(async_lock::Mutex::new(())),
        });
        entries.insert(source.into(), Arc::downgrade(&gate));
        gate
    }
}

impl ServicePresenceGate {
    pub(crate) async fn acquire(self: Arc<Self>) -> ServicePresenceLease {
        let guard = self.mutex.lock_arc().await;
        ServicePresenceLease {
            _guard: guard,
            _gate: self,
        }
    }
}

impl Drop for ServicePresenceGate {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut entries = registry.entries.lock();
            if entries
                .get(&self.source)
                .is_some_and(|entry| std::ptr::eq(entry.as_ptr(), self))
            {
                entries.remove(&self.source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::runtime::Runtime;
    use futures_util::poll;

    #[test]
    fn leases_release_keys_after_canceled_acquisition_and_allow_distinct_resources()
    -> std::io::Result<()> {
        Runtime::new()?.block_on(async {
            let gates = Arc::new(ServicePresenceGates::default());
            let lease = gates.gate("alice@localhost/desk").acquire().await;
            let mut waiting = Box::pin(gates.gate("alice@localhost/desk").acquire());
            assert!(poll!(&mut waiting).is_pending());
            let other = gates.gate("alice@localhost/phone").acquire().await;
            assert_eq!(gates.entries.lock().len(), 2);
            drop(waiting);
            drop(lease);
            assert!(!gates.entries.lock().contains_key("alice@localhost/desk"));
            let replacement = gates.gate("alice@localhost/desk").acquire().await;
            drop(replacement);
            drop(other);
            assert!(gates.entries.lock().is_empty());
        });
        Ok(())
    }
}
