// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex as PlMutex;

type Pair = (Box<str>, Box<str>);

#[derive(Default)]
pub(super) struct InboundStreams {
    active: PlMutex<HashMap<Pair, usize>>,
}

pub(super) struct Permit {
    streams: Arc<InboundStreams>,
    pair: Pair,
}

impl InboundStreams {
    pub(super) fn acquire(
        self: &Arc<Self>,
        local: &str,
        remote: &str,
        max: usize,
    ) -> Option<Permit> {
        let mut active = self.active.lock();
        let pair = (local.into(), remote.into());
        let count = active.entry(pair.clone()).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Permit {
            streams: Arc::clone(self),
            pair,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut active = self.streams.active.lock();
        if let Some(count) = active.get_mut(&self.pair) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.pair);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_are_shared_per_pair_and_remove_empty_entries() {
        let streams = Arc::new(InboundStreams::default());
        let first = streams.acquire("local.test", "remote.test", 1);
        assert!(first.is_some());
        assert!(streams.acquire("local.test", "remote.test", 1).is_none());
        let other = streams.acquire("other.test", "remote.test", 1);
        assert!(other.is_some());
        drop(first);
        assert_eq!(streams.active.lock().len(), 1);
        let again = streams.acquire("local.test", "remote.test", 1);
        assert!(again.is_some());
        drop((again, other));
        assert!(streams.active.lock().is_empty());
    }
}
