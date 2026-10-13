// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_channel::oneshot;
use lonewolf_util::arena::ChunkAllocator;
use parking_lot::Mutex as PlMutex;

use super::{RoutedStanza, RouterError};

const MAX_PENDING: usize = 4096;
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const ID_PREFIX: &str = "lw-iq-";

pub(crate) struct IqRequests<A: ChunkAllocator> {
    next: AtomicU64,
    pending: PlMutex<HashMap<u64, Waiting<A>>>,
    limit: usize,
}

struct Waiting<A: ChunkAllocator> {
    responder: Box<str>,
    reply: oneshot::Sender<RoutedStanza<A>>,
}

/// Removes its entry when dropped, so a cancelled wait frees its slot.
pub(crate) struct PendingIq<A: ChunkAllocator> {
    requests: Arc<IqRequests<A>>,
    id: u64,
    response: oneshot::Receiver<RoutedStanza<A>>,
}

impl<A: ChunkAllocator> IqRequests<A> {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_limit(MAX_PENDING)
    }

    fn with_limit(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(0),
            pending: PlMutex::new(HashMap::new()),
            limit,
        })
    }

    pub(crate) fn register(self: &Arc<Self>, responder: &str) -> Result<PendingIq<A>, RouterError> {
        let mut pending = self.pending.lock();
        if pending.len() >= self.limit {
            return Err(RouterError::ResourceLimit);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (reply, response) = oneshot::channel();
        pending.insert(
            id,
            Waiting {
                responder: responder.into(),
                reply,
            },
        );
        Ok(PendingIq {
            requests: Arc::clone(self),
            id,
            response,
        })
    }

    pub(crate) fn complete(&self, id: &str, from: &str, response: RoutedStanza<A>) -> bool {
        let Some(id) = id
            .strip_prefix(ID_PREFIX)
            .and_then(|id| id.parse::<u64>().ok())
        else {
            return false;
        };
        let mut pending = self.pending.lock();
        if pending
            .get(&id)
            .is_none_or(|waiting| waiting.responder.as_ref() != from)
        {
            return false;
        }
        if let Some(waiting) = pending.remove(&id) {
            let _ = waiting.reply.send(response);
            return true;
        }
        false
    }
}

impl<A: ChunkAllocator> PendingIq<A> {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) async fn response(&mut self) -> Option<RoutedStanza<A>> {
        (&mut self.response).await.ok()
    }
}

impl<A: ChunkAllocator> Drop for PendingIq<A> {
    fn drop(&mut self) {
        self.requests.pending.lock().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use compio::runtime::Runtime;
    use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
    use lonewolf_xmpp::stanza::{IqType, Stanza, StanzaNamespace, StanzaType};

    use super::*;

    fn response() -> Result<RoutedStanza<GlobalChunkAllocator>, Box<dyn Error>> {
        let mut arena = Arena::try_new(Default::default())?;
        let stanza = Stanza::builder_in(
            StanzaType::Iq(IqType::Result),
            StanzaNamespace::Client,
            &mut arena,
        )
        .id(Some("response"))?
        .build()?;
        Ok(RoutedStanza::from_parts(stanza, arena))
    }

    #[test]
    fn complete_delivers_to_the_matching_responder() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let requests = IqRequests::new();
            let mut pending = requests.register("bob@localhost/desk")?;
            assert!(requests.complete(
                &format!("{ID_PREFIX}{}", pending.id),
                "bob@localhost/desk",
                response()?
            ));
            let response = pending.response().await.ok_or("missing response")?;
            assert_eq!(
                response.resolve()?.stanza_type(),
                StanzaType::Iq(IqType::Result)
            );
            assert!(requests.pending.lock().is_empty());
            Ok(())
        })
    }

    #[test]
    fn complete_ignores_other_senders_and_keeps_waiting() -> Result<(), Box<dyn Error>> {
        Runtime::new()?.block_on(async {
            let requests = IqRequests::new();
            let mut pending = requests.register("bob@localhost/desk")?;
            let id = format!("{ID_PREFIX}{}", pending.id);
            for (id, sender) in [
                ("untracked", "bob@localhost/desk"),
                ("lw-iq-invalid", "bob@localhost/desk"),
                (id.as_str(), "carol@localhost/desk"),
                (id.as_str(), "bob@localhost/phone"),
            ] {
                assert!(!requests.complete(id, sender, response()?));
                assert_eq!(requests.pending.lock().len(), 1);
            }
            assert!(requests.complete(&id, "bob@localhost/desk", response()?));
            assert!(pending.response().await.is_some());
            Ok(())
        })
    }

    #[test]
    fn dropping_a_pending_request_frees_its_slot() -> Result<(), Box<dyn Error>> {
        let requests = IqRequests::<GlobalChunkAllocator>::with_limit(1);
        let pending = requests.register("bob@localhost/desk")?;
        drop(pending);
        let _next = requests.register("bob@localhost/desk")?;
        assert_eq!(requests.pending.lock().len(), 1);
        Ok(())
    }

    #[test]
    fn register_fails_beyond_the_pending_limit() -> Result<(), Box<dyn Error>> {
        let requests = IqRequests::<GlobalChunkAllocator>::with_limit(2);
        let _first = requests.register("bob@localhost/desk")?;
        let _second = requests.register("carol@localhost/desk")?;
        assert!(matches!(
            requests.register("alice@localhost/desk"),
            Err(RouterError::ResourceLimit)
        ));
        assert_eq!(requests.pending.lock().len(), 2);
        Ok(())
    }
}
