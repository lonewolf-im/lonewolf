// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_executor::block_on;
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{StorageError, StorageErrorKind};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_xmpp::jid::{Jid, JidRef};

use super::*;
use crate::ExtensionFuture;
use crate::delivery::{BoundResource, DeliveryError, SessionLookup};
use crate::discovery::Discovery;

struct UnexpectedSessions;

impl SessionLookup for UnexpectedSessions {
    fn resources<'a>(
        &'a self,
        _account: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("a blocklist fetch must not look up sessions");
    }
}

#[derive(Default)]
struct FailingRead(AtomicUsize);

impl BlockingReads for FailingRead {
    async fn blocklist(&self, _: &AccountKey) -> Result<Vec<RosterJid>, BlockError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(StorageError::new(StorageErrorKind::Unavailable).into())
    }

    async fn is_blocked(&self, _: &AccountKey, _: JidRef<'_>) -> Result<bool, BlockError> {
        panic!("a blocklist fetch must read the entire list");
    }
}

#[test]
fn invalid_or_failed_read_cannot_stage_an_interest_effect() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let mut arena = Arena::<GlobalChunkAllocator>::try_new(Default::default())?;
        let sender = Jid::parse_in("alice@example.test/desk", &mut arena)?;
        let payload = Element::builder_in(BLOCKLIST, NAMESPACE, &mut arena)?.build()?;
        let unexpected = Element::builder_in(BLOCKLIST, NAMESPACE, &mut arena)?
            .attribute("unexpected", "", "true")?
            .build()?;
        let discovery = Discovery::default();
        let mut response = Arena::try_new(Default::default())?;
        let store = FailingRead::default();
        let sender = sender.resolve(&arena)?;
        let request = |element: Element, requester| {
            Ok::<_, lonewolf_util::arena::HandleError>(IqRequest {
                sender,
                target: sender.bare(),
                discovery: &discovery,
                sessions: &UnexpectedSessions,
                requester: Some(requester),
                lang: None,
                space: None,
                payload: element.resolve(&arena)?,
            })
        };
        for (payload, requester, condition) in [
            (
                unexpected,
                Requester::Owner,
                StanzaErrorCondition::BadRequest,
            ),
            (payload, Requester::Other, StanzaErrorCondition::Forbidden),
        ] {
            let Err(error) =
                get_blocklist(request(payload, requester)?, &store, &mut response).await
            else {
                return Err("rejection staged an effect".into());
            };
            assert_eq!(error.condition(), condition);
        }
        assert_eq!(store.0.load(Ordering::Relaxed), 0);
        let Err(error) =
            get_blocklist(request(payload, Requester::Owner)?, &store, &mut response).await
        else {
            return Err("failed read staged an effect".into());
        };
        assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
        assert_eq!(
            error.failure(),
            Some(Failure {
                kind: FailureKind::Storage(StorageErrorKind::Unavailable),
                operation: "blocklist_read",
            }),
        );
        assert_eq!(store.0.load(Ordering::Relaxed), 1);
        Ok(())
    })
}
