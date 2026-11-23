// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_executor::block_on;
use lonewolf_storage::blocking::BlockDelta;
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{StorageError, StorageErrorKind};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_xmpp::jid::{Jid, JidRef};

use super::*;
use crate::ExtensionFuture;
use crate::delivery::{BoundResource, DeliveryError, SessionLookup};
use crate::discovery::Discovery;

struct UnexpectedSessions;

impl HostLookup for UnexpectedSessions {
    fn is_local_host(&self, _: &str) -> bool {
        panic!("a failed edit must not prepare an effect")
    }
}

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

struct FailingMatch;

impl BlockingReads for FailingMatch {
    async fn blocklist(&self, _: &AccountKey) -> Result<Vec<RosterJid>, BlockError> {
        panic!("policy must look up only the addressed peer");
    }

    async fn is_blocked(&self, _: &AccountKey, _: JidRef<'_>) -> Result<bool, BlockError> {
        Err(StorageError::new(StorageErrorKind::Unavailable).into())
    }
}

#[test]
fn policy_read_failure_refuses_admission_without_a_blocked_condition() -> Result<(), Box<dyn Error>>
{
    block_on(async {
        let mut arena = Arena::<GlobalChunkAllocator>::try_new(Default::default())?;
        let owner = Jid::parse_in("alice@example.test", &mut arena)?;
        let own_resource = Jid::parse_in("alice@example.test/phone", &mut arena)?;
        let peer = Jid::parse_in("bob@example.test/desk", &mut arena)?;
        let account = AccountKey::try_from(owner.resolve(&arena)?)?;
        let kind = StanzaType::Iq(IqType::Get);
        for direction in [Direction::Outbound, Direction::Inbound] {
            let request = PolicyRequest {
                account: &account,
                direction,
                peer: peer.resolve(&arena)?,
                kind,
            };
            assert!(matches!(
                check_blocklist(request, &FailingMatch).await,
                Err(HandlerError::Internal {
                    condition: StanzaErrorCondition::ServiceUnavailable,
                    failure: Failure {
                        kind: FailureKind::Storage(StorageErrorKind::Unavailable),
                        ..
                    },
                })
            ));
            let request = PolicyRequest {
                account: &account,
                direction,
                peer: own_resource.resolve(&arena)?,
                kind,
            };
            assert_eq!(
                check_blocklist(request, &FailingMatch).await,
                Ok(Verdict::Allow)
            );
        }
        Ok(())
    })
}

#[derive(Default)]
struct FailingWrite(usize);

impl BlockingWrites for FailingWrite {
    async fn change_blocklist(
        &mut self,
        owner: &AccountKey,
        change: BlockChange<'_>,
    ) -> Result<BlockDelta, BlockError> {
        assert_eq!(owner.as_str(), "alice@example.test");
        let BlockChange::Block(items) = change else {
            panic!("expected a block mutation");
        };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].as_str(), "peer.example");
        self.0 += 1;
        Err(StorageError::new(StorageErrorKind::Unavailable).into())
    }

    async fn delete_blocklist(&mut self, _: &AccountKey) -> Result<(), StorageError> {
        panic!("a block request cannot delete the account's blocklist");
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

#[test]
fn explicit_non_owner_and_failed_write_cannot_stage_a_push() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let mut arena = Arena::<GlobalChunkAllocator>::try_new(Default::default())?;
        let sender = Jid::parse_in("alice@example.test/desk", &mut arena)?;
        let item = Element::builder_in("item", NAMESPACE, &mut arena)?
            .attribute("jid", "", "Peer.EXAMPLE")?
            .build()?;
        let payload = Element::builder_in(BLOCK, NAMESPACE, &mut arena)?
            .child(item)?
            .build()?;
        let discovery = Discovery::default();
        let mut response = Arena::try_new(Default::default())?;
        let mut store = FailingWrite::default();
        let sender = sender.resolve(&arena)?;
        let request = |requester| {
            Ok::<_, lonewolf_util::arena::HandleError>(IqRequest {
                sender,
                target: sender.bare(),
                discovery: &discovery,
                sessions: &UnexpectedSessions,
                requester,
                lang: None,
                space: None,
                payload: payload.resolve(&arena)?,
            })
        };
        for requester in [Requester::Other, Requester::PresenceAuthorized] {
            let Err(error) = set_blocklist(
                request(Some(requester))?,
                &mut store,
                &UnexpectedSessions,
                &mut response,
            )
            .await
            else {
                return Err("non-owner staged a push".into());
            };
            assert_eq!(error.condition(), StanzaErrorCondition::Forbidden);
        }
        assert_eq!(store.0, 0);
        let Err(error) = set_blocklist(
            request(None)?,
            &mut store,
            &UnexpectedSessions,
            &mut response,
        )
        .await
        else {
            return Err("failed write staged a push".into());
        };
        assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
        assert_eq!(
            error.failure(),
            Some(Failure {
                kind: FailureKind::Storage(StorageErrorKind::Unavailable),
                operation: "blocklist_write",
            }),
        );
        assert_eq!(store.0, 1);
        Ok(())
    })
}
