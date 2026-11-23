// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::blocking::{
    BlockChange, BlockDelta, BlockError, BlockingReads, BlockingWrites,
};
use lonewolf_storage::{Storage, StorageErrorKind};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{BuildError, Element, IqType, StanzaErrorCondition, StanzaType};

use crate::delivery::{Failure, FailureKind, HandlerError, HostLookup, SessionTag};
use crate::discovery::DiscoScope;
use crate::iq::{
    IqDestinationRule, IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestKey,
    IqRequestType, IqRoute, IqScope, Requester,
};
use crate::policy::{Direction, PolicyFuture, PolicyHandler, PolicyRequest, Verdict};
use crate::{Effects, Extension, RegistrationError, Slots};

mod xml;

pub const NAME: &str = "blocking";
pub const NAMESPACE: &str = "urn:xmpp:blocking";
const BLOCKLIST: &str = "blocklist";
const BLOCK: &str = "block";
const UNBLOCK: &str = "unblock";

#[derive(Default)]
pub struct Blocking;

pub struct BlockingPresenceChange {
    owner: AccountKey,
    delta: BlockDelta,
}

impl BlockingPresenceChange {
    pub fn owner(&self) -> &AccountKey {
        &self.owner
    }

    pub fn delta(&self) -> &BlockDelta {
        &self.delta
    }
}

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Blocking {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        slots.policy(self.clone());
        let handler: Arc<dyn IqHandler<A, S>> = self;
        for (kind, name) in [
            (IqRequestType::Get, BLOCKLIST),
            (IqRequestType::Set, BLOCK),
            (IqRequestType::Set, UNBLOCK),
        ] {
            slots.iq(
                IqRoute {
                    scope: IqScope::Account,
                    kind,
                    namespace: NAMESPACE,
                    name,
                },
                Arc::clone(&handler),
            )?;
            slots.iq_destination(
                IqRequestKey {
                    kind,
                    namespace: NAMESPACE,
                    name,
                },
                IqDestinationRule::SenderBare,
            )?;
        }
        Ok(())
    }
}

impl<S: Storage> PolicyHandler<S> for Blocking {
    fn checks_explicit_addresses(&self) -> bool {
        true
    }

    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a S::Read,
    ) -> PolicyFuture<'a> {
        Box::pin(check_blocklist(request, transaction))
    }
}

async fn check_blocklist(
    request: PolicyRequest<'_>,
    transaction: &impl BlockingReads,
) -> Result<Verdict, HandlerError> {
    if request.peer.bare().as_str() == request.account.as_str() {
        return Ok(Verdict::Allow);
    }
    let matched = transaction
        .is_blocked(request.account, request.peer)
        .await
        .map_err(|error| HandlerError::Internal {
            condition: StanzaErrorCondition::ServiceUnavailable,
            failure: Failure {
                kind: match error {
                    BlockError::Storage(error) => FailureKind::Storage(error.kind()),
                    _ => FailureKind::Storage(StorageErrorKind::Other),
                },
                operation: "blocklist_policy_read",
            },
        })?;
    if !matched {
        return Ok(Verdict::Allow);
    }
    Ok(match (request.direction, request.kind) {
        (Direction::Outbound, _) => Verdict::OutboundBlocked,
        (Direction::Inbound, kind) if kind.is_error() => Verdict::Drop,
        (
            Direction::Inbound,
            StanzaType::Message(_) | StanzaType::Iq(IqType::Get | IqType::Set),
        ) => Verdict::Reject {
            condition: StanzaErrorCondition::ServiceUnavailable,
            application: None,
            text: None,
        },
        (Direction::Inbound, _) => Verdict::Drop,
    })
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Blocking {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            get_blocklist(request, transaction, response)
                .await
                .map_err(IqError::without_payload)
        })
    }

    fn get_missing_account(
        &self,
        _request: IqRequest<'_, A>,
        _response: &mut Arena<A>,
    ) -> Result<Option<Element>, IqError> {
        Err(IqError::without_payload(
            StanzaErrorCondition::ServiceUnavailable.into(),
        ))
    }

    fn set<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        transaction: &'a mut S::Write,
        hosts: &'a dyn HostLookup,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            set_blocklist(request, transaction, hosts, response)
                .await
                .map_err(IqError::without_payload)
        })
    }
}

async fn get_blocklist<A: ChunkAllocator>(
    request: IqRequest<'_, A>,
    transaction: &impl BlockingReads,
    response: &mut Arena<A>,
) -> Result<IqReply<A>, HandlerError> {
    if request.requester != Some(Requester::Owner) {
        return Err(StanzaErrorCondition::Forbidden.into());
    }
    let owner = owner(&request)?;
    xml::validate_get(request.payload)?;
    let rules = transaction
        .blocklist(&owner)
        .await
        .map_err(|error| storage_error(error, "blocklist_read"))?;
    let payload = xml::build_items(BLOCKLIST, &rules, response).map_err(|error| match error {
        BuildError::Allocation(_) | BuildError::TreeLimitExceeded => {
            StanzaErrorCondition::ResourceConstraint
        }
        _ => StanzaErrorCondition::InternalServerError,
    })?;
    let effects = Effects::new(vec![owner], |delivery| {
        delivery.tag_session(SessionTag::Blocklist)
    });
    Ok(IqReply::new(Some(payload), effects))
}

async fn set_blocklist<A: ChunkAllocator>(
    request: IqRequest<'_, A>,
    transaction: &mut impl BlockingWrites,
    hosts: &dyn HostLookup,
    response: &mut Arena<A>,
) -> Result<IqReply<A>, HandlerError> {
    let owner = owner(&request)?;
    let (command, items) = xml::parse_change(request.payload, response)?;
    let change = match command {
        xml::ChangeKind::Block => BlockChange::Block(&items),
        xml::ChangeKind::Unblock if items.is_empty() => BlockChange::Clear,
        xml::ChangeKind::Unblock => BlockChange::Unblock(&items),
    };
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| StanzaErrorCondition::InternalServerError)?;
    let mut push_id = u128::from_ne_bytes(nonce);
    let delta = transaction
        .change_blocklist(&owner, change)
        .await
        .map_err(|error| storage_error(error, "blocklist_write"))?;
    let local = delta.inserted.iter().chain(&delta.removed).any(|rule| {
        hosts.is_local_host(rule.domain())
            && rule
                .as_str()
                .split_once('/')
                .is_none_or(|(bare, _)| bare != rule.domain())
    });
    let change = (!delta.inserted.is_empty() || !delta.removed.is_empty()).then(|| {
        Arc::new(BlockingPresenceChange {
            owner: owner.clone(),
            delta,
        })
    });
    let local_change = if local { change.clone() } else { None };
    let mut effects = Effects::new(vec![owner.clone()], move |delivery| {
        Box::pin(async move {
            let pushed = delivery
                .push_to_tagged(
                    &owner,
                    SessionTag::Blocklist,
                    Box::new(move |to, arena| {
                        let id = format!("blocklist-{push_id:032x}");
                        push_id = push_id.wrapping_add(1);
                        xml::build_push(to, &id, command, &items, arena)
                    }),
                )
                .await;
            if let Some(change) = change {
                pushed.and(delivery.blocking_presence(&change).await)
            } else {
                pushed
            }
        })
    });
    effects.local_blocklist_edit = local_change;
    Ok(IqReply::new(None, effects))
}

fn owner<A: ChunkAllocator>(request: &IqRequest<'_, A>) -> Result<AccountKey, HandlerError> {
    if request
        .requester
        .is_some_and(|requester| requester != Requester::Owner)
        || request.target != request.sender.bare()
        || request.sender.resourcepart().is_none()
    {
        return Err(StanzaErrorCondition::Forbidden.into());
    }
    AccountKey::try_from(request.target)
        .map_err(|_| StanzaErrorCondition::InternalServerError.into())
}

fn storage_error(error: BlockError, operation: &'static str) -> HandlerError {
    match error {
        BlockError::NoAccount => StanzaErrorCondition::ServiceUnavailable.into(),
        BlockError::QuotaExceeded => StanzaErrorCondition::ResourceConstraint.into(),
        BlockError::Storage(error) => HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: Failure {
                kind: FailureKind::Storage(error.kind()),
                operation,
            },
        },
    }
}

#[cfg(test)]
mod tests;
