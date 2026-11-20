// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::blocking::{BlockError, BlockingReads};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{BuildError, Element, StanzaErrorCondition};

use crate::delivery::{Failure, FailureKind, HandlerError, SessionTag};
use crate::iq::{
    IqDestinationRule, IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestKey,
    IqRequestType, IqRoute, IqScope, Requester,
};
use crate::{Effects, Extension, RegistrationError, Slots};

mod xml;

pub const NAME: &str = "blocking";
pub const NAMESPACE: &str = "urn:xmpp:blocking";
const BLOCKLIST: &str = "blocklist";

#[derive(Default)]
pub struct Blocking;

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Blocking {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.iq(
            IqRoute {
                scope: IqScope::Account,
                kind: IqRequestType::Get,
                namespace: NAMESPACE,
                name: BLOCKLIST,
            },
            self,
        )?;
        slots.iq_destination(
            IqRequestKey {
                kind: IqRequestType::Get,
                namespace: NAMESPACE,
                name: BLOCKLIST,
            },
            IqDestinationRule::SenderBare,
        )
    }
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
}

async fn get_blocklist<A: ChunkAllocator>(
    request: IqRequest<'_, A>,
    transaction: &impl BlockingReads,
    response: &mut Arena<A>,
) -> Result<IqReply<A>, HandlerError> {
    if request.requester != Some(Requester::Owner)
        || request.target != request.sender.bare()
        || request.sender.resourcepart().is_none()
    {
        return Err(StanzaErrorCondition::Forbidden.into());
    }
    let owner = AccountKey::try_from(request.target)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    xml::validate_get(request.payload)?;
    let rules = transaction.blocklist(&owner).await.map_err(read_error)?;
    let payload = xml::build_blocklist(&rules, response).map_err(|error| match error {
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

fn read_error(error: BlockError) -> HandlerError {
    match error {
        BlockError::NoAccount => StanzaErrorCondition::ServiceUnavailable.into(),
        BlockError::QuotaExceeded => StanzaErrorCondition::ResourceConstraint.into(),
        BlockError::Storage(error) => HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: Failure {
                kind: FailureKind::Storage(error.kind()),
                operation: "blocklist_read",
            },
        },
    }
}

#[cfg(test)]
mod tests;
