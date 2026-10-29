// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::iq::Requester;
use lonewolf_extension::presence::PresenceRequestType;
use lonewolf_storage::RedbRead;
use lonewolf_storage::account::{AccountError, AccountKey, AccountReads};
use lonewolf_util::arena::{Arena, ArenaError, ChunkAllocator, HandleError};
use lonewolf_xmpp::jid::{JidError, JidRef};
use lonewolf_xmpp::stanza::{
    BuildError, Element, IqType, Stanza, StanzaErrorCondition, StanzaErrorText, StanzaRef,
    StanzaType, error_element_in,
};

use crate::delivery::storage_failure;
use crate::router::{RouterError, RouterHandle};

pub(crate) struct ReplyError;

impl From<BuildError> for ReplyError {
    fn from(_: BuildError) -> Self {
        Self
    }
}

impl From<RouterError> for ReplyError {
    fn from(_: RouterError) -> Self {
        Self
    }
}

impl From<ArenaError> for ReplyError {
    fn from(_: ArenaError) -> Self {
        Self
    }
}

impl From<HandleError> for ReplyError {
    fn from(_: HandleError) -> Self {
        Self
    }
}

impl From<JidError> for ReplyError {
    fn from(_: JidError) -> Self {
        Self
    }
}

#[derive(Clone, Copy)]
pub(crate) enum IqTarget {
    Server,
    Present,
    Missing,
}

pub(crate) async fn iq_target(
    transaction: &impl AccountReads,
    target: Option<&AccountKey>,
) -> Result<IqTarget, HandlerError> {
    let Some(target) = target else {
        return Ok(IqTarget::Server);
    };
    match transaction.account(target).await {
        Ok(Some(_)) => Ok(IqTarget::Present),
        Ok(None) => Ok(IqTarget::Missing),
        Err(AccountError::Storage(error)) => Err(HandlerError::Internal {
            condition: StanzaErrorCondition::InternalServerError,
            failure: storage_failure(error, "iq_account_read"),
        }),
        Err(_) => Err(StanzaErrorCondition::InternalServerError.into()),
    }
}

pub(crate) async fn require_iq_account(
    transaction: &impl AccountReads,
    target: Option<&AccountKey>,
) -> Result<(), HandlerError> {
    match iq_target(transaction, target).await? {
        IqTarget::Missing => Err(StanzaErrorCondition::ServiceUnavailable.into()),
        IqTarget::Server | IqTarget::Present => Ok(()),
    }
}

pub(crate) async fn iq_requester<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    account: &AccountKey,
    sender: JidRef<'_>,
    transaction: &RedbRead,
) -> Result<Requester, HandlerError> {
    if sender.bare().as_str() == account.as_str() {
        return Ok(Requester::Owner);
    }
    let Some(handler) = router
        .presence_handlers(account.domain())
        .and_then(|handlers| handlers.find(PresenceRequestType::Available))
    else {
        return Ok(Requester::Other);
    };
    Ok(if handler.visibility(account, sender, transaction).await? {
        Requester::PresenceAuthorized
    } else {
        Requester::Other
    })
}

pub(crate) fn result_reply<A: ChunkAllocator>(
    request: &StanzaRef<'_, Arena<A>>,
    sender: JidRef<'_>,
    payload: Option<Element>,
    response: &mut Arena<A>,
) -> Result<Stanza, ReplyError> {
    let recipient = sender.clone_in(response)?;
    let from = request
        .to()?
        .map(|from| from.clone_in(response))
        .transpose()?;
    let mut builder = Stanza::builder_in(
        StanzaType::Iq(IqType::Result),
        request.namespace(),
        response,
    )
    .id(request.id()?)?
    .from(from)?
    .to(Some(recipient))?;
    if let Some(payload) = payload {
        builder = builder.child(payload)?;
    }
    Ok(builder.build()?)
}

pub(crate) fn error_reply_omitting_payload<A: ChunkAllocator>(
    request: &StanzaRef<'_, Arena<A>>,
    sender: JidRef<'_>,
    condition: StanzaErrorCondition,
    text: StanzaErrorText,
    response: &mut Arena<A>,
) -> Result<Stanza, ReplyError> {
    if !matches!(
        request.stanza_type(),
        StanzaType::Iq(IqType::Get | IqType::Set)
    ) {
        return Err(BuildError::NotIqRequest.into());
    }
    let recipient = sender.clone_in(response)?;
    let from = request
        .to()?
        .map(|from| from.clone_in(response))
        .transpose()?;
    let error = error_element_in(request.namespace(), condition, None, text, response)?;
    Ok(
        Stanza::builder_in(StanzaType::Iq(IqType::Error), request.namespace(), response)
            .id(request.id()?)?
            .lang(request.lang()?)?
            .from(from)?
            .to(Some(recipient))?
            .child(error)?
            .build()?,
    )
}
