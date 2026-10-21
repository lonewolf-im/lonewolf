// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::stanza::{ElementRef, StanzaErrorCondition, XML_NAMESPACE};

use crate::delivery::HandlerError;
use crate::discovery::DiscoScope;
use crate::iq::{
    IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope, Requester,
};
use crate::{Effects, Extension, RegistrationError, Slots};

pub const NAME: &str = "ping";
pub const NAMESPACE: &str = "urn:xmpp:ping";

#[derive(Default)]
pub struct Ping;

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Ping {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        let server = IqRoute {
            scope: IqScope::Server,
            kind: IqRequestType::Get,
            namespace: NAMESPACE,
            name: "ping",
        };
        slots.iq(server, self.clone())?;
        slots.iq(
            IqRoute {
                scope: IqScope::Account,
                ..server
            },
            self,
        )?;
        slots.disco_feature(DiscoScope::Server, NAMESPACE);
        slots.disco_feature(DiscoScope::Account, NAMESPACE);
        Ok(())
    }
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Ping {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _transaction: &'a S::Read,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move { answer(request).map_err(Into::into) })
    }
}

fn answer<A: ChunkAllocator>(request: IqRequest<'_, A>) -> Result<IqReply<A>, HandlerError> {
    if request.target.localpart().is_some() {
        match request.requester {
            Some(Requester::Owner | Requester::PresenceAuthorized) => {}
            Some(Requester::Other) => return Err(StanzaErrorCondition::ServiceUnavailable.into()),
            None => return Err(StanzaErrorCondition::InternalServerError.into()),
        }
    }
    validate_payload(request.payload)?;
    Ok(IqReply::new(None, Effects::none()))
}

fn validate_payload<R: ArenaRead>(payload: ElementRef<'_, R>) -> Result<(), HandlerError> {
    if payload.name() != "ping" || payload.namespace() != NAMESPACE {
        return Err(StanzaErrorCondition::BadRequest.into());
    }
    for attribute in payload
        .attributes()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
    {
        let attribute = attribute.map_err(|_| StanzaErrorCondition::InternalServerError)?;
        if attribute.name != "lang" || attribute.namespace != XML_NAMESPACE {
            return Err(StanzaErrorCondition::BadRequest.into());
        }
    }
    if let Some(child) = payload
        .children()
        .map_err(|_| StanzaErrorCondition::InternalServerError)?
        .next()
    {
        child.map_err(|_| StanzaErrorCondition::InternalServerError)?;
        return Err(StanzaErrorCondition::BadRequest.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
