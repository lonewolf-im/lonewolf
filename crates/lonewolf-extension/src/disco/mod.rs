// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{Element, StanzaErrorCondition};

use crate::discovery::{
    DiscoScope, Discovery, INFO_NAMESPACE, ITEMS_NAMESPACE, Identity, Query, QueryKind, info_in,
    item_in, items_in,
};
use crate::iq::{IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope};
use crate::{Effects, Extension, RegistrationError, Slots};

pub const NAME: &str = "disco";

const SERVER_INFO: IqRoute = IqRoute {
    scope: IqScope::Server,
    kind: IqRequestType::Get,
    namespace: INFO_NAMESPACE,
    name: "query",
};
const SERVER_ITEMS: IqRoute = IqRoute {
    namespace: ITEMS_NAMESPACE,
    ..SERVER_INFO
};
const SERVER_IDENTITY: Identity = Identity {
    category: "server",
    kind: "im",
    name: None,
};

#[derive(Default)]
pub struct Disco;

impl<A: ChunkAllocator, S: Storage> Extension<A, S> for Disco {
    fn name(&self) -> &'static str {
        NAME
    }

    fn register(
        self: Arc<Self>,
        _host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError> {
        slots.iq(SERVER_INFO, self.clone())?;
        slots.iq(SERVER_ITEMS, self.clone())?;
        slots.disco_identity(DiscoScope::Server, SERVER_IDENTITY);
        slots.disco_feature(DiscoScope::Server, INFO_NAMESPACE);
        slots.disco_feature(DiscoScope::Server, ITEMS_NAMESPACE);
        Ok(())
    }
}

impl<A: ChunkAllocator, S: Storage> IqHandler<A, S> for Disco {
    fn get<'a>(
        &'a self,
        request: IqRequest<'a, A>,
        _transaction: &'a S::Read,
        response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async move {
            let query = Query::parse(request.payload)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .ok_or(StanzaErrorCondition::BadRequest)?;
            let payload = if request.target.localpart().is_none() {
                let result = answer_server(query, request.discovery, response);
                let outcome = if query.node.is_some() {
                    "unknown_node"
                } else {
                    "answered"
                };
                if result.is_ok() || matches!(result, Err(StanzaErrorCondition::ItemNotFound)) {
                    match query.kind {
                        QueryKind::Info => tracing::debug!(
                            operation = "disco_info",
                            scope = "server",
                            outcome,
                            "discovery query answered"
                        ),
                        QueryKind::Items => tracing::debug!(
                            operation = "disco_items",
                            scope = "server",
                            outcome,
                            item_count = if query.node.is_none() {
                                request.discovery.services().len()
                            } else {
                                0
                            },
                            "discovery query answered"
                        ),
                    }
                }
                result?
            } else {
                return Err(StanzaErrorCondition::ServiceUnavailable.into());
            };
            Ok(IqReply::new(Some(payload), Effects::none()))
        })
    }
}

fn answer_server<A: ChunkAllocator>(
    query: Query<'_>,
    discovery: &Discovery,
    response: &mut Arena<A>,
) -> Result<Element, StanzaErrorCondition> {
    if query.node.is_some() {
        return Err(StanzaErrorCondition::ItemNotFound);
    }
    let built = match query.kind {
        QueryKind::Info => info_in(
            None,
            discovery.identities(DiscoScope::Server),
            discovery.features(DiscoScope::Server),
            response,
        ),
        QueryKind::Items => {
            let mut items = Vec::with_capacity(discovery.services().len());
            for domain in discovery.services() {
                items.push(
                    item_in(domain, None, None, response)
                        .map_err(|_| StanzaErrorCondition::ResourceConstraint)?,
                );
            }
            items_in(None, &items, response)
        }
    };
    built.map_err(|_| StanzaErrorCondition::ResourceConstraint)
}

#[cfg(test)]
mod tests;
