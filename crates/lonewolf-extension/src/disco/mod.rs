// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{BuildError, Element, StanzaErrorCondition};

use crate::delivery::{BoundResource, Failure, FailureKind, HandlerError};
use crate::discovery::{
    DiscoScope, Discovery, INFO_NAMESPACE, ITEMS_NAMESPACE, Identity, Query, QueryKind, info_in,
    item_in, items_in,
};
use crate::iq::{
    IqError, IqFuture, IqHandler, IqReply, IqRequest, IqRequestType, IqRoute, IqScope, Requester,
};
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
const ACCOUNT_INFO: IqRoute = IqRoute {
    scope: IqScope::Account,
    ..SERVER_INFO
};
const ACCOUNT_ITEMS: IqRoute = IqRoute {
    scope: IqScope::Account,
    ..SERVER_ITEMS
};
const ACCOUNT_IDENTITY: Identity = Identity {
    category: "account",
    kind: "registered",
    name: None,
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
        slots.iq(ACCOUNT_INFO, self.clone())?;
        slots.iq(ACCOUNT_ITEMS, self)?;
        slots.disco_identity(DiscoScope::Account, ACCOUNT_IDENTITY);
        slots.disco_feature(DiscoScope::Account, INFO_NAMESPACE);
        slots.disco_feature(DiscoScope::Account, ITEMS_NAMESPACE);
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
                .ok_or(HandlerError::described(StanzaErrorCondition::BadRequest,
                    lonewolf_xmpp::stanza::StanzaErrorText::Static("Discovery requires a query element in the disco#info or disco#items namespace.")))?;
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
                let requester = request
                    .requester
                    .ok_or(StanzaErrorCondition::InternalServerError)?;
                let account = request.target;
                let answer = account_answer(query.kind, requester, query.node);
                let mut item_count = 0;
                let result: Result<_, HandlerError> = match answer {
                    AccountAnswer::ServiceUnavailable => {
                        Err(StanzaErrorCondition::ServiceUnavailable.into())
                    }
                    AccountAnswer::ItemNotFound => Err(StanzaErrorCondition::ItemNotFound.into()),
                    AccountAnswer::EmptyItems => items_in(query.node, &[], response)
                        .map_err(|_| StanzaErrorCondition::ResourceConstraint.into()),
                    AccountAnswer::Info => info_in(
                        None,
                        request.discovery.identities(DiscoScope::Account),
                        request.discovery.features(DiscoScope::Account),
                        response,
                    )
                    .map_err(|_| StanzaErrorCondition::ResourceConstraint.into()),
                    AccountAnswer::Resources => {
                        let account = AccountKey::try_from(request.target)
                            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
                        let resources =
                            request.sessions.resources(&account).await.map_err(|_| {
                                HandlerError::Internal {
                                    condition: StanzaErrorCondition::InternalServerError,
                                    failure: Failure {
                                        kind: FailureKind::Delivery,
                                        operation: "disco_items_resources",
                                    },
                                }
                            })?;
                        item_count = resources
                            .iter()
                            .filter(|resource| requester == Requester::Owner || resource.available)
                            .count();
                        resource_items(request.target.as_str(), requester, &resources, response)
                            .map_err(|_| StanzaErrorCondition::ResourceConstraint.into())
                    }
                };
                if result.is_ok()
                    || matches!(
                        result,
                        Err(HandlerError::Stanza(
                            StanzaErrorCondition::ServiceUnavailable
                                | StanzaErrorCondition::ItemNotFound
                        ))
                    )
                {
                    let outcome = match answer {
                        AccountAnswer::ServiceUnavailable | AccountAnswer::EmptyItems => "hidden",
                        AccountAnswer::ItemNotFound => "unknown_node",
                        AccountAnswer::Info | AccountAnswer::Resources => "answered",
                    };
                    match query.kind {
                        QueryKind::Info => tracing::debug!(
                            operation = "disco_info",
                            scope = "account",
                            outcome,
                            owner_jid = ?account.as_str(),
                            "discovery query answered"
                        ),
                        QueryKind::Items => tracing::debug!(
                            operation = "disco_items",
                            scope = "account",
                            outcome,
                            item_count,
                            owner_jid = ?account.as_str(),
                            "discovery query answered"
                        ),
                    }
                }
                result?
            };
            Ok(IqReply::new(Some(payload), Effects::none()))
        })
    }

    fn get_missing_account(
        &self,
        request: IqRequest<'_, A>,
        response: &mut Arena<A>,
    ) -> Result<Option<Element>, IqError> {
        let query = Query::parse(request.payload)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?
            .ok_or(HandlerError::described(StanzaErrorCondition::BadRequest,
                    lonewolf_xmpp::stanza::StanzaErrorText::Static("Discovery requires a query element in the disco#info or disco#items namespace.")))?;
        let result: Result<_, HandlerError> =
            match account_answer(query.kind, Requester::Other, query.node) {
                AccountAnswer::ServiceUnavailable => {
                    Err(StanzaErrorCondition::ServiceUnavailable.into())
                }
                AccountAnswer::EmptyItems => items_in(query.node, &[], response)
                    .map(Some)
                    .map_err(|_| StanzaErrorCondition::ResourceConstraint.into()),
                _ => Err(StanzaErrorCondition::InternalServerError.into()),
            };
        if result.is_ok()
            || matches!(
                result,
                Err(HandlerError::Stanza(
                    StanzaErrorCondition::ServiceUnavailable
                ))
            )
        {
            match query.kind {
                QueryKind::Info => tracing::debug!(
                    operation = "disco_info",
                    scope = "account",
                    outcome = "missing",
                    "discovery query answered"
                ),
                QueryKind::Items => tracing::debug!(
                    operation = "disco_items",
                    scope = "account",
                    outcome = "missing",
                    item_count = 0,
                    "discovery query answered"
                ),
            }
        }
        result.map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountAnswer {
    ServiceUnavailable,
    EmptyItems,
    ItemNotFound,
    Info,
    Resources,
}

fn account_answer(kind: QueryKind, requester: Requester, node: Option<&str>) -> AccountAnswer {
    let authorized = matches!(requester, Requester::Owner | Requester::PresenceAuthorized);
    match (kind, authorized, node) {
        (QueryKind::Info, false, _) => AccountAnswer::ServiceUnavailable,
        (QueryKind::Items, false, _) => AccountAnswer::EmptyItems,
        (_, true, Some(_)) => AccountAnswer::ItemNotFound,
        (QueryKind::Info, true, None) => AccountAnswer::Info,
        (QueryKind::Items, true, None) => AccountAnswer::Resources,
    }
}

fn resource_items<A: ChunkAllocator>(
    account: &str,
    requester: Requester,
    resources: &[BoundResource],
    response: &mut Arena<A>,
) -> Result<Element, BuildError> {
    let mut jid = String::new();
    let mut items = Vec::with_capacity(resources.len());
    for resource in resources {
        if requester != Requester::Owner && !resource.available {
            continue;
        }
        jid.clear();
        jid.push_str(account);
        jid.push('/');
        jid.push_str(&resource.resource);
        items.push(item_in(&jid, None, None, response)?);
    }
    items_in(None, &items, response)
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
