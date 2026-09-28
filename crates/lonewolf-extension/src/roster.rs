// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::roster::{RosterItem, RosterRepository, RosterSnapshot, SubscriptionState};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{Element, NodeRef, StanzaErrorCondition};

use crate::iq::{
    IqEffect, IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqResponse, IqRoute,
    IqScope,
};

pub const NAME: &str = "roster";
pub const NAMESPACE: &str = "jabber:iq:roster";

pub fn registrations<A, R>(repository: R) -> [IqRegistration<A>; 1]
where
    A: ChunkAllocator,
    R: RosterRepository + 'static,
{
    [IqRegistration::new(
        IqRoute {
            scope: IqScope::Account,
            kind: IqRequestType::Get,
            namespace: NAMESPACE,
            name: "query",
        },
        Arc::new(Roster { repository }),
    )]
}

struct Roster<R> {
    repository: R,
}

impl<A, R> IqHandler<A> for Roster<R>
where
    A: ChunkAllocator,
    R: RosterRepository,
{
    fn handle<'a>(&'a self, request: IqRequest<'a, A>, response: &'a mut Arena<A>) -> IqFuture<'a> {
        Box::pin(async move {
            if request.target != request.sender.bare() {
                return Err(StanzaErrorCondition::Forbidden);
            }
            for child in request
                .payload
                .children()
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
            {
                if let NodeRef::Element(child) =
                    child.map_err(|_| StanzaErrorCondition::InternalServerError)?
                    && child.name() == "item"
                    && child.namespace() == NAMESPACE
                {
                    return Err(StanzaErrorCondition::BadRequest);
                }
            }
            let owner = AccountKey::try_from(request.sender.bare())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let snapshot = self
                .repository
                .snapshot(&owner)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            build_response(snapshot, response)
        })
    }
}

fn build_response<A: ChunkAllocator>(
    snapshot: RosterSnapshot,
    response: &mut Arena<A>,
) -> Result<IqResponse, StanzaErrorCondition> {
    let mut items = Vec::with_capacity(snapshot.items.len());
    for item in snapshot.items {
        items.push(build_item(item, response)?);
    }
    let mut query = Element::builder_in("query", NAMESPACE, response)
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    for item in items {
        query = query
            .child(item)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    query
        .build()
        .map(|query| IqResponse::new(Some(query)).with_effect(IqEffect::MarkRosterInterested))
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

fn build_item<A: ChunkAllocator>(
    item: RosterItem,
    response: &mut Arena<A>,
) -> Result<Element, StanzaErrorCondition> {
    let mut groups = Vec::with_capacity(item.groups.len());
    for group in &item.groups {
        groups.push(
            Element::builder_in("group", NAMESPACE, response)
                .and_then(|builder| builder.text(group))
                .and_then(|builder| builder.build())
                .map_err(|_| StanzaErrorCondition::InternalServerError)?,
        );
    }
    let mut builder = Element::builder_in("item", NAMESPACE, response)
        .and_then(|builder| builder.attribute("jid", "", item.jid.as_str()))
        .and_then(|builder| match item.name.as_deref() {
            Some(name) => builder.attribute("name", "", name),
            None => Ok(builder),
        })
        .and_then(|builder| {
            builder.attribute(
                "subscription",
                "",
                subscription_name(item.subscription.state),
            )
        })
        .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    if item.subscription.pending_out {
        builder = builder
            .attribute("ask", "", "subscribe")
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    if item.subscription.approved {
        builder = builder
            .attribute("approved", "", "true")
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    for group in groups {
        builder = builder
            .child(group)
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
    }
    builder
        .build()
        .map_err(|_| StanzaErrorCondition::InternalServerError)
}

const fn subscription_name(state: SubscriptionState) -> &'static str {
    match state {
        SubscriptionState::None => "none",
        SubscriptionState::To => "to",
        SubscriptionState::From => "from",
        SubscriptionState::Both => "both",
    }
}

#[cfg(test)]
mod tests;
