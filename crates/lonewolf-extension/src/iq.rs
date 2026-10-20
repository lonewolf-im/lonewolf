// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{Element, ElementRef, Stanza, StanzaErrorCondition};

use crate::delivery::{HandlerError, HostLookup};
use crate::discovery::Discovery;
use crate::{Effects, ExtensionFuture, RegistrationError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IqScope {
    Server,
    Account,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IqRequestType {
    Get,
    Set,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IqRoute {
    pub scope: IqScope,
    pub kind: IqRequestType,
    pub namespace: &'static str,
    pub name: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requester {
    /// The sender's bare JID is the target account.
    Owner,
    /// The target's host lets the sender receive the account's presence.
    PresenceAuthorized,
    Other,
}

pub struct IqRequest<'a, A: ChunkAllocator> {
    /// The authenticated bound JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    /// An omitted destination resolves to the authenticated account's bare JID.
    pub target: JidRef<'a>,
    pub discovery: &'a Discovery,
    /// Set for account `get` requests; server targets and `set` requests use `None`.
    pub requester: Option<Requester>,
    pub payload: ElementRef<'a, Arena<A>>,
}

pub struct IqReply<A> {
    pub payload: Option<Element>,
    pub effects: Effects<A>,
    /// Stanzas in the response arena that precede the reply on the requester's stream.
    pub results: Vec<Stanza>,
}

impl<A: ChunkAllocator> IqReply<A> {
    pub fn new(payload: Option<Element>, effects: Effects<A>) -> Self {
        Self {
            payload,
            effects,
            results: Vec::new(),
        }
    }

    /// Each result must be addressed to the request's sender.
    pub fn with_results(mut self, results: Vec<Stanza>) -> Self {
        self.results = results;
        self
    }
}

pub type IqFuture<'a, A> = ExtensionFuture<'a, Result<IqReply<A>, HandlerError>>;

/// Every future runs on the connection worker and can be cancelled on shutdown.
/// Handlers authorize `request.target` against `request.sender` themselves.
pub trait IqHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Answers a `get` from one consistent snapshot. The result payload is allocated in
    /// `response`; the effects may address only the target account.
    fn get<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _transaction: &'a S::Read,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }

    /// Answers a `get` to a missing account in place of `get`.
    /// Overrides must answer as `get` does when the account hides the requested data.
    fn get_missing_account(
        &self,
        _request: IqRequest<'_, A>,
        _response: &mut Arena<A>,
    ) -> Result<Option<Element>, HandlerError> {
        Err(StanzaErrorCondition::ServiceUnavailable.into())
    }

    /// Applies a `set` inside the transaction; the reply and the effects follow its commit.
    fn set<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _transaction: &'a mut S::Write,
        _hosts: &'a dyn HostLookup,
        _response: &'a mut Arena<A>,
    ) -> IqFuture<'a, A> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }
}

pub struct IqRegistry<A: ChunkAllocator, S: Storage> {
    handlers: Vec<(IqRoute, Arc<dyn IqHandler<A, S>>)>,
}

impl<A: ChunkAllocator, S: Storage> Default for IqRegistry<A, S> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator, S: Storage> IqRegistry<A, S> {
    pub(crate) fn register(
        &mut self,
        route: IqRoute,
        handler: Arc<dyn IqHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        match self
            .handlers
            .binary_search_by_key(&route, |(entry, _)| *entry)
        {
            Ok(_) => Err(RegistrationError::DuplicateRoute(route)),
            Err(index) => {
                self.handlers.insert(index, (route, handler));
                Ok(())
            }
        }
    }

    pub fn find(
        &self,
        scope: IqScope,
        kind: IqRequestType,
        namespace: &str,
        name: &str,
    ) -> Option<&Arc<dyn IqHandler<A, S>>> {
        let index = self
            .handlers
            .binary_search_by(|(route, _)| {
                (route.scope, route.kind, route.namespace, route.name)
                    .cmp(&(scope, kind, namespace, name))
            })
            .ok()?;
        Some(&self.handlers[index].1)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}
