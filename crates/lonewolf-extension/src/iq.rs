// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{Element, ElementRef, Stanza, StanzaErrorCondition};

use crate::delivery::{HandlerError, HostLookup};
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

pub struct IqRequest<'a, A: ChunkAllocator> {
    /// The authenticated bound JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    /// An omitted destination resolves to the authenticated account's bare JID.
    pub target: JidRef<'a>,
    pub payload: ElementRef<'a, Arena<A>>,
    /// Whether deliveries addressed to the requesting resource were queued before this
    /// request's view of storage. They are written ahead of the reply, so a get that
    /// would summarize changes must send state that supersedes them instead. Always
    /// false for a set, whose view is fixed only when it commits.
    pub preceded: bool,
}

/// The result payload and the deliveries that follow a handled IQ.
pub struct IqReply<A> {
    pub payload: Option<Element>,
    /// Stanzas the requesting stream writes right after the result, in order. They are
    /// allocated in the response arena and never pass through a mailbox, so their count
    /// is bounded only by the response.
    pub followups: Vec<Stanza>,
    pub effects: Effects<A>,
}

impl<A: ChunkAllocator> IqReply<A> {
    pub fn new(payload: Option<Element>, effects: Effects<A>) -> Self {
        Self {
            payload,
            followups: Vec::new(),
            effects,
        }
    }

    pub fn followed_by(mut self, followups: Vec<Stanza>) -> Self {
        self.followups = followups;
        self
    }
}

pub type IqFuture<'a, A> = ExtensionFuture<'a, Result<IqReply<A>, HandlerError>>;

/// Every future runs on the connection worker and can be cancelled on shutdown.
/// Handlers authorize `request.target` against `request.sender` themselves. The
/// defaults answer `service-unavailable` for extensions without IQ routes.
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

    pub(crate) fn registrations(
        &self,
    ) -> impl Iterator<Item = (IqRoute, Arc<dyn IqHandler<A, S>>)> + '_ {
        self.handlers
            .iter()
            .map(|(route, handler)| (*route, Arc::clone(handler)))
    }
}
