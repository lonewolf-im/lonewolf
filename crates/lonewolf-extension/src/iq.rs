// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{Element, ElementRef, StanzaErrorCondition};

pub use crate::RegistrationError;
use crate::roster::{RosterOrder, RosterPush};

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
    pub kind: IqRequestType,
    pub payload: ElementRef<'a, Arena<A>>,
}

#[derive(Default)]
pub enum IqEffect {
    #[default]
    None,
    MarkRosterInterested(RosterOrder),
    PushRoster(RosterPush),
}

pub struct IqResponse {
    payload: Option<Element>,
    effect: IqEffect,
}

impl IqResponse {
    pub fn new(payload: Option<Element>) -> Self {
        Self {
            payload,
            effect: IqEffect::None,
        }
    }

    pub fn with_effect(mut self, effect: IqEffect) -> Self {
        self.effect = effect;
        self
    }

    pub fn into_parts(self) -> (Option<Element>, IqEffect) {
        (self.payload, self.effect)
    }
}

pub type IqResult = Result<IqResponse, StanzaErrorCondition>;
pub type IqFuture<'a> = Pin<Box<dyn Future<Output = IqResult> + 'a>>;

pub trait IqHandler<A: ChunkAllocator>: Send + Sync {
    /// Authorize access to `request.target` using `request.sender`.
    /// Allocate response payloads in `response`.
    /// The future runs on the connection's worker and can be cancelled on shutdown.
    fn handle<'a>(&'a self, request: IqRequest<'a, A>, response: &'a mut Arena<A>) -> IqFuture<'a>;
}

pub struct IqRegistration<A: ChunkAllocator> {
    route: IqRoute,
    handler: Arc<dyn IqHandler<A>>,
}

impl<A: ChunkAllocator> IqRegistration<A> {
    pub fn new(route: IqRoute, handler: Arc<dyn IqHandler<A>>) -> Self {
        Self { route, handler }
    }
}

impl<A: ChunkAllocator> Clone for IqRegistration<A> {
    fn clone(&self) -> Self {
        Self {
            route: self.route,
            handler: Arc::clone(&self.handler),
        }
    }
}

pub struct IqRegistry<A: ChunkAllocator> {
    handlers: Vec<IqRegistration<A>>,
}

impl<A: ChunkAllocator> Default for IqRegistry<A> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator> IqRegistry<A> {
    pub fn register(&mut self, handler: IqRegistration<A>) -> Result<(), RegistrationError> {
        match self
            .handlers
            .binary_search_by_key(&handler.route, |entry| entry.route)
        {
            Ok(_) => Err(RegistrationError::DuplicateRoute(handler.route)),
            Err(index) => {
                self.handlers.insert(index, handler);
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
    ) -> Option<&dyn IqHandler<A>> {
        let index = self
            .handlers
            .binary_search_by(|entry| {
                let route = entry.route;
                (route.scope, route.kind, route.namespace, route.name)
                    .cmp(&(scope, kind, namespace, name))
            })
            .ok()?;
        Some(self.handlers[index].handler.as_ref())
    }

    pub(crate) fn registrations(&self) -> &[IqRegistration<A>] {
        &self.handlers
    }
}
