// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{Element, ElementRef, StanzaErrorCondition};

use crate::delivery::{Delivery, HandlerError};
use crate::{ExtensionFuture, RegistrationError};

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

pub type IqResult = Result<Option<Element>, HandlerError>;
pub type IqFuture<'a> = ExtensionFuture<'a, IqResult>;

pub trait IqHandler<A: ChunkAllocator>: Send + Sync {
    /// Authorize access to `request.target` using `request.sender`.
    /// Allocate the response payload in `response` and perform side effects
    /// through `delivery` before returning.
    /// The future runs on the connection's worker and can be cancelled on shutdown.
    /// The default answers `service-unavailable` for extensions without IQ routes.
    fn handle<'a>(
        &'a self,
        _request: IqRequest<'a, A>,
        _response: &'a mut Arena<A>,
        _delivery: &'a dyn Delivery<A>,
    ) -> IqFuture<'a> {
        Box::pin(async { Err(StanzaErrorCondition::ServiceUnavailable.into()) })
    }
}

pub struct IqRegistry<A: ChunkAllocator> {
    handlers: Vec<(IqRoute, Arc<dyn IqHandler<A>>)>,
}

impl<A: ChunkAllocator> Default for IqRegistry<A> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator> IqRegistry<A> {
    pub(crate) fn register(
        &mut self,
        route: IqRoute,
        handler: Arc<dyn IqHandler<A>>,
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
    ) -> Option<&dyn IqHandler<A>> {
        let index = self
            .handlers
            .binary_search_by(|(route, _)| {
                (route.scope, route.kind, route.namespace, route.name)
                    .cmp(&(scope, kind, namespace, name))
            })
            .ok()?;
        Some(self.handlers[index].1.as_ref())
    }

    pub(crate) fn registrations(
        &self,
    ) -> impl Iterator<Item = (IqRoute, Arc<dyn IqHandler<A>>)> + '_ {
        self.handlers
            .iter()
            .map(|(route, handler)| (*route, Arc::clone(handler)))
    }
}
