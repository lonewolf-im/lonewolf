// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{Element, ElementRef, Stanza, StanzaErrorCondition};

use crate::delivery::{Failure, HandlerError, HostLookup, SessionLookup, TagChange};
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
pub struct IqRequestKey {
    pub kind: IqRequestType,
    pub namespace: &'static str,
    pub name: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IqDestinationRule {
    /// Allows an omitted target or an exact match for the authenticated sender's bare JID.
    SenderBare,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmlSpace {
    Default,
    Preserve,
    Invalid,
}

impl XmlSpace {
    pub fn from_attribute(value: &str) -> Self {
        match value {
            "default" => Self::Default,
            "preserve" => Self::Preserve,
            _ => Self::Invalid,
        }
    }
}

pub struct IqRequest<'a, A: ChunkAllocator> {
    /// The authenticated bound JID, independent of the client's `from` attribute.
    pub sender: JidRef<'a>,
    /// An omitted destination resolves to the authenticated account's bare JID.
    pub target: JidRef<'a>,
    pub discovery: &'a Discovery,
    /// Live routing state, which can change after the transaction's snapshot was taken.
    pub sessions: &'a dyn SessionLookup,
    /// Set for account `get` requests; server targets and `set` requests use `None`.
    pub requester: Option<Requester>,
    /// The enclosing IQ language can be empty to reset inherited language.
    pub lang: Option<&'a str>,
    /// The enclosing IQ space directive is independent of payload attributes.
    pub space: Option<XmlSpace>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IqErrorPayload {
    Include,
    Omit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IqError {
    error: HandlerError,
    payload: IqErrorPayload,
}

impl IqError {
    pub const fn without_payload(error: HandlerError) -> Self {
        Self {
            error,
            payload: IqErrorPayload::Omit,
        }
    }

    pub const fn handler_error(&self) -> &HandlerError {
        &self.error
    }

    pub const fn payload(&self) -> IqErrorPayload {
        self.payload
    }

    pub const fn condition(&self) -> StanzaErrorCondition {
        self.error.condition()
    }

    pub const fn failure(&self) -> Option<Failure> {
        self.error.failure()
    }
}

impl From<HandlerError> for IqError {
    fn from(error: HandlerError) -> Self {
        Self {
            error,
            payload: IqErrorPayload::Include,
        }
    }
}

impl From<StanzaErrorCondition> for IqError {
    fn from(condition: StanzaErrorCondition) -> Self {
        HandlerError::from(condition).into()
    }
}

pub type IqFuture<'a, A> = ExtensionFuture<'a, Result<IqReply<A>, IqError>>;

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

    /// Overrides must answer as `get` does when the account hides the requested data.
    fn get_missing_account(
        &self,
        _request: IqRequest<'_, A>,
        _response: &mut Arena<A>,
    ) -> Result<Option<Element>, IqError> {
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

pub struct SessionIqReply {
    pub payload: Option<Element>,
    /// Applied to the requesting session before the reply.
    pub change: Option<TagChange>,
}

/// Answers an account `set` that changes only the requesting session's routing state.
pub trait SessionIqHandler<A: ChunkAllocator>: Send + Sync {
    /// Runs without storage and must not block; handlers authorize `request.target` themselves.
    fn set(
        &self,
        request: IqRequest<'_, A>,
        response: &mut Arena<A>,
    ) -> Result<SessionIqReply, IqError>;
}

type SessionHandler<A> = ((&'static str, &'static str), Arc<dyn SessionIqHandler<A>>);

pub struct IqRegistry<A: ChunkAllocator, S: Storage> {
    handlers: Vec<(IqRoute, Arc<dyn IqHandler<A, S>>)>,
    destinations: Vec<(IqRequestKey, IqDestinationRule)>,
    sessions: Vec<SessionHandler<A>>,
}

impl<A: ChunkAllocator, S: Storage> Default for IqRegistry<A, S> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
            destinations: Vec::new(),
            sessions: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator, S: Storage> IqRegistry<A, S> {
    pub(crate) fn register(
        &mut self,
        route: IqRoute,
        handler: Arc<dyn IqHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        if route.scope == IqScope::Account
            && route.kind == IqRequestType::Set
            && self.find_session(route.namespace, route.name).is_some()
        {
            return Err(RegistrationError::DuplicateRoute(route));
        }
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

    pub(crate) fn register_session(
        &mut self,
        namespace: &'static str,
        name: &'static str,
        handler: Arc<dyn SessionIqHandler<A>>,
    ) -> Result<(), RegistrationError> {
        let route = IqRoute {
            scope: IqScope::Account,
            kind: IqRequestType::Set,
            namespace,
            name,
        };
        if self
            .find(route.scope, route.kind, namespace, name)
            .is_some()
        {
            return Err(RegistrationError::DuplicateRoute(route));
        }
        match self
            .sessions
            .binary_search_by_key(&(namespace, name), |(key, _)| *key)
        {
            Ok(_) => Err(RegistrationError::DuplicateRoute(route)),
            Err(index) => {
                self.sessions.insert(index, ((namespace, name), handler));
                Ok(())
            }
        }
    }

    pub fn find_session(
        &self,
        namespace: &str,
        name: &str,
    ) -> Option<&Arc<dyn SessionIqHandler<A>>> {
        let index = self
            .sessions
            .binary_search_by(|(key, _)| key.cmp(&(namespace, name)))
            .ok()?;
        Some(&self.sessions[index].1)
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

    pub(crate) fn register_destination(
        &mut self,
        key: IqRequestKey,
        rule: IqDestinationRule,
    ) -> Result<(), RegistrationError> {
        match self
            .destinations
            .binary_search_by_key(&key, |(entry, _)| *entry)
        {
            Ok(_) => Err(RegistrationError::DuplicateIqDestinationRule(key)),
            Err(index) => {
                self.destinations.insert(index, (key, rule));
                Ok(())
            }
        }
    }

    pub fn destination_rule(
        &self,
        kind: IqRequestType,
        namespace: &str,
        name: &str,
    ) -> Option<IqDestinationRule> {
        let index = self
            .destinations
            .binary_search_by(|(key, _)| {
                (key.kind, key.namespace, key.name).cmp(&(kind, namespace, name))
            })
            .ok()?;
        Some(self.destinations[index].1)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.handlers.is_empty() && self.destinations.is_empty() && self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{IqError, IqErrorPayload, XmlSpace};
    use crate::delivery::{Failure, FailureKind, HandlerError};
    use lonewolf_xmpp::stanza::StanzaErrorCondition;

    #[test]
    fn iq_error_payload_policy_preserves_condition_and_failure() {
        let condition = StanzaErrorCondition::ResourceConstraint;
        let failure = Failure {
            kind: FailureKind::Delivery,
            operation: "iq_test",
        };
        for error in [
            HandlerError::Stanza(condition),
            HandlerError::Internal { condition, failure },
        ] {
            for (iq_error, payload) in [
                (IqError::from(error), IqErrorPayload::Include),
                (IqError::without_payload(error), IqErrorPayload::Omit),
            ] {
                assert_eq!(iq_error.handler_error(), &error);
                assert_eq!(iq_error.condition(), error.condition());
                assert_eq!(iq_error.failure(), error.failure());
                assert_eq!(iq_error.payload(), payload);
            }
        }
        let converted = IqError::from(condition);
        assert_eq!(converted.payload(), IqErrorPayload::Include);
        assert_eq!(converted.condition(), condition);
        assert_eq!(converted.failure(), None);
    }

    #[test]
    fn xml_space_matches_only_exact_directives() {
        for (value, expected) in [
            ("default", XmlSpace::Default),
            ("preserve", XmlSpace::Preserve),
            ("", XmlSpace::Invalid),
            ("unknown", XmlSpace::Invalid),
            ("Default", XmlSpace::Invalid),
            ("PRESERVE", XmlSpace::Invalid),
            (" preserve ", XmlSpace::Invalid),
            ("default\npreserve", XmlSpace::Invalid),
        ] {
            assert_eq!(XmlSpace::from_attribute(value), expected, "{value:?}");
        }
    }
}
