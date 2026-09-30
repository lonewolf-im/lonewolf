// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;

pub mod delivery;
pub mod iq;
pub mod presence;
pub mod roster;

pub type ExtensionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

use delivery::{Delivery, DeliveryFuture, HandlerError, HostLookup};
use iq::{IqHandler, IqRegistry, IqRoute};
use presence::{PresenceHandler, PresenceRegistry, PresenceRequestType};

/// What a handler asks the server to do once its view of storage is fixed.
///
/// The server runs the deliveries after the transaction committed, and for each
/// account named in `accounts` in the order the handlers' storage views were fixed, so
/// a client never sees an older change after a newer one.
pub struct Effects<A> {
    /// The accounts whose clients the deliveries address.
    pub accounts: Vec<AccountKey>,
    pub deliver: Deliver<A>,
}

pub type Deliver<A> = Box<dyn for<'d> FnOnce(&'d dyn Delivery<A>) -> DeliveryFuture<'d>>;

impl<A: ChunkAllocator> Effects<A> {
    pub fn new(
        accounts: Vec<AccountKey>,
        deliver: impl for<'d> FnOnce(&'d dyn Delivery<A>) -> DeliveryFuture<'d> + 'static,
    ) -> Self {
        Self {
            accounts,
            deliver: Box::new(deliver),
        }
    }

    pub fn none() -> Self {
        Self::new(Vec::new(), |_| Box::pin(async { Ok(()) }))
    }
}

/// A server feature that hosts enable by name.
/// One instance serves every host that enables it.
///
/// Handlers change state only through the transaction they are given and return the
/// deliveries that follow as [`Effects`]; the server commits, orders, and delivers.
pub trait Extension<A: ChunkAllocator, S: Storage>:
    IqHandler<A, S> + PresenceHandler<A, S>
{
    /// The name hosts use to enable the extension, nonempty and without surrounding whitespace.
    fn name(&self) -> &'static str;

    /// The IQ routes dispatched to this extension's IQ handler.
    fn iq_routes(&self) -> &'static [IqRoute] {
        &[]
    }

    /// The presence kinds dispatched to this extension's presence handler.
    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        &[]
    }

    /// Clears the extension's state for the account inside the deletion's transaction
    /// and returns what to deliver once it commits.
    fn forget_account<'a>(
        &'a self,
        _transaction: &'a mut S::Write,
        _account: &'a AccountKey,
        _hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Effects<A>, HandlerError>> {
        Box::pin(async { Ok(Effects::none()) })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RegistrationError {
    InvalidExtensionName,
    DuplicateExtension(&'static str),
    UnknownExtension(String),
    DuplicateRoute(IqRoute),
    DuplicatePresenceRoute(PresenceRequestType),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExtensionName => {
                formatter.write_str("extension name must be nonempty and trimmed")
            }
            Self::DuplicateExtension(name) => {
                write!(formatter, "extension {name:?} appears more than once")
            }
            Self::UnknownExtension(name) => write!(formatter, "unknown extension {name:?}"),
            Self::DuplicateRoute(route) => write!(formatter, "conflicting IQ route {route:?}"),
            Self::DuplicatePresenceRoute(route) => {
                write!(formatter, "conflicting presence route {route:?}")
            }
        }
    }
}

impl Error for RegistrationError {}

pub struct ExtensionRegistry<A: ChunkAllocator, S: Storage> {
    iq: IqRegistry<A, S>,
    presence: PresenceRegistry<A, S>,
    extensions: Vec<Arc<dyn Extension<A, S>>>,
}

impl<A: ChunkAllocator, S: Storage> Default for ExtensionRegistry<A, S> {
    fn default() -> Self {
        Self {
            iq: IqRegistry::default(),
            presence: PresenceRegistry::default(),
            extensions: Vec::new(),
        }
    }
}

impl<A: ChunkAllocator, S: Storage> ExtensionRegistry<A, S> {
    pub fn iq(&self) -> &IqRegistry<A, S> {
        &self.iq
    }

    pub fn presence(&self) -> &PresenceRegistry<A, S> {
        &self.presence
    }

    /// The enabled extensions, in the order they were enabled.
    pub fn extensions(&self) -> &[Arc<dyn Extension<A, S>>] {
        &self.extensions
    }
}

pub struct Extensions<A: ChunkAllocator, S: Storage> {
    available: BTreeMap<&'static str, ExtensionRegistry<A, S>>,
}

impl<A: ChunkAllocator, S: Storage> Default for Extensions<A, S> {
    fn default() -> Self {
        Self {
            available: BTreeMap::new(),
        }
    }
}

impl<A: ChunkAllocator, S: Storage> Extensions<A, S> {
    pub fn register(
        &mut self,
        extension: Arc<dyn Extension<A, S>>,
    ) -> Result<(), RegistrationError> {
        let name = extension.name();
        if name.is_empty() || name.trim() != name {
            return Err(RegistrationError::InvalidExtensionName);
        }
        if self.available.contains_key(name) {
            return Err(RegistrationError::DuplicateExtension(name));
        }
        let iq_routes = extension.iq_routes();
        let presence_kinds = extension.presence_kinds();
        let mut registry = ExtensionRegistry::default();
        let iq: Arc<dyn IqHandler<A, S>> = extension.clone();
        for route in iq_routes {
            registry.iq.register(*route, Arc::clone(&iq))?;
        }
        let presence: Arc<dyn PresenceHandler<A, S>> = extension.clone();
        for kind in presence_kinds {
            registry.presence.register(*kind, Arc::clone(&presence))?;
        }
        registry.extensions.push(extension);
        self.available.insert(name, registry);
        Ok(())
    }

    /// Handler instances are shared across every host that enables the extension.
    pub fn enable<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<ExtensionRegistry<A, S>, RegistrationError> {
        let mut enabled = ExtensionRegistry::default();
        let mut selected = BTreeSet::new();
        for name in names {
            let (name, handlers) = self
                .available
                .get_key_value(name)
                .ok_or_else(|| RegistrationError::UnknownExtension(name.into()))?;
            if !selected.insert(*name) {
                return Err(RegistrationError::DuplicateExtension(name));
            }
            for (route, handler) in handlers.iq.registrations() {
                enabled.iq.register(route, handler)?;
            }
            for (kind, handler) in handlers.presence.registrations() {
                enabled.presence.register(kind, handler)?;
            }
            enabled
                .extensions
                .extend(handlers.extensions.iter().cloned());
        }
        Ok(enabled)
    }
}

#[cfg(test)]
mod tests;
