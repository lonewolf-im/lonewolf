// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_util::arena::ChunkAllocator;

pub mod delivery;
pub mod iq;
pub mod order;
pub mod presence;
pub mod roster;

pub type ExtensionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

use iq::{IqHandler, IqRegistry, IqRoute};
use presence::{PresenceHandler, PresenceRegistry, PresenceRequestType};

/// A server feature that hosts enable by name.
/// One instance serves every host that enables it.
pub trait Extension<A: ChunkAllocator>: IqHandler<A> + PresenceHandler<A> {
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

pub struct ExtensionRegistry<A: ChunkAllocator> {
    iq: IqRegistry<A>,
    presence: PresenceRegistry<A>,
}

impl<A: ChunkAllocator> Default for ExtensionRegistry<A> {
    fn default() -> Self {
        Self {
            iq: IqRegistry::default(),
            presence: PresenceRegistry::default(),
        }
    }
}

impl<A: ChunkAllocator> ExtensionRegistry<A> {
    pub fn iq(&self) -> &IqRegistry<A> {
        &self.iq
    }

    pub fn presence(&self) -> &PresenceRegistry<A> {
        &self.presence
    }
}

pub struct Extensions<A: ChunkAllocator> {
    available: BTreeMap<&'static str, ExtensionRegistry<A>>,
}

impl<A: ChunkAllocator> Default for Extensions<A> {
    fn default() -> Self {
        Self {
            available: BTreeMap::new(),
        }
    }
}

impl<A: ChunkAllocator> Extensions<A> {
    pub fn register(&mut self, extension: Arc<dyn Extension<A>>) -> Result<(), RegistrationError> {
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
        let iq: Arc<dyn IqHandler<A>> = extension.clone();
        for route in iq_routes {
            registry.iq.register(*route, Arc::clone(&iq))?;
        }
        let presence: Arc<dyn PresenceHandler<A>> = extension;
        for kind in presence_kinds {
            registry.presence.register(*kind, Arc::clone(&presence))?;
        }
        self.available.insert(name, registry);
        Ok(())
    }

    /// Handler instances are shared across every host that enables the extension.
    pub fn enable<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<ExtensionRegistry<A>, RegistrationError> {
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
        }
        Ok(enabled)
    }
}

#[cfg(test)]
mod tests;
