// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use lonewolf_util::arena::ChunkAllocator;

pub mod iq;
pub mod presence;
pub mod roster;

use iq::{IqRegistration, IqRegistry, IqRoute};
use presence::PresenceRoute;
use presence::{PresenceRegistration, PresenceRegistry};

#[derive(Debug, Eq, PartialEq)]
pub enum RegistrationError {
    InvalidExtensionName,
    DuplicateExtension(&'static str),
    UnknownExtension(String),
    DuplicateRoute(IqRoute),
    DuplicatePresenceRoute(PresenceRoute),
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
    pub fn register(
        &mut self,
        name: &'static str,
        iq_handlers: impl IntoIterator<Item = IqRegistration<A>>,
        presence_handlers: impl IntoIterator<Item = PresenceRegistration<A>>,
    ) -> Result<(), RegistrationError> {
        if name.is_empty() || name.trim() != name {
            return Err(RegistrationError::InvalidExtensionName);
        }
        if self.available.contains_key(name) {
            return Err(RegistrationError::DuplicateExtension(name));
        }
        let mut registry = ExtensionRegistry::default();
        for handler in iq_handlers {
            registry.iq.register(handler)?;
        }
        for handler in presence_handlers {
            registry.presence.register(handler)?;
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
            for handler in handlers.iq.registrations() {
                enabled.iq.register(handler.clone())?;
            }
            for handler in handlers.presence.registrations() {
                enabled.presence.register(handler.clone())?;
            }
        }
        Ok(enabled)
    }
}

#[cfg(test)]
mod tests;
