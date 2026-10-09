// SPDX-License-Identifier: Apache-2.0

//! Handler interfaces for extensions built into this workspace; they are not a stable API for independent crates.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;

pub mod account;
pub mod delivery;
pub mod iq;
pub mod message;
pub mod offline;
pub mod presence;
pub mod roster;
mod slots;

pub use slots::Slots;

pub type ExtensionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

use account::AccountHandler;
use delivery::{Delivery, DeliveryFuture};
use iq::{IqRegistry, IqRoute};
use message::MessageHandler;
use presence::{PresenceRegistry, PresenceRequestType};

/// Deliveries run after commit, in storage-view order for each account in `accounts`.
pub struct Effects<A> {
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

/// One instance serves every host that enables it.
/// Handlers use only the supplied transaction and return ordered deliveries as [`Effects`].
pub trait Extension<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// The name hosts use to enable the extension, nonempty and without surrounding whitespace.
    fn name(&self) -> &'static str;

    /// Extensions that every host enabling this one must also enable.
    fn depends(&self) -> &'static [&'static str] {
        &[]
    }

    /// Adds this extension's handlers for one host.
    fn register(
        self: Arc<Self>,
        host: &str,
        slots: &mut Slots<'_, A, S>,
    ) -> Result<(), RegistrationError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum RegistrationError {
    InvalidExtensionName,
    DuplicateExtension(&'static str),
    UnknownExtension(String),
    DuplicateRoute(IqRoute),
    DuplicatePresenceRoute(PresenceRequestType),
    DuplicateMessageHandler,
    MissingDependency {
        extension: &'static str,
        dependency: &'static str,
    },
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
            Self::DuplicateMessageHandler => formatter.write_str("conflicting message handlers"),
            Self::MissingDependency {
                extension,
                dependency,
            } => write!(
                formatter,
                "extension {extension:?} requires extension {dependency:?}"
            ),
        }
    }
}

impl Error for RegistrationError {}

pub struct ExtensionRegistry<A: ChunkAllocator, S: Storage> {
    iq: IqRegistry<A, S>,
    presence: PresenceRegistry<A, S>,
    messages: Option<Arc<dyn MessageHandler<A, S>>>,
    #[expect(clippy::type_complexity)]
    accounts: Vec<(&'static str, Arc<dyn AccountHandler<A, S>>)>,
    stream_features: String,
    enabled: Vec<&'static str>,
}

impl<A: ChunkAllocator, S: Storage> Default for ExtensionRegistry<A, S> {
    fn default() -> Self {
        Self {
            iq: IqRegistry::default(),
            presence: PresenceRegistry::default(),
            messages: None,
            accounts: Vec::new(),
            stream_features: String::new(),
            enabled: Vec::new(),
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

    pub fn messages(&self) -> Option<&Arc<dyn MessageHandler<A, S>>> {
        self.messages.as_ref()
    }

    #[expect(clippy::type_complexity)]
    pub fn account_handlers(&self) -> &[(&'static str, Arc<dyn AccountHandler<A, S>>)] {
        &self.accounts
    }

    pub fn enabled(&self) -> &[&'static str] {
        &self.enabled
    }

    pub fn stream_features(&self) -> &str {
        &self.stream_features
    }
}

pub struct Extensions<A: ChunkAllocator, S: Storage> {
    available: BTreeMap<&'static str, Arc<dyn Extension<A, S>>>,
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
        self.available.insert(name, extension);
        Ok(())
    }

    /// Handler instances are shared across every host that enables the extension.
    pub fn enable_host<'a>(
        &self,
        host: &str,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<ExtensionRegistry<A, S>, RegistrationError> {
        let mut selected = Vec::new();
        let mut selected_names = BTreeSet::new();
        for name in names {
            let (name, extension) = self
                .available
                .get_key_value(name)
                .ok_or_else(|| RegistrationError::UnknownExtension(name.into()))?;
            if !selected_names.insert(*name) {
                return Err(RegistrationError::DuplicateExtension(name));
            }
            selected.push(extension);
        }
        for extension in &selected {
            for dependency in extension.depends() {
                if !selected_names.contains(dependency) {
                    return Err(RegistrationError::MissingDependency {
                        extension: extension.name(),
                        dependency,
                    });
                }
            }
        }
        let mut registry = ExtensionRegistry::default();
        for extension in selected {
            Arc::clone(extension)
                .register(host, &mut Slots::new(&mut registry, extension.name()))?;
            registry.enabled.push(extension.name());
        }
        Ok(registry)
    }
}

#[cfg(test)]
mod tests;
