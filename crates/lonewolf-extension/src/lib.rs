// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use lonewolf_util::arena::ChunkAllocator;

pub mod iq;

use iq::{IqRegistration, IqRegistry, RegistrationError};

pub struct Extensions<A: ChunkAllocator> {
    available: BTreeMap<&'static str, IqRegistry<A>>,
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
        handlers: impl IntoIterator<Item = IqRegistration<A>>,
    ) -> Result<(), RegistrationError> {
        if name.is_empty() || name.trim() != name {
            return Err(RegistrationError::InvalidExtensionName);
        }
        if self.available.contains_key(name) {
            return Err(RegistrationError::DuplicateExtension(name));
        }
        let mut registry = IqRegistry::default();
        for handler in handlers {
            registry.register(handler)?;
        }
        self.available.insert(name, registry);
        Ok(())
    }

    /// Handler instances are shared across hosts; requests identify the target host.
    pub fn enable<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Result<IqRegistry<A>, RegistrationError> {
        let mut enabled = IqRegistry::default();
        let mut selected = BTreeSet::new();
        for name in names {
            let (name, handlers) = self
                .available
                .get_key_value(name)
                .ok_or_else(|| RegistrationError::UnknownExtension(name.into()))?;
            if !selected.insert(*name) {
                return Err(RegistrationError::DuplicateExtension(name));
            }
            for handler in handlers.registrations() {
                enabled.register(handler.clone())?;
            }
        }
        Ok(enabled)
    }
}

#[cfg(test)]
mod tests;
