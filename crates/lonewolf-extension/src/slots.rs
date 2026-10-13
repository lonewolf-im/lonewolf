// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use crate::account::AccountHandler;
use crate::iq::{IqHandler, IqRoute};
use crate::message::MessageHandler;
use crate::presence::{PresenceHandler, PresenceRequestType};
use crate::service::ServiceHandler;
use crate::{ExtensionRegistry, RegistrationError};

pub struct Slots<'r, A: ChunkAllocator, S: Storage> {
    registry: &'r mut ExtensionRegistry<A, S>,
    extension: &'static str,
}

impl<'r, A: ChunkAllocator, S: Storage> Slots<'r, A, S> {
    pub(crate) fn new(registry: &'r mut ExtensionRegistry<A, S>, extension: &'static str) -> Self {
        Self {
            registry,
            extension,
        }
    }

    pub fn iq(
        &mut self,
        route: IqRoute,
        handler: Arc<dyn IqHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        self.registry.iq.register(route, handler)
    }

    pub fn presence(
        &mut self,
        kind: PresenceRequestType,
        handler: Arc<dyn PresenceHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        self.registry.presence.register(kind, handler)
    }

    /// Registers every stanza addressed to the normalized domain or a JID under it.
    pub fn service(
        &mut self,
        domain: &str,
        handler: Arc<dyn ServiceHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        let invalid = || RegistrationError::InvalidServiceDomain(domain.into());
        let mut arena = Arena::try_new(ArenaConfig::default()).map_err(|_| invalid())?;
        let jid = Jid::from_parts_in(None, domain, None, &mut arena).map_err(|_| invalid())?;
        if jid.resolve(&arena).map_err(|_| invalid())?.domainpart() != domain {
            return Err(invalid());
        }
        if self
            .registry
            .services
            .iter()
            .any(|(registered, _)| registered == domain)
        {
            return Err(RegistrationError::DuplicateService(domain.into()));
        }
        self.registry.services.push((domain.into(), handler));
        Ok(())
    }

    /// Registers the host's only offline fallback.
    pub fn offline(
        &mut self,
        handler: Arc<dyn MessageHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        if self.registry.messages.is_some() {
            return Err(RegistrationError::DuplicateMessageHandler);
        }
        self.registry.messages = Some(handler);
        Ok(())
    }

    /// Appends an XML element advertised to authenticated clients.
    pub fn stream_feature(&mut self, feature: &'static str) {
        self.registry.stream_features.push_str(feature);
    }

    /// Adds a handler that runs inside every account deletion transaction on this host.
    pub fn account(&mut self, handler: Arc<dyn AccountHandler<A, S>>) {
        self.registry.accounts.push((self.extension, handler));
    }
}
