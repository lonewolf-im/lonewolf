// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use crate::account::AccountHandler;
use crate::archive::ArchiveHandler;
use crate::discovery::{DiscoScope, Identity};
use crate::iq::{IqHandler, IqRoute};
use crate::message::MessageHandler;
use crate::observer::{MessageObserver, SessionObserver};
use crate::policy::PolicyHandler;
use crate::presence::{PresenceDecorator, PresenceHandler, PresenceRequestType};
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
        Arc::make_mut(&mut self.registry.discovery).add_service(domain);
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

    pub fn stream_feature(&mut self, feature: &'static str) {
        self.registry.stream_features.push_str(feature);
    }

    pub fn archive(
        &mut self,
        handler: Arc<dyn ArchiveHandler<A, S>>,
    ) -> Result<(), RegistrationError> {
        if self.registry.archive.is_some() {
            return Err(RegistrationError::DuplicateArchiveHandler);
        }
        self.registry.archive = Some(handler);
        Ok(())
    }

    pub fn message_observer(&mut self, handler: Arc<dyn MessageObserver<A, S>>) {
        self.registry
            .message_observers
            .push((self.extension, handler));
    }

    pub fn session_observer(&mut self, handler: Arc<dyn SessionObserver<A, S>>) {
        self.registry
            .session_observers
            .push((self.extension, handler));
    }

    /// Claims the broadcast presence child for this host.
    pub fn presence_decoration(
        &mut self,
        name: &'static str,
        namespace: &'static str,
        handler: Arc<dyn PresenceDecorator<A, S>>,
    ) -> Result<(), RegistrationError> {
        if self.registry.presence_decorations.iter().any(
            |(_, registered_name, registered_namespace, _)| {
                *registered_name == name && *registered_namespace == namespace
            },
        ) {
            return Err(RegistrationError::DuplicatePresenceDecoration { name, namespace });
        }
        self.registry
            .presence_decorations
            .push((self.extension, name, namespace, handler));
        Ok(())
    }

    pub fn policy(&mut self, handler: Arc<dyn PolicyHandler<S>>) {
        self.registry.policies.push((self.extension, handler));
    }

    pub fn disco_feature(&mut self, scope: DiscoScope, feature: &'static str) {
        Arc::make_mut(&mut self.registry.discovery).add_feature(scope, feature);
    }

    pub fn disco_identity(&mut self, scope: DiscoScope, identity: Identity) {
        Arc::make_mut(&mut self.registry.discovery).add_identity(scope, identity);
    }

    /// Adds a handler that runs inside every account deletion transaction on this host.
    pub fn account(&mut self, handler: Arc<dyn AccountHandler<A, S>>) {
        self.registry.accounts.push((self.extension, handler));
    }
}
