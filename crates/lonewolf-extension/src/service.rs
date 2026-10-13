// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::Storage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::RoutedStanza;

use crate::ExtensionFuture;
use crate::delivery::{DeliveryError, DeliveryFuture, HandlerError, HostLookup};

pub struct ServiceContext<'a, A: ChunkAllocator, S: Storage> {
    pub domain: &'a str,
    pub storage: &'a S,
    pub outbound: &'a dyn ServiceOutbound<A>,
}

pub trait ServiceOutbound<A: ChunkAllocator>: HostLookup {
    fn arena(&self) -> Result<Arena<A>, DeliveryError>;

    /// Requires a sender in the service domain and a local account or resource destination.
    /// Messages follow client delivery rules, including offline storage.
    fn route<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a>;
}

pub trait ServiceHandler<A: ChunkAllocator, S: Storage>: Send + Sync {
    /// Receives an authenticated sender and must not block the calling worker.
    /// Errors answer IQ requests and messages other than errors.
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<A>,
        context: ServiceContext<'a, A, S>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>>;
}
