// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::ExtensionFuture;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::service::{ServiceContext, ServiceHandler};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::{RoutedStanza, StanzaErrorCondition, StanzaErrorText};

use super::registry::{ComponentRegistry, EnqueueError, NOT_CONNECTED_TEXT};

pub(crate) fn discovery_parent<'a>(
    domain: &str,
    hosts: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    hosts
        .filter(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_err()
                && domain
                    .strip_suffix(*host)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
        .max_by_key(|host| host.len())
}

pub(crate) struct ComponentService<A: ChunkAllocator> {
    domain: Arc<str>,
    registry: ComponentRegistry<A>,
}

impl<A: ChunkAllocator> ComponentService<A> {
    pub(crate) fn new(domain: Arc<str>, registry: ComponentRegistry<A>) -> Self {
        Self { domain, registry }
    }
}

impl<A: ChunkAllocator + Clone> ServiceHandler<A, RedbStorage> for ComponentService<A> {
    fn route<'a>(
        &'a self,
        stanza: RoutedStanza<A>,
        _context: ServiceContext<'a, A, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        let result = self
            .registry
            .enqueue(&self.domain, stanza)
            .map_err(|error| match error {
                EnqueueError::Busy => {
                    HandlerError::Stanza(StanzaErrorCondition::ResourceConstraint)
                }
                EnqueueError::NotConnected | EnqueueError::Stopped => HandlerError::described(
                    StanzaErrorCondition::RemoteServerTimeout,
                    StanzaErrorText::Static(NOT_CONNECTED_TEXT),
                ),
            });
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
mod tests {
    use super::discovery_parent;

    #[test]
    fn discovery_chooses_the_closest_dns_parent_and_never_an_ip_literal() {
        let hosts = ["localhost", "chat.localhost", "127.0.0.1", "[::1]"];
        for (domain, expected) in [
            ("muc.chat.localhost", Some("chat.localhost")),
            ("muc.localhost", Some("localhost")),
            ("chat.localhost", Some("localhost")),
            ("localhost", None),
            ("muc.notlocalhost", None),
            ("muc.127.0.0.1", None),
            ("remote.example", None),
        ] {
            assert_eq!(discovery_parent(domain, hosts.into_iter()), expected);
        }
    }
}
