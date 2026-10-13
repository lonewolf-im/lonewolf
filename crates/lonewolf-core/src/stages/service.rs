// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::delivery::{DeliveryError, DeliveryFuture, HostLookup};
use lonewolf_extension::service::{ServiceContext, ServiceOutbound};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{IqType, MessageType, PresenceType, StanzaErrorCondition, StanzaType};

use super::message::{self, DeliveryOutcome};
use super::{Stage, StageFailure};
use crate::delivery::WorkHandle;
use crate::router::{Destination, RoutedStanza, RouterError, RouterHandle, ServiceRoute};

mod presence;
pub(crate) use presence::{ServicePresenceGate, ServicePresenceGates, ServicePresenceLease};

pub(crate) enum ServiceOutcome<A: ChunkAllocator> {
    Handled,
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
    },
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    route: &ServiceRoute<A>,
    stanza: RoutedStanza<A>,
) -> Result<ServiceOutcome<A>, StageFailure> {
    let outbound = Outbound {
        router: stage.router,
        storage: stage.storage,
        allocator: stage.allocator,
        work: stage.work,
        domain: &route.domain,
    };
    let result = route
        .handler
        .route(
            stanza.clone(),
            ServiceContext {
                domain: &route.domain,
                storage: stage.storage,
                outbound: &outbound,
            },
        )
        .await;
    if let Err(error) = result {
        if let Some(failure) = error.failure() {
            tracing::error!(
                failure_kind = failure.kind.as_str(),
                operation = failure.operation,
                service_domain = %route.domain,
                "internal operation failed"
            );
        }
        let reject = match stanza.resolve()?.stanza_type() {
            StanzaType::Iq(IqType::Get | IqType::Set) => true,
            StanzaType::Message(kind) => kind != MessageType::Error,
            _ => false,
        };
        if reject {
            return Ok(ServiceOutcome::Rejected {
                stanza,
                condition: error.condition(),
            });
        }
    }
    Ok(ServiceOutcome::Handled)
}

struct Outbound<'a, A: ChunkAllocator> {
    router: &'a RouterHandle<A>,
    storage: &'a RedbStorage,
    allocator: &'a A,
    work: &'a WorkHandle,
    domain: &'a str,
}

impl<A: ChunkAllocator + Clone> HostLookup for Outbound<'_, A> {
    fn is_local_host(&self, domain: &str) -> bool {
        self.router.is_local_host(domain)
    }
}

impl<A: ChunkAllocator + Clone + 'static> ServiceOutbound<A> for Outbound<'_, A> {
    fn arena(&self) -> Result<Arena<A>, DeliveryError> {
        Ok(Arena::try_new_in(
            Default::default(),
            self.allocator.clone(),
        )?)
    }

    fn route<'a>(&'a self, stanza: RoutedStanza<A>) -> DeliveryFuture<'a> {
        Box::pin(async move {
            let view = stanza.resolve()?;
            if view
                .from()?
                .is_none_or(|from| from.domainpart() != self.domain)
            {
                tracing::warn!(service_domain = %self.domain, outcome = "invalid_from", "service stanza rejected");
                return Err(DeliveryError);
            }
            let to = view.to()?.ok_or(DeliveryError)?;
            let destination = self.router.destination(to);
            match destination {
                Destination::Account | Destination::Resource => match view.stanza_type() {
                    StanzaType::Message(kind) => {
                        let stage = Stage {
                            router: self.router,
                            storage: self.storage,
                            allocator: self.allocator,
                            work: self.work,
                        };
                        match message::deliver(&stage, stanza, kind).await {
                            Ok(
                                DeliveryOutcome::Routed
                                | DeliveryOutcome::Stored
                                | DeliveryOutcome::Discarded,
                            ) => Ok(()),
                            Ok(DeliveryOutcome::Rejected { .. }) | Err(_) => Err(DeliveryError),
                        }
                    }
                    StanzaType::Presence(kind) => {
                        let delivered = if kind == PresenceType::Error {
                            self.router.route_presence_error(stanza).await
                        } else if destination == Destination::Resource {
                            self.router.route_full(stanza).await
                        } else {
                            self.router.route_presence(stanza).await
                        };
                        match delivered {
                            Ok(()) | Err(RouterError::NotFound | RouterError::Busy) => Ok(()),
                            Err(_) => Err(DeliveryError),
                        }
                    }
                    StanzaType::Iq(_) => {
                        if destination == Destination::Resource {
                            self.router
                                .route_full(stanza)
                                .await
                                .map_err(|_| DeliveryError)
                        } else {
                            Err(DeliveryError)
                        }
                    }
                },
                Destination::Service
                | Destination::Server
                | Destination::ServerResource
                | Destination::Remote => Err(DeliveryError),
            }
        })
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
