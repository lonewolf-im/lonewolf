// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;

use lonewolf_extension::delivery::{DeliveryError, DeliveryFuture, HostLookup};
use lonewolf_extension::policy::Verdict;
use lonewolf_extension::service::{ServiceContext, ServiceOutbound};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{IqType, MessageType, PresenceType, StanzaErrorCondition, StanzaType};

use super::ingress::{
    Origin,
    checks::{self, Snapshot},
    message::{self, MessageDisposition},
};
use super::{Stage, StageFailure};
use crate::component::registry::ComponentRegistry;
use crate::delivery::WorkHandle;
use crate::router::{Destination, RoutedStanza, RouterError, RouterHandle, ServiceRoute};

mod presence;
pub(crate) use presence::{ServicePresenceGate, ServicePresenceGates, ServicePresenceLease};

pub(crate) enum ServiceOutcome<A: ChunkAllocator> {
    Handled,
    Rejected {
        stanza: RoutedStanza<A>,
        condition: StanzaErrorCondition,
        text: lonewolf_xmpp::stanza::StanzaErrorText,
    },
}

pub(crate) async fn dispatch<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    route: &ServiceRoute<A>,
    stanza: RoutedStanza<A>,
) -> Result<ServiceOutcome<A>, StageFailure> {
    dispatch_with_component_reply(stage, route, stanza, None).await
}

pub(crate) struct ComponentReplyTarget<'a, A: ChunkAllocator> {
    pub(crate) registry: &'a ComponentRegistry<A>,
    pub(crate) domain: &'a str,
    pub(crate) connection_id: u64,
}

pub(crate) async fn dispatch_with_component_reply<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    route: &ServiceRoute<A>,
    stanza: RoutedStanza<A>,
    target: Option<ComponentReplyTarget<'_, A>>,
) -> Result<ServiceOutcome<A>, StageFailure> {
    let outbound = Outbound {
        router: stage.router,
        storage: stage.storage,
        allocator: stage.allocator,
        work: stage.work,
        domain: &route.domain,
        component_reply: target.map(|target| ComponentReply {
            target,
            request: &stanza,
            claimed: Cell::new(false),
        }),
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
        if outbound
            .component_reply
            .as_ref()
            .is_some_and(|reply| reply.claimed.get())
        {
            return Ok(ServiceOutcome::Handled);
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
                text: error.text(),
            });
        }
    }
    Ok(ServiceOutcome::Handled)
}

struct ComponentReply<'a, A: ChunkAllocator> {
    target: ComponentReplyTarget<'a, A>,
    request: &'a RoutedStanza<A>,
    claimed: Cell<bool>,
}

impl<A: ChunkAllocator> ComponentReply<'_, A> {
    fn claim(&self, from: JidRef<'_>, to: JidRef<'_>, id: &str) -> Result<(), DeliveryError> {
        if self.claimed.get() || to.domainpart() != self.target.domain {
            return Err(DeliveryError);
        }
        let request = self.request.resolve()?;
        if !matches!(
            request.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        ) || request.id()? != Some(id)
            || request.to()? != Some(from)
            || request.from()? != Some(to)
        {
            return Err(DeliveryError);
        }
        self.claimed.set(true);
        Ok(())
    }
}

struct Outbound<'a, A: ChunkAllocator> {
    router: &'a RouterHandle<A>,
    storage: &'a RedbStorage,
    allocator: &'a A,
    work: &'a WorkHandle,
    domain: &'a str,
    component_reply: Option<ComponentReply<'a, A>>,
}

impl<A: ChunkAllocator + Clone> HostLookup for Outbound<'_, A> {
    fn is_local_host(&self, domain: &str) -> bool {
        self.router.is_local_host(domain)
    }

    fn federates(&self, local_domain: &str) -> bool {
        self.router.federates_domain(local_domain)
    }

    fn is_component_domain(&self, domain: &str) -> bool {
        self.router.is_component_domain(domain)
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
            let Some(from) = view.from()?.filter(|from| from.domainpart() == self.domain) else {
                tracing::warn!(service_domain = %self.domain, outcome = "invalid_from", "service stanza rejected");
                return Err(DeliveryError);
            };
            let to = view.to()?.ok_or(DeliveryError)?;
            let destination = self.router.destination(to);
            if matches!(destination, Destination::Account | Destination::Resource)
                && !matches!(view.stanza_type(), StanzaType::Message(_))
                && !self.router.policies(to.domainpart()).is_empty()
            {
                let origin = Origin::Service {
                    domain: self.domain,
                };
                let parties = checks::parties(self.router, &origin, to, view.kind())
                    .map_err(|_| DeliveryError)?;
                let stage = Stage {
                    router: self.router,
                    storage: self.storage,
                    allocator: self.allocator,
                    work: self.work,
                };
                match checks::check(&stage, &origin, &view, &parties, Snapshot::Fresh)
                    .await
                    .map_err(|_| DeliveryError)?
                {
                    Verdict::Allow => {}
                    Verdict::Drop => return Ok(()),
                    Verdict::Reject { .. } => return Err(DeliveryError),
                }
            }
            match destination {
                Destination::Account | Destination::Resource => match view.stanza_type() {
                    StanzaType::Message(kind) => {
                        let stage = Stage {
                            router: self.router,
                            storage: self.storage,
                            allocator: self.allocator,
                            work: self.work,
                        };
                        let origin = Origin::Service {
                            domain: self.domain,
                        };
                        match message::handle(&stage, &origin, stanza, kind)
                            .await
                            .map_err(|_| DeliveryError)?
                        {
                            MessageDisposition::Done => Ok(()),
                            MessageDisposition::Reply(_) => Err(DeliveryError),
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
                Destination::Remote => self.router.route_remote(stanza).map_err(|_| DeliveryError),
                Destination::Service => {
                    let reply = self.component_reply.as_ref().ok_or(DeliveryError)?;
                    if !matches!(
                        view.stanza_type(),
                        StanzaType::Iq(IqType::Result | IqType::Error)
                    ) {
                        return Err(DeliveryError);
                    }
                    reply.claim(from, to, view.id()?.ok_or(DeliveryError)?)?;
                    let target = &reply.target;
                    let _ = target
                        .registry
                        .reply(target.domain, target.connection_id, stanza);
                    Ok(())
                }
                Destination::Server | Destination::ServerResource => Err(DeliveryError),
            }
        })
    }
}

#[cfg(test)]
mod tests;
