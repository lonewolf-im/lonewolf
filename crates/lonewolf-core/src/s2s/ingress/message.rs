// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::observer::{MessageEvent, MessageOutcome, MessageRole};
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::stanza::MessageType;

use super::{InboundPeer, IngressContext, IngressFailure, reply_error};
use crate::delivery::RouterDelivery;
use crate::router::{Destination, RoutedStanza};
use crate::stages::message::{self, DeliveryOutcome};
use crate::stages::{Stage, archive, observe, policy};

pub(crate) async fn handle<A: ChunkAllocator + Clone + 'static>(
    context: &IngressContext<A>,
    _peer: &InboundPeer,
    routed: RoutedStanza<A>,
    kind: MessageType,
) -> Result<(), IngressFailure> {
    let stage = Stage {
        router: &context.router,
        storage: &context.storage,
        allocator: &context.allocator,
        work: &context.work,
    };
    let view = routed.resolve().map_err(|_| IngressFailure)?;
    let to = view
        .to()
        .map_err(|_| IngressFailure)?
        .ok_or(IngressFailure)?;
    let destination = context.router.destination(to);
    let mut received = None;
    let mut recipient = None;
    let mut observers = false;
    let routed = match destination {
        Destination::Account | Destination::Resource => {
            observers = !context.router.message_observers(to.domainpart()).is_empty();
            let archive_needed = context.router.archive_handler(to.domainpart()).is_some();
            let policies = !context.router.policies(to.domainpart()).is_empty();
            if observers || archive_needed || policies {
                recipient = Some(AccountKey::try_from(to.bare()).map_err(|_| IngressFailure)?);
            }
            if policies {
                let checks = [policy::Check {
                    account: recipient.as_ref().ok_or(IngressFailure)?,
                    direction: Direction::Inbound,
                    peer: view
                        .from()
                        .map_err(|_| IngressFailure)?
                        .ok_or(IngressFailure)?,
                }];
                match policy::evaluate(&stage, view.stanza_type(), &checks).await? {
                    Verdict::Allow => {}
                    Verdict::Drop => return Ok(()),
                    Verdict::Reject {
                        condition,
                        application,
                        text,
                    } => {
                        return reply_error(
                            context,
                            &routed,
                            condition,
                            application,
                            text.unwrap_or_else(|| condition.default_text()),
                        );
                    }
                }
            }
            if archive_needed {
                match archive::archive(&stage, routed, None, recipient.as_ref()).await? {
                    archive::ArchiveStep::Accepted(archived) => {
                        received = archived.received;
                        archived.stanza
                    }
                    archive::ArchiveStep::Rejected {
                        stanza,
                        condition,
                        text,
                    } => {
                        return reply_error(context, &stanza, condition, None, text);
                    }
                }
            } else {
                routed
            }
        }
        Destination::Server | Destination::ServerResource => routed,
        Destination::Service | Destination::Remote => return Err(IngressFailure),
    };
    let observed = observers.then(|| routed.clone());
    let outcome = message::deliver(&stage, routed, kind).await?;
    if let (
        Some(observed),
        Some(recipient),
        DeliveryOutcome::Routed { admitted } | DeliveryOutcome::Stored { admitted },
    ) = (observed.as_ref(), recipient.as_ref(), &outcome)
    {
        let delivery = RouterDelivery::new(&context.router, &context.allocator, None);
        observe::message(
            &stage,
            &delivery,
            MessageEvent {
                account: recipient,
                role: MessageRole::Received,
                stanza: observed,
                outcome: MessageOutcome::from(&outcome),
                holders: admitted.as_slice(),
                archived: received,
                rejection: None,
            },
        )
        .await;
    }
    if let DeliveryOutcome::Rejected {
        stanza,
        condition,
        text,
    } = outcome
    {
        reply_error(context, &stanza, condition, None, text)?;
    }
    Ok(())
}
