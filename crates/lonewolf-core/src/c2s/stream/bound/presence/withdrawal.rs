// SPDX-License-Identifier: Apache-2.0

use futures_channel::oneshot;
use futures_util::future::Shared;
use lonewolf_extension::presence::{PresenceRequestType, PresenceTransition, PresenceUpdate};
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbRead, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{PresenceType, StanzaType};

use super::super::{CloseOutcome, close_storage_failure};
use super::{PresenceContext, ResourcePresence};
use crate::delivery::report_handler_failure;
use crate::order::Ticket;
use crate::router::local::DirectedWithdrawal;
use crate::router::{RoutedStanza, SessionHandle};
use crate::stages::{Stage, policy, service};

impl<A: ChunkAllocator + Clone> PresenceContext<A> {
    pub(in super::super) async fn end(
        self,
        presence: ResourcePresence,
        fallback: RoutedStanza<A>,
    ) -> Result<(), CloseOutcome> {
        let stage = self.stage();
        let account = self.session.account();
        let withdrawal = self
            .session
            .end_presence()
            .await
            .map_err(|_| CloseOutcome::InternalError)?;
        let notice = withdrawal.unavailable.as_ref().unwrap_or(&fallback);
        let mut subscribers = None;
        let mut ticket = None;
        let mut snapshot = None;
        let explicit = self.router.has_explicit_policy();
        let needs_directed_policy = explicit && !withdrawal.directed.recipients.is_empty();
        let prepared = if withdrawal.unavailable.is_some() || needs_directed_policy {
            async {
                let handler = withdrawal.unavailable.as_ref().and_then(|_| {
                    self.router
                        .presence_handlers(account.domain())
                        .and_then(|handlers| handlers.find(PresenceRequestType::Unavailable))
                });
                let (transaction, admitted) = self
                    .router
                    .order()
                    .fix(vec![account.clone()], async {
                        if handler.is_some() || needs_directed_policy {
                            self.storage.begin_read().await.map(Some).map_err(|error| {
                                close_storage_failure(
                                    error,
                                    "presence_terminal_begin_read",
                                    account,
                                )
                            })
                        } else {
                            Ok(None)
                        }
                    })
                    .await?;
                ticket = Some(admitted);
                snapshot = transaction;
                let mut audience = match (handler, snapshot.as_ref()) {
                    (Some(handler), Some(transaction)) => {
                        let view = notice.resolve()?;
                        let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                        handler
                            .audience(
                                PresenceUpdate {
                                    sender,
                                    transition: PresenceTransition::Unavailable,
                                },
                                transaction,
                            )
                            .await
                            .map_err(|error| {
                                report_handler_failure(&error, account);
                                CloseOutcome::InternalError
                            })?
                    }
                    _ => None,
                };
                if let (Some(audience), Some(transaction)) = (audience.as_mut(), snapshot.as_ref())
                {
                    let view = notice.resolve()?;
                    let sender = view.from()?.ok_or(CloseOutcome::InternalError)?;
                    policy::filter_audience(
                        &self.router,
                        transaction,
                        &self.allocator,
                        account,
                        sender,
                        StanzaType::Presence(PresenceType::Unavailable),
                        audience,
                    )
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?;
                }
                subscribers = audience.map(|audience| audience.subscribers);
                Ok(())
            }
            .await
        } else {
            Ok(())
        };
        let delivered = WithdrawalDelivery {
            notice,
            directed: &withdrawal.directed,
            snapshot: snapshot.as_ref(),
        }
        .deliver(
            &stage,
            ticket,
            subscribers,
            Some(SessionEnd {
                session: &self.session,
                pending: presence.service_pending,
                directed_allowed: !needs_directed_policy || snapshot.is_some(),
            }),
        )
        .await;
        drop(presence.service_lease);
        prepared.and(delivered)
    }
}

pub(super) struct WithdrawalDelivery<'a, A: ChunkAllocator> {
    pub(super) notice: &'a RoutedStanza<A>,
    pub(super) directed: &'a DirectedWithdrawal,
    pub(super) snapshot: Option<&'a RedbRead>,
}

pub(super) struct SessionEnd<'a, A: ChunkAllocator> {
    session: &'a SessionHandle<A>,
    pending: Option<Shared<oneshot::Receiver<()>>>,
    directed_allowed: bool,
}

impl<A: ChunkAllocator + Clone> WithdrawalDelivery<'_, A> {
    pub(super) async fn deliver(
        &self,
        stage: &Stage<'_, A>,
        mut ticket: Option<Ticket>,
        subscribers: Option<Vec<RosterJid>>,
        end: Option<SessionEnd<'_, A>>,
    ) -> Result<(), CloseOutcome> {
        if let Some(ticket) = ticket.as_mut() {
            ticket.turn().await;
        }
        let mut covered = Vec::new();
        let mut terminal_broadcast = false;
        let broadcast = async {
            if let Some(subscribers) = subscribers {
                if let Some(end) = &end
                    && end.session.replacement_is_available().await?
                {
                    covered = subscribers;
                    return Ok(());
                }
                stage
                    .router
                    .broadcast_presence(self.notice, &subscribers, self.snapshot, None)
                    .await?;
                covered = subscribers;
                if end.is_some() {
                    terminal_broadcast = true;
                } else {
                    stage
                        .router
                        .broadcast_component_presence(self.notice, &covered, None)?;
                }
            }
            Ok(())
        }
        .await
        .map_err(|_: crate::router::RouterError| CloseOutcome::InternalError);
        let directed_allowed = end.as_ref().is_none_or(|end| end.directed_allowed);
        let local = if directed_allowed {
            self.send_directed(stage, &covered).await
        } else {
            Ok(())
        };
        let finished = if let Some(end) = &end {
            end.session
                .finish_presence(self.directed.source_token)
                .await
                .map_err(|_| CloseOutcome::InternalError)
        } else {
            Ok(())
        };
        // A service can store a message for this account during withdrawal.
        drop(ticket);
        if let Some(pending) = end.and_then(|end| end.pending) {
            let _ = pending.await;
        }
        let components = if terminal_broadcast {
            stage
                .router
                .broadcast_component_presence(self.notice, &covered, None)
                .map_err(|_| CloseOutcome::InternalError)
        } else {
            Ok(())
        };
        let services = if directed_allowed {
            self.send_services(stage, &covered).await
        } else {
            Ok(())
        };
        broadcast
            .and(local)
            .and(finished)
            .and(components)
            .and(services)
    }
    fn recipients<'a>(&'a self, covered: &'a [RosterJid]) -> impl Iterator<Item = &'a str> {
        self.directed
            .recipients
            .iter()
            .map(|recipient| recipient.as_str())
            .filter(|recipient| {
                !covered
                    .iter()
                    .any(|subscriber| subscriber.as_str() == *recipient)
            })
    }

    async fn send_directed(
        &self,
        stage: &Stage<'_, A>,
        covered: &[RosterJid],
    ) -> Result<(), CloseOutcome> {
        stage
            .router
            .send_directed(
                self.notice,
                self.recipients(covered)
                    .filter(|recipient| stage.router.service(domain_of(recipient)).is_none()),
                self.snapshot,
            )
            .await
            .map_err(|_| CloseOutcome::InternalError)
    }

    async fn send_services(
        &self,
        stage: &Stage<'_, A>,
        covered: &[RosterJid],
    ) -> Result<(), CloseOutcome> {
        for recipient in self.recipients(covered) {
            if let Some(route) = stage.router.service(domain_of(recipient)) {
                let mut arena = Arena::try_new_in(Default::default(), stage.allocator.clone())?;
                let target = Jid::parse_in(recipient, &mut arena)?;
                let stanza = self
                    .notice
                    .resolve()?
                    .to_builder_in(&mut arena)?
                    .to(Some(target))?
                    .build()?;
                let stanza = RoutedStanza::from_parts(stanza, arena);
                if stage
                    .router
                    .presence_allowed(self.snapshot, &stanza)
                    .await
                    .map_err(|_| CloseOutcome::InternalError)?
                {
                    service::dispatch(stage, route, stanza).await?;
                }
            }
        }
        Ok(())
    }
}

fn domain_of(jid: &str) -> &str {
    let bare = jid.split_once('/').map_or(jid, |(bare, _)| bare);
    bare.split_once('@').map_or(bare, |(_, domain)| domain)
}

#[cfg(test)]
mod tests {
    use super::domain_of;

    #[test]
    fn domain_lookup_ignores_at_signs_in_resourceparts() {
        for (jid, domain) in [
            ("echo.localhost", "echo.localhost"),
            ("echo.localhost/nick@other", "echo.localhost"),
            ("room@echo.localhost/nick@other", "echo.localhost"),
        ] {
            assert_eq!(domain_of(jid), domain);
        }
    }
}
