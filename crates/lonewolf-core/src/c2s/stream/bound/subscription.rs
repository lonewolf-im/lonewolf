// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::Effects;
use lonewolf_extension::delivery::HandlerError;
use lonewolf_extension::policy::{Direction, Verdict};
use lonewolf_extension::presence::{
    PresenceHandler, PresenceRequest, PresenceRequestType, PresenceSend,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage, RedbWrite, Storage};
use lonewolf_util::arena::ChunkAllocator;
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{Stanza, StanzaErrorCondition};

use super::{
    BoundSession, CloseOutcome, Outbox, OutboxWriter, close_storage_failure,
    explicit_presence_policy, presence_addresses, subscription_target,
};
use crate::delivery::{
    EffectsDiagnostics, EffectsError, EffectsIdentity, Pending, RouterDelivery, WorkGroup,
    commit_and_deliver, report_handler_failure,
};
use crate::router::{
    Destination, MailboxEntry, Registration, RoutedStanza, RouterError, RouterHandle,
};
use crate::stages::{ingress, policy};

enum Preparation<A: ChunkAllocator> {
    Done,
    OutboundBlocked,
    Rejected(HandlerError),
    Commit(Pending<Result<Vec<MailboxEntry<A>>, EffectsError>>),
}

impl<A: ChunkAllocator> Preparation<A> {
    fn denied(verdict: Verdict) -> Option<Self> {
        match verdict {
            Verdict::Allow => None,
            Verdict::OutboundBlocked => Some(Self::OutboundBlocked),
            Verdict::Drop | Verdict::Reject { .. } => Some(Self::Done),
        }
    }
}

struct Target {
    remote: bool,
    component: bool,
    federated: bool,
}

struct SubscriptionPolicy {
    local_recipient: bool,
    outbound: bool,
    inbound: bool,
    explicit: bool,
}

impl SubscriptionPolicy {
    fn for_target<A: ChunkAllocator + Clone>(
        router: &RouterHandle<A>,
        account: &AccountKey,
        target: JidRef<'_>,
    ) -> Self {
        let other = target.as_str() != account.as_str();
        let local_recipient = other && router.destination(target) == Destination::Account;
        let configured =
            |selection: policy::Selection, domain| selection.configured(router, domain);
        Self {
            local_recipient,
            outbound: other && configured(policy::Selection::Standard, account.domain()),
            inbound: local_recipient
                && configured(policy::Selection::Standard, target.domainpart()),
            explicit: other
                && (configured(policy::Selection::Explicit, account.domain())
                    || local_recipient
                        && configured(policy::Selection::Explicit, target.domainpart())),
        }
    }
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> BoundSession<'_, A, W> {
    pub(super) async fn handle_subscription(
        &mut self,
        parsed: Parsed<Stanza, A>,
        kind: PresenceRequestType,
    ) -> Result<(), CloseOutcome> {
        let target = self.subscription_target(&parsed)?;
        let (source, routed) = self.stamp_subscription(parsed)?;
        if !self.admit_routed(&source)? {
            return Ok(());
        }
        let (_, recipient) = presence_addresses(&routed)?;
        let subscription = Subscription {
            registration: &self.registration,
            router: &self.router,
            storage: &self.storage,
            policy: SubscriptionPolicy::for_target(
                &self.router,
                self.registration.account(),
                recipient,
            ),
            kind,
            source: &source,
            routed,
            target,
        };
        let result = subscription
            .process(&mut self.outbox, &self.allocator)
            .await?;
        self.finish_subscription(&source, result).await
    }

    fn subscription_target(&self, parsed: &Parsed<Stanza, A>) -> Result<Target, CloseOutcome> {
        let stanza = parsed.value().resolve(parsed.arena())?;
        let target = stanza.to()?.ok_or(CloseOutcome::InternalError)?;
        let remote = self.router.destination(target) == Destination::Remote;
        Ok(Target {
            remote,
            component: self.router.is_component_domain(target.domainpart()),
            federated: remote
                && self
                    .router
                    .federates_domain(self.registration.account().domain()),
        })
    }

    fn stamp_subscription(
        &self,
        parsed: Parsed<Stanza, A>,
    ) -> Result<(RoutedStanza<A>, RoutedStanza<A>), CloseOutcome> {
        let (source, mut arena) = parsed.into_parts();
        let (source, sender, _) = self.stamp_in(source, &mut arena, false)?;
        let routed = source
            .derive_in(&mut arena)?
            .from(Some(sender.bare()))?
            .bare_to()
            .build()?;
        Ok(RoutedStanza::from_parts_pair(source, routed, arena))
    }

    async fn finish_subscription(
        &mut self,
        source: &RoutedStanza<A>,
        prepared: Preparation<A>,
    ) -> Result<(), CloseOutcome> {
        match prepared {
            Preparation::Done => Ok(()),
            Preparation::OutboundBlocked => self.reply_outbound_blocked(source),
            Preparation::Rejected(error) => {
                self.reply_rejection_with_text(source, error.condition(), None, error.text())
            }
            Preparation::Commit(mut committed) => {
                self.outbox
                    .drain_until(&self.registration, committed.turned())
                    .await?;
                let queued = committed
                    .finished()
                    .await
                    .ok_or(CloseOutcome::InternalError)?
                    .map_err(|_| CloseOutcome::InternalError)?;
                self.outbox.delivered(queued);
                Ok(())
            }
        }
    }
}

struct SubscriptionWrite<A: ChunkAllocator> {
    transaction: RedbWrite,
    snapshot: Option<RedbRead>,
    delivery: RouterDelivery<A>,
}

struct Subscription<'a, A: ChunkAllocator> {
    registration: &'a Registration<A>,
    router: &'a RouterHandle<A>,
    storage: &'a RedbStorage,
    kind: PresenceRequestType,
    source: &'a RoutedStanza<A>,
    routed: RoutedStanza<A>,
    target: Target,
    policy: SubscriptionPolicy,
}

impl<A: ChunkAllocator + Clone> Subscription<'_, A> {
    async fn process<W: OutboxWriter<A>>(
        self,
        outbox: &mut Outbox<'_, A, W>,
        allocator: &A,
    ) -> Result<Preparation<A>, CloseOutcome> {
        let sender = self
            .router
            .presence_handlers(self.registration.account().domain())
            .and_then(|handlers| handlers.find(self.kind));
        if sender.is_none() && !self.target.remote && !self.policy.explicit {
            return Ok(Preparation::Done);
        }
        let snapshot = self.standard_snapshot(outbox).await?;
        if let Some(denied) = self.check_outbound(outbox, snapshot.as_ref()).await? {
            return Ok(denied);
        }
        let Some(handler) = sender else {
            drop(snapshot);
            return outbox
                .drain_until(self.registration, self.without_handler())
                .await?;
        };
        if let Err(error) = outbox
            .drain_until(
                self.registration,
                self.authorize(handler, request(self.source, self.kind)?),
            )
            .await?
        {
            return Ok(Preparation::Rejected(error));
        }
        let delivery = RouterDelivery::new(self.router, allocator, Some(self.registration));
        outbox
            .drain_until(
                self.registration,
                self.prepare(handler, snapshot, delivery, outbox.work),
            )
            .await?
    }

    async fn standard_snapshot<W: OutboxWriter<A>>(
        &self,
        outbox: &mut Outbox<'_, A, W>,
    ) -> Result<Option<RedbRead>, CloseOutcome> {
        if self.policy.outbound || self.policy.inbound {
            return Ok(Some(
                outbox
                    .drain_until(
                        self.registration,
                        self.read_policy("presence_subscription_begin_read"),
                    )
                    .await??,
            ));
        }
        Ok(None)
    }

    async fn read_policy(&self, operation: &'static str) -> Result<RedbRead, CloseOutcome> {
        self.storage
            .begin_read()
            .await
            .map_err(|error| close_storage_failure(error, operation, self.registration.account()))
    }

    async fn check_outbound<W: OutboxWriter<A>>(
        &self,
        outbox: &mut Outbox<'_, A, W>,
        snapshot: Option<&RedbRead>,
    ) -> Result<Option<Preparation<A>>, CloseOutcome> {
        let Some(snapshot) = snapshot.filter(|_| self.policy.outbound) else {
            return Ok(None);
        };
        let (_, peer) = presence_addresses(&self.routed)?;
        let checks = [policy::Check {
            account: self.registration.account(),
            direction: Direction::Outbound,
            peer,
        }];
        let verdict = outbox
            .drain_until(
                self.registration,
                policy::evaluate_selected_in(
                    self.router,
                    snapshot,
                    self.routed.resolve()?.stanza_type(),
                    &checks,
                    policy::Selection::Standard,
                ),
            )
            .await??;
        Ok(Preparation::denied(verdict))
    }

    async fn authorize(
        &self,
        handler: &dyn PresenceHandler<A, RedbStorage>,
        request: PresenceRequest<'_, A>,
    ) -> Result<(), HandlerError> {
        let result = handler.authorize(request).await;
        if let Err(error) = &result {
            report_handler_failure(error, self.registration.account());
        }
        result
    }

    async fn without_handler(self) -> Result<Preparation<A>, CloseOutcome> {
        let (verdict, _admission) =
            explicit_presence_policy(self.router, self.storage, self.registration, self.source)
                .await?;
        if let Some(denied) = Preparation::denied(verdict) {
            return Ok(denied);
        }
        if self.target.remote && self.registration.liveness().is_alive() {
            return route_remote(self.router, self.routed, self.target.federated);
        }
        Ok(Preparation::Done)
    }

    async fn prepare(
        &self,
        handler: &dyn PresenceHandler<A, RedbStorage>,
        standard: Option<RedbRead>,
        delivery: RouterDelivery<A>,
        work: &WorkGroup,
    ) -> Result<Preparation<A>, CloseOutcome> {
        let bare = request(&self.routed, self.kind)?;
        let transaction = self.storage.begin_write().await.map_err(|error| {
            close_storage_failure(
                error,
                "presence_subscription_begin_write",
                self.registration.account(),
            )
        })?;
        let explicit = if self.policy.explicit {
            let snapshot = self
                .read_policy("presence_subscription_policy_begin_read")
                .await?;
            if let Some(denied) = self.check_explicit(&snapshot, bare.target).await? {
                return Ok(denied);
            }
            Some(snapshot)
        } else {
            None
        };
        if !self.registration.liveness().is_alive() {
            return Ok(Preparation::Done);
        }
        let mut write = SubscriptionWrite {
            transaction,
            snapshot: explicit,
            delivery,
        };
        let sent = handler
            .send(
                request(self.source, self.kind)?,
                &mut write.transaction,
                &write.delivery,
            )
            .await;
        let effects = match sent {
            Ok(PresenceSend::Continue) => return self.forward(bare, standard, write, work).await,
            Ok(PresenceSend::Handled(effects)) => Ok(effects),
            Err(error) => Err(error),
        };
        drop(standard);
        self.commit(write, effects, work).await
    }

    async fn forward(
        &self,
        bare: PresenceRequest<'_, A>,
        standard: Option<RedbRead>,
        mut write: SubscriptionWrite<A>,
        work: &WorkGroup,
    ) -> Result<Preparation<A>, CloseOutcome> {
        let allowed = self.inbound_allowed(standard.as_ref(), &bare).await?;
        drop(standard);
        if !allowed || !self.registration.liveness().is_alive() {
            return Ok(Preparation::Done);
        }
        if self.target.component {
            drop(write.transaction);
            self.router
                .route_to_component_or_bounce(self.routed.clone())
                .await
                .map_err(|_| CloseOutcome::InternalError)?;
            return Ok(Preparation::Done);
        }
        if self.target.remote {
            return route_remote(self.router, self.routed.clone(), self.target.federated);
        }
        if self.missing_resource(&write.transaction).await? {
            return Ok(Preparation::Done);
        }
        let effects = self
            .receive(bare, &mut write.transaction, &write.delivery)
            .await;
        self.commit(write, effects, work).await
    }

    async fn check_explicit(
        &self,
        snapshot: &RedbRead,
        target: JidRef<'_>,
    ) -> Result<Option<Preparation<A>>, CloseOutcome> {
        let recipient = self
            .policy
            .local_recipient
            .then(|| AccountKey::try_from(target))
            .transpose()?;
        let verdict = ingress::checks::check_selected(
            (self.router, self.storage),
            Some(self.registration.account()),
            recipient.as_ref(),
            &self.source.resolve()?,
            None,
            ingress::checks::Snapshot::Ordered(snapshot),
            policy::Selection::Explicit,
        )
        .await?;
        Ok(Preparation::denied(verdict))
    }

    async fn inbound_allowed(
        &self,
        snapshot: Option<&RedbRead>,
        bare: &PresenceRequest<'_, A>,
    ) -> Result<bool, CloseOutcome> {
        let Some(snapshot) = snapshot.filter(|_| self.policy.inbound) else {
            return Ok(true);
        };
        let recipient = AccountKey::try_from(bare.target)?;
        let checks = [policy::Check {
            account: &recipient,
            direction: Direction::Inbound,
            peer: bare.sender,
        }];
        Ok(policy::evaluate_selected_in(
            self.router,
            snapshot,
            self.routed.resolve()?.stanza_type(),
            &checks,
            policy::Selection::Standard,
        )
        .await?
            == Verdict::Allow)
    }

    async fn missing_resource(&self, transaction: &RedbWrite) -> Result<bool, CloseOutcome> {
        let (_, target) = presence_addresses(self.source)?;
        Ok(self.kind != PresenceRequestType::Subscribe
            && self.router.is_local_host(target.domainpart())
            && target.resourcepart().is_some()
            && subscription_target(self.router, transaction, target)
                .await?
                .is_none())
    }

    async fn receive(
        &self,
        bare: PresenceRequest<'_, A>,
        transaction: &mut RedbWrite,
        delivery: &RouterDelivery<A>,
    ) -> Result<Effects<A>, HandlerError> {
        let handler = self
            .router
            .presence_handlers(bare.target.domainpart())
            .and_then(|handlers| handlers.find(self.kind))
            .ok_or(HandlerError::Stanza(
                StanzaErrorCondition::ServiceUnavailable,
            ))?;
        handler.receive(bare, transaction, delivery).await
    }

    async fn commit(
        &self,
        mut write: SubscriptionWrite<A>,
        effects: Result<Effects<A>, HandlerError>,
        work: &WorkGroup,
    ) -> Result<Preparation<A>, CloseOutcome> {
        if !self.registration.liveness().is_alive() {
            return Ok(Preparation::Done);
        }
        let effects = match effects {
            Ok(effects) => effects,
            Err(error) => {
                drop(write.transaction);
                report_handler_failure(&error, self.registration.account());
                return Ok(Preparation::Rejected(error));
            }
        };
        if write.snapshot.is_none()
            && self
                .router
                .presence_effects_need_snapshot(&effects.accounts)
        {
            write.snapshot = Some(
                self.read_policy("presence_subscription_policy_begin_read")
                    .await?,
            );
            if !self.registration.liveness().is_alive() {
                return Ok(Preparation::Done);
            }
        }
        Ok(Preparation::Commit(commit_and_deliver(
            work.start(),
            Arc::clone(self.router.order()),
            write.transaction,
            effects,
            write
                .delivery
                .with_presence_snapshot(write.snapshot.map(Arc::new)),
            Some(self.registration.mailbox()),
            EffectsDiagnostics {
                identity: EffectsIdentity::Account(self.registration.account().clone()),
                commit_operation: "presence_subscription_commit",
                delivery_operation: "presence_subscription_effects",
            },
        )))
    }
}

fn request<A: ChunkAllocator>(
    stanza: &RoutedStanza<A>,
    kind: PresenceRequestType,
) -> Result<PresenceRequest<'_, A>, CloseOutcome> {
    let (sender, target) = presence_addresses(stanza)?;
    Ok(PresenceRequest {
        kind,
        sender,
        target,
        stanza,
    })
}

fn route_remote<A: ChunkAllocator + Clone>(
    router: &RouterHandle<A>,
    stanza: RoutedStanza<A>,
    federated: bool,
) -> Result<Preparation<A>, CloseOutcome> {
    if !federated {
        return Ok(Preparation::Rejected(
            StanzaErrorCondition::RemoteServerNotFound.into(),
        ));
    }
    let condition = match router.route_remote(stanza) {
        Ok(()) => return Ok(Preparation::Done),
        Err(RouterError::Busy) => StanzaErrorCondition::ResourceConstraint,
        Err(RouterError::RemoteNotFound | RouterError::RemoteUnsupported) => {
            StanzaErrorCondition::RemoteServerNotFound
        }
        Err(RouterError::RemoteTimeout) => StanzaErrorCondition::RemoteServerTimeout,
        Err(_) => return Err(CloseOutcome::InternalError),
    };
    Ok(Preparation::Rejected(condition.into()))
}
