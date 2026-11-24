// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::blocking::{Blocking, NAME};
use lonewolf_extension::presence::{PresenceFuture, PresenceHandler, PresenceRequestType};
use lonewolf_extension::{Extension, Extensions, RegistrationError, Slots};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::blocking::{BlockChange, BlockingWrites};
use lonewolf_storage::roster::RosterJid;
use lonewolf_storage::{RedbRead, RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, GlobalChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{
    PresenceType, RoutedStanza, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
    error_element_in,
};

use super::super::{Context, dispatch};
use crate::Config;
use crate::component::metrics::ComponentMetrics;
use crate::component::registry::ComponentRegistry;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::{Router, local::LocalRouter};

struct FailingPresenceFilter(AtomicUsize);

impl Extension<GlobalChunkAllocator, RedbStorage> for FailingPresenceFilter {
    fn name(&self) -> &'static str {
        "failing-presence-filter"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.presence(PresenceRequestType::Available, self)
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for FailingPresenceFilter {
    fn accepts_presence<'a>(
        &'a self,
        owner: &'a AccountKey,
        contact: JidRef<'a>,
        _: &'a RedbRead,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            assert_eq!(owner.as_str(), "bob@localhost");
            assert_eq!(contact.as_str(), "room@muc.localhost");
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(StanzaErrorCondition::InternalServerError.into())
        })
    }
}

#[test]
fn component_roster_filter_failure_is_silent_and_is_not_a_subscription_denial()
-> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        const DOMAIN: &str = "muc.localhost";
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let config = Config::default();
        let components =
            toml::from_str("[domains.'muc.localhost']\nsecret='component-test-secret-0001'")?;
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(
            &components,
            crate::component::credentials::load(&components)?,
            &config.limits.components,
            Arc::clone(&metrics),
        );
        let mut attachment = registry.attach(DOMAIN).map_err(|_| "attachment")?;
        let filter = Arc::new(FailingPresenceFilter(AtomicUsize::new(0)));
        let mut extensions = Extensions::default();
        extensions.register(filter.clone())?;
        let router = Router::new(
            Hosts::new(&config.hosts, None)?,
            LocalRouter::new(GlobalChunkAllocator),
        )
        .with_extensions(BTreeMap::from([(
            "localhost".into(),
            extensions.enable_host("localhost", [filter.name()])?,
        )]));
        let mut work = WorkGroup::new();
        let context = Context {
            router: router.handle(),
            storage,
            allocator: GlobalChunkAllocator,
            work: work.handle(),
            registry,
            connection_id: attachment.id(),
        };
        let mut arena = Arena::try_new(Default::default())?;
        let from = Jid::parse_in("room@muc.localhost/guest", &mut arena)?;
        let bare = Jid::parse_in("bob@localhost", &mut arena)?;
        let full = Jid::parse_in("bob@localhost/desk", &mut arena)?;
        let owner = AccountKey::try_from(bare.resolve(&arena)?)?;
        let desk = context
            .router
            .register(&owner, Some("desk"), NonZeroUsize::MIN)
            .await?;
        let kind = StanzaType::Presence(PresenceType::Available);
        let available = Stanza::builder_in(kind, StanzaNamespace::Client, &mut arena)
            .from(Some(full))?
            .build()?;
        let rejected = Stanza::builder_in(kind, StanzaNamespace::ComponentAccept, &mut arena)
            .from(Some(from))?
            .to(Some(bare))?
            .build()?;
        let direct = Stanza::builder_in(kind, StanzaNamespace::ComponentAccept, &mut arena)
            .from(Some(from))?
            .to(Some(full))?
            .build()?;
        let [available, rejected, direct] =
            RoutedStanza::from_parts_shared(vec![available, rejected, direct], arena)
                .try_into()
                .map_err(|_| "stanza count")?;
        desk.handle().set_presence(Some(0), available, None).await?;
        dispatch(&context, DOMAIN, rejected)
            .await
            .map_err(|_| "bare presence dispatch")?;
        assert!(desk.take_queued().is_empty());
        assert!(attachment.try_next().is_none());
        assert_eq!(filter.0.load(Ordering::Relaxed), 1);

        dispatch(&context, DOMAIN, direct)
            .await
            .map_err(|_| "full presence dispatch")?;
        let queued = desk.take_queued();
        assert_eq!(queued.len(), 1);
        let delivered = queued[0].stanza.resolve()?;
        assert_eq!(
            delivered.from()?.ok_or("from")?.as_str(),
            "room@muc.localhost/guest"
        );
        assert_eq!(delivered.to()?.ok_or("to")?.as_str(), "bob@localhost/desk");
        assert_eq!(filter.0.load(Ordering::Relaxed), 1);

        let mut root = prometheus_client::registry::Registry::default();
        metrics.register(&mut root);
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &root)?;
        let denial_sample = "component_dropped_stanzas_total{reason=\"presence_not_subscribed\"}";
        assert!(!output.lines().any(|line| line.starts_with(denial_sample)));
        drop(desk);
        drop(attachment);
        work.drain().await;
        router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn component_presence_errors_follow_the_recipient_host_policy() -> Result<(), Box<dyn Error>> {
    Runtime::new()?.block_on(async {
        const DOMAIN: &str = "muc.localhost";
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let config = Config::default();
        let registry = ComponentRegistry::new(
            &config.components,
            crate::component::credentials::load(&config.components)?,
            &config.limits.components,
            ComponentMetrics::new(1, 1),
        );
        let mut arena = Arena::try_new(Default::default())?;
        let target = Jid::parse_in("bob@localhost/phone", &mut arena)?;
        let peer = Jid::parse_in("room@muc.localhost/guest", &mut arena)?;
        let owner = AccountKey::try_from(target.resolve(&arena)?.bare())?;
        let mut write = storage.begin_write().await?;
        write
            .create_account(NewAccount {
                key: owner.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [1; 16],
                    SCRAM_POLICY_ITERATIONS,
                    [2; 20],
                    [3; 20],
                ))),
            })
            .await?;
        write
            .change_blocklist(
                &owner,
                BlockChange::Block(&[RosterJid::from(peer.resolve(&arena)?)]),
            )
            .await?;
        write.commit().await?;
        let namespace = StanzaNamespace::ComponentAccept;
        let kind = StanzaType::Presence(PresenceType::Error);
        let condition = StanzaErrorCondition::ServiceUnavailable;
        let error = error_element_in(
            namespace,
            condition,
            None,
            condition.default_text(),
            &mut arena,
        )?;
        let stanza = Stanza::builder_in(kind, namespace, &mut arena)
            .from(Some(peer))?
            .to(Some(target))?
            .child(error)?
            .build()?;
        let stanza = RoutedStanza::from_parts(stanza, arena);
        for names in [&[NAME][..], &[][..]] {
            let mut extensions = Extensions::default();
            extensions.register(Arc::new(Blocking))?;
            let router = Router::new(
                Hosts::new(&config.hosts, None)?,
                LocalRouter::new(GlobalChunkAllocator),
            )
            .with_extensions(BTreeMap::from([(
                "localhost".into(),
                extensions.enable_host("localhost", names.iter().copied())?,
            )]));
            let mut work = WorkGroup::new();
            let context = Context {
                router: router.handle(),
                storage: storage.clone(),
                allocator: GlobalChunkAllocator,
                work: work.handle(),
                registry: registry.clone(),
                connection_id: 1,
            };
            let phone = context
                .router
                .register(&owner, Some("phone"), NonZeroUsize::MIN)
                .await?;
            dispatch(&context, DOMAIN, stanza.clone())
                .await
                .map_err(|_| "component dispatch")?;
            let delivered = phone.take_queued();
            assert_eq!(delivered.len(), usize::from(names.is_empty()));
            if let Some(entry) = delivered.first() {
                assert_eq!(entry.stanza.resolve()?.stanza_type(), kind);
            }
            drop(phone);
            work.drain().await;
            router.shutdown().await?;
        }
        Ok(())
    })
}
