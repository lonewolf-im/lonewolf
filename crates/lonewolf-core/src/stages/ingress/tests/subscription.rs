// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::Effects;
use lonewolf_extension::delivery::{DeliveryError, HostLookup};
use lonewolf_extension::presence::{
    PresenceHandler, PresenceRequest, PresenceRequestType, ReceiveFuture,
};
use lonewolf_extension::roster::Roster;
use lonewolf_storage::account::{AccountWrites, NewAccount};
use lonewolf_storage::roster::{
    RosterItem, RosterJid, RosterReads, RosterSubscription, RosterWrites, SubscriptionState,
};
use lonewolf_storage::{RedbWrite, WriteTransaction};
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition};

use super::*;
use crate::component::metrics::ComponentMetrics;
use crate::component::{credentials, registry::ComponentRegistry};
use crate::router::ServiceRoute;
use crate::s2s::outbound::test_support::{AdmissionState, Fixture as RemoteFixture};
use crate::stages::ingress::presence::{
    SubscriptionIngress, SubscriptionReceipt, receive_subscription,
};

const DOMAIN: &str = "irc.example.test";
const CONTACTS: [&str; 2] = [DOMAIN, "irc-server.example.test@irc.example.test"];
const OWNER: &str = "bob@example.com";
const RESOURCE: &str = "bob@example.com/desk";

struct SubscriptionFixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    handle: RouterHandle<GlobalChunkAllocator>,
    remote: RemoteFixture,
    registry: ComponentRegistry<GlobalChunkAllocator>,
    metrics: Arc<ComponentMetrics>,
    work: WorkGroup,
    worker: WorkHandle,
}

impl SubscriptionFixture {
    fn new(extension: Arc<dyn Extension<GlobalChunkAllocator, RedbStorage>>) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let remote = RemoteFixture::new(AdmissionState::Link)?;
        let config: Config = toml::from_str(
            "[components.domains.'irc.example.test']\nsecret='component-test-secret-0001'",
        )?;
        let metrics = ComponentMetrics::new(1, 1);
        let registry = ComponentRegistry::new(
            &config.components,
            credentials::load(&config.components)?,
            &config.limits.components,
            Arc::clone(&metrics),
        );
        let mut extensions = Extensions::default();
        let name = extension.name();
        extensions.register(extension)?;
        let router = Router::new(remote.hosts(), LocalRouter::new(GlobalChunkAllocator))
            .with_remote(remote.remote())
            .with_services(BTreeMap::from([(
                DOMAIN.into(),
                ServiceRoute::component(Arc::from(DOMAIN), registry.clone()),
            )]))
            .with_extensions(BTreeMap::from([(
                "example.com".into(),
                extensions.enable_host("example.com", [name])?,
            )]));
        let handle = router.handle();
        let work = WorkGroup::new();
        let worker = work.handle();
        assert!(handle.federates_domain("example.com"));
        assert!(handle.is_component_domain(DOMAIN));
        Ok(Self {
            _directory: directory,
            storage,
            router,
            handle,
            remote,
            registry,
            metrics,
            work,
            worker,
        })
    }

    async fn receive(
        &self,
        contact: &str,
        ingress: SubscriptionIngress,
    ) -> TestResult<SubscriptionReceipt<GlobalChunkAllocator>> {
        let stage = Stage {
            router: &self.handle,
            storage: &self.storage,
            allocator: &GlobalChunkAllocator,
            work: &self.worker,
        };
        receive_subscription(
            &stage,
            presence(PresenceType::Subscribe, contact, Some(RESOURCE))?,
            PresenceRequestType::Subscribe,
            ingress,
        )
        .await
        .map_err(|_| "subscription stage failed".into())
    }

    fn assert_no_admission_rejections(&self) -> TestResult {
        let mut root = prometheus_client::registry::Registry::default();
        self.metrics
            .register(root.sub_registry_with_prefix("lonewolf"));
        let mut samples = String::new();
        prometheus_client::encoding::text::encode(&mut samples, &root)?;
        assert!(
            !samples
                .lines()
                .any(|line| line.starts_with("lonewolf_component_admission_rejections_total{")),
            "{samples}"
        );
        Ok(())
    }

    async fn finish(mut self) -> TestResult {
        assert!(self.remote.receive()?.is_none());
        self.work.drain().await;
        self.remote
            .finish(Instant::now() + Duration::from_secs(5))
            .await?;
        self.router.shutdown().await?;
        Ok(())
    }
}

fn presence(
    kind: PresenceType,
    from: &str,
    to: Option<&str>,
) -> Result<RoutedStanza<GlobalChunkAllocator>, DeliveryError> {
    let mut arena = Arena::try_new(Default::default())?;
    let from = Jid::parse_in(from, &mut arena)?;
    let to = to.map(|to| Jid::parse_in(to, &mut arena)).transpose()?;
    let stanza = Stanza::builder_in(
        StanzaType::Presence(kind),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(to)?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

fn contact_key(contact: &str) -> TestResult<RosterJid> {
    let mut arena = Arena::try_new(Default::default())?;
    let jid = Jid::parse_in(contact, &mut arena)?;
    Ok(RosterJid::from(jid.resolve(&arena)?))
}

fn assert_presence(
    stanza: &RoutedStanza<GlobalChunkAllocator>,
    kind: PresenceType,
    from: &str,
    to: &str,
) -> TestResult {
    let view = stanza.resolve()?;
    assert_eq!(view.stanza_type(), StanzaType::Presence(kind));
    assert_eq!(view.from()?.ok_or("from")?.as_str(), from);
    assert_eq!(view.to()?.ok_or("to")?.as_str(), to);
    Ok(())
}

#[test]
fn federated_subscription_ingress_preserves_roster_rules_on_service_domains() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = SubscriptionFixture::new(Arc::new(Roster::default()))?;
        let owner = account(OWNER)?;
        let mut write = fixture.storage.begin_write().await?;
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
        let grant = RosterSubscription {
            state: SubscriptionState::From,
            ..Default::default()
        };
        for contact in CONTACTS {
            write
                .put_roster_item(
                    &owner,
                    &RosterItem {
                        jid: contact_key(contact)?,
                        name: None,
                        groups: Vec::new(),
                        subscription: grant,
                    },
                    Default::default(),
                )
                .await?;
        }
        write.commit().await?;
        let mut link = fixture.registry.attach(DOMAIN).map_err(|_| "attach")?;
        for (contact, has_localpart) in CONTACTS.into_iter().zip([false, true]) {
            let receipt = fixture
                .receive(contact, SubscriptionIngress::Federated)
                .await?;
            match (has_localpart, receipt) {
                (false, SubscriptionReceipt::Done) => {}
                (
                    true,
                    SubscriptionReceipt::Failed {
                        stanza,
                        committed: true,
                    },
                ) => {
                    assert_presence(&stanza, PresenceType::Subscribe, contact, OWNER)?;
                }
                _ => return Err("unexpected federated subscription receipt".into()),
            }
            assert!(link.try_next().is_none());
            fixture.assert_no_admission_rejections()?;
            assert!(matches!(
                fixture
                    .receive(contact, SubscriptionIngress::Component)
                    .await?,
                SubscriptionReceipt::Done
            ));
            assert_presence(
                &link.try_next().ok_or("component approval")?,
                PresenceType::Subscribed,
                OWNER,
                contact,
            )?;
            assert!(link.try_next().is_none());
            let read = fixture.storage.begin_read().await?;
            assert_eq!(
                read.roster_subscription(&owner, &contact_key(contact)?)
                    .await?,
                Some(grant)
            );
            assert!(read.pending_requests(&owner).await?.is_empty());
        }
        drop(link);
        fixture.finish().await
    })
}

#[derive(Default)]
struct SubscriptionDeliveryProbe(PlMutex<Vec<bool>>);

impl Extension<GlobalChunkAllocator, RedbStorage> for SubscriptionDeliveryProbe {
    fn name(&self) -> &'static str {
        "subscription-delivery-probe"
    }

    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.presence(PresenceRequestType::Subscribe, self)
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for SubscriptionDeliveryProbe {
    fn receive<'a>(
        &'a self,
        request: PresenceRequest<'a, GlobalChunkAllocator>,
        _: &'a mut RedbWrite,
        hosts: &'a dyn HostLookup,
    ) -> ReceiveFuture<'a, GlobalChunkAllocator> {
        Box::pin(async move {
            let owner = AccountKey::try_from(request.target)
                .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            let contact = RosterJid::from(request.sender);
            let component = hosts.is_component_domain(contact.domain());
            assert!(hosts.federates(owner.domain()));
            assert!(hosts.is_local_host(owner.domain()));
            self.0.lock().push(component);
            let reply = presence(
                PresenceType::Subscribed,
                owner.as_str(),
                Some(contact.as_str()),
            )
            .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            Ok(Effects::new(vec![owner.clone()], move |delivery| {
                Box::pin(async move {
                    assert_eq!(delivery.is_component_domain(contact.domain()), component);
                    delivery.current_presence(&owner, contact.as_str()).await?;
                    delivery
                        .unavailable_presence(&owner, contact.as_str())
                        .await?;
                    delivery.to_remote(reply).await
                })
            }))
        })
    }
}

#[test]
fn shared_subscription_effects_use_the_ingress_delivery_scope() -> TestResult {
    Runtime::new()?.block_on(async {
        let probe = Arc::new(SubscriptionDeliveryProbe::default());
        let fixture = SubscriptionFixture::new(probe.clone())?;
        let session = fixture
            .handle
            .register(&account(OWNER)?, Some("desk"), NonZeroUsize::MIN)
            .await?;
        session
            .handle()
            .set_presence(
                Some(0),
                presence(PresenceType::Available, RESOURCE, None)?,
                Some(presence(PresenceType::Unavailable, RESOURCE, None)?),
            )
            .await?;
        let mut link = fixture.registry.attach(DOMAIN).map_err(|_| "attach")?;
        for contact in CONTACTS {
            assert!(matches!(
                fixture
                    .receive(contact, SubscriptionIngress::Federated)
                    .await?,
                SubscriptionReceipt::Failed {
                    committed: true,
                    ..
                }
            ));
            assert!(link.try_next().is_none());
            fixture.assert_no_admission_rejections()?;
            assert!(matches!(
                fixture
                    .receive(contact, SubscriptionIngress::Component)
                    .await?,
                SubscriptionReceipt::Done
            ));
            for (kind, from) in [
                (PresenceType::Available, RESOURCE),
                (PresenceType::Unavailable, RESOURCE),
                (PresenceType::Subscribed, OWNER),
            ] {
                assert_presence(
                    &link.try_next().ok_or("component delivery")?,
                    kind,
                    from,
                    contact,
                )?;
            }
            assert!(link.try_next().is_none());
        }
        assert_eq!(*probe.0.lock(), [false, true, false, true]);
        drop((session, link));
        fixture.finish().await
    })
}
