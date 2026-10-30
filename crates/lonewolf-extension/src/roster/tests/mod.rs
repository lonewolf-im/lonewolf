// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::roster::RosterQuota;

mod options;
mod state;

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use futures_executor::block_on;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterJid, RosterReads, RosterSnapshot,
    RosterSubscription, RosterVersion, RosterWrites, SubscriptionState,
};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    Element, PresenceType, RoutedStanza, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use super::{NAMESPACE, Roster};
use crate::account::AccountHandler;
use crate::delivery::{
    BoundResource, Delivery, DeliveryError, DeliveryFuture, HandlerError, HostLookup,
    SessionLookup, SessionTag, StanzaFactory,
};
use crate::discovery::Discovery;
use crate::iq::{IqHandler, IqReply, IqRequest, IqRequestType, Requester};
use crate::presence::{
    PresenceAudience, PresenceHandler, PresenceRequest, PresenceRequestType, PresenceSend,
    PresenceTransition, PresenceUpdate,
};
use crate::{Effects, ExtensionFuture, Extensions};

type TestIqHandler = dyn IqHandler<GlobalChunkAllocator, RedbStorage>;
type TestPresenceHandler = dyn PresenceHandler<GlobalChunkAllocator, RedbStorage>;
type TestAccountHandler = dyn AccountHandler<GlobalChunkAllocator, RedbStorage>;

struct NoSessions;

impl SessionLookup for NoSessions {
    fn resources<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct TestRoster {
    storage: RedbStorage,
}

#[derive(Default)]
struct RecordingDelivery {
    federated: bool,
    remote: RefCell<Vec<String>>,
    events: RefCell<Vec<&'static str>>,
    tags: RefCell<Vec<SessionTag>>,
    retired: RefCell<Vec<AccountKey>>,
    retirement_unavailable: RefCell<Vec<usize>>,
    pushes: RefCell<Vec<String>>,
    controls: RefCell<Vec<String>>,
    unavailable: Cell<usize>,
    current: Cell<usize>,
    failing_deliveries: Cell<usize>,
}

impl HostLookup for RecordingDelivery {
    fn is_local_host(&self, domain: &str) -> bool {
        domain == "example.com" || domain == "other.example"
    }

    fn federates(&self, local_domain: &str) -> bool {
        self.federated && local_domain == "example.com"
    }
}

impl Delivery<GlobalChunkAllocator> for RecordingDelivery {
    fn to_remote<'a>(&'a self, stanza: RoutedStanza<GlobalChunkAllocator>) -> DeliveryFuture<'a> {
        self.events.borrow_mut().push("remote");
        let result = (|| {
            let mut xml = String::new();
            stanza
                .resolve()?
                .write_xml(&mut xml)
                .map_err(|_| DeliveryError)?;
            self.remote.borrow_mut().push(xml);
            Ok(())
        })();
        Box::pin(async move { result })
    }
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Arena::try_new(ArenaConfig::default()).map_err(|_| DeliveryError)
    }

    fn tag_session<'a>(&'a self, tag: SessionTag) -> DeliveryFuture<'a> {
        self.tags.borrow_mut().push(tag);
        Box::pin(async { Ok(()) })
    }

    fn to_available<'a>(&'a self, _: RoutedStanza<GlobalChunkAllocator>) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn to_tagged<'a>(
        &'a self,
        _: SessionTag,
        stanza: RoutedStanza<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        let remaining = self.failing_deliveries.get();
        if remaining > 0 {
            self.failing_deliveries.set(remaining - 1);
            return Box::pin(async { Err(DeliveryError) });
        }
        let mut xml = String::new();
        stanza
            .resolve()
            .and_then(|stanza| {
                stanza
                    .write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write control"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        self.controls.borrow_mut().push(xml);
        Box::pin(async { Ok(()) })
    }

    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        _: SessionTag,
        build: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        self.events.borrow_mut().push("push");
        let result = self.record_push(&format!("{}/desk", account.as_str()), build);
        Box::pin(async { result })
    }

    fn retire_tagged<'a>(&'a self, account: &'a AccountKey, _: SessionTag) -> DeliveryFuture<'a> {
        self.retired.borrow_mut().push(account.clone());
        self.retirement_unavailable
            .borrow_mut()
            .push(self.unavailable.get());
        Box::pin(async { Ok(()) })
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        self.events.borrow_mut().push("current");
        self.current.set(self.current.get() + 1);
        Box::pin(async { Ok(()) })
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        self.events.borrow_mut().push("unavailable");
        self.unavailable.set(self.unavailable.get() + 1);
        Box::pin(async { Ok(()) })
    }
}

impl RecordingDelivery {
    fn record_push(
        &self,
        to: &str,
        mut build: StanzaFactory<GlobalChunkAllocator>,
    ) -> Result<(), DeliveryError> {
        let mut arena =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let to = Jid::parse_in(to, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let push = build(to, &mut arena)?;
        let mut xml = String::new();
        push.resolve(&arena)
            .and_then(|push| {
                push.write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write push"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        self.pushes.borrow_mut().push(xml);
        Ok(())
    }
}

fn roster() -> (tempfile::TempDir, TestRoster) {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))
        .unwrap_or_else(|error| panic!("{error}"));
    (directory, TestRoster { storage })
}

fn snapshot(roster: &TestRoster, owner: &AccountKey) -> RosterSnapshot {
    block_on(async {
        let transaction = roster.storage.begin_read().await?;
        transaction.roster(owner, RosterQuota::default()).await
    })
    .unwrap_or_else(|error: RosterError| panic!("{error}"))
}

fn item(roster: &TestRoster, owner: &AccountKey, jid: &RosterJid) -> Option<RosterItem> {
    block_on(async {
        let transaction = roster.storage.begin_read().await?;
        transaction
            .roster_item(owner, jid, RosterQuota::default())
            .await
    })
    .unwrap_or_else(|error: RosterError| panic!("{error}"))
}

fn pending(roster: &TestRoster, owner: &AccountKey) -> Vec<PendingSubscription> {
    block_on(async {
        let transaction = roster.storage.begin_read().await?;
        transaction.pending_requests(owner).await
    })
    .unwrap_or_else(|error: RosterError| panic!("{error}"))
}

fn subscribed(jid: RosterJid, state: SubscriptionState) -> RosterItem {
    RosterItem {
        jid,
        name: None,
        groups: Vec::new(),
        subscription: RosterSubscription {
            state,
            pending_out: false,
            approved: false,
        },
    }
}

struct IqCall {
    request: Arena<GlobalChunkAllocator>,
    response: Arena<GlobalChunkAllocator>,
    sender: Jid,
    query: Element,
}

impl IqCall {
    fn new(item_jid: &str) -> Self {
        Self::build(item_jid, None)
    }

    fn versioned(ver: &str) -> Self {
        Self::build("", Some(ver))
    }

    fn build(item_jid: &str, ver: Option<&str>) -> Self {
        let mut request =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let response =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let sender = Jid::parse_in("alice@example.com/desk", &mut request)
            .unwrap_or_else(|error| panic!("{error}"));
        let item = (!item_jid.is_empty()).then(|| {
            Element::builder_in("item", NAMESPACE, &mut request)
                .and_then(|item| item.attribute("jid", "", item_jid))
                .and_then(|item| item.build())
                .unwrap_or_else(|error| panic!("{error:?}"))
        });
        let mut query = Element::builder_in("query", NAMESPACE, &mut request)
            .unwrap_or_else(|error| panic!("{error:?}"));
        if let Some(ver) = ver {
            query = query
                .attribute("ver", "", ver)
                .unwrap_or_else(|error| panic!("{error:?}"));
        }
        if let Some(item) = item {
            query = query
                .child(item)
                .unwrap_or_else(|error| panic!("{error:?}"));
        }
        let query = query.build().unwrap_or_else(|error| panic!("{error:?}"));
        Self {
            request,
            response,
            sender,
            query,
        }
    }

    async fn handle(
        &mut self,
        roster: &TestRoster,
        kind: IqRequestType,
        delivery: &RecordingDelivery,
    ) -> Result<IqReply<GlobalChunkAllocator>, crate::iq::IqError> {
        let sender = self
            .sender
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = self
            .query
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery = Discovery::default();
        let request = IqRequest {
            sender,
            target: sender.bare(),
            discovery: &discovery,
            sessions: &NoSessions,
            requester: (kind == IqRequestType::Get).then_some(Requester::Owner),
            lang: None,
            space: None,
            payload,
        };
        match kind {
            IqRequestType::Get => {
                let transaction = roster
                    .storage
                    .begin_read()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                TestIqHandler::get(
                    &Roster::default(),
                    request,
                    &transaction,
                    &mut self.response,
                )
                .await
            }
            IqRequestType::Set => {
                let mut transaction = roster
                    .storage
                    .begin_write()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let reply = TestIqHandler::set(
                    &Roster::default(),
                    request,
                    &mut transaction,
                    delivery,
                    &mut self.response,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                Ok(reply)
            }
        }
    }
}

fn handle_iq(
    roster: &TestRoster,
    kind: IqRequestType,
    item_jid: &str,
    delivery: &RecordingDelivery,
) -> Result<Vec<AccountKey>, crate::iq::IqError> {
    let mut call = IqCall::new(item_jid);
    let reply = block_on(call.handle(roster, kind, delivery))?;
    let Effects { accounts, deliver } = reply.effects;
    block_on(deliver(delivery)).unwrap_or_else(|error| panic!("{error}"));
    Ok(accounts)
}

fn roster_get(
    roster: &TestRoster,
    ver: Option<&str>,
    delivery: &RecordingDelivery,
) -> Option<String> {
    let mut call = ver.map_or_else(|| IqCall::new(""), IqCall::versioned);
    let reply = block_on(call.handle(roster, IqRequestType::Get, delivery))
        .unwrap_or_else(|error| panic!("{error:?}"));
    block_on((reply.effects.deliver)(delivery)).unwrap_or_else(|error| panic!("{error}"));
    reply.payload.map(|payload| {
        let mut xml = String::new();
        payload
            .resolve(&call.response)
            .and_then(|payload| {
                payload
                    .write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write payload"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        xml
    })
}

fn put_item(roster: &TestRoster, owner: &AccountKey, jid: &str) -> RosterVersion {
    let item = subscribed(RosterJid::from(&account(jid)), SubscriptionState::None);
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let version = transaction
            .put_roster_item(owner, &item, RosterQuota::default())
            .await?;
        transaction.commit().await?;
        Ok::<_, RosterError>(version)
    })
    .unwrap_or_else(|error| panic!("{error}"))
}

fn remove_item(roster: &TestRoster, owner: &AccountKey, jid: &str) -> RosterVersion {
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let removed = transaction
            .remove_roster_item(owner, &RosterJid::from(&account(jid)))
            .await?
            .unwrap_or_else(|| panic!("missing item"));
        transaction.commit().await?;
        Ok::<_, RosterError>(removed.version)
    })
    .unwrap_or_else(|error| panic!("{error}"))
}

struct SubscribeCall {
    stanza: RoutedStanza<GlobalChunkAllocator>,
}

impl SubscribeCall {
    fn new(sender: &str, target: &str) -> Self {
        let mut arena =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let sender = Jid::parse_in(sender, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let target = Jid::parse_in(target, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let stanza = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Subscribe),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(Some(sender))
        .and_then(|stanza| stanza.to(Some(target)))
        .and_then(|stanza| stanza.build())
        .unwrap_or_else(|error| panic!("{error:?}"));
        Self {
            stanza: RoutedStanza::from_parts(stanza, arena),
        }
    }

    async fn receive(
        &self,
        roster: &TestRoster,
        delivery: &RecordingDelivery,
    ) -> Result<Effects<GlobalChunkAllocator>, HandlerError> {
        let view = self
            .stanza
            .resolve()
            .unwrap_or_else(|error| panic!("{error}"));
        let sender = view
            .from()
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing sender"));
        let target = view
            .to()
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing target"));
        let mut transaction = roster
            .storage
            .begin_write()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let effects = TestPresenceHandler::receive(
            &Roster::default(),
            PresenceRequest {
                kind: PresenceRequestType::Subscribe,
                sender,
                target,
                stanza: &self.stanza,
            },
            &mut transaction,
            delivery,
        )
        .await?;
        transaction
            .commit()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        Ok(effects)
    }
}

fn receive_subscribe(
    roster: &TestRoster,
    sender: &str,
    target: &str,
    delivery: &RecordingDelivery,
) -> Result<Vec<AccountKey>, HandlerError> {
    let call = SubscribeCall::new(sender, target);
    let Effects { accounts, deliver } = block_on(call.receive(roster, delivery))?;
    block_on(deliver(delivery)).unwrap_or_else(|error| panic!("{error}"));
    Ok(accounts)
}

fn audience(roster: &TestRoster, sender: &str, transition: PresenceTransition) -> PresenceAudience {
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let sender = Jid::parse_in(sender, &mut arena).unwrap_or_else(|error| panic!("{error}"));
    let sender = sender
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    block_on(async {
        let transaction = roster
            .storage
            .begin_read()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        TestPresenceHandler::audience(
            &Roster::default(),
            PresenceUpdate { sender, transition },
            &transaction,
        )
        .await
    })
    .unwrap_or_else(|error| panic!("{error:?}"))
    .unwrap_or_else(|| panic!("expected an audience"))
}

fn names(accounts: &[AccountKey]) -> Vec<&str> {
    let mut names: Vec<&str> = accounts.iter().map(AccountKey::as_str).collect();
    names.sort_unstable();
    names
}

fn account(jid: &str) -> AccountKey {
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let jid = Jid::parse_in(jid, &mut arena).unwrap_or_else(|error| panic!("{error}"));
    AccountKey::try_from(
        jid.resolve(&arena)
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

#[test]
fn roster_retrieval_tags_the_requesting_session_as_interested() {
    let (_directory, roster) = roster();
    let delivery = RecordingDelivery::default();
    let accounts = handle_iq(&roster, IqRequestType::Get, "", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(names(&accounts), ["alice@example.com"]);
    assert_eq!(*delivery.tags.borrow(), [SessionTag::Interested]);
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn roster_get_without_a_version_returns_the_roster_unstamped() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    create_account(&roster, &alice);
    put_item(&roster, &alice, "bob@example.com");
    let delivery = RecordingDelivery::default();
    let payload = roster_get(&roster, None, &delivery).unwrap_or_else(|| panic!("no payload"));
    assert!(payload.contains(r#"jid="bob@example.com""#), "{payload}");
    assert!(!payload.contains("ver="), "{payload}");
    assert_eq!(*delivery.tags.borrow(), [SessionTag::Interested]);
}

#[test]
fn versioned_roster_get_returns_nothing_only_for_the_current_version() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    create_account(&roster, &alice);
    put_item(&roster, &alice, "bob@example.com");
    put_item(&roster, &alice, "carol@example.com");
    assert_eq!(remove_item(&roster, &alice, "bob@example.com").get(), 3);
    let delivery = RecordingDelivery::default();

    for other in ["", "abc", "0", "2", "9"] {
        let payload = roster_get(&roster, Some(other), &delivery)
            .unwrap_or_else(|| panic!("no payload for {other:?}"));
        assert!(payload.contains(r#"ver="3""#), "{payload}");
        assert!(payload.contains(r#"jid="carol@example.com""#), "{payload}");
        assert!(!payload.contains(r#"jid="bob@example.com""#), "{payload}");
    }
    let payload = roster_get(&roster, Some("3"), &delivery);
    assert!(payload.is_none(), "{payload:?}");
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn roster_update_pushes_the_item_to_interested_resources() {
    let (_directory, roster) = roster();
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let alice =
        Jid::parse_in("alice@example.com", &mut arena).unwrap_or_else(|error| panic!("{error}"));
    let alice = AccountKey::try_from(
        alice
            .resolve(&arena)
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    create_account(&roster, &alice);
    let delivery = RecordingDelivery::default();
    let accounts = handle_iq(&roster, IqRequestType::Set, "bob@example.com", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(names(&accounts), ["alice@example.com"]);
    assert!(delivery.tags.borrow().is_empty());
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert!(
        pushes[0].contains(r#"to="alice@example.com/desk""#),
        "{pushes:?}"
    );
    assert!(pushes[0].contains(r#"id="roster-1""#), "{pushes:?}");
    assert!(
        pushes[0].contains(r#"<item jid="bob@example.com" subscription="none"/>"#),
        "{pushes:?}"
    );
}

#[test]
fn roster_set_from_a_deleted_account_is_forbidden() {
    let (_directory, roster) = roster();
    let delivery = RecordingDelivery::default();
    let result = handle_iq(&roster, IqRequestType::Set, "bob@example.com", &delivery);
    assert!(
        matches!(
            result,
            Err(error) if error == HandlerError::Stanza(StanzaErrorCondition::Forbidden).into()
        ),
        "{result:?}"
    );
    assert!(delivery.pushes.borrow().is_empty());
    handle_iq(&roster, IqRequestType::Get, "", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
}

#[test]
fn subscription_request_from_a_deleted_account_is_forbidden() {
    let (_directory, roster) = roster();
    let bob = account("bob@example.com");
    create_account(&roster, &bob);
    let delivery = RecordingDelivery::default();
    let result = receive_subscribe(&roster, "alice@example.com", "bob@example.com", &delivery);
    assert!(
        matches!(
            result,
            Err(HandlerError::Stanza(StanzaErrorCondition::Forbidden))
        ),
        "{result:?}"
    );
    let result = receive_subscribe(&roster, "bob@example.com", "alice@example.com", &delivery);
    assert!(
        matches!(
            result,
            Err(HandlerError::Stanza(
                StanzaErrorCondition::ServiceUnavailable
            ))
        ),
        "{result:?}"
    );
    let bob_roster = snapshot(&roster, &bob);
    assert!(bob_roster.items.is_empty());
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn subscription_request_effects_name_both_local_parties() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    create_account(&roster, &alice);
    create_account(&roster, &bob);
    let delivery = RecordingDelivery::default();
    let accounts = receive_subscribe(&roster, "bob@example.com", "alice@example.com", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(names(&accounts), ["alice@example.com", "bob@example.com"]);
    let requests = pending(&roster, &alice);
    assert_eq!(requests.len(), 1, "{requests:?}");
    let bob_item =
        item(&roster, &bob, &RosterJid::from(&alice)).unwrap_or_else(|| panic!("missing item"));
    assert!(bob_item.subscription.pending_out);
}

#[test]
fn only_the_initial_transition_collects_granted_contacts() {
    let (_directory, roster) = roster();
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let alice = Jid::parse_in("alice@example.com/desk", &mut arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let bob =
        Jid::parse_in("bob@example.com", &mut arena).unwrap_or_else(|error| panic!("{error}"));
    let alice = alice
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let bob = bob
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let alice_account =
        AccountKey::try_from(alice.bare()).unwrap_or_else(|error| panic!("{error}"));
    let bob_account = AccountKey::try_from(bob).unwrap_or_else(|error| panic!("{error}"));
    create_account(&roster, &alice_account);
    create_account(&roster, &bob_account);
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        transaction
            .put_roster_item(
                &alice_account,
                &subscribed(RosterJid::from(bob), SubscriptionState::To),
                RosterQuota::default(),
            )
            .await?;
        transaction
            .put_roster_item(
                &bob_account,
                &subscribed(RosterJid::from(alice.bare()), SubscriptionState::From),
                RosterQuota::default(),
            )
            .await?;
        transaction.commit().await.map_err(RosterError::from)
    })
    .unwrap_or_else(|error| panic!("{error}"));
    for (transition, expected) in [
        (PresenceTransition::Initial, vec![bob_account.clone()]),
        (PresenceTransition::Update, Vec::new()),
        (PresenceTransition::Unavailable, Vec::new()),
    ] {
        let audience = audience(&roster, "alice@example.com/desk", transition);
        assert_eq!(audience.contacts, expected, "{transition:?}");
        assert!(audience.subscribers.is_empty(), "{transition:?}");
    }
}

fn create_account(roster: &TestRoster, key: &AccountKey) {
    let verifier = ScramSha1Verifier::new([11; 16], SCRAM_POLICY_ITERATIONS, [12; 20], [13; 20]);
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: key.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(verifier)),
            })
            .await?;
        transaction.commit().await.map_err(Into::into)
    })
    .unwrap_or_else(|error: lonewolf_storage::account::AccountError| panic!("{error}"));
}

#[test]
fn forgetting_an_account_cleans_storage_even_when_a_notification_fails() {
    let (_directory, roster) = roster();
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let accounts = ["alice@example.com", "bob@example.com", "carol@example.com"].map(|jid| {
        let jid = Jid::parse_in(jid, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        AccountKey::try_from(
            jid.resolve(&arena)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"))
    });
    let [alice, bob, carol] = &accounts;
    for account in &accounts {
        create_account(&roster, account);
    }
    let dave =
        Jid::parse_in("dave@remote.example", &mut arena).unwrap_or_else(|error| panic!("{error}"));
    let dave = dave
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    block_on(async {
        let mut repository = roster.storage.begin_write().await?;
        repository
            .put_roster_item(
                alice,
                &subscribed(RosterJid::from(bob), SubscriptionState::To),
                RosterQuota::default(),
            )
            .await?;
        repository
            .put_roster_item(
                bob,
                &subscribed(RosterJid::from(alice), SubscriptionState::From),
                RosterQuota::default(),
            )
            .await?;
        repository
            .put_roster_item(
                alice,
                &subscribed(RosterJid::from(carol), SubscriptionState::Both),
                RosterQuota::default(),
            )
            .await?;
        repository
            .put_roster_item(
                carol,
                &subscribed(RosterJid::from(alice), SubscriptionState::Both),
                RosterQuota::default(),
            )
            .await?;
        repository
            .put_roster_item(
                alice,
                &subscribed(RosterJid::from(dave), SubscriptionState::Both),
                RosterQuota::default(),
            )
            .await?;
        repository.commit().await.map_err(RosterError::from)
    })
    .unwrap_or_else(|error| panic!("{error}"));
    let delivery = RecordingDelivery {
        failing_deliveries: Cell::new(1),
        ..RecordingDelivery::default()
    };

    let effects = block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        transaction.delete_account(alice).await?;
        let effects = TestAccountHandler::forget_account(
            &Roster::default(),
            &mut transaction,
            alice,
            Arc::new(roster.storage.begin_read().await?),
            &delivery,
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
        transaction.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(effects)
    })
    .unwrap_or_else(|error| panic!("{error}"));
    let result = block_on(effects(&delivery));
    assert!(result.is_err(), "{result:?}");

    let alice_roster = snapshot(&roster, alice);
    assert!(alice_roster.items.is_empty());
    assert_eq!(alice_roster.version.get(), 0);
    for contact in [bob, carol] {
        let item = item(&roster, contact, &RosterJid::from(alice))
            .unwrap_or_else(|| panic!("missing item"));
        assert_eq!(item.subscription.state, SubscriptionState::None);
    }
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert!(
        pushes[0].contains(r#"to="carol@example.com/desk""#),
        "{pushes:?}"
    );
}

#[test]
fn visibility_uses_owner_grant_and_keeps_its_read_snapshot() {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let observer = account("bob@example.com");
    create_account(&roster, &owner);
    create_account(&roster, &observer);
    let mut arena = Arena::try_new(Default::default()).unwrap_or_else(|error| panic!("{error}"));
    let observer_jid = Jid::parse_in("bob@example.com/phone", &mut arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let observer_jid = observer_jid
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        transaction
            .put_roster_item(
                &observer,
                &subscribed(RosterJid::from(&owner), SubscriptionState::Both),
                RosterQuota::default(),
            )
            .await?;
        transaction.commit().await?;
        let snapshot = roster.storage.begin_read().await?;
        assert!(
            !TestPresenceHandler::visibility(&Roster::default(), &owner, observer_jid, &snapshot)
                .await
                .map_err(|error| format!("{error:?}"))?
        );
        drop(snapshot);
        for state in [
            SubscriptionState::None,
            SubscriptionState::To,
            SubscriptionState::From,
            SubscriptionState::Both,
        ] {
            let mut transaction = roster.storage.begin_write().await?;
            transaction
                .put_roster_item(
                    &owner,
                    &subscribed(RosterJid::from(&observer), state),
                    RosterQuota::default(),
                )
                .await?;
            transaction.commit().await?;
            let snapshot = roster.storage.begin_read().await?;
            let expected = matches!(state, SubscriptionState::From | SubscriptionState::Both);
            assert_eq!(
                TestPresenceHandler::visibility(
                    &Roster::default(),
                    &owner,
                    observer_jid,
                    &snapshot
                )
                .await
                .map_err(|error| format!("{error:?}"))?,
                expected
            );
            let mut transaction = roster.storage.begin_write().await?;
            transaction
                .remove_roster_item(&owner, &RosterJid::from(&observer))
                .await?;
            transaction.commit().await?;
            assert_eq!(
                TestPresenceHandler::visibility(
                    &Roster::default(),
                    &owner,
                    observer_jid,
                    &snapshot
                )
                .await
                .map_err(|error| format!("{error:?}"))?,
                expected
            );
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn probe_visibility_preserves_pending_requests_preapproval_and_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    let observer = account("bob@example.com");
    create_account(&roster, &owner);
    create_account(&roster, &observer);
    let mut arena = Arena::try_new(Default::default())?;
    let observer_jid = Jid::parse_in("bob@example.com/phone", &mut arena)?.resolve(&arena)?;
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let mut item = subscribed(RosterJid::from(&observer), SubscriptionState::None);
        item.subscription.approved = true;
        item.subscription.pending_out = true;
        transaction
            .put_roster_item(&owner, &item, RosterQuota::default())
            .await?;
        transaction
            .put_pending_request(
                &owner,
                PendingSubscription {
                    sender: RosterJid::from(&observer),
                    stanza: Box::from(b"stored".as_slice()),
                },
                std::num::NonZeroUsize::MAX,
            )
            .await?;
        transaction.commit().await?;
        let transaction = roster.storage.begin_read().await?;
        let before = transaction.roster(&owner, RosterQuota::default()).await?;
        let pending = transaction.pending_requests(&owner).await?;
        let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
        catalog.register(Arc::new(Roster::default()))?;
        let registry = catalog.enable_host("example.com", ["roster"])?;
        assert!(
            registry
                .presence()
                .find(PresenceRequestType::Probe)
                .is_some()
        );
        assert!(
            !TestPresenceHandler::visibility(
                &Roster::default(),
                &owner,
                observer_jid,
                &transaction
            )
            .await
            .map_err(|error| format!("{error:?}"))?
        );
        assert_eq!(
            transaction.roster(&owner, RosterQuota::default()).await?,
            before
        );
        assert_eq!(transaction.pending_requests(&owner).await?, pending);
        Ok(())
    })
}

#[test]
fn withdrawal_effects_notify_pending_contacts_only_after_commit()
-> Result<(), Box<dyn std::error::Error>> {
    for granted in [false, true] {
        let (_directory, roster) = roster();
        let alice = account("alice@example.com");
        let bob = account("bob@example.com");
        create_account(&roster, &alice);
        create_account(&roster, &bob);
        let delivery = RecordingDelivery::default();
        receive_subscribe(&roster, "alice@example.com", "bob@example.com", &delivery)
            .map_err(|error| format!("{error:?}"))?;
        if granted {
            block_on(async {
                let mut tx = roster.storage.begin_write().await?;
                tx.put_roster_item(
                    &bob,
                    &subscribed(RosterJid::from(&alice), SubscriptionState::From),
                    RosterQuota::default(),
                )
                .await?;
                tx.put_roster_item(
                    &alice,
                    &subscribed(RosterJid::from(&bob), SubscriptionState::To),
                    RosterQuota::default(),
                )
                .await?;
                tx.commit().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
        }
        delivery.pushes.borrow_mut().clear();
        let mut arena = Arena::try_new(Default::default())?;
        let from = Jid::parse_in("alice@example.com", &mut arena)?;
        let to = Jid::parse_in("bob@example.com", &mut arena)?;
        let stanza = Stanza::builder_in(
            StanzaType::Presence(PresenceType::Unsubscribe),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(Some(from))?
        .to(Some(to))?
        .build()?;
        let stanza = RoutedStanza::from_parts(stanza, arena);
        for rollback in [true, false] {
            let effects = block_on(async {
                let mut tx = roster.storage.begin_write().await?;
                let view = stanza.resolve()?;
                let effects = TestPresenceHandler::receive(
                    &Roster::default(),
                    PresenceRequest {
                        kind: PresenceRequestType::Unsubscribe,
                        sender: view.from()?.ok_or("missing sender")?,
                        target: view.to()?.ok_or("missing target")?,
                        stanza: &stanza,
                    },
                    &mut tx,
                    &delivery,
                )
                .await
                .map_err(|error| format!("{error:?}"))?;
                assert!(delivery.controls.borrow().is_empty());
                assert!(delivery.pushes.borrow().is_empty());
                assert_eq!(delivery.unavailable.get(), 0);
                if rollback {
                    drop(tx);
                    Ok::<_, Box<dyn std::error::Error>>(None)
                } else {
                    tx.commit().await?;
                    Ok(Some(effects))
                }
            })?;
            if let Some(effects) = effects {
                assert!(pending(&roster, &bob).is_empty());
                block_on((effects.deliver)(&delivery))?;
                assert_eq!(delivery.controls.borrow().len(), 1);
                assert_eq!(delivery.unavailable.get(), usize::from(granted));
                assert_eq!(delivery.pushes.borrow().len(), if granted { 2 } else { 1 });
            } else {
                assert_eq!(pending(&roster, &bob).len(), 1);
                assert!(
                    item(&roster, &alice, &RosterJid::from(&bob)).is_some_and(|item| {
                        item.subscription.pending_out
                            || item.subscription.state == SubscriptionState::To
                    })
                );
            }
        }
        delivery.controls.borrow_mut().clear();
        delivery.pushes.borrow_mut().clear();
        delivery.unavailable.set(0);
        block_on(async {
            let mut tx = roster.storage.begin_write().await?;
            let view = stanza.resolve()?;
            let effects = TestPresenceHandler::receive(
                &Roster::default(),
                PresenceRequest {
                    kind: PresenceRequestType::Unsubscribe,
                    sender: view.from()?.ok_or("missing sender")?,
                    target: view.to()?.ok_or("missing target")?,
                    stanza: &stanza,
                },
                &mut tx,
                &delivery,
            )
            .await
            .map_err(|error| format!("{error:?}"))?;
            tx.commit().await?;
            (effects.deliver)(&delivery).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        assert!(delivery.controls.borrow().is_empty());
        assert!(delivery.pushes.borrow().is_empty());
        assert_eq!(delivery.unavailable.get(), 0);
    }
    Ok(())
}

struct FailingReads(lonewolf_storage::StorageErrorKind);

fn read_failure(kind: lonewolf_storage::StorageErrorKind) -> lonewolf_storage::StorageError {
    lonewolf_storage::StorageError::with_source(
        kind,
        std::io::Error::other("seeded-sensitive-backend-source"),
    )
}

impl lonewolf_storage::account::AccountReads for FailingReads {
    async fn account(
        &self,
        _key: &AccountKey,
    ) -> Result<Option<lonewolf_storage::account::Account>, lonewolf_storage::account::AccountError>
    {
        Err(read_failure(self.0).into())
    }
    async fn scram(
        &self,
        _key: &AccountKey,
        _hash: lonewolf_auth::scram::ScramHash,
    ) -> Result<Option<ScramVerifier>, lonewolf_storage::account::AccountError> {
        unreachable!("failure test does not authenticate")
    }
    async fn accounts_after(
        &self,
        _after: Option<&AccountKey>,
        _limit: std::num::NonZeroUsize,
    ) -> Result<Vec<lonewolf_storage::account::Account>, lonewolf_storage::account::AccountError>
    {
        unreachable!("failure test does not list accounts")
    }
}

impl RosterReads for FailingReads {
    async fn roster(
        &self,
        _owner: &AccountKey,
        _quota: lonewolf_storage::roster::RosterQuota,
    ) -> Result<RosterSnapshot, RosterError> {
        Err(read_failure(self.0).into())
    }
    async fn roster_item(
        &self,
        _owner: &AccountKey,
        _jid: &RosterJid,
        _quota: lonewolf_storage::roster::RosterQuota,
    ) -> Result<Option<RosterItem>, RosterError> {
        Err(read_failure(self.0).into())
    }
    async fn pending_requests(
        &self,
        _owner: &AccountKey,
    ) -> Result<Vec<PendingSubscription>, RosterError> {
        Err(read_failure(self.0).into())
    }
    async fn pending_request(
        &self,
        _owner: &AccountKey,
        _sender: &RosterJid,
    ) -> Result<Option<PendingSubscription>, RosterError> {
        Err(read_failure(self.0).into())
    }
    async fn roster_version(
        &self,
        _: &AccountKey,
    ) -> Result<lonewolf_storage::roster::RosterVersion, lonewolf_storage::roster::RosterError>
    {
        Err(read_failure(self.0).into())
    }
    async fn roster_subscription(
        &self,
        _: &AccountKey,
        _: &lonewolf_storage::roster::RosterJid,
    ) -> Result<
        Option<lonewolf_storage::roster::RosterSubscription>,
        lonewolf_storage::roster::RosterError,
    > {
        Err(read_failure(self.0).into())
    }
    async fn next_roster_subscription(
        &self,
        _: &AccountKey,
        _: Option<&lonewolf_storage::roster::RosterJid>,
    ) -> Result<
        Option<(
            lonewolf_storage::roster::RosterJid,
            lonewolf_storage::roster::RosterSubscription,
        )>,
        lonewolf_storage::roster::RosterError,
    > {
        Err(read_failure(self.0).into())
    }
    async fn next_pending_sender(
        &self,
        _: &AccountKey,
        _: Option<&lonewolf_storage::roster::RosterJid>,
    ) -> Result<Option<lonewolf_storage::roster::RosterJid>, lonewolf_storage::roster::RosterError>
    {
        Err(read_failure(self.0).into())
    }
    async fn pending_request_exists(
        &self,
        _: &AccountKey,
        _: &lonewolf_storage::roster::RosterJid,
    ) -> Result<bool, lonewolf_storage::roster::RosterError> {
        Err(read_failure(self.0).into())
    }
}

#[test]
fn roster_read_and_mutation_failures_keep_storage_categories_and_operation() {
    use crate::delivery::{Failure, FailureKind};
    use lonewolf_storage::StorageErrorKind;
    for kind in [
        StorageErrorKind::Unavailable,
        StorageErrorKind::CorruptData,
        StorageErrorKind::UnsupportedVersion,
        StorageErrorKind::CommitUnknown,
        StorageErrorKind::Other,
    ] {
        let reads = FailingReads(kind);
        let owner = account("alice@example.com");
        let read = block_on(super::account_exists(&reads, &owner, "roster_read"))
            .expect_err("storage must fail");
        let write =
            block_on(super::require_account(&reads, &owner)).expect_err("storage must fail");
        let contact = RosterJid::from(&account("bob@example.com"));
        let audience = block_on(super::granting_contacts(
            &reads,
            contact.clone(),
            &[contact],
        ))
        .expect_err("storage must fail");
        for (error, operation) in [
            (read, "roster_read"),
            (write, "roster_write"),
            (audience, "roster_read"),
        ] {
            assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
            assert_eq!(
                error.failure(),
                Some(Failure {
                    kind: FailureKind::Storage(kind),
                    operation
                })
            );
            assert!(!format!("{error:?}").contains("seeded-sensitive-backend-source"));
        }
    }
    for (cause, condition) in [
        (
            RosterError::ValueTooLarge,
            StanzaErrorCondition::NotAcceptable,
        ),
        (
            RosterError::PendingLimitExceeded,
            StanzaErrorCondition::ResourceConstraint,
        ),
        (RosterError::NoAccount, StanzaErrorCondition::Forbidden),
    ] {
        let error = super::roster_error(cause, "roster_write");
        assert_eq!(error.condition(), condition);
        assert_eq!(error.failure(), None);
    }
}

async fn sender_hook(
    call: &SubscribeCall,
    kind: PresenceRequestType,
    transaction: &mut lonewolf_storage::RedbWrite,
    delivery: &RecordingDelivery,
) -> Result<PresenceSend<GlobalChunkAllocator>, HandlerError> {
    let view = call
        .stanza
        .resolve()
        .unwrap_or_else(|error| panic!("{error}"));
    TestPresenceHandler::send(
        &Roster::default(),
        PresenceRequest {
            kind,
            sender: view.from().expect("sender address").expect("sender"),
            target: view.to().expect("target address").expect("target"),
            stanza: &call.stanza,
        },
        transaction,
        delivery,
    )
    .await
}

#[test]
fn sender_preapproval_preserves_fields_and_rolls_back_before_commit()
-> Result<(), Box<dyn std::error::Error>> {
    for target in [
        "future@example.com",
        "future@remote.invalid",
        "future@other.example",
    ] {
        let (_directory, roster) = roster();
        let owner = account("alice@example.com");
        let contact = RosterJid::from(&account(target));
        create_account(&roster, &owner);
        let mut stored = subscribed(contact.clone(), SubscriptionState::To);
        stored.name = Some("Future".into());
        stored.groups = vec!["Friends".into(), "Work".into()];
        stored.subscription.pending_out = true;
        block_on(async {
            let mut transaction = roster.storage.begin_write().await?;
            transaction
                .put_roster_item(&owner, &stored, RosterQuota::default())
                .await?;
            transaction.commit().await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        let before = snapshot(&roster, &owner);
        let delivery = RecordingDelivery::default();
        let call = SubscribeCall::new("alice@example.com/desk", target);
        for rollback in [true, false] {
            let effects = block_on(async {
                let mut transaction = roster.storage.begin_write().await?;
                let PresenceSend::Handled(effects) = sender_hook(
                    &call,
                    PresenceRequestType::Subscribed,
                    &mut transaction,
                    &delivery,
                )
                .await
                .map_err(|error| format!("{error:?}"))?
                else {
                    panic!("preapproval must be handled");
                };
                assert_eq!(effects.accounts, vec![owner.clone()]);
                assert!(delivery.pushes.borrow().is_empty());
                if rollback {
                    drop(transaction);
                    Ok::<_, Box<dyn std::error::Error>>(None)
                } else {
                    transaction.commit().await?;
                    Ok(Some(effects))
                }
            })?;
            if let Some(effects) = effects {
                stored.subscription.approved = true;
                assert_eq!(item(&roster, &owner, &contact), Some(stored.clone()));
                assert_eq!(
                    snapshot(&roster, &owner).version.get(),
                    before.version.get() + 1
                );
                block_on((effects.deliver)(&delivery))?;
                assert_eq!(delivery.pushes.borrow().len(), 1);
            } else {
                assert_eq!(item(&roster, &owner, &contact), Some(stored.clone()));
                assert_eq!(snapshot(&roster, &owner).version, before.version);
            }
        }
        for (kind, approved, pushes) in [
            (PresenceRequestType::Subscribed, true, 1),
            (PresenceRequestType::Unsubscribed, false, 2),
            (PresenceRequestType::Unsubscribed, false, 2),
        ] {
            let before_version = snapshot(&roster, &owner).version;
            let changed = stored.subscription.approved != approved;
            block_on(async {
                let mut transaction = roster.storage.begin_write().await?;
                let PresenceSend::Handled(effects) =
                    sender_hook(&call, kind, &mut transaction, &delivery)
                        .await
                        .map_err(|error| format!("{error:?}"))?
                else {
                    panic!("sender operation must be handled");
                };
                assert_eq!(effects.accounts, vec![owner.clone()]);
                transaction.commit().await?;
                (effects.deliver)(&delivery).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
            stored.subscription.approved = approved;
            assert_eq!(item(&roster, &owner, &contact), Some(stored.clone()));
            assert_eq!(
                snapshot(&roster, &owner).version.get(),
                before_version.get() + u64::from(changed)
            );
            assert_eq!(delivery.pushes.borrow().len(), pushes);
        }
        assert!(delivery.controls.borrow().is_empty());
        assert_eq!(delivery.current.get(), 0);
        assert_eq!(delivery.unavailable.get(), 0);
        assert!(pending(&roster, &owner).is_empty());
        block_on(async {
            let read = roster.storage.begin_read().await?;
            assert!(
                lonewolf_storage::account::AccountReads::account(&read, &account(target))
                    .await?
                    .is_none()
            );
            assert!(
                read.roster(&account(target), RosterQuota::default())
                    .await?
                    .items
                    .is_empty()
            );
            assert!(read.pending_requests(&account(target)).await?.is_empty());
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    Ok(())
}

#[test]
fn sender_hook_classifies_grants_pending_requests_and_target_forms_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    for state in [
        None,
        Some(SubscriptionState::None),
        Some(SubscriptionState::To),
        Some(SubscriptionState::From),
        Some(SubscriptionState::Both),
    ] {
        for has_pending in [false, true] {
            for kind in [
                PresenceRequestType::Subscribed,
                PresenceRequestType::Unsubscribed,
            ] {
                let (_directory, roster) = roster();
                let owner = account("alice@example.com");
                let contact = RosterJid::from(&account("future@remote.invalid"));
                create_account(&roster, &owner);
                block_on(async {
                    let mut transaction = roster.storage.begin_write().await?;
                    if let Some(state) = state {
                        transaction
                            .put_roster_item(
                                &owner,
                                &subscribed(contact.clone(), state),
                                RosterQuota::default(),
                            )
                            .await?;
                    }
                    if has_pending {
                        transaction
                            .put_pending_request(
                                &owner,
                                PendingSubscription {
                                    sender: contact.clone(),
                                    stanza: b"<presence type='subscribe'/>".as_slice().into(),
                                },
                                std::num::NonZeroUsize::MAX,
                            )
                            .await?;
                    }
                    transaction.commit().await?;
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
                let before = snapshot(&roster, &owner);
                let before_pending = pending(&roster, &owner);
                let delivery = RecordingDelivery::default();
                let granted = state.is_some_and(super::state::grants);
                let should_continue = match kind {
                    PresenceRequestType::Subscribed => !granted && has_pending,
                    PresenceRequestType::Unsubscribed => granted || has_pending,
                    _ => unreachable!(),
                };
                block_on(async {
                    let mut transaction = roster.storage.begin_write().await?;
                    let call =
                        SubscribeCall::new("alice@example.com/desk", "future@remote.invalid");
                    let result = sender_hook(&call, kind, &mut transaction, &delivery)
                        .await
                        .map_err(|error| format!("{error:?}"))?;
                    match result {
                        PresenceSend::Continue => assert!(should_continue),
                        PresenceSend::Handled(effects) => {
                            assert!(!should_continue);
                            assert_eq!(effects.accounts, vec![owner.clone()]);
                        }
                    }
                    if should_continue || granted || kind == PresenceRequestType::Unsubscribed {
                        assert_eq!(
                            transaction
                                .roster(&owner, RosterQuota::default())
                                .await?
                                .version,
                            before.version
                        );
                        assert_eq!(
                            transaction
                                .roster(&owner, RosterQuota::default())
                                .await?
                                .items,
                            before.items
                        );
                    }
                    transaction.commit().await?;
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
                assert_eq!(pending(&roster, &owner), before_pending);
                assert!(delivery.pushes.borrow().is_empty());
                for target in [
                    "future@remote.invalid/phone",
                    "remote.invalid",
                    "remote.invalid/phone",
                ] {
                    let call = SubscribeCall::new("alice@example.com/desk", target);
                    block_on(async {
                        let mut transaction = roster.storage.begin_write().await?;
                        let before = transaction.roster(&owner, RosterQuota::default()).await?;
                        assert!(matches!(
                            sender_hook(&call, kind, &mut transaction, &delivery)
                                .await
                                .map_err(|error| format!("{error:?}"))?,
                            PresenceSend::Continue
                        ));
                        assert_eq!(
                            transaction
                                .roster(&owner, RosterQuota::default())
                                .await?
                                .version,
                            before.version
                        );
                        assert_eq!(
                            transaction
                                .roster(&owner, RosterQuota::default())
                                .await?
                                .items,
                            before.items
                        );
                        Ok::<_, Box<dyn std::error::Error>>(())
                    })?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn sender_hook_creates_only_preapprovals_and_requires_a_live_sender()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    create_account(&roster, &owner);
    let delivery = RecordingDelivery::default();
    let call = SubscribeCall::new("alice@example.com/desk", "future@remote.invalid");
    for kind in PresenceRequestType::ALL {
        if kind == PresenceRequestType::Subscribed || kind == PresenceRequestType::Unsubscribed {
            continue;
        }
        block_on(async {
            let mut transaction = roster.storage.begin_write().await?;
            assert!(matches!(
                sender_hook(&call, kind, &mut transaction, &delivery)
                    .await
                    .map_err(|error| format!("{error:?}"))?,
                PresenceSend::Continue
            ));
            transaction.commit().await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
    }
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let PresenceSend::Handled(effects) = sender_hook(
            &call,
            PresenceRequestType::Unsubscribed,
            &mut transaction,
            &delivery,
        )
        .await
        .map_err(|error| format!("{error:?}"))?
        else {
            panic!("cancellation must be handled");
        };
        assert_eq!(effects.accounts, vec![owner.clone()]);
        transaction.commit().await?;
        (effects.deliver)(&delivery).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(snapshot(&roster, &owner).version.get(), 0);
    assert!(snapshot(&roster, &owner).items.is_empty());
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        let PresenceSend::Handled(effects) = sender_hook(
            &call,
            PresenceRequestType::Subscribed,
            &mut transaction,
            &delivery,
        )
        .await
        .map_err(|error| format!("{error:?}"))?
        else {
            panic!("preapproval must be handled");
        };
        transaction.commit().await?;
        (effects.deliver)(&delivery).await?;
        let mut transaction = roster.storage.begin_write().await?;
        transaction.delete_account(&owner).await?;
        transaction
            .remove_roster_item(&owner, &RosterJid::from(&account("future@remote.invalid")))
            .await?;
        for kind in [
            PresenceRequestType::Subscribed,
            PresenceRequestType::Unsubscribed,
        ] {
            assert!(matches!(
                sender_hook(&call, kind, &mut transaction, &delivery).await,
                Err(HandlerError::Stanza(StanzaErrorCondition::Forbidden))
            ));
        }
        assert!(
            transaction
                .roster(&owner, RosterQuota::default())
                .await?
                .items
                .is_empty()
        );
        transaction.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(delivery.pushes.borrow().len(), 1);
    Ok(())
}

#[test]
fn default_roster_quota_fits_response_arena_with_group_and_escape_expansion()
-> Result<(), Box<dyn std::error::Error>> {
    use lonewolf_storage::roster::{MAX_GROUPS_PER_ITEM, RosterQuota};
    for skewed in [false, true] {
        let mut items = Vec::new();
        let mut bytes = 0usize;
        for i in 0..1000 {
            let jid = RosterJid::from(&account(&format!("contact{i:04}@example.com")));
            let mut item = subscribed(jid, SubscriptionState::Both);
            item.subscription.pending_out = true;
            item.subscription.approved = true;
            item.groups = (0..MAX_GROUPS_PER_ITEM)
                .map(|_| Box::<str>::from("<&\"'\t\n"))
                .collect();
            bytes += "owner@example.com".len()
                + 1
                + item.jid.as_str().len()
                + 10
                + item.groups.iter().map(|g| 4 + g.len()).sum::<usize>();
            items.push(item);
        }
        let remaining = RosterQuota::default().max_bytes.get() - bytes;
        if skewed {
            items[0].name = Some("&".repeat(remaining).into_boxed_str());
        } else {
            for item in &mut items {
                item.name = Some("&".repeat(remaining / 1000).into_boxed_str());
            }
        }
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let query = super::xml::build_response(items, Some(RosterVersion::new(1)), &mut arena)
            .map_err(|e| format!("{e:?}"))?;
        let mut xml = String::new();
        query.resolve(&arena)?.write_xml(&mut xml)?;
        assert!(arena.stats().reserved_bytes <= lonewolf_util::arena::DEFAULT_MAX_RESERVED_BYTES);
        assert!(xml.len() > RosterQuota::default().max_bytes.get());
    }
    Ok(())
}

#[test]
fn cleanup_replays_pinned_metadata_once_for_overlap_and_pending_only_contacts()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, fixture) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let carol = account("carol@example.com");
    for owner in [&alice, &bob, &carol] {
        create_account(&fixture, owner);
    }
    block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        for contact in [
            "alice@example.com",
            "bob@example.com",
            "missing@example.com",
            "remote@remote.invalid",
        ] {
            tx.put_roster_item(
                &alice,
                &subscribed(RosterJid::from(&account(contact)), SubscriptionState::Both),
                Default::default(),
            )
            .await?;
        }
        let mut bob_item = subscribed(RosterJid::from(&alice), SubscriptionState::Both);
        bob_item.name = Some("Before".into());
        tx.put_roster_item(&bob, &bob_item, Default::default())
            .await?;
        tx.put_roster_item(
            &carol,
            &subscribed(RosterJid::from(&alice), SubscriptionState::Both),
            Default::default(),
        )
        .await?;
        for sender in [&bob, &carol] {
            tx.put_pending_request(
                &alice,
                PendingSubscription {
                    sender: RosterJid::from(sender),
                    stanza: b"pending".as_slice().into(),
                },
                std::num::NonZeroUsize::new(10).unwrap(),
            )
            .await?;
        }
        tx.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let delivery = RecordingDelivery::default();
    let deliver = block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        let before = Arc::new(fixture.storage.begin_read().await?);
        tx.delete_account(&alice).await?;
        let deliver = TestAccountHandler::forget_account(
            &Roster::default(),
            &mut tx,
            &alice,
            before,
            &delivery,
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        tx.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(deliver)
    })?;
    assert_eq!(snapshot(&fixture, &bob).version.get(), 2);
    assert_eq!(snapshot(&fixture, &carol).version.get(), 2);
    assert_eq!(
        item(&fixture, &carol, &RosterJid::from(&alice))
            .ok_or("missing")?
            .subscription
            .state,
        SubscriptionState::From
    );
    assert!(pending(&fixture, &alice).is_empty());
    block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        let mut changed = subscribed(RosterJid::from(&alice), SubscriptionState::None);
        changed.name = Some("After".into());
        tx.put_roster_item(&bob, &changed, Default::default())
            .await?;
        tx.commit().await?;
        deliver(&delivery).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 2);
    assert!(pushes[0].contains("Before"));
    assert!(!pushes[0].contains("After"));
    assert!(pushes.iter().all(|push| push.contains("roster-2")));
    assert_eq!(delivery.controls.borrow().len(), 3);
    Ok(())
}

#[test]
fn current_version_get_skips_legacy_metadata_and_uses_its_consistent_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    let (_directory, fixture) = roster();
    let owner = account("alice@example.com");
    create_account(&fixture, &owner);
    let first = put_item(&fixture, &owner, "bob@example.com");
    let policy = Roster::new(BTreeMap::from([(
        "example.com".into(),
        super::RosterLimits {
            max_items: NonZeroUsize::MIN,
            max_bytes: NonZeroUsize::MIN,
            ..Default::default()
        },
    )]));
    let before = block_on(fixture.storage.begin_read())?;
    put_item(&fixture, &owner, "carol@example.com");
    block_on(async {
        let mut call = IqCall::versioned(&first.get().to_string());
        let sender = call.sender.resolve(&call.request)?;
        let payload = call.query.resolve(&call.request)?;
        let discovery = Discovery::default();
        let request = IqRequest {
            sender,
            target: sender.bare(),
            discovery: &discovery,
            sessions: &NoSessions,
            requester: Some(Requester::Owner),
            lang: None,
            space: None,
            payload,
        };
        let reply = <Roster as IqHandler<GlobalChunkAllocator, RedbStorage>>::get(
            &policy,
            request,
            &before,
            &mut call.response,
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        assert!(reply.payload.is_none());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn cleanup_quota_retirement_uses_counterpart_host_and_continues()
-> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    let (_directory, fixture) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    let carol = account("carol@other.example");
    for owner in [&alice, &bob, &carol] {
        create_account(&fixture, owner);
    }
    block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        for contact in [&bob, &carol] {
            tx.put_roster_item(
                &alice,
                &subscribed(RosterJid::from(contact), SubscriptionState::Both),
                Default::default(),
            )
            .await?;
            tx.put_roster_item(
                contact,
                &subscribed(RosterJid::from(&alice), SubscriptionState::Both),
                Default::default(),
            )
            .await?;
        }
        tx.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let policy = Roster::new(BTreeMap::from([(
        "example.com".into(),
        super::RosterLimits {
            max_bytes: NonZeroUsize::MIN,
            ..Default::default()
        },
    )]));
    let delivery = RecordingDelivery::default();
    let deliver = block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        let before = Arc::new(fixture.storage.begin_read().await?);
        tx.delete_account(&alice).await?;
        let deliver =
            TestAccountHandler::forget_account(&policy, &mut tx, &alice, before, &delivery)
                .await
                .map_err(|e| format!("{e:?}"))?;
        tx.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(deliver)
    })?;
    block_on(deliver(&delivery))?;
    assert_eq!(*delivery.retired.borrow(), vec![bob.clone()]);
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 1);
    assert!(pushes[0].contains("carol@other.example/desk"));
    assert_eq!(delivery.controls.borrow().len(), 4);
    assert_eq!(snapshot(&fixture, &bob).version.get(), 2);
    assert_eq!(snapshot(&fixture, &carol).version.get(), 2);
    Ok(())
}

#[test]
fn legacy_transition_retirements_follow_notifications_and_survive_delivery_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::num::NonZeroUsize;
    for fail in [false, true] {
        for kind in [
            PresenceRequestType::Unsubscribe,
            PresenceRequestType::Unsubscribed,
        ] {
            let (_directory, fixture) = roster();
            let alice = account("alice@example.com");
            let bob = account("bob@example.com");
            for owner in [&alice, &bob] {
                create_account(&fixture, owner);
            }
            block_on(async {
                let mut tx = fixture.storage.begin_write().await?;
                for (owner, contact) in [(&alice, &bob), (&bob, &alice)] {
                    let mut item = subscribed(RosterJid::from(contact), SubscriptionState::Both);
                    item.name = Some("x".repeat(256).into_boxed_str());
                    tx.put_roster_item(owner, &item, Default::default()).await?;
                    tx.put_pending_request(
                        owner,
                        PendingSubscription {
                            sender: RosterJid::from(contact),
                            stanza: b"pending".as_slice().into(),
                        },
                        NonZeroUsize::new(10).ok_or("invalid")?,
                    )
                    .await?;
                }
                tx.commit().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
            let policy = Roster::new(BTreeMap::from([(
                "example.com".into(),
                super::RosterLimits {
                    max_bytes: NonZeroUsize::new(128).ok_or("invalid")?,
                    ..Default::default()
                },
            )]));
            let delivery = RecordingDelivery {
                failing_deliveries: Cell::new(usize::from(fail)),
                ..Default::default()
            };
            let call = SubscribeCall::new("alice@example.com/desk", "bob@example.com");
            let effects = block_on(async {
                let mut tx = fixture.storage.begin_write().await?;
                let view = call.stanza.resolve()?;
                let effects = TestPresenceHandler::receive(
                    &policy,
                    PresenceRequest {
                        kind,
                        sender: view.from()?.ok_or("missing")?,
                        target: view.to()?.ok_or("missing")?,
                        stanza: &call.stanza,
                    },
                    &mut tx,
                    &delivery,
                )
                .await
                .map_err(|e| format!("{e:?}"))?;
                tx.commit().await?;
                Ok::<_, Box<dyn std::error::Error>>(effects)
            })?;
            let result = block_on((effects.deliver)(&delivery));
            assert_eq!(result.is_err(), fail);
            let retired = delivery.retired.borrow();
            assert_eq!(retired.len(), 2);
            assert!(
                delivery
                    .retirement_unavailable
                    .borrow()
                    .iter()
                    .all(|count| *count == delivery.unavailable.get())
            );
            assert!(retired.contains(&alice));
            assert!(retired.contains(&bob));
            assert!(delivery.pushes.borrow().is_empty());
            for owner in [&alice, &bob] {
                let current = snapshot(&fixture, owner);
                assert_eq!(current.version.get(), 2);
                assert_eq!(
                    current.items[0].name.as_deref(),
                    Some("x".repeat(256).as_str())
                );
            }
            let pending_owner = if kind == PresenceRequestType::Unsubscribe {
                &bob
            } else {
                &alice
            };
            assert!(pending(&fixture, pending_owner).is_empty());
            assert_eq!(
                delivery.unavailable.get(),
                usize::from(kind == PresenceRequestType::Unsubscribed || !fail)
            );
        }
    }
    Ok(())
}

#[test]
fn legacy_self_preapproval_transitions_twice_and_retires_once()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, fixture) = roster();
    let owner = account("alice@example.com");
    create_account(&fixture, &owner);
    block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        let mut item = subscribed(RosterJid::from(&owner), SubscriptionState::None);
        item.name = Some("x".repeat(256).into_boxed_str());
        item.subscription.approved = true;
        tx.put_roster_item(&owner, &item, Default::default())
            .await?;
        tx.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let policy = Roster::new(std::collections::BTreeMap::from([(
        "example.com".into(),
        super::RosterLimits {
            max_bytes: std::num::NonZeroUsize::new(128).ok_or("invalid")?,
            ..Default::default()
        },
    )]));
    let delivery = RecordingDelivery::default();
    let call = SubscribeCall::new("alice@example.com/desk", "alice@example.com");
    block_on(async {
        let mut tx = fixture.storage.begin_write().await?;
        let view = call.stanza.resolve()?;
        let effects = TestPresenceHandler::receive(
            &policy,
            PresenceRequest {
                kind: PresenceRequestType::Subscribe,
                sender: view.from()?.ok_or("missing")?,
                target: view.to()?.ok_or("missing")?,
                stanza: &call.stanza,
            },
            &mut tx,
            &delivery,
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        tx.commit().await?;
        (effects.deliver)(&delivery).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    let current = snapshot(&fixture, &owner);
    assert_eq!(current.version.get(), 3);
    assert_eq!(current.items[0].subscription.state, SubscriptionState::Both);
    assert!(!current.items[0].subscription.approved);
    assert_eq!(
        current.items[0].name.as_deref(),
        Some("x".repeat(256).as_str())
    );
    assert_eq!(*delivery.retired.borrow(), vec![owner]);
    Ok(())
}

#[test]
fn initial_probes_include_watched_contacts_without_reciprocal_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, roster) = roster();
    let owner = account("alice@example.com");
    create_account(&roster, &owner);
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        for (jid, state) in [
            ("none@remote.test", SubscriptionState::None),
            ("from@remote.test", SubscriptionState::From),
            ("to@remote.test", SubscriptionState::To),
            ("pending@remote.test", SubscriptionState::To),
            ("both@remote.test", SubscriptionState::Both),
            ("alice@example.com", SubscriptionState::Both),
        ] {
            transaction
                .put_roster_item(
                    &owner,
                    &subscribed(RosterJid::from(&account(jid)), state),
                    RosterQuota::default(),
                )
                .await?;
        }
        transaction
            .put_pending_request(
                &owner,
                PendingSubscription {
                    sender: RosterJid::from(&account("pending@remote.test")),
                    stanza: Box::from(b"stored".as_slice()),
                },
                std::num::NonZeroUsize::MAX,
            )
            .await?;
        transaction.commit().await.map_err(RosterError::from)
    })?;
    for transition in [
        PresenceTransition::Initial,
        PresenceTransition::Update,
        PresenceTransition::Unavailable,
    ] {
        let audience = audience(&roster, "alice@example.com/desk", transition);
        let mut probes: Vec<_> = audience.probes.iter().map(RosterJid::as_str).collect();
        probes.sort_unstable();
        let expected = if transition == PresenceTransition::Initial {
            vec!["both@remote.test", "pending@remote.test", "to@remote.test"]
        } else {
            Vec::new()
        };
        assert_eq!(probes, expected, "{transition:?}");
        assert!(audience.contacts.is_empty());
    }
    Ok(())
}

#[test]
fn remote_outbound_subscription_table_and_disabled_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    use PresenceRequestType::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
    use SubscriptionState::{Both, From, None as NoSubscription, To};
    let rows = [
        (
            NoSubscription,
            false,
            false,
            [
                (NoSubscription, true, false, true),
                (NoSubscription, false, false, true),
                (NoSubscription, false, false, false),
                (NoSubscription, false, false, false),
            ],
        ),
        (
            NoSubscription,
            true,
            false,
            [
                (NoSubscription, true, false, true),
                (NoSubscription, false, false, true),
                (NoSubscription, true, false, false),
                (NoSubscription, true, false, false),
            ],
        ),
        (
            NoSubscription,
            false,
            true,
            [
                (NoSubscription, true, true, true),
                (NoSubscription, false, true, true),
                (From, false, false, true),
                (NoSubscription, false, false, true),
            ],
        ),
        (
            NoSubscription,
            true,
            true,
            [
                (NoSubscription, true, true, true),
                (NoSubscription, false, true, true),
                (From, true, false, true),
                (NoSubscription, true, false, true),
            ],
        ),
        (
            To,
            false,
            false,
            [
                (To, false, false, true),
                (NoSubscription, false, false, true),
                (To, false, false, false),
                (To, false, false, false),
            ],
        ),
        (
            To,
            false,
            true,
            [
                (To, false, true, true),
                (NoSubscription, false, true, true),
                (Both, false, false, true),
                (To, false, false, true),
            ],
        ),
        (
            From,
            false,
            false,
            [
                (From, true, false, true),
                (From, false, false, true),
                (From, false, false, false),
                (NoSubscription, false, false, true),
            ],
        ),
        (
            From,
            true,
            false,
            [
                (From, true, false, true),
                (From, false, false, true),
                (From, true, false, false),
                (NoSubscription, true, false, true),
            ],
        ),
        (
            Both,
            false,
            false,
            [
                (Both, false, false, true),
                (From, false, false, true),
                (Both, false, false, false),
                (To, false, false, true),
            ],
        ),
    ];
    for federated in [true, false] {
        for (state, pending_out, pending_in, expected) in rows {
            for (index, kind) in [Subscribe, Unsubscribe, Subscribed, Unsubscribed]
                .into_iter()
                .enumerate()
            {
                let (_directory, fixture) = roster();
                let owner = account("alice@example.com");
                let contact = account("bob@remote.invalid");
                create_account(&fixture, &owner);
                let approved = kind == Unsubscribed || (kind == Subscribed && pending_in);
                let original = RosterSubscription {
                    state,
                    pending_out,
                    approved,
                };
                block_on(async {
                    let mut tx = fixture.storage.begin_write().await?;
                    tx.put_roster_item(
                        &owner,
                        &RosterItem {
                            subscription: original,
                            ..subscribed(RosterJid::from(&contact), state)
                        },
                        Default::default(),
                    )
                    .await?;
                    if pending_in {
                        tx.put_pending_request(
                            &owner,
                            PendingSubscription {
                                sender: RosterJid::from(&contact),
                                stanza: b"pending request".as_slice().into(),
                            },
                            std::num::NonZeroUsize::MIN,
                        )
                        .await?;
                    }
                    tx.commit().await?;
                    Ok::<_, Box<dyn std::error::Error>>(())
                })?;
                let before = snapshot(&fixture, &owner);
                let stored_request = pending(&fixture, &owner);
                let delivery = RecordingDelivery {
                    federated,
                    ..Default::default()
                };
                let mut call = SubscribeCall::new("alice@example.com/desk", "bob@remote.invalid");
                let mut arena = delivery.arena()?;
                let stanza = call
                    .stanza
                    .resolve()?
                    .clone_in(&mut arena)?
                    .derive_in(&mut arena)?
                    .stanza_type(StanzaType::Presence(match kind {
                        Subscribe => PresenceType::Subscribe,
                        Unsubscribe => PresenceType::Unsubscribe,
                        Subscribed => PresenceType::Subscribed,
                        Unsubscribed => PresenceType::Unsubscribed,
                        _ => return Err("unexpected kind".into()),
                    }))
                    .build()?;
                call.stanza = RoutedStanza::from_parts(stanza, arena);
                let handled = block_on(async {
                    let mut tx = fixture.storage.begin_write().await?;
                    let result = sender_hook(&call, kind, &mut tx, &delivery)
                        .await
                        .map_err(|e| format!("{e:?}"))?;
                    tx.commit().await?;
                    match result {
                        PresenceSend::Handled(effects) => {
                            assert_eq!(effects.accounts.as_slice(), std::slice::from_ref(&owner));
                            (effects.deliver)(&delivery).await?;
                            Ok::<_, Box<dyn std::error::Error>>(true)
                        }
                        PresenceSend::Continue => Ok(false),
                    }
                })?;
                let granted = matches!(state, From | Both);
                let (expected_subscription, expected_pending, route, current, unavailable) =
                    if federated {
                        let (state, pending_out, pending, route) = expected[index];
                        let approved = match kind {
                            Subscribed if !route && !granted => true,
                            Subscribed if route => false,
                            Unsubscribed => false,
                            _ => approved,
                        };
                        (
                            RosterSubscription {
                                state,
                                pending_out,
                                approved,
                            },
                            pending,
                            route,
                            kind == Subscribed && route,
                            kind == Unsubscribed && granted,
                        )
                    } else {
                        let mut next = original;
                        if kind == Subscribed && !granted && !pending_in {
                            next.approved = true;
                        }
                        if kind == Unsubscribed && !granted && !pending_in {
                            next.approved = false;
                        }
                        (next, pending_in, false, false, false)
                    };
                assert_eq!(
                    handled,
                    federated
                        || ((kind == Subscribed || kind == Unsubscribed)
                            && !pending_in
                            && !granted)
                        || (kind == Subscribed && granted),
                    "{federated} {state:?} {pending_out} {pending_in} {kind:?}"
                );
                assert_eq!(
                    item(&fixture, &owner, &RosterJid::from(&contact))
                        .ok_or("missing item")?
                        .subscription,
                    expected_subscription,
                    "{federated} {state:?} {kind:?}"
                );
                let changed = expected_subscription != original;
                assert_eq!(
                    snapshot(&fixture, &owner).version.get(),
                    before.version.get() + u64::from(changed)
                );
                assert_eq!(
                    pending(&fixture, &owner),
                    if expected_pending {
                        stored_request
                    } else {
                        Vec::new()
                    }
                );
                assert_eq!(delivery.remote.borrow().len(), usize::from(route));
                for xml in delivery.remote.borrow().iter() {
                    assert!(
                        xml.contains("from='alice@example.com'")
                            || xml.contains("from=\"alice@example.com\""),
                        "{xml}"
                    );
                    assert!(
                        xml.contains("to='bob@remote.invalid'")
                            || xml.contains("to=\"bob@remote.invalid\""),
                        "{xml}"
                    );
                    assert!(!xml.contains("/desk"), "{xml}");
                }
                assert_eq!(delivery.pushes.borrow().len(), usize::from(changed));
                assert_eq!(delivery.current.get(), usize::from(current));
                assert_eq!(delivery.unavailable.get(), usize::from(unavailable));
                let mut events = Vec::new();
                if route {
                    events.push("remote");
                }
                if changed {
                    events.push("push");
                }
                if current {
                    events.push("current");
                }
                if unavailable {
                    events.push("unavailable");
                }
                assert_eq!(*delivery.events.borrow(), events);
                assert!(snapshot(&fixture, &contact).items.is_empty());
                assert!(pending(&fixture, &contact).is_empty());
                assert!(delivery.controls.borrow().is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn remote_removal_and_account_deletion_notify_only_the_remote_contact()
-> Result<(), Box<dyn std::error::Error>> {
    for deleting in [false, true] {
        for (state, pending_out, pending_in, kinds) in [
            (
                SubscriptionState::Both,
                false,
                false,
                vec![PresenceType::Unsubscribe, PresenceType::Unsubscribed],
            ),
            (
                SubscriptionState::From,
                false,
                false,
                vec![PresenceType::Unsubscribed],
            ),
            (
                SubscriptionState::None,
                true,
                false,
                vec![PresenceType::Unsubscribe],
            ),
            (
                SubscriptionState::None,
                false,
                true,
                vec![PresenceType::Unsubscribed],
            ),
        ] {
            let (_directory, fixture) = roster();
            let owner = account("alice@example.com");
            let contact = account("bob@remote.invalid");
            create_account(&fixture, &owner);
            block_on(async {
                let mut tx = fixture.storage.begin_write().await?;
                tx.put_roster_item(
                    &owner,
                    &RosterItem {
                        subscription: RosterSubscription {
                            state,
                            pending_out,
                            approved: true,
                        },
                        ..subscribed(RosterJid::from(&contact), state)
                    },
                    Default::default(),
                )
                .await?;
                if pending_in {
                    tx.put_pending_request(
                        &owner,
                        PendingSubscription {
                            sender: RosterJid::from(&contact),
                            stanza: b"pending".as_slice().into(),
                        },
                        std::num::NonZeroUsize::MIN,
                    )
                    .await?;
                }
                tx.commit().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
            let delivery = RecordingDelivery {
                federated: true,
                ..Default::default()
            };
            block_on(async {
                let mut tx = fixture.storage.begin_write().await?;
                let deliver = if deleting {
                    let before = Arc::new(fixture.storage.begin_read().await?);
                    tx.delete_account(&owner).await?;
                    TestAccountHandler::forget_account(
                        &Roster::default(),
                        &mut tx,
                        &owner,
                        before,
                        &delivery,
                    )
                    .await
                    .map_err(|e| format!("{e:?}"))?
                } else {
                    let effects = super::subscription::remove_item(
                        &Roster::default(),
                        &mut tx,
                        owner.clone(),
                        RosterJid::from(&contact),
                        RosterJid::from(&owner),
                        &delivery,
                    )
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                    assert_eq!(effects.accounts.as_slice(), std::slice::from_ref(&owner));
                    effects.deliver
                };
                tx.commit().await?;
                deliver(&delivery).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            })?;
            let controls = delivery.remote.borrow();
            assert_eq!(controls.len(), kinds.len());
            for (xml, kind) in controls.iter().zip(kinds) {
                let kind = StanzaType::Presence(kind).as_str().ok_or("kind")?;
                assert!(
                    xml.contains(&format!("type=\"{kind}\""))
                        || xml.contains(&format!("type='{kind}'")),
                    "{xml}"
                );
                assert!(
                    xml.contains("from=\"alice@example.com\"")
                        || xml.contains("from='alice@example.com'"),
                    "{xml}"
                );
                assert!(
                    xml.contains("to=\"bob@remote.invalid\"")
                        || xml.contains("to='bob@remote.invalid'"),
                    "{xml}"
                );
                assert!(!xml.contains("/desk"), "{xml}");
            }
            assert_eq!(
                delivery.unavailable.get(),
                usize::from(matches!(
                    state,
                    SubscriptionState::From | SubscriptionState::Both
                ))
            );
            assert_eq!(delivery.pushes.borrow().len(), usize::from(!deleting));
            assert!(snapshot(&fixture, &owner).items.is_empty());
            assert!(pending(&fixture, &owner).is_empty());
            assert!(snapshot(&fixture, &contact).items.is_empty());
            assert!(pending(&fixture, &contact).is_empty());
            assert!(delivery.controls.borrow().is_empty());
        }
    }
    Ok(())
}
