// SPDX-License-Identifier: Apache-2.0

mod state;

use std::cell::{Cell, RefCell};

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
use crate::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HandlerError, HostLookup, SessionTag, StanzaFactory,
};
use crate::iq::{IqHandler, IqReply, IqRequest, IqRequestType};
use crate::presence::{
    PresenceAudience, PresenceHandler, PresenceRequest, PresenceRequestType, PresenceTransition,
    PresenceUpdate,
};
use crate::{Effects, Extension};

type TestIqHandler = dyn IqHandler<GlobalChunkAllocator, RedbStorage>;
type TestPresenceHandler = dyn PresenceHandler<GlobalChunkAllocator, RedbStorage>;
type TestExtension = dyn Extension<GlobalChunkAllocator, RedbStorage>;

/// The storage the roster extension acts on in a test.
struct TestRoster {
    storage: RedbStorage,
}

#[derive(Default)]
struct RecordingDelivery {
    tags: RefCell<Vec<SessionTag>>,
    pushes: RefCell<Vec<String>>,
    /// How many upcoming tagged deliveries fail.
    failing_deliveries: Cell<usize>,
}

impl HostLookup for RecordingDelivery {
    fn is_local_host(&self, domain: &str) -> bool {
        domain == "example.com"
    }
}

impl Delivery<GlobalChunkAllocator> for RecordingDelivery {
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
        _: RoutedStanza<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        let remaining = self.failing_deliveries.get();
        if remaining > 0 {
            self.failing_deliveries.set(remaining - 1);
            return Box::pin(async { Err(DeliveryError) });
        }
        Box::pin(async { Ok(()) })
    }

    fn push_to_session<'a>(
        &'a self,
        build: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        self.record_push("alice@example.com/desk", build);
        Box::pin(async { Ok(()) })
    }

    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        _: SessionTag,
        build: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        self.record_push(&format!("{}/desk", account.as_str()), build);
        Box::pin(async { Ok(()) })
    }

    fn current_presence<'a>(&'a self, _: &'a AccountKey, _: &'a AccountKey) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn unavailable_presence<'a>(
        &'a self,
        _: &'a AccountKey,
        _: &'a AccountKey,
    ) -> DeliveryFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

impl RecordingDelivery {
    fn record_push(&self, to: &str, mut build: StanzaFactory<GlobalChunkAllocator>) {
        let mut arena =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let to = Jid::parse_in(to, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let push = build(to, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let mut xml = String::new();
        push.resolve(&arena)
            .and_then(|push| {
                push.write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write push"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        self.pushes.borrow_mut().push(xml);
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
        transaction.roster(owner).await
    })
    .unwrap_or_else(|error: RosterError| panic!("{error}"))
}

fn item(roster: &TestRoster, owner: &AccountKey, jid: &RosterJid) -> Option<RosterItem> {
    block_on(async {
        let transaction = roster.storage.begin_read().await?;
        transaction.roster_item(owner, jid).await
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

/// A roster IQ from alice's desk whose borrowed arenas outlive the handler future.
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
    ) -> Result<IqReply<GlobalChunkAllocator>, HandlerError> {
        let sender = self
            .sender
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = self
            .query
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = IqRequest {
            sender,
            target: sender.bare(),
            payload,
        };
        match kind {
            IqRequestType::Get => {
                let transaction = roster
                    .storage
                    .begin_read()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                TestIqHandler::get(&Roster, request, &transaction, &mut self.response).await
            }
            IqRequestType::Set => {
                let mut transaction = roster
                    .storage
                    .begin_write()
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let reply = TestIqHandler::set(
                    &Roster,
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
) -> Result<Vec<AccountKey>, HandlerError> {
    let mut call = IqCall::new(item_jid);
    let reply = block_on(call.handle(roster, kind, delivery))?;
    let Effects { accounts, deliver } = reply.effects;
    block_on(deliver(delivery)).unwrap_or_else(|error| panic!("{error}"));
    Ok(accounts)
}

/// Answers a roster get from alice's desk and returns the result payload as XML, after
/// running its effects against `delivery`.
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
        let version = transaction.put_roster_item(owner, &item).await?;
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

/// A subscription request as the target host receives it, with bare addresses.
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
            &Roster,
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
        TestPresenceHandler::audience(&Roster, PresenceUpdate { sender, transition }, &transaction)
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
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn versioned_roster_get_answers_from_the_version_the_client_holds() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    create_account(&roster, &alice);
    put_item(&roster, &alice, "bob@example.com");
    put_item(&roster, &alice, "carol@example.com");
    let delivery = RecordingDelivery::default();

    for unknown in ["", "abc", "9"] {
        let payload = roster_get(&roster, Some(unknown), &delivery)
            .unwrap_or_else(|| panic!("no payload for {unknown:?}"));
        assert!(payload.contains(r#"ver="2""#), "{payload}");
        assert!(payload.contains(r#"jid="bob@example.com""#), "{payload}");
        assert!(payload.contains(r#"jid="carol@example.com""#), "{payload}");
    }
    assert!(delivery.pushes.borrow().is_empty());

    assert!(roster_get(&roster, Some("2"), &delivery).is_none());
    assert!(delivery.pushes.borrow().is_empty());

    assert!(roster_get(&roster, Some("1"), &delivery).is_none());
    {
        let pushes = delivery.pushes.borrow();
        assert_eq!(pushes.len(), 1, "{pushes:?}");
        assert!(
            pushes[0].contains(r#"jid="carol@example.com""#),
            "{pushes:?}"
        );
        assert!(pushes[0].contains(r#"ver="2""#), "{pushes:?}");
        assert!(pushes[0].contains(r#"id="roster-2""#), "{pushes:?}");
        assert!(
            pushes[0].contains(r#"to="alice@example.com/desk""#),
            "{pushes:?}"
        );
    }
    delivery.pushes.borrow_mut().clear();

    assert!(roster_get(&roster, Some("0"), &delivery).is_none());
    let pushes = delivery.pushes.borrow();
    assert_eq!(pushes.len(), 2, "{pushes:?}");
    assert!(pushes[0].contains(r#"jid="bob@example.com""#), "{pushes:?}");
    assert!(pushes[0].contains(r#"ver="1""#), "{pushes:?}");
    assert!(
        pushes[1].contains(r#"jid="carol@example.com""#),
        "{pushes:?}"
    );
    assert!(pushes[1].contains(r#"ver="2""#), "{pushes:?}");
}

#[test]
fn versioned_roster_get_behind_a_removal_returns_the_whole_roster() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    create_account(&roster, &alice);
    put_item(&roster, &alice, "bob@example.com");
    put_item(&roster, &alice, "carol@example.com");
    assert_eq!(remove_item(&roster, &alice, "bob@example.com").get(), 3);
    let delivery = RecordingDelivery::default();

    let payload = roster_get(&roster, Some("2"), &delivery).unwrap_or_else(|| panic!("no payload"));
    assert!(payload.contains(r#"ver="3""#), "{payload}");
    assert!(payload.contains(r#"jid="carol@example.com""#), "{payload}");
    assert!(!payload.contains(r#"jid="bob@example.com""#), "{payload}");
    assert!(delivery.pushes.borrow().is_empty());

    assert!(roster_get(&roster, Some("3"), &delivery).is_none());
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
            Err(HandlerError::Stanza(StanzaErrorCondition::Forbidden))
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
            )
            .await?;
        transaction
            .put_roster_item(
                &bob_account,
                &subscribed(RosterJid::from(alice.bare()), SubscriptionState::From),
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
            )
            .await?;
        repository
            .put_roster_item(
                bob,
                &subscribed(RosterJid::from(alice), SubscriptionState::From),
            )
            .await?;
        repository
            .put_roster_item(
                alice,
                &subscribed(RosterJid::from(carol), SubscriptionState::Both),
            )
            .await?;
        repository
            .put_roster_item(
                carol,
                &subscribed(RosterJid::from(alice), SubscriptionState::Both),
            )
            .await?;
        repository
            .put_roster_item(
                alice,
                &subscribed(RosterJid::from(dave), SubscriptionState::Both),
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
        let effects = TestExtension::forget_account(&Roster, &mut transaction, alice, &delivery)
            .await
            .map_err(|error| format!("{error:?}"))?;
        transaction.commit().await?;
        Ok::<_, Box<dyn std::error::Error>>(effects)
    })
    .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        names(&effects.accounts),
        ["alice@example.com", "bob@example.com", "carol@example.com"]
    );
    let result = block_on((effects.deliver)(&delivery));
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
