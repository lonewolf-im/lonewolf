// SPDX-License-Identifier: Apache-2.0

mod state;

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use futures_executor::block_on;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::roster::{
    PendingSubscription, RosterError, RosterItem, RosterJid, RosterReads, RosterSnapshot,
    RosterSubscription, RosterWrites, SubscriptionState,
};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    Element, PresenceType, RoutedStanza, Stanza, StanzaErrorCondition, StanzaNamespace, StanzaType,
};

use super::{NAMESPACE, Roster};
use crate::delivery::{
    Delivery, DeliveryError, DeliveryFuture, HandlerError, SessionTag, StanzaFactory,
};
use crate::iq::{IqFuture, IqHandler, IqRequest, IqRequestType};
use crate::presence::{
    PresenceHandler, PresenceRequest, PresenceRequestType, PresenceTransition, PresenceUpdate,
    ReceiveFuture,
};

type TestRoster = Roster<RedbStorage>;

#[derive(Default)]
struct RecordingDelivery {
    tags: RefCell<Vec<SessionTag>>,
    pushes: RefCell<Vec<String>>,
    /// How many upcoming tagged deliveries fail.
    failing_deliveries: Cell<usize>,
}

impl Delivery<GlobalChunkAllocator> for RecordingDelivery {
    fn arena(&self) -> Result<Arena<GlobalChunkAllocator>, DeliveryError> {
        Arena::try_new(ArenaConfig::default()).map_err(|_| DeliveryError)
    }

    fn is_local_host(&self, domain: &str) -> bool {
        domain == "example.com"
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

    fn push_to_tagged<'a>(
        &'a self,
        account: &'a AccountKey,
        _: SessionTag,
        mut build: StanzaFactory<GlobalChunkAllocator>,
    ) -> DeliveryFuture<'a> {
        let full_jid = format!("{}/desk", account.as_str());
        let mut arena =
            Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
        let to = Jid::parse_in(&full_jid, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let push = build(to, &mut arena).unwrap_or_else(|error| panic!("{error}"));
        let mut xml = String::new();
        push.resolve(&arena)
            .and_then(|push| {
                push.write_xml(&mut xml)
                    .map_err(|_| panic!("cannot write push"))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        self.pushes.borrow_mut().push(xml);
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

fn roster() -> (tempfile::TempDir, TestRoster) {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))
        .unwrap_or_else(|error| panic!("{error}"));
    (directory, Roster::new(storage))
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

fn delete_account(roster: &TestRoster, key: &AccountKey) {
    block_on(async {
        let mut transaction = roster.storage.begin_write().await?;
        transaction.begin_account_deletion(key).await?;
        transaction.commit().await.map_err(Into::into)
    })
    .unwrap_or_else(|error: lonewolf_storage::account::AccountError| panic!("{error}"))
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

    fn handle<'a>(
        &'a mut self,
        roster: &'a TestRoster,
        kind: IqRequestType,
        delivery: &'a RecordingDelivery,
    ) -> IqFuture<'a> {
        let sender = self
            .sender
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = self
            .query
            .resolve(&self.request)
            .unwrap_or_else(|error| panic!("{error}"));
        IqHandler::<GlobalChunkAllocator>::handle(
            roster,
            IqRequest {
                sender,
                target: sender.bare(),
                kind,
                payload,
            },
            &mut self.response,
            delivery,
        )
    }
}

fn handle_iq(
    roster: &TestRoster,
    kind: IqRequestType,
    item_jid: &str,
    delivery: &RecordingDelivery,
) -> Result<(), HandlerError> {
    let mut call = IqCall::new(item_jid);
    block_on(call.handle(roster, kind, delivery)).map(|_| ())
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

    fn receive<'a>(
        &'a self,
        roster: &'a TestRoster,
        delivery: &'a RecordingDelivery,
    ) -> ReceiveFuture<'a> {
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
        PresenceHandler::<GlobalChunkAllocator>::receive(
            roster,
            PresenceRequest {
                kind: PresenceRequestType::Subscribe,
                sender,
                target,
                stanza: &self.stanza,
            },
            delivery,
        )
    }
}

fn receive_subscribe(
    roster: &TestRoster,
    sender: &str,
    target: &str,
    delivery: &RecordingDelivery,
) -> Result<(), HandlerError> {
    let call = SubscribeCall::new(sender, target);
    block_on(call.receive(roster, delivery))
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

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn roster_retrieval_tags_the_requesting_session_as_interested() {
    let (_directory, roster) = roster();
    let delivery = RecordingDelivery::default();
    handle_iq(&roster, IqRequestType::Get, "", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(*delivery.tags.borrow(), [SessionTag::Interested]);
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
    handle_iq(&roster, IqRequestType::Set, "bob@example.com", &delivery)
        .unwrap_or_else(|error| panic!("{error:?}"));
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
fn roster_set_checks_the_account_after_acquiring_its_order() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    create_account(&roster, &alice);
    let delivery = RecordingDelivery::default();
    let mut call = IqCall::new("bob@example.com");
    let order = block_on(roster.order.lock(&alice));
    let mut set = pin!(call.handle(&roster, IqRequestType::Set, &delivery));
    assert!(poll_once(set.as_mut()).is_pending());
    delete_account(&roster, &alice);
    drop(order);
    let result = block_on(set);
    assert!(
        matches!(
            result,
            Err(HandlerError::Stanza(StanzaErrorCondition::Forbidden))
        ),
        "{result:?}"
    );
    assert!(delivery.pushes.borrow().is_empty());
    let alice_roster = snapshot(&roster, &alice);
    assert!(alice_roster.items.is_empty());
}

#[test]
fn subscription_request_checks_the_contact_after_acquiring_the_order() {
    let (_directory, roster) = roster();
    let alice = account("alice@example.com");
    let bob = account("bob@example.com");
    create_account(&roster, &alice);
    create_account(&roster, &bob);
    let delivery = RecordingDelivery::default();
    let call = SubscribeCall::new("bob@example.com", "alice@example.com");
    let order = block_on(roster.order.lock(&alice));
    let mut request = pin!(call.receive(&roster, &delivery));
    assert!(poll_once(request.as_mut()).is_pending());
    delete_account(&roster, &alice);
    drop(order);
    let result = block_on(request);
    assert!(
        matches!(
            result,
            Err(HandlerError::Stanza(
                StanzaErrorCondition::ServiceUnavailable
            ))
        ),
        "{result:?}"
    );
    let pending = pending(&roster, &alice);
    assert!(pending.is_empty());
    let bob_roster = snapshot(&roster, &bob);
    assert!(bob_roster.items.is_empty());
    assert!(delivery.pushes.borrow().is_empty());
}

#[test]
fn availability_audience_holds_the_owner_order_until_dropped() {
    let (_directory, roster) = roster();
    let mut arena =
        Arena::try_new(ArenaConfig::default()).unwrap_or_else(|error| panic!("{error}"));
    let sender = Jid::parse_in("bob@example.com/phone", &mut arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let sender = sender
        .resolve(&arena)
        .unwrap_or_else(|error| panic!("{error}"));
    let owner = AccountKey::try_from(sender.bare()).unwrap_or_else(|error| panic!("{error}"));
    let audience = block_on(PresenceHandler::<GlobalChunkAllocator>::audience(
        &roster,
        PresenceUpdate {
            sender,
            transition: PresenceTransition::Initial,
        },
    ))
    .unwrap_or_else(|error| panic!("{error:?}"))
    .unwrap_or_else(|| panic!("expected an audience"));
    assert!(audience.pending.is_empty());
    assert!(audience.subscribers.is_empty());
    assert!(audience.contacts.is_empty());
    assert!(roster.order.is_locked(&owner));
    drop(audience);
    assert!(!roster.order.is_locked(&owner));
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
        let audience = block_on(PresenceHandler::<GlobalChunkAllocator>::audience(
            &roster,
            PresenceUpdate {
                sender: alice,
                transition,
            },
        ))
        .unwrap_or_else(|error| panic!("{error:?}"))
        .unwrap_or_else(|| panic!("expected an audience"));
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

    let result = block_on(roster.forget_account(alice, &delivery));
    assert!(
        matches!(result, Err(HandlerError::Delivery(_))),
        "{result:?}"
    );

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
