// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramHash, ScramIterations, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::roster::{
    RosterItem, RosterJid, RosterSubscription, RosterWrites, SubscriptionState,
};
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::Arena;
use lonewolf_xmpp::jid::Jid;

use super::support::xml::Element;
use super::support::{C2sSuite, Client, TestResult};

const DECORATION_NAMESPACE: &str = "urn:lonewolf:test:decoration";

fn accounts(suite: &C2sSuite) -> TestResult {
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")
}

fn await_events(client: &mut Client, expected: &[&str]) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        client.send("<iq type='get' to='localhost' id='events'><events xmlns='urn:lonewolf:test:sessions'/></iq>")?;
        let reply = client.receive()?;
        reply.assert_name("jabber:client", "iq");
        assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
        let events = reply.child("urn:lonewolf:test:sessions", "events")?;
        let kinds = events
            .children
            .iter()
            .filter(|event| event.attribute("session") == Some("alice@localhost/a"))
            .map(|event| event.attribute("kind").ok_or("event has no kind"))
            .collect::<Result<Vec<_>, _>>()?;
        if kinds == expected {
            return Ok(());
        }
        assert!(expected.starts_with(&kinds), "unexpected events: {kinds:?}");
        assert!(
            Instant::now() < deadline,
            "events did not finish: {kinds:?}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn session_events_follow_the_resource_lifecycle() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-session-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "password", "a")?;
    let mut bob = suite.connect("bob", "password", "b")?;
    alice.send("<presence id='initial'/>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("initial"));
    alice.send("<presence id='update'><show>away</show></presence>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("update"));
    alice.send("<presence type='unavailable' id='unavailable'/>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("unavailable"));
    alice.close()?;
    await_events(
        &mut bob,
        &[
            "bound",
            "presence:initial",
            "presence:update",
            "presence:unavailable",
            "ended",
        ],
    )?;
    bob.close()
}

#[test]
fn sessions_without_explicit_unavailable_end_with_ended() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-session-observer'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "password", "a")?;
    let mut bob = suite.connect("bob", "password", "b")?;
    alice.send("<presence id='initial'/>")?;
    assert_eq!(alice.receive()?.attribute("id"), Some("initial"));
    drop(alice);
    await_events(&mut bob, &["bound", "presence:initial", "ended"])?;
    bob.close()
}

fn seed_mutual_subscription(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let storage = RedbStorage::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(Default::default())?;
    let alice = Jid::parse_in("alice@localhost", &mut arena)?;
    let bob = Jid::parse_in("bob@localhost", &mut arena)?;
    let alice = AccountKey::try_from(alice.resolve(&arena)?)?;
    let bob = AccountKey::try_from(bob.resolve(&arena)?)?;
    Runtime::new()?.block_on(async {
        let mut transaction = storage.begin_write().await?;
        for (owner, contact) in [(&alice, &bob), (&bob, &alice)] {
            let iterations = ScramIterations::new(SCRAM_POLICY_ITERATIONS.get())?;
            let sha1 = ScramVerifier::derive(ScramHash::Sha1, "password", [1; 16], iterations)?;
            let sha256 = ScramVerifier::derive(ScramHash::Sha256, "password", [2; 16], iterations)?;
            let credentials = match (sha1, sha256) {
                (ScramVerifier::Sha1(sha1), ScramVerifier::Sha256(sha256)) => {
                    ScramCredentials::both(sha1, sha256)
                }
                _ => return Err("unexpected verifier hashes".into()),
            };
            transaction
                .create_account(NewAccount {
                    key: owner.clone(),
                    credentials,
                })
                .await?;
            transaction
                .put_roster_item(
                    owner,
                    &RosterItem {
                        jid: RosterJid::from(contact),
                        name: None,
                        groups: Vec::new(),
                        subscription: RosterSubscription {
                            state: SubscriptionState::Both,
                            pending_out: false,
                            approved: false,
                        },
                    },
                )
                .await?;
        }
        transaction.commit().await?;
        TestResult::Ok(())
    })
}

fn assert_decoration(presence: &Element) -> TestResult {
    presence.assert_name("jabber:client", "presence");
    let children = presence
        .children
        .iter()
        .filter(|child| child.name == "x" && child.namespace == DECORATION_NAMESPACE)
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 1, "{presence:?}");
    assert_eq!(children[0].attribute("n"), Some("1"), "{presence:?}");
    Ok(())
}

#[test]
fn broadcast_presence_carries_the_decoration() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup(
        "'roster', 'test-decoration'",
        seed_mutual_subscription,
    )?;
    let mut alice = suite.connect("alice", "password", "a")?;
    let mut bob = suite.connect("bob", "password", "b")?;
    bob.send("<presence id='bob'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("bob"));
    alice.send(
        "<presence id='alice'><x xmlns='urn:lonewolf:test:decoration' n='client'/></presence>",
    )?;
    let echo = alice.receive()?;
    assert_eq!(echo.attribute("id"), Some("alice"));
    assert_decoration(&echo)?;
    let broadcast = bob.receive()?;
    assert_eq!(broadcast.attribute("id"), Some("alice"));
    assert_decoration(&broadcast)?;
    assert_eq!(echo.children, broadcast.children);
    assert_eq!(alice.receive()?.attribute("id"), Some("bob"));
    alice.close()?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    bob.close()
}

#[test]
fn failing_decorations_leave_the_presence_undecorated() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup(
        "'roster', 'test-decoration', 'test-failing-decoration'",
        seed_mutual_subscription,
    )?;
    let mut alice = suite.connect("alice", "password", "a")?;
    let mut bob = suite.connect("bob", "password", "b")?;
    bob.send("<presence id='bob'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("bob"));
    alice.send("<presence id='alice'/>")?;
    assert_decoration(&alice.receive()?)?;
    let presence = bob.receive()?;
    assert_decoration(&presence)?;
    assert!(
        !presence
            .children
            .iter()
            .any(|child| child.name == "y" && child.namespace == "urn:lonewolf:test:failing"),
        "{presence:?}"
    );
    assert_eq!(alice.receive()?.attribute("id"), Some("bob"));
    alice.close()?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    bob.close()
}

#[test]
fn directed_presence_is_not_decorated() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-decoration'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "password", "a")?;
    let mut bob = suite.connect("bob", "password", "b")?;
    alice.send("<presence to='bob@localhost/b' id='directed'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/a' to='bob@localhost/b' id='directed'/>")?;
    alice.close()?;
    let withdrawal = bob.receive()?;
    assert_eq!(withdrawal.attribute("type"), Some("unavailable"));
    assert!(withdrawal.children.is_empty(), "{withdrawal:?}");
    bob.close()
}

#[test]
fn conflicting_decorations_prevent_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-decoration', 'test-conflicting-decoration'")
        .err()
        .ok_or("server started with conflicting decorations")?;
    assert!(
        error
            .to_string()
            .contains("conflicting presence decorations"),
        "{error}"
    );
    Ok(())
}
