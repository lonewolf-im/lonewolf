// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use compio::runtime::Runtime;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::offline::OfflineWrites;
use lonewolf_storage::{RedbStorage, Storage, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;

use super::support::{C2sSuite, Client, TestResult};

fn accounts(suite: &C2sSuite) -> TestResult {
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")
}

fn barrier(client: &mut Client, full: &str) -> TestResult {
    client.send(&format!("<message to='{full}' type='chat' id='barrier'/>"))?;
    client.expect_xml(&format!(
        "<message xmlns='jabber:client' from='{full}' to='{full}' type='chat' id='barrier'/>"
    ))
}

fn inspect(
    client: &mut Client,
    owner: &str,
    count: usize,
    through: u64,
    last_to: Option<&str>,
) -> TestResult {
    client.send("<iq type='get' id='inspect'><query xmlns='urn:lonewolf:test:offline'/></iq>")?;
    let last_to = last_to.map_or_else(String::new, |target| format!(" last_to='{target}'"));
    client.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='inspect' to='{owner}'><query xmlns='urn:lonewolf:test:offline' count='{count}' through='{through}'{last_to}/></iq>"))?;
    barrier(client, owner)
}

#[test]
fn chat_and_missing_full_normal_are_stored_without_a_sender_reply() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='bob@localhost' type='chat' id='chat'><body>Hello</body></message>")?;
    alice.send("<message to='bob@localhost/missing' type='normal' id='normal'><body>Hello</body></message>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    inspect(
        &mut bob,
        "bob@localhost/phone",
        2,
        2,
        Some("bob@localhost/missing"),
    )?;
    bob.close()?;
    alice.close()
}

#[test]
fn missing_full_normal_is_rejected_when_another_recipient_resource_is_eligible() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    alice.send("<message to='bob@localhost/missing' type='normal' id='missing'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost/missing' to='alice@localhost/desk' id='missing' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    inspect(&mut bob, "bob@localhost/phone", 0, 0, None)?;
    bob.close()?;
    alice.close()
}

#[test]
fn standalone_chat_states_do_not_consume_the_two_message_quota() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions = ['offline', 'test-offline-inspect']\n[hosts.localhost.offline]\nmax_messages_per_account = 2",
    )?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='bob@localhost' type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>")?;
    alice.send("<message to='bob@localhost' type='chat'><active xmlns='http://jabber.org/protocol/chatstates'/><thread>discussion</thread></message>")?;
    alice.send("<message to='bob@localhost' type='chat' id='first'/>")?;
    alice.send("<message to='bob@localhost' type='chat' id='second'/>")?;
    alice.send("<message to='bob@localhost' type='chat' id='third'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost' to='alice@localhost/desk' id='third' type='error'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    inspect(&mut bob, "bob@localhost/phone", 2, 2, Some("bob@localhost"))?;
    bob.close()?;
    alice.close()
}

#[test]
fn headline_groupchat_and_error_keep_their_existing_offline_behaviour() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='bob@localhost' type='headline' id='headline'/>")?;
    alice.send("<message to='bob@localhost' type='error' id='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    alice.send("<message to='bob@localhost' type='groupchat' id='groupchat'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@localhost' to='alice@localhost/desk' id='groupchat' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    inspect(&mut bob, "bob@localhost/phone", 0, 0, None)?;
    bob.close()?;
    alice.close()
}

#[test]
fn unknown_local_account_still_receives_service_unavailable() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='unknown@localhost' type='chat' id='unknown'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='unknown@localhost' to='alice@localhost/desk' id='unknown' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    alice.close()
}

#[test]
fn negative_priority_recipient_gets_no_live_delivery_and_the_message_is_stored() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    bob.send("<presence><priority>-1</priority></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'><priority>-1</priority></presence>")?;
    alice
        .send("<message to='bob@localhost' type='chat' id='stored'><body>Hello</body></message>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(&mut bob, "bob@localhost/phone", 1, 1, Some("bob@localhost"))?;
    bob.close()?;
    alice.close()
}

#[test]
fn unavailable_sender_can_store_a_message_to_its_own_account() -> TestResult {
    let suite = C2sSuite::with_extensions("'offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='alice@localhost' type='chat' id='self'/>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(
        &mut alice,
        "alice@localhost/desk",
        1,
        1,
        Some("alice@localhost"),
    )?;
    alice.close()
}

#[test]
fn recipient_host_selects_the_handler_and_quota() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions = []\n[hosts.'other.localhost']\nextensions = ['offline']\n[hosts.'other.localhost'.offline]\nmax_messages_per_account = 2\n[hosts.'other.localhost'.tls]\ncertificate_chain_path = 'certificate.pem'\nprivate_key_path = 'private-key.pem'",
    )?;
    suite.create_account("alice", "pencil")?;
    suite.create_account_jid("bob@other.localhost", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='bob@other.localhost' type='chat' id='first'/>")?;
    alice.send("<message to='bob@other.localhost' type='chat' id='second'/>")?;
    alice.send("<message to='bob@other.localhost' type='chat' id='third'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='bob@other.localhost' to='alice@localhost/desk' id='third' type='error'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>")?;
    alice.close()
}

#[test]
fn availability_fixed_before_store_commit_gets_the_chat_live_without_a_delay() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-slow-offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    alice
        .send("<message to='bob@localhost' type='chat' id='raced'><body>Hello</body></message>")?;
    suite.wait_for_log("test offline store waiting")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='raced'><body>Hello</body></message>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(&mut bob, "bob@localhost/phone", 0, 0, None)?;
    bob.close()?;
    alice.close()
}

#[test]
fn full_normal_race_keeps_the_original_target_stored_when_another_resource_becomes_eligible()
-> TestResult {
    let suite = C2sSuite::with_extensions("'test-slow-offline', 'test-offline-inspect'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    alice.send(
        "<message to='bob@localhost/missing' type='normal' id='raced'><body>Hello</body></message>",
    )?;
    suite.wait_for_log("test offline store waiting")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(
        &mut bob,
        "bob@localhost/phone",
        1,
        1,
        Some("bob@localhost/missing"),
    )?;
    bob.close()?;
    alice.close()
}

fn seed_retained_offline_message(directory: &Path) -> TestResult {
    fs::create_dir(directory.join("data"))?;
    let storage = RedbStorage::open(directory.join("data/lonewolf.dat"))?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("bob@localhost", &mut arena)?;
    let key = AccountKey::try_from(jid.resolve(&arena)?)?;
    Runtime::new()?.block_on(async {
        let mut transaction = storage.begin_write().await?;
        transaction
            .create_account(NewAccount {
                key: key.clone(),
                credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                    [11; 16],
                    SCRAM_POLICY_ITERATIONS,
                    [12; 20],
                    [13; 20],
                ))),
            })
            .await?;
        transaction
            .push_offline_message(
                &key,
                1,
                b"<message xmlns='jabber:client' to='bob@localhost'/>",
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    })
}

#[test]
fn deleting_and_recreating_an_account_clears_backlog_when_offline_is_disabled() -> TestResult {
    let suite = C2sSuite::with_extensions_and_setup(
        "'test-offline-inspect'",
        seed_retained_offline_message,
    )?;
    suite.delete_account("bob")?;
    suite.create_account("bob", "secret")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    inspect(&mut bob, "bob@localhost/phone", 0, 0, None)?;
    bob.send("<iq type='set' id='push'><push xmlns='urn:lonewolf:test:offline'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='push' to='bob@localhost/phone'><pushed xmlns='urn:lonewolf:test:offline' sequence='1'/></iq>")?;
    bob.close()
}

#[test]
fn sender_drains_more_than_mailbox_capacity_while_live_acknowledgement_is_blocked() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-blocked-offline-ack'")?;
    accounts(&suite)?;
    suite.create_account("charlie", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    let mut charlie = suite.connect("charlie", "secret", "laptop")?;
    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<message to='bob@localhost' type='chat' id='raced'/>")?;
    suite.wait_for_log("test offline store waiting")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='raced'/>")?;
    suite.wait_for_log("test offline acknowledgement waiting")?;
    for index in 0..80 {
        charlie.send(&format!(
            "<message to='alice@localhost/desk' type='chat' id='incoming-{index}'/>"
        ))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='charlie@localhost/laptop' to='alice@localhost/desk' type='chat' id='incoming-{index}'/>"))?;
    }
    bob.send("<iq to='localhost' type='get' id='release'><release xmlns='urn:lonewolf:test:offline'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' from='localhost' to='bob@localhost/phone' type='result' id='release'><released xmlns='urn:lonewolf:test:offline'/></iq>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(&mut bob, "bob@localhost/phone", 0, 0, None)?;
    charlie.close()?;
    bob.close()?;
    alice.close()
}

#[test]
fn failed_live_acknowledgement_retains_the_stored_copy_and_logs_once() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-blocked-offline-ack'")?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = suite.connect("bob", "secret", "phone")?;
    alice.send("<message to='bob@localhost' type='chat' id='raced'/>")?;
    suite.wait_for_log("test offline store waiting")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='raced'/>")?;
    suite.wait_for_log("test offline acknowledgement waiting")?;
    bob.send("<iq to='localhost' type='get' id='release'><release xmlns='urn:lonewolf:test:offline' fail='true'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' from='localhost' to='bob@localhost/phone' type='result' id='release'><released xmlns='urn:lonewolf:test:offline'/></iq>")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    inspect(&mut bob, "bob@localhost/phone", 1, 1, Some("bob@localhost"))?;
    let logs = suite.wait_for_log("offline message acknowledgement failed")?;
    assert_eq!(
        logs.matches("offline message acknowledgement failed")
            .count(),
        1
    );
    bob.close()?;
    alice.close()
}
