// SPDX-License-Identifier: Apache-2.0

use std::sync::Barrier;
use std::thread;

use super::{C2sSuite, Client, TestResult, request_roster};

const CAP_ONE: &str = "[hosts.localhost]\nextensions = ['roster']\n[hosts.localhost.roster]\nmax_pending_subscription_requests = 1";

fn accounts(suite: &C2sSuite) -> TestResult {
    for name in ["alice", "bob", "carol", "dave"] {
        suite.create_account(name, "password")?;
    }
    Ok(())
}

fn barrier(client: &mut Client, full: &str) -> TestResult {
    client.send(&format!("<message to='{full}' id='barrier'/>"))?;
    client.expect_xml(&format!(
        "<message xmlns='jabber:client' from='{full}' to='{full}' id='barrier'/>"
    ))
}

fn subscribe(client: &mut Client, target: &str, id: &str) -> TestResult {
    client.send(&format!(
        "<presence to='{target}' type='subscribe' id='{id}'/>"
    ))
}

fn expect_overflow(client: &mut Client, from: &str, to: &str, id: &str) -> TestResult {
    client.expect_xml(&format!("<presence xmlns='jabber:client' from='{from}' to='{to}' type='error' id='{id}'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"))
}

fn available(client: &mut Client, full: &str, bare: &str) -> TestResult {
    client.send("<presence/>")?;
    client.expect_xml(&format!(
        "<presence xmlns='jabber:client' from='{full}' to='{bare}'/>"
    ))
}

#[test]
fn duplicate_resources_refresh_one_pending_request_and_disconnect_keeps_capacity_used() -> TestResult
{
    let suite = C2sSuite::with_hosts(CAP_ONE)?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut alice_phone = suite.connect("alice", "password", "phone")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    subscribe(&mut alice, "bob@localhost", "first")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    subscribe(&mut alice_phone, "bob@localhost", "refreshed")?;
    barrier(&mut alice_phone, "alice@localhost/phone")?;
    alice.close()?;
    alice_phone.close()?;
    subscribe(&mut carol, "bob@localhost", "rejected")?;
    expect_overflow(
        &mut carol,
        "bob@localhost",
        "carol@localhost/desk",
        "rejected",
    )?;
    request_roster(
        &mut carol,
        "unchanged",
        "<iq xmlns='jabber:client' type='result' id='unchanged' to='carol@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>",
    )?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    available(&mut bob, "bob@localhost/phone", "bob@localhost")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost' to='bob@localhost' type='subscribe' id='refreshed'/>")?;
    barrier(&mut bob, "bob@localhost/phone")?;
    barrier(&mut carol, "carol@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn listeners_and_workers_share_one_recipient_pending_limit() -> TestResult {
    let suite = C2sSuite::with_hosts_and_profile(
        &format!(
            "{CAP_ONE}\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'second'\n[limits.c2s.profiles.second]\nmax_stanza_bytes = 32768"
        ),
        "default",
    )?;
    accounts(&suite)?;
    let mut alice = Client::connect_at(
        &suite,
        suite.listener_address(0)?,
        "alice",
        "password",
        "desk",
    )?;
    let mut carol = Client::connect_at(
        &suite,
        suite.listener_address(1)?,
        "carol",
        "password",
        "phone",
    )?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    available(&mut bob, "bob@localhost/phone", "bob@localhost")?;
    let start = Barrier::new(2);
    let outcomes = thread::scope(|scope| -> TestResult<Vec<bool>> {
        let mut writers = Vec::new();
        for (client, full, id) in [
            (&mut alice, "alice@localhost/desk", "alice-request"),
            (&mut carol, "carol@localhost/phone", "carol-request"),
        ] {
            let start = &start;
            writers.push(scope.spawn(move || -> Result<bool, String> {
                (|| -> TestResult<bool> {
                    start.wait();
                    subscribe(client, "bob@localhost", id)?;
                    client.send(&format!("<message to='{full}' id='barrier'/>"))?;
                    let first = client.receive()?;
                    let accepted = first.name == "message";
                    if !accepted {
                        first.assert_xml(&format!("<presence xmlns='jabber:client' from='bob@localhost' to='{full}' type='error' id='{id}'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"))?;
                        client.expect_xml(&format!("<message xmlns='jabber:client' from='{full}' to='{full}' id='barrier'/>"))?;
                    } else {
                        first.assert_xml(&format!("<message xmlns='jabber:client' from='{full}' to='{full}' id='barrier'/>"))?;
                    }
                    Ok(accepted)
                })().map_err(|error| error.to_string())
            }));
        }
        writers
            .into_iter()
            .map(|writer| {
                writer
                    .join()
                    .map_err(|_| "requester panicked")?
                    .map_err(Into::into)
            })
            .collect()
    })?;
    assert_eq!(outcomes.iter().filter(|accepted| **accepted).count(), 1);
    let (sender, id) = if outcomes[0] {
        ("alice", "alice-request")
    } else {
        ("carol", "carol-request")
    };
    bob.expect_xml(&format!("<presence xmlns='jabber:client' from='{sender}@localhost' to='bob@localhost' type='subscribe' id='{id}'/>"))?;
    barrier(&mut bob, "bob@localhost/phone")?;
    bob.close()?;
    alice.close()?;
    carol.close()
}

#[test]
fn pending_limit_uses_the_recipient_host_override() -> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions = ['roster']\n[hosts.localhost.roster]\nmax_pending_subscription_requests = 3\n[hosts.'other.localhost']\nextensions = ['roster']\n[hosts.'other.localhost'.roster]\nmax_pending_subscription_requests = 1\n[hosts.'other.localhost'.tls]\ncertificate_chain_path = 'certificate.pem'\nprivate_key_path = 'private-key.pem'",
    )?;
    accounts(&suite)?;
    suite.create_account_jid("bob@other.localhost", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    subscribe(&mut alice, "bob@other.localhost", "first")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    subscribe(&mut carol, "bob@other.localhost", "rejected")?;
    expect_overflow(
        &mut carol,
        "bob@other.localhost",
        "carol@localhost/desk",
        "rejected",
    )?;
    subscribe(&mut alice, "bob@localhost", "local-first")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    subscribe(&mut carol, "bob@localhost", "local-second")?;
    barrier(&mut carol, "carol@localhost/desk")?;
    alice.close()?;
    carol.close()
}

#[test]
fn approval_denial_and_withdrawal_each_release_pending_capacity() -> TestResult {
    for resolution in ["subscribed", "unsubscribed", "unsubscribe"] {
        let suite = C2sSuite::with_hosts(CAP_ONE)?;
        accounts(&suite)?;
        let mut alice = suite.connect("alice", "password", "desk")?;
        let mut carol = suite.connect("carol", "password", "desk")?;
        let mut bob = suite.connect("bob", "password", "phone")?;
        subscribe(&mut alice, "bob@localhost", "first")?;
        barrier(&mut alice, "alice@localhost/desk")?;
        subscribe(&mut carol, "bob@localhost", "full")?;
        expect_overflow(&mut carol, "bob@localhost", "carol@localhost/desk", "full")?;
        if resolution == "unsubscribe" {
            alice.send("<presence to='bob@localhost' type='unsubscribe'/>")?;
            barrier(&mut alice, "alice@localhost/desk")?;
        } else {
            bob.send(&format!(
                "<presence to='alice@localhost' type='{resolution}'/>"
            ))?;
            barrier(&mut bob, "bob@localhost/phone")?;
        }
        subscribe(&mut carol, "bob@localhost", "admitted")?;
        barrier(&mut carol, "carol@localhost/desk")?;
        available(&mut bob, "bob@localhost/phone", "bob@localhost")?;
        bob.expect_xml("<presence xmlns='jabber:client' from='carol@localhost' to='bob@localhost' type='subscribe' id='admitted'/>")?;
        barrier(&mut bob, "bob@localhost/phone")?;
        bob.close()?;
        alice.close()?;
        carol.close()?;
    }
    Ok(())
}

#[test]
fn deleting_requesters_and_recreating_recipients_releases_pending_capacity() -> TestResult {
    let suite = C2sSuite::with_hosts(CAP_ONE)?;
    accounts(&suite)?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    let mut dave = suite.connect("dave", "password", "desk")?;
    subscribe(&mut alice, "bob@localhost", "first")?;
    barrier(&mut alice, "alice@localhost/desk")?;
    subscribe(&mut carol, "bob@localhost", "full")?;
    expect_overflow(&mut carol, "bob@localhost", "carol@localhost/desk", "full")?;
    suite.delete_account("alice")?;
    alice.expect_stream_error("not-authorized")?;
    subscribe(&mut carol, "bob@localhost", "after-sender-deletion")?;
    barrier(&mut carol, "carol@localhost/desk")?;
    subscribe(&mut dave, "bob@localhost", "full-again")?;
    expect_overflow(
        &mut dave,
        "bob@localhost",
        "dave@localhost/desk",
        "full-again",
    )?;
    suite.delete_account("bob")?;
    suite.create_account("bob", "password")?;
    subscribe(&mut dave, "bob@localhost", "after-recreation")?;
    barrier(&mut dave, "dave@localhost/desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    available(&mut bob, "bob@localhost/phone", "bob@localhost")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='dave@localhost' to='bob@localhost' type='subscribe' id='after-recreation'/>")?;
    barrier(&mut bob, "bob@localhost/phone")?;
    bob.close()?;
    carol.close()?;
    dave.close()
}
