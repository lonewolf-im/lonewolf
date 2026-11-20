// SPDX-License-Identifier: Apache-2.0

use super::mutations::{assert_result, send_change};
use crate::support::{C2sSuite, Client, PASSWORD, Signal, TestResult, barrier};

const ALICE: &str = "alice@localhost";
const BOB: &str = "bob@localhost";
const DESK: &str = "bob@localhost/desk";
const PHONE: &str = "bob@localhost/phone";

fn suite() -> TestResult<C2sSuite> {
    let suite = C2sSuite::with_extensions("'roster', 'blocking', 'presence-policy-witness'")?;
    for name in ["alice", "bob", "witness"] {
        suite.create_account(name, PASSWORD)?;
    }
    Ok(suite)
}

fn install_rule(client: &mut Client) -> TestResult {
    send_change(client, "block", "<item jid='BOB@LOCALHOST/phone'/>")?;
    assert_result(&client.receive()?);
    Ok(())
}

fn subscribe(subscriber: &mut Client, from: &str, publisher: &mut Client, to: &str) -> TestResult {
    publisher.send(&format!("<presence type='subscribed' to='{from}'/>"))?;
    barrier(publisher)?;
    subscriber.send(&format!("<presence type='subscribe' to='{to}'/>"))?;
    barrier(subscriber)
}

fn presence(client: &mut Client, from: &str, to: &str, attrs: &str) -> TestResult {
    client.expect_xml(&format!(
        "<presence xmlns='jabber:client' from='{from}' to='{to}' {attrs}/>"
    ))
}

fn available_bob(desk: &mut Client, phone: &mut Client) -> TestResult {
    desk.send("<presence id='desk'/>")?;
    presence(desk, DESK, BOB, "id='desk'")?;
    phone.send("<presence id='phone'/>")?;
    presence(phone, DESK, BOB, "id='desk'")?;
    presence(phone, PHONE, BOB, "id='phone'")?;
    presence(desk, PHONE, BOB, "id='phone'")?;
    barrier(phone)
}

fn after_publication(source: &mut Client, source_jid: &str, witness: &mut Client) -> TestResult {
    source.send("<message to='witness@localhost/check' id='complete'/>")?;
    witness.expect_xml(&format!("<message xmlns='jabber:client' from='{source_jid}' to='witness@localhost/check' id='complete'/>"))
}

#[test]
fn presence_snapshot_excludes_only_the_blocked_source() -> TestResult {
    let suite = suite()?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut desk = suite.connect("bob", PASSWORD, "desk")?;
    let mut phone = suite.connect("bob", PASSWORD, "phone")?;
    let mut witness = suite.connect("witness", PASSWORD, "check")?;
    subscribe(&mut alice, ALICE, &mut desk, BOB)?;
    install_rule(&mut alice)?;
    available_bob(&mut desk, &mut phone)?;

    let before = suite.signal_count(Signal::ConcretePresenceSource)?;
    alice.send("<presence id='online'/>")?;
    after_publication(&mut alice, "alice@localhost/desk", &mut witness)?;
    assert!(
        suite.signal_count(Signal::ConcretePresenceSource)? > before,
        "the allowed full source must be eligible under the recipient's policy"
    );
    presence(&mut alice, "alice@localhost/desk", ALICE, "id='online'")?;
    presence(&mut alice, DESK, ALICE, "id='desk'")?;
    barrier(&mut alice)?;

    alice.send("<presence type='probe' to='bob@localhost' id='current'/>")?;
    presence(&mut alice, DESK, "alice@localhost/desk", "id='desk'")?;
    barrier(&mut alice)?;
    Ok(())
}

#[test]
fn presence_broadcast_excludes_only_the_blocked_target() -> TestResult {
    let suite = suite()?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut desk = suite.connect("bob", PASSWORD, "desk")?;
    let mut phone = suite.connect("bob", PASSWORD, "phone")?;
    let mut witness = suite.connect("witness", PASSWORD, "check")?;
    subscribe(&mut desk, BOB, &mut alice, ALICE)?;
    install_rule(&mut alice)?;
    available_bob(&mut desk, &mut phone)?;

    let before = suite.signal_count(Signal::ConcretePresenceTarget)?;
    for attrs in [
        "id='initial'",
        "id='update'",
        "type='unavailable' id='gone'",
        "id='returned'",
    ] {
        alice.send(&format!("<presence {attrs}/>"))?;
        presence(&mut alice, "alice@localhost/desk", ALICE, attrs)?;
        after_publication(&mut alice, "alice@localhost/desk", &mut witness)?;
        assert!(
            suite.signal_count(Signal::ConcretePresenceTarget)? > before,
            "the allowed full recipient must be eligible under the publisher's policy"
        );
        presence(&mut desk, "alice@localhost/desk", BOB, attrs)?;
        barrier(&mut phone)?;
        barrier(&mut alice)?;
    }
    alice.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    presence(&mut desk, "alice@localhost/desk", BOB, "type='unavailable'")?;
    barrier(&mut phone)?;
    Ok(())
}

#[test]
fn subscription_effects_and_disconnect_respect_policy() -> TestResult {
    let suite = suite()?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut desk = suite.connect("bob", PASSWORD, "desk")?;
    let mut phone = suite.connect("bob", PASSWORD, "phone")?;
    let mut witness = suite.connect("witness", PASSWORD, "check")?;
    install_rule(&mut alice)?;
    available_bob(&mut desk, &mut phone)?;
    alice.send("<presence id='online'/>")?;
    presence(&mut alice, "alice@localhost/desk", ALICE, "id='online'")?;
    alice.send("<presence type='subscribe' to='bob@localhost'/>")?;
    presence(&mut desk, ALICE, BOB, "type='subscribe'")?;
    desk.send("<presence type='subscribed' to='alice@localhost'/>")?;
    after_publication(&mut desk, DESK, &mut witness)?;
    assert!(
        suite.signal_count(Signal::ConcretePresenceSource)? > 0,
        "current presence on grant must evaluate the allowed full source"
    );
    presence(&mut alice, DESK, ALICE, "id='desk'")?;
    barrier(&mut alice)?;
    for id in ["first-update", "second-update"] {
        desk.send(&format!("<presence id='{id}'/>"))?;
        presence(&mut desk, DESK, BOB, &format!("id='{id}'"))?;
        presence(&mut alice, DESK, ALICE, &format!("id='{id}'"))?;
        barrier(&mut alice)?;
    }
    desk.send("<presence type='unsubscribed' to='alice@localhost'/>")?;
    presence(&mut alice, DESK, ALICE, "type='unavailable'")?;
    after_publication(&mut desk, DESK, &mut witness)?;
    barrier(&mut alice)?;

    let mut sibling = suite.connect("alice", PASSWORD, "other")?;
    for (target, closed) in [("alice@localhost/desk", 1), (ALICE, 2)] {
        desk.send(&format!("<presence to='{target}' id='directed'/>"))?;
        presence(&mut alice, DESK, target, "id='directed'")?;
        alice.send("<presence to='bob@localhost' type='probe' id='directed-probe'/>")?;
        presence(
            &mut alice,
            DESK,
            "alice@localhost/desk",
            "id='directed-probe'",
        )?;
        barrier(&mut alice)?;
        sibling.send("<presence to='bob@localhost/desk' type='probe' id='scope'/>")?;
        if target == ALICE {
            presence(&mut sibling, DESK, "alice@localhost/other", "id='scope'")?;
        } else {
            presence(
                &mut sibling,
                BOB,
                "alice@localhost/other",
                "type='unsubscribed' id='scope'",
            )?;
        }
        desk.close()?;
        suite.wait_for_closed("stream_end", closed)?;
        presence(&mut alice, DESK, target, "type='unavailable'")?;
        desk = suite.connect("bob", PASSWORD, "desk")?;
        alice.send("<presence to='bob@localhost/desk' type='probe' id='new-holder'/>")?;
        presence(
            &mut alice,
            BOB,
            "alice@localhost/desk",
            "type='unsubscribed' id='new-holder'",
        )?;
    }
    Ok(())
}

#[test]
fn own_resources_keep_each_others_presence_under_a_domain_block() -> TestResult {
    let suite = suite()?;
    let mut desk = suite.connect("bob", PASSWORD, "desk")?;
    let mut phone = suite.connect("bob", PASSWORD, "phone")?;
    send_change(&mut desk, "block", "<item jid='localhost'/>")?;
    assert_result(&desk.receive()?);
    available_bob(&mut desk, &mut phone)?;
    phone.close()?;
    presence(&mut desk, PHONE, BOB, "type='unavailable'")?;
    desk.close()
}

#[test]
fn pending_presence_uses_the_stored_sender_and_the_current_policy() -> TestResult {
    let suite = suite()?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut witness = suite.connect("witness", PASSWORD, "check")?;
    for sender in [&mut bob, &mut witness] {
        sender.send("<presence type='subscribe' to='alice@localhost'/>")?;
        barrier(sender)?;
    }
    send_change(
        &mut alice,
        "block",
        "<item jid='bob@localhost/phone'/><item jid='witness@localhost'/>",
    )?;
    assert_result(&alice.receive()?);
    alice.send("<presence id='online'/>")?;
    presence(&mut alice, "alice@localhost/desk", ALICE, "id='online'")?;
    presence(&mut alice, BOB, ALICE, "type='subscribe'")?;
    barrier(&mut alice)?;
    alice.close()
}
