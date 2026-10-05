// SPDX-License-Identifier: Apache-2.0

use super::support::{C2sSuite, Client, TestResult};

fn sentinel(from: &mut Client, to: &mut Client, target: &str) -> TestResult {
    from.send(&format!("<message to='{target}' id='sentinel'/>"))?;
    let message = to.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("id"), Some("sentinel"), "{message:?}");
    Ok(())
}

#[test]
fn directed_presence_reaches_a_full_and_a_bare_jid_and_broadcasts_skip_them() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    carol.send("<presence/>")?;
    carol.expect_xml(
        "<presence xmlns='jabber:client' from='carol@localhost/desk' to='carol@localhost'/>",
    )?;

    alice.send("<presence to='bob@localhost/desk' id='to-bob'><show>chat</show></presence>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='to-bob' from='alice@localhost/desk' to='bob@localhost/desk'><show>chat</show></presence>")?;
    alice.send("<presence to='carol@localhost' id='to-carol'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' id='to-carol' from='alice@localhost/desk' to='carol@localhost'/>")?;

    alice.send("<presence id='broadcast'><show>away</show></presence>")?;
    alice.expect_xml("<presence xmlns='jabber:client' id='broadcast' from='alice@localhost/desk' to='alice@localhost'><show>away</show></presence>")?;
    sentinel(&mut alice, &mut bob, "bob@localhost/desk")?;
    sentinel(&mut alice, &mut carol, "carol@localhost/desk")?;

    alice.send("<presence type='unavailable' id='gone'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='alice@localhost'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' type='unavailable' id='gone' from='alice@localhost/desk' to='carol@localhost'/>")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn directed_unavailable_presence_forgets_the_recipient() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.send("<presence to='bob@localhost/desk' type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn closing_the_stream_sends_unavailable_to_directed_recipients() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.close()?;

    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    bob.close()
}

#[test]
fn directed_presence_to_an_absent_recipient_is_dropped_silently() -> TestResult {
    let suite = C2sSuite::start()?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut carol = suite.connect("carol", "password", "desk")?;

    for target in [
        "nobody@localhost",
        "bob@localhost/tablet",
        "bob@remote.example",
        "localhost",
    ] {
        alice.send(&format!("<presence to='{target}'/>"))?;
    }
    sentinel(&mut alice, &mut bob, "bob@localhost/desk")?;

    alice.close()?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    bob.close()?;
    carol.close()
}

#[test]
fn repeated_directed_presence_and_the_own_account_are_told_once() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut phone = suite.connect("alice", "password", "phone")?;
    let mut bob = suite.connect("bob", "password", "desk")?;

    alice.send("<presence to='bob@localhost/desk' id='first'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='first' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    alice.send("<presence to='bob@localhost/desk' id='again'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' id='again' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    alice.send("<presence to='alice@localhost/phone' id='self'/>")?;
    phone.expect_xml("<presence xmlns='jabber:client' id='self' from='alice@localhost/desk' to='alice@localhost/phone'/>")?;

    alice.close()?;
    bob.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/desk'/>")?;
    sentinel(&mut phone, &mut bob, "bob@localhost/desk")?;
    bob.send("<message to='alice@localhost/phone' id='sentinel'/>")?;
    let message = phone.receive()?;
    assert_eq!(message.attribute("id"), Some("sentinel"), "{message:?}");
    phone.close()?;
    bob.close()
}

#[test]
fn incoming_directed_unavailable_removes_only_its_full_recipient_grant() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, "password")?;
    }
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "desk")?;
    let mut phone = suite.connect("bob", "password", "phone")?;
    let mut carol = suite.connect("carol", "password", "desk")?;
    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/desk'/>",
    )?;
    alice.send("<presence to='bob@localhost/phone'/>")?;
    phone.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone'/>",
    )?;
    bob.send("<presence to='alice@localhost/desk' type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='bob@localhost/desk' to='alice@localhost/desk'/>")?;
    alice.close()?;
    phone.expect_xml("<presence xmlns='jabber:client' type='unavailable' from='alice@localhost/desk' to='bob@localhost/phone'/>")?;
    sentinel(&mut carol, &mut bob, "bob@localhost/desk")?;
    phone.close()?;
    bob.close()?;
    carol.close()
}
