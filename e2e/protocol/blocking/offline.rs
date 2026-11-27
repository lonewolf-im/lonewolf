// SPDX-License-Identifier: Apache-2.0

use lonewolf_extension::REPLAY_PAGE_BYTES;

use crate::offline::{await_empty, receive_stored};
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

fn suite(users: &[&str]) -> TestResult<C2sSuite> {
    let suite = C2sSuite::with_extensions("'offline', 'blocking', 'test-offline-inspect'")?;
    for user in users {
        suite.create_account(user, PASSWORD)?;
    }
    Ok(suite)
}

fn change(client: &mut Client, command: &str, peer: &str) -> TestResult {
    client.send(&format!("<iq type='set' id='list-change'><{command} xmlns='urn:xmpp:blocking'><item jid='{peer}'/></{command}></iq>"))?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("id"), Some("list-change"));
    assert_eq!(reply.attribute("type"), Some("result"));
    assert!(reply.children.is_empty());
    Ok(())
}

fn queue(client: &mut Client, id: &str, body: &str) -> TestResult {
    client.send(&format!(
        "<message to='bob@localhost' type='chat' id='{id}'><body>{body}</body></message>"
    ))?;
    barrier(client)
}

fn available(bob: &mut Client, resource: &str) -> TestResult {
    bob.send("<presence/>")?;
    bob.expect_xml(&format!(
        "<presence xmlns='jabber:client' from='bob@localhost/{resource}' to='bob@localhost'/>"
    ))
}

#[test]
fn offline_backlog_rechecks_first_and_later_pages() -> TestResult {
    let suite = suite(&["alice", "bob"])?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let body = "x".repeat(REPLAY_PAGE_BYTES.get() / 3);
    queue(&mut phone, "first", &body)?;
    queue(&mut desk, "second", &body)?;
    queue(&mut phone, "third", &body)?;
    queue(&mut desk, "fourth", &body)?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    change(&mut bob, "block", "alice@localhost/phone")?;
    available(&mut bob, "tablet")?;
    for id in ["second", "fourth"] {
        let message = bob.receive()?;
        assert_eq!(message.attribute("id"), Some(id));
        assert_eq!(message.attribute("from"), Some("alice@localhost/desk"));
        assert_eq!(message.child("jabber:client", "body")?.text, body);
    }
    await_empty(&mut bob, "bob@localhost/tablet")?;
    let metrics = suite.scrape_metrics()?;
    let pages = metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                r#"lonewolf_c2s_replay_pages_total{listener="0",kind="offline_message"} "#,
            )
        })
        .ok_or("missing offline replay page count")?;
    assert!(pages.parse::<u64>()? >= 2);
    change(&mut bob, "unblock", "alice@localhost/phone")?;
    bob.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    let mut bob = suite.connect("bob", PASSWORD, "tablet")?;
    available(&mut bob, "tablet")?;
    barrier(&mut bob)?;
    barrier(&mut phone)?;
    barrier(&mut desk)?;
    bob.close()
}

#[test]
fn blocked_offline_replay_records_a_bounded_sample() -> TestResult {
    let suite = suite(&["alice", "bob", "carol", "witness"])?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    let mut witness = suite.connect("witness", PASSWORD, "desk")?;
    queue(&mut alice, "deferred", "one")?;
    queue(&mut carol, "discarded", "two")?;
    queue(&mut witness, "allowed", "three")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    change(&mut bob, "block", "carol@localhost")?;
    change(&mut alice, "block", "bob@localhost/phone")?;
    available(&mut bob, "phone")?;
    bob.send("<message to='witness@localhost/desk' id='replay-complete'/>")?;
    witness.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='witness@localhost/desk' id='replay-complete'/>")?;
    let metrics = suite.scrape_metrics()?;
    let samples: Vec<_> = metrics
        .lines()
        .filter(|line| {
            line.starts_with("lonewolf_c2s_replay_records_total{")
                && line.contains(r#"kind="offline_message""#)
        })
        .collect();
    assert_eq!(samples.len(), 3);
    for wanted in [
        r#"lonewolf_c2s_replay_records_total{listener="0",kind="offline_message",outcome="blocked"} 2"#,
        r#"lonewolf_c2s_replay_records_total{listener="0",kind="offline_message",outcome="delivered"} 1"#,
        r#"lonewolf_c2s_replay_records_total{listener="0",kind="offline_message",outcome="invalid"} 0"#,
    ] {
        assert!(samples.contains(&wanted), "missing {wanted} in {samples:?}");
    }
    receive_stored(
        &mut bob,
        "<message xmlns='jabber:client' from='witness@localhost/desk' to='bob@localhost' type='chat' id='allowed'><body>three</body></message>",
    )?;
    barrier(&mut bob)?;
    bob.close()
}
