// SPDX-License-Identifier: Apache-2.0

use super::addressed::checked_error;
use super::mutations::{assert_result, send_change};
use crate::support::{C2sSuite, Client, PASSWORD, TestResult};

const ALICE: &str = "alice@localhost/desk";
const BOB: &str = "bob@localhost/desk";
const BOB_ITEM: &str = "<item jid='bob@localhost'/>";
const HIT: &str =
    r#"lonewolf_storage_blocklist_cache_lookups_total{store="primary",outcome="hit"}"#;
const MISS: &str =
    r#"lonewolf_storage_blocklist_cache_lookups_total{store="primary",outcome="miss"}"#;
const BYPASS: &str =
    r#"lonewolf_storage_blocklist_cache_lookups_total{store="primary",outcome="bypass"}"#;
const WRITTEN: &str =
    r#"lonewolf_storage_blocklist_cache_updates_total{store="primary",outcome="written"}"#;

fn connect_pair() -> TestResult<(C2sSuite, Client, Client)> {
    let suite = C2sSuite::with_extensions("'blocking'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let alice = suite.connect("alice", PASSWORD, "desk")?;
    let bob = suite.connect("bob", PASSWORD, "desk")?;
    Ok((suite, alice, bob))
}

fn deliver(
    sender: &mut Client,
    from: &str,
    recipient: &mut Client,
    to: &str,
    id: &str,
) -> TestResult {
    sender.send(&format!("<message to='{to}' id='{id}'/>"))?;
    recipient.expect_xml(&format!(
        "<message xmlns='jabber:client' from='{from}' to='{to}' id='{id}'/>"
    ))
}

#[test]
fn steady_messages_use_cached_blocklists() -> TestResult {
    let (mut suite, mut alice, mut bob) = connect_pair()?;
    deliver(&mut alice, ALICE, &mut bob, BOB, "warm")?;
    deliver(&mut bob, BOB, &mut alice, ALICE, "warm")?;
    let hits = suite.metric_value(HIT)?;
    let misses = suite.metric_value(MISS)?;
    let bypasses = suite.metric_value(BYPASS)?;

    for sequence in 0..20 {
        let id = sequence.to_string();
        deliver(&mut alice, ALICE, &mut bob, BOB, &id)?;
        deliver(&mut bob, BOB, &mut alice, ALICE, &id)?;
    }
    assert!(suite.metric_value(HIT)? >= hits + 80);
    assert_eq!(suite.metric_value(MISS)?, misses);
    assert_eq!(suite.metric_value(BYPASS)?, bypasses);
    alice.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn block_applies_to_the_next_stanza_without_a_reload() -> TestResult {
    let (mut suite, mut alice, mut bob) = connect_pair()?;
    deliver(&mut alice, ALICE, &mut bob, BOB, "warm")?;
    deliver(&mut bob, BOB, &mut alice, ALICE, "warm")?;
    let misses = suite.metric_value(MISS)?;
    let written = suite.metric_value(WRITTEN)?;

    send_change(&mut alice, "block", BOB_ITEM)?;
    assert_result(&alice.receive()?);
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut bob, "message", false)?;
    alice.send("<message to='bob@localhost/desk' id='attempt'/>")?;
    checked_error(&mut alice, "message", true)?;
    send_change(&mut alice, "unblock", BOB_ITEM)?;
    assert_result(&alice.receive()?);
    deliver(&mut bob, BOB, &mut alice, ALICE, "allowed")?;

    assert_eq!(suite.metric_value(MISS)?, misses);
    assert_eq!(suite.metric_value(WRITTEN)?, written + 2);
    alice.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn recreated_account_starts_with_an_empty_cached_list() -> TestResult {
    let (mut suite, mut alice, mut bob) = connect_pair()?;
    send_change(&mut alice, "block", BOB_ITEM)?;
    assert_result(&alice.receive()?);
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut bob, "message", false)?;
    alice.close()?;
    suite.delete_account("alice")?;
    suite.create_account("alice", PASSWORD)?;
    let mut recreated = suite.connect("alice", PASSWORD, "desk")?;
    deliver(&mut bob, BOB, &mut recreated, ALICE, "recreated")?;
    recreated.close()?;
    bob.close()?;
    suite.stop()
}

const OPENED: &str = r#"lonewolf_storage_read_snapshots_total{store="primary",outcome="opened"}"#;
const REUSED: &str = r#"lonewolf_storage_read_snapshots_total{store="primary",outcome="reused"}"#;

#[test]
fn steady_messages_reuse_one_snapshot() -> TestResult {
    let (mut suite, mut alice, mut bob) = connect_pair()?;
    deliver(&mut alice, ALICE, &mut bob, BOB, "warm")?;
    deliver(&mut bob, BOB, &mut alice, ALICE, "warm")?;
    let opened = suite.metric_value(OPENED)?;
    let reused = suite.metric_value(REUSED)?;

    for sequence in 0..20 {
        let id = sequence.to_string();
        deliver(&mut alice, ALICE, &mut bob, BOB, &id)?;
        deliver(&mut bob, BOB, &mut alice, ALICE, &id)?;
    }
    assert_eq!(suite.metric_value(OPENED)?, opened);
    assert!(suite.metric_value(REUSED)? >= reused + 40);
    alice.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn a_commit_makes_the_next_stanza_open_a_new_snapshot() -> TestResult {
    let (mut suite, mut alice, mut bob) = connect_pair()?;
    deliver(&mut alice, ALICE, &mut bob, BOB, "warm")?;
    deliver(&mut bob, BOB, &mut alice, ALICE, "warm")?;
    let opened = suite.metric_value(OPENED)?;
    let misses = suite.metric_value(MISS)?;

    send_change(&mut alice, "block", BOB_ITEM)?;
    assert_result(&alice.receive()?);
    bob.send("<message to='alice@localhost/desk' id='attempt'/>")?;
    checked_error(&mut bob, "message", false)?;
    assert!(suite.metric_value(OPENED)? > opened);
    assert_eq!(suite.metric_value(MISS)?, misses);
    alice.close()?;
    bob.close()?;
    suite.stop()
}
