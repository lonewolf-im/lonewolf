// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::workflow::{ACCOUNTS, iq_reply, stanza_error, traffic};
use crate::support::federation::{FederatedPair, PairOptions};
use crate::support::{PASSWORD, TestResult};

#[test]
fn software_version_of_remote_server() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(
        ad,
        bd,
        PairOptions {
            a_extensions: "'roster', 'version'".into(),
            b_extensions: "'roster', 'version'".into(),
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    a.send(&format!(
        "<iq type='get' id='server-version' to='{bd}'><query xmlns='jabber:iq:version'/></iq>"
    ))?;
    let reply = iq_reply(
        &mut a,
        "server-version",
        "result",
        bd,
        &format!("{aj}/desk"),
    )?;
    let query = reply.child("jabber:iq:version", "query")?;
    assert_eq!(query.child("jabber:iq:version", "name")?.text, "Lonewolf");
    assert_eq!(
        query.child("jabber:iq:version", "version")?.text,
        "integration-test"
    );
    assert!(!query.children.iter().any(|child| child.name == "os"));
    a.send(&format!(
        "<iq type='get' id='account-version' to='{bj}'><query xmlns='jabber:iq:version'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(
            &mut a,
            "account-version",
            "error",
            &bj,
            &format!("{aj}/desk"),
        )?,
        "service-unavailable",
    )?;
    traffic(
        &pair,
        "software_version_of_remote_server",
        [0, 2, 0],
        [0, 2, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn remote_software_version_follows_each_servers_settings() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster'".into(),
            b_extensions: "'roster', 'version'".into(),
            b_extra_toml: "[hosts.\"b.test\".version]\nshow_os = true".into(),
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut a = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut b = pair.b.connect("bob", PASSWORD, "phone")?;
    a.send(
        "<iq type='get' id='remote-version' to='b.test'><query xmlns='jabber:iq:version'/></iq>",
    )?;
    let reply = iq_reply(
        &mut a,
        "remote-version",
        "result",
        "b.test",
        "alice@a.test/desk",
    )?;
    let query = reply.child("jabber:iq:version", "query")?;
    assert_eq!(query.child("jabber:iq:version", "name")?.text, "Lonewolf");
    assert_eq!(
        query.child("jabber:iq:version", "version")?.text,
        "integration-test"
    );
    assert_eq!(
        query.child("jabber:iq:version", "os")?.text,
        std::env::consts::OS
    );
    b.send(
        "<iq type='get' id='local-version' to='a.test'><query xmlns='jabber:iq:version'/></iq>",
    )?;
    stanza_error(
        &iq_reply(
            &mut b,
            "local-version",
            "error",
            "a.test",
            "bob@b.test/phone",
        )?,
        "service-unavailable",
    )?;
    traffic(
        &pair,
        "remote_software_version_follows_each_servers_settings",
        [0, 2, 0],
        [0, 2, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()
}
