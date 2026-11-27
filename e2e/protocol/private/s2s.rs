// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::workflow::{
    ACCOUNTS, iq_reply, stanza_error, traffic, workflow_options,
};
use crate::support::federation::{FederatedPair, PairOptions};
use crate::support::{PASSWORD, TestResult, barrier};

#[test]
fn remote_private_xml_requests_are_forbidden() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut options = workflow_options();
    options.a_extensions = "'roster'".into();
    options.b_extensions = "'roster', 'private'".into();
    let mut pair = FederatedPair::start(ad, bd, options)?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    b.send("<iq type='set' id='original'><query xmlns='jabber:iq:private'><n xmlns='urn:n'>original</n></query></iq>")?;
    b.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='original' to='{bj}/phone'/>"
    ))?;
    let full = format!("{bj}/phone");
    for (kind, target, payload) in [
        ("get", bj.as_str(), "<n xmlns='urn:n'/>"),
        ("set", bj.as_str(), "<n xmlns='urn:n'>remote</n>"),
        ("get", full.as_str(), "<n xmlns='urn:n'/>"),
        ("set", bd, "<n xmlns='urn:n'>remote</n>"),
    ] {
        a.send(&format!("<iq type='{kind}' id='remote' to='{target}'><query xmlns='jabber:iq:private'>{payload}</query></iq>"))?;
        let reply = iq_reply(&mut a, "remote", "error", target, &format!("{aj}/desk"))?;
        stanza_error(&reply, "forbidden")?;
        assert_eq!(reply.children.len(), 1);
    }
    barrier(&mut b)?;
    b.send(
        "<iq type='get' id='own'><query xmlns='jabber:iq:private'><n xmlns='urn:n'/></query></iq>",
    )?;
    b.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='own' to='{bj}/phone'><query xmlns='jabber:iq:private'><n xmlns='urn:n' xml:lang='' xml:space='default'>original</n></query></iq>"))?;
    traffic(
        &pair,
        "remote_private_xml_requests_are_forbidden",
        [0, 4, 0],
        [0, 4, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn private_xml_requests_to_remote_jids_never_leave_the_server() -> TestResult {
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster', 'private'".into(),
            b_extensions: "'roster', 'private'".into(),
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    let mut a = pair.a.connect("alice", PASSWORD, "desk")?;
    for (kind, target) in [
        ("get", "bob@b.test"),
        ("set", "bob@b.test/phone"),
        ("set", "b.test"),
    ] {
        a.send(&format!("<iq type='{kind}' id='local' to='{target}'><query xmlns='jabber:iq:private'><n xmlns='urn:n'>1</n></query></iq>"))?;
        let reply = iq_reply(&mut a, "local", "error", target, "alice@a.test/desk")?;
        stanza_error(&reply, "forbidden")?;
        assert_eq!(reply.children.len(), 1);
    }
    traffic(
        &pair,
        "private_xml_requests_to_remote_jids_never_leave_the_server",
        [0, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    pair.stop()?;
    Ok(())
}
