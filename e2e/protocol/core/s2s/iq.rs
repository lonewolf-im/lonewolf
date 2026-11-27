// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::FederatedPair;
use crate::support::federation::subscribe_mutually;
use crate::support::federation::workflow::{
    ACCOUNTS, iq_reply, presence, stanza_error, traffic, workflow_options,
};
use crate::support::{PASSWORD, TestResult};

#[test]
fn iq_to_remote_full_jid_after_subscription_is_answered_by_the_client() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
    for kind in ["get", "set"] {
        a.send(&format!("<iq type='{kind}' id='client-iq' to='{bj}/phone'><query xmlns='urn:test:remote-client'/></iq>"))?;
        let request = b.receive()?;
        request.assert_name("jabber:client", "iq");
        assert_eq!(request.attribute("type"), Some(kind));
        assert_eq!(request.attribute("id"), Some("client-iq"));
        assert_eq!(
            request.attribute("from"),
            Some(format!("{aj}/desk").as_str())
        );
        assert_eq!(
            request.attribute("to"),
            Some(format!("{bj}/phone").as_str())
        );
        request.child("urn:test:remote-client", "query")?;
        b.send(&format!("<iq type='result' id='client-iq' to='{aj}/desk'><answer xmlns='urn:test:remote-client'>{kind}</answer></iq>"))?;
        let reply = iq_reply(
            &mut a,
            "client-iq",
            "result",
            &format!("{bj}/phone"),
            &format!("{aj}/desk"),
        )?;
        assert_eq!(reply.child("urn:test:remote-client", "answer")?.text, kind);
    }
    a.send(&format!("<iq type='get' id='client-error' to='{bj}/phone'><query xmlns='urn:test:remote-client'/></iq>"))?;
    let request = b.receive()?;
    request.assert_name("jabber:client", "iq");
    assert_eq!(request.attribute("type"), Some("get"));
    assert_eq!(request.attribute("id"), Some("client-error"));
    assert_eq!(
        request.attribute("from"),
        Some(format!("{aj}/desk").as_str())
    );
    assert_eq!(
        request.attribute("to"),
        Some(format!("{bj}/phone").as_str())
    );
    request.child("urn:test:remote-client", "query")?;
    b.send(&format!("<iq type='error' id='client-error' to='{aj}/desk'><query xmlns='urn:test:remote-client'/><error type='cancel'><feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"))?;
    stanza_error(
        &iq_reply(
            &mut a,
            "client-error",
            "error",
            &format!("{bj}/phone"),
            &format!("{aj}/desk"),
        )?,
        "feature-not-implemented",
    )?;
    traffic(
        &pair,
        "iq_to_remote_full_jid_after_subscription_is_answered_by_the_client",
        [0, 3, 3],
        [0, 3, 3],
    )?;
    a.close()?;
    presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn iq_to_unknown_remote_resource_returns_service_unavailable() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
    a.send(&format!("<iq type='get' id='missing-resource' to='{bj}/missing'><query xmlns='urn:test:remote-client'/></iq>"))?;
    stanza_error(
        &iq_reply(
            &mut a,
            "missing-resource",
            "error",
            &format!("{bj}/missing"),
            &format!("{aj}/desk"),
        )?,
        "service-unavailable",
    )?;
    for kind in ["get", "set"] {
        let missing = format!("missing@{bd}");
        a.send(&format!("<iq type='{kind}' id='missing-account' to='{missing}'><query xmlns='urn:test:remote-client'/></iq>"))?;
        stanza_error(
            &iq_reply(
                &mut a,
                "missing-account",
                "error",
                &missing,
                &format!("{aj}/desk"),
            )?,
            "service-unavailable",
        )?;
    }
    crate::support::barrier(&mut b)?;
    traffic(
        &pair,
        "iq_to_unknown_remote_resource_returns_service_unavailable",
        [0, 3, 3],
        [0, 3, 3],
    )?;
    a.close()?;
    presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
