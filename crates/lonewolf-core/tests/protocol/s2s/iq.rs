// SPDX-License-Identifier: Apache-2.0

use super::{DIRECTIONS, iq_reply, stanza_error, traffic, workflow_options};
use crate::support::federation::FederatedPair;
use crate::support::federation::subscribe_mutually;
use crate::support::{PASSWORD, TestResult};

#[test]
fn disco_info_of_remote_server() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        a.send(&format!("<iq type='get' id='disco' to='{bd}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
        let reply = iq_reply(&mut a, "disco", "result", bd, &format!("{aj}/desk"))?;
        let query = reply.child("http://jabber.org/protocol/disco#info", "query")?;
        let identity = query.child("http://jabber.org/protocol/disco#info", "identity")?;
        assert_eq!(identity.attribute("category"), Some("server"));
        assert_eq!(identity.attribute("type"), Some("im"));
        for feature in [
            "jabber:iq:roster",
            "msgoffline",
            "urn:xmpp:carbons:2",
            "urn:xmpp:ping",
            "vcard-temp",
        ] {
            assert!(query.children.iter().any(|child| child.name == "feature" && child.attribute("var") == Some(feature)));
        }
        traffic(&pair, "disco_info_of_remote_server", [0, 1, 0], [0, 1, 0])?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn ping_remote_account_requires_subscription() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        a.send(&format!(
            "<iq type='get' id='private-ping' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        stanza_error(
            &iq_reply(&mut a, "private-ping", "error", &bj, &format!("{aj}/desk"))?,
            "service-unavailable",
        )?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        a.send(&format!(
            "<iq type='get' id='authorized-ping' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        assert!(
            iq_reply(
                &mut a,
                "authorized-ping",
                "result",
                &bj,
                &format!("{aj}/desk")
            )?
            .children
            .is_empty()
        );
        traffic(
            &pair,
            "ping_remote_account_requires_subscription",
            [0, 2, 3],
            [0, 2, 3],
        )?;
        a.close()?;
        super::presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn vcard_of_remote_account_is_public() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        b.send("<iq type='set' id='publish'><vCard xmlns='vcard-temp'><FN>Public remote name</FN></vCard></iq>")?;
        b.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='publish' to='{bj}/phone'/>"
        ))?;
        a.send(&format!(
            "<iq type='get' id='public-card' to='{bj}'><vCard xmlns='vcard-temp'/></iq>"
        ))?;
        let reply = iq_reply(&mut a, "public-card", "result", &bj, &format!("{aj}/desk"))?;
        assert_eq!(
            reply
                .child("vcard-temp", "vCard")?
                .child("vcard-temp", "FN")?
                .text,
            "Public remote name"
        );
        traffic(
            &pair,
            "vcard_of_remote_account_is_public",
            [0, 1, 0],
            [0, 1, 0],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn iq_to_remote_full_jid_after_subscription_is_answered_by_the_client() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
        super::presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn iq_to_unknown_remote_resource_returns_service_unavailable() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
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
        super::presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn remote_vcard_set_is_forbidden() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut options = workflow_options();
        // Disable the source vCard handler so the remote server must reject this SET.
        options.a_extensions = "'roster'".into();
        let mut pair = FederatedPair::start(ad, bd, options)?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        b.send("<iq type='set' id='original-card'><vCard xmlns='vcard-temp'><FN>Original name</FN></vCard></iq>")?;
        b.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='original-card' to='{bj}/phone'/>"
        ))?;
        a.send(&format!("<iq type='set' id='forbidden-card' to='{bj}'><vCard xmlns='vcard-temp'><FN>Unwanted change</FN></vCard></iq>"))?;
        stanza_error(
            &iq_reply(
                &mut a,
                "forbidden-card",
                "error",
                &bj,
                &format!("{aj}/desk"),
            )?,
            "forbidden",
        )?;
        b.send("<iq type='get' id='own-card'><vCard xmlns='vcard-temp'/></iq>")?;
        let reply = b.receive()?;
        assert_eq!(reply.attribute("type"), Some("result"));
        assert_eq!(reply.attribute("id"), Some("own-card"));
        assert_eq!(
            reply
                .child("vcard-temp", "vCard")?
                .child("vcard-temp", "FN")?
                .text,
            "Original name"
        );
        traffic(&pair, "remote_vcard_set_is_forbidden", [0, 1, 0], [0, 1, 0])?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}
