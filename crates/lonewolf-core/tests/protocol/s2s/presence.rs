// SPDX-License-Identifier: Apache-2.0

use super::{DIRECTIONS, available, iq_reply, traffic, workflow_options};
use super::{presence, roster};
use crate::support::federation::FederatedPair;
use crate::support::federation::{
    peer::{self, RawS2sListener, RawS2sPeer},
    subscribe_mutually,
};
use crate::support::{PASSWORD, TestResult};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[test]
fn mutual_subscription_then_initial_presence_probes_remote_contacts() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        b.send("<presence><show>away</show><status>Current remote presence</status></presence>")?;
        presence(&mut b, &format!("{bj}/phone"), &bj, None)?;
        presence(&mut a, &format!("{bj}/phone"), &aj, None)?;
        a.close()?;
        presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        let mut a = pair.a.connect(an, PASSWORD, "returned")?;
        roster(&mut a)?;
        available(&mut a, &aj, "returned")?;
        let current = presence(&mut a, &format!("{bj}/phone"), &aj, None)?;
        assert_eq!(current.child("jabber:client", "show")?.text, "away");
        assert_eq!(
            current.child("jabber:client", "status")?.text,
            "Current remote presence"
        );
        presence(&mut b, &format!("{aj}/returned"), &bj, None)?;
        traffic(
            &pair,
            "mutual_subscription_then_initial_presence_probes_remote_contacts",
            [0, 0, 6],
            [0, 0, 5],
        )?;
        a.close()?;
        presence(&mut b, &format!("{aj}/returned"), &bj, Some("unavailable"))?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn presence_updates_and_logout_reach_remote_subscribers() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        a.send("<presence><show>dnd</show><status>Remote update</status></presence>")?;
        presence(&mut a, &format!("{aj}/desk"), &aj, None)?;
        let update = presence(&mut b, &format!("{aj}/desk"), &bj, None)?;
        assert_eq!(update.child("jabber:client", "show")?.text, "dnd");
        assert_eq!(
            update.child("jabber:client", "status")?.text,
            "Remote update"
        );
        a.close()?;
        presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        traffic(
            &pair,
            "presence_updates_and_logout_reach_remote_subscribers",
            [0, 0, 5],
            [0, 0, 3],
        )?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn directed_presence_to_remote_jid_is_withdrawn_at_logout() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        available(&mut a, &aj, "desk")?;
        available(&mut b, &bj, "phone")?;
        a.send(&format!(
            "<presence to='{bj}/phone'><show>chat</show></presence>"
        ))?;
        let directed = presence(&mut b, &format!("{aj}/desk"), &format!("{bj}/phone"), None)?;
        assert_eq!(directed.child("jabber:client", "show")?.text, "chat");
        a.close()?;
        presence(
            &mut b,
            &format!("{aj}/desk"),
            &format!("{bj}/phone"),
            Some("unavailable"),
        )?;
        traffic(
            &pair,
            "directed_presence_to_remote_jid_is_withdrawn_at_logout",
            [0, 0, 2],
            [0, 0, 0],
        )?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn unauthorized_remote_probe_gets_unsubscribed() -> TestResult {
    for (ad, an, bd, _) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        available(&mut a, &aj, "desk")?;
        let directory = tempfile::tempdir()?;
        let identity = pair.ca.server(directory.path(), "charlie", &["c.test"])?;
        let listener = RawS2sListener::bind()?;
        pair.dns
            .srv("c.test", &[(0, 0, listener.address()?.port(), "c.c.test")]);
        pair.dns.a("c.c.test", Ipv4Addr::LOCALHOST);
        let mut peer = RawS2sPeer::connect(pair.a.s2s_addresses()?[0], "c.test", ad)?;
        peer.expect_starttls_features()?;
        let mut peer = peer.start_tls(peer::client_config(&pair.ca, Arc::clone(&identity))?)?;
        peer.expect_external_offered()?;
        peer.auth_external(Some("c.test"))?;
        peer.expect_sasl_success()?;
        let mut peer = peer.restart("c.test", ad)?;
        peer.send(&format!(
            "<presence xmlns='jabber:server' type='probe' from='charlie@c.test/desk' to='{aj}'/>"
        ))?;
        let mut replies = listener.accept(
            "c.test",
            ad,
            peer::server_config(&pair.ca, identity, ad)?,
            true,
        )?;
        let reply = replies.receive()?;
        reply.assert_name("jabber:server", "presence");
        assert_eq!(reply.attribute("type"), Some("unsubscribed"));
        assert_eq!(reply.attribute("from"), Some(aj.as_str()));
        assert_eq!(reply.attribute("to"), Some("charlie@c.test/desk"));
        pair.a
            .wait_for_metric("lonewolf_s2s_stanzas_received_total{kind=\"presence\"} 1")?;
        pair.a
            .wait_for_metric("lonewolf_s2s_stanzas_sent_total{kind=\"presence\"} 1")?;
        for direction in ["inbound", "outbound"] {
            pair.a.wait_for_metric(&format!("lonewolf_s2s_authentications_total{{direction=\"{direction}\",outcome=\"success\"}} 1"))?;
        }
        pair.a
            .wait_for_metric("lonewolf_s2s_connections_accepted_total{listener=\"0\"} 1")?;
        pair.a
            .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
        for line in pair
            .a
            .scrape_metrics()?
            .lines()
            .filter(|line| line.starts_with("lonewolf_s2s_"))
        {
            eprintln!("METRIC_LEDGER unauthorized_remote_probe_gets_unsubscribed {ad} {line}");
        }
        crate::support::barrier(&mut a)?;
        peer.close()?;
        replies.close()?;
        a.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn remote_user_reaches_hosted_service() -> TestResult {
    for (ad, _, bd, bn) in DIRECTIONS {
        let service = format!("svc.{ad}");
        let mut options = workflow_options();
        options.a_extensions.push_str(", 'test-federated-service'");
        let mut pair = FederatedPair::start(ad, bd, options)?;
        pair.a.stop()?;
        pair.ca
            .server(pair.a.fixture_path(), "host", &[ad, &service])?;
        pair.a.restart()?;
        let port = pair.a.s2s_addresses()?[0].port();
        pair.dns.srv(ad, &[(0, 0, port, "service-host.test")]);
        pair.dns.srv(&service, &[(0, 0, port, "service-host.test")]);
        pair.dns.a("service-host.test", Ipv4Addr::LOCALHOST);
        pair.b.create_account(bn, PASSWORD)?;
        let bj = format!("{bn}@{bd}");
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        b.send(&format!("<message type='chat' id='service-echo' to='{service}'><body>Hosted service echo</body></message>"))?;
        b.expect_xml(&format!("<message xmlns='jabber:client' type='chat' id='service-echo' xml:lang='en' from='{service}' to='{bj}/phone'><body>Hosted service echo</body></message>"))?;
        b.send(&format!("<iq type='get' id='service-info' to='{service}'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>"))?;
        let reply = iq_reply(
            &mut b,
            "service-info",
            "result",
            &service,
            &format!("{bj}/phone"),
        )?;
        let identity = reply
            .child("http://jabber.org/protocol/disco#info", "query")?
            .child("http://jabber.org/protocol/disco#info", "identity")?;
        assert_eq!(identity.attribute("category"), Some("component"));
        assert_eq!(identity.attribute("name"), Some("Echo"));
        traffic(
            &pair,
            "remote_user_reaches_hosted_service",
            [1, 1, 0],
            [1, 1, 0],
        )?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}
