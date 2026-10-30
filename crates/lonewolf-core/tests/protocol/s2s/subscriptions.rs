// SPDX-License-Identifier: Apache-2.0

use super::{DIRECTIONS, available, iq_reply, stanza_error, traffic, workflow_options};
use super::{presence, push, roster};
use crate::support::federation::FederatedPair;
use crate::support::federation::subscribe_mutually;
use crate::support::{PASSWORD, TestResult};

#[test]
fn subscription_request_and_approval() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        assert!(
            roster(&mut a)?
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
        assert!(
            roster(&mut b)?
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
        available(&mut a, &aj, "desk")?;
        available(&mut b, &bj, "phone")?;
        a.send(&format!("<presence type='subscribe' to='{bj}'/>"))?;
        push(&mut a, &bj, "none", Some("subscribe"))?;
        presence(&mut b, &aj, &bj, Some("subscribe"))?;
        b.send(&format!("<presence type='subscribed' to='{aj}'/>"))?;
        push(&mut b, &aj, "from", None)?;
        presence(&mut a, &bj, &aj, Some("subscribed"))?;
        push(&mut a, &bj, "to", None)?;
        presence(&mut a, &format!("{bj}/phone"), &aj, None)?;
        traffic(
            &pair,
            "subscription_request_and_approval",
            [0, 0, 1],
            [0, 0, 2],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn subscription_request_to_offline_contact_is_delivered_when_online() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        roster(&mut a)?;
        available(&mut a, &aj, "desk")?;
        a.send(&format!(
            "<presence type='subscribe' id='first' to='{bj}'/>"
        ))?;
        push(&mut a, &bj, "none", Some("subscribe"))?;
        a.send(&format!(
            "<presence type='subscribe' id='second' to='{bj}'/>"
        ))?;
        a.send(&format!(
            "<iq type='get' id='pending-fence' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
        ))?;
        stanza_error(
            &iq_reply(&mut a, "pending-fence", "error", &bj, &format!("{aj}/desk"))?,
            "service-unavailable",
        )?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        roster(&mut b)?;
        available(&mut b, &bj, "phone")?;
        let request = presence(&mut b, &aj, &bj, Some("subscribe"))?;
        assert_eq!(request.attribute("id"), Some("first"));
        crate::support::barrier(&mut b)?;
        traffic(
            &pair,
            "subscription_request_to_offline_contact_is_delivered_when_online",
            [0, 1, 2],
            [0, 1, 0],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn preapproved_subscription_is_auto_approved() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        roster(&mut a)?;
        roster(&mut b)?;
        available(&mut a, &aj, "desk")?;
        available(&mut b, &bj, "phone")?;
        b.send(&format!("<presence type='subscribed' to='{aj}'/>"))?;
        push(&mut b, &aj, "none", None)?;
        let approved = roster(&mut b)?;
        assert_eq!(
            approved
                .child("jabber:iq:roster", "query")?
                .child("jabber:iq:roster", "item")?
                .attribute("approved"),
            Some("true")
        );
        a.send(&format!("<presence type='subscribe' to='{bj}'/>"))?;
        push(&mut a, &bj, "none", Some("subscribe"))?;
        presence(&mut a, &bj, &aj, Some("subscribed"))?;
        push(&mut a, &bj, "to", None)?;
        presence(&mut a, &format!("{bj}/phone"), &aj, None)?;
        push(&mut b, &aj, "from", None)?;
        crate::support::barrier(&mut b)?;
        traffic(
            &pair,
            "preapproved_subscription_is_auto_approved",
            [0, 0, 1],
            [0, 0, 2],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn unsubscribe_and_unsubscribed_update_both_rosters() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        a.send(&format!("<presence type='unsubscribe' to='{bj}'/>"))?;
        push(&mut a, &bj, "from", None)?;
        presence(&mut b, &aj, &bj, Some("unsubscribe"))?;
        push(&mut b, &aj, "to", None)?;
        presence(&mut a, &format!("{bj}/phone"), &aj, Some("unavailable"))?;
        a.send(&format!("<presence type='unsubscribed' to='{bj}'/>"))?;
        push(&mut a, &bj, "none", None)?;
        presence(&mut b, &aj, &bj, Some("unsubscribed"))?;
        push(&mut b, &aj, "none", None)?;
        presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;

        for (client, contact) in [(&mut a, &bj), (&mut b, &aj)] {
            let reply = roster(client)?;
            let item = reply
                .child("jabber:iq:roster", "query")?
                .child("jabber:iq:roster", "item")?;
            assert_eq!(item.attribute("jid"), Some(contact.as_str()));
            assert_eq!(item.attribute("subscription"), Some("none"));
        }
        traffic(
            &pair,
            "unsubscribe_and_unsubscribed_update_both_rosters",
            [0, 0, 6],
            [0, 0, 5],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn roster_removal_notifies_remote_contact() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        a.send(&format!("<iq type='set' id='remove'><query xmlns='jabber:iq:roster'><item jid='{bj}' subscription='remove'/></query></iq>"))?;
        a.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='remove' to='{aj}/desk'/>"
        ))?;
        push(&mut a, &bj, "remove", None)?;
        presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        presence(&mut b, &aj, &bj, Some("unsubscribe"))?;
        push(&mut b, &aj, "to", None)?;
        presence(&mut b, &aj, &bj, Some("unsubscribed"))?;
        push(&mut b, &aj, "none", None)?;
        presence(&mut a, &format!("{bj}/phone"), &aj, Some("unavailable"))?;
        assert!(
            roster(&mut a)?
                .child("jabber:iq:roster", "query")?
                .children
                .is_empty()
        );
        let remaining = roster(&mut b)?;
        assert_eq!(
            remaining
                .child("jabber:iq:roster", "query")?
                .child("jabber:iq:roster", "item")?
                .attribute("subscription"),
            Some("none")
        );
        traffic(
            &pair,
            "roster_removal_notifies_remote_contact",
            [0, 0, 6],
            [0, 0, 5],
        )?;
        a.close()?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}

#[test]
fn account_deletion_notifies_remote_contacts() -> TestResult {
    for (ad, an, bd, bn) in DIRECTIONS {
        let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
        pair.a.create_account(an, PASSWORD)?;
        pair.b.create_account(bn, PASSWORD)?;
        let aj = format!("{an}@{ad}");
        let bj = format!("{bn}@{bd}");
        let mut a = pair.a.connect(an, PASSWORD, "desk")?;
        let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
        subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
        pair.a.delete_account(an)?;
        presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
        presence(&mut b, &aj, &bj, Some("unsubscribe"))?;
        push(&mut b, &aj, "to", None)?;
        presence(&mut b, &aj, &bj, Some("unsubscribed"))?;
        push(&mut b, &aj, "none", None)?;
        let reply = roster(&mut b)?;
        assert_eq!(
            reply
                .child("jabber:iq:roster", "query")?
                .child("jabber:iq:roster", "item")?
                .attribute("subscription"),
            Some("none")
        );
        a.expect_stream_error("not-authorized")?;
        traffic(
            &pair,
            "account_deletion_notifies_remote_contacts",
            [0, 0, 6],
            [0, 0, 5],
        )?;
        b.close()?;
        pair.stop()?;
    }
    Ok(())
}
