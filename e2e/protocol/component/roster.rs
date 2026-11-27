// SPDX-License-Identifier: Apache-2.0

use super::routing::traffic;
use super::stream_conformance::assert_counter;
use crate::support::component::{ComponentClient, NAMESPACE};
use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, barrier};

pub(super) const DOMAIN: &str = "irc.example.test";
pub(super) const SERVER: &str = "irc-server.example.test@irc.example.test";
pub(super) const CONFIG: &str =
    "[components.domains.'irc.example.test']\nsecret='component-test-secret-0001'";
const CLIENT: &str = "jabber:client";
const ROSTER: &str = "jabber:iq:roster";
const ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
const ALICE: &str = "alice@localhost";
const DESK: &str = "alice@localhost/desk";
const PHONE: &str = "alice@localhost/phone";

pub(super) fn attach(suite: &C2sSuite) -> TestResult<ComponentClient> {
    ComponentClient::authenticated(suite, DOMAIN, "component-test-secret-0001")
}

fn send_component_ping(component: &mut ComponentClient) -> TestResult {
    component.send(&format!("<iq type='get' from='{DOMAIN}' to='localhost' id='barrier'><ping xmlns='urn:xmpp:ping'/></iq>"))
}

fn expect_component_pong(component: &mut ComponentClient) -> TestResult {
    component.expect_xml(&format!(
        "<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='{DOMAIN}' id='barrier'/>"
    ))
}

pub(super) fn component_barrier(component: &mut ComponentClient) -> TestResult {
    send_component_ping(component)?;
    expect_component_pong(component)
}

fn request_roster(alice: &mut Client) -> TestResult {
    alice.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")
}

fn assert_roster_result(reply: &Element) -> TestResult {
    reply.assert_name(CLIENT, "iq");
    assert_eq!(reply.attribute("id"), Some("roster"));
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    reply.child(ROSTER, "query")?;
    Ok(())
}

pub(super) fn get_roster(alice: &mut Client) -> TestResult<Element> {
    request_roster(alice)?;
    let reply = alice.receive()?;
    assert_roster_result(&reply)?;
    Ok(reply)
}

fn available_alice(suite: &C2sSuite) -> TestResult<Client> {
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    get_roster(&mut alice)?;
    alice.send("<presence/>")?;
    alice.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' from='{DESK}' to='{ALICE}'/>"
    ))?;
    Ok(alice)
}

fn online() -> TestResult<(C2sSuite, Client, ComponentClient)> {
    let suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let alice = available_alice(&suite)?;
    let component = attach(&suite)?;
    Ok((suite, alice, component))
}

fn assert_item(
    iq: &Element,
    contact: &str,
    state: &str,
    ask: Option<&str>,
    approved: bool,
) -> TestResult {
    let query = iq.child(ROSTER, "query")?;
    assert_eq!(query.children.len(), 1, "{query:?}");
    let item = query.child(ROSTER, "item")?;
    assert_eq!(item.attribute("jid"), Some(contact));
    assert_eq!(item.attribute("subscription"), Some(state));
    assert_eq!(item.attribute("ask"), ask);
    assert_eq!(item.attribute("approved"), approved.then_some("true"));
    Ok(())
}

fn acknowledge_push(
    alice: &mut Client,
    push: &Element,
    contact: &str,
    state: &str,
    ask: Option<&str>,
    approved: bool,
) -> TestResult {
    push.assert_name(CLIENT, "iq");
    assert_eq!(push.attribute("type"), Some("set"));
    assert_eq!(push.attribute("to"), Some(DESK));
    assert_item(push, contact, state, ask, approved)?;
    let id = push.attribute("id").ok_or("missing roster push ID")?;
    alice.send(&format!("<iq type='result' id='{id}'/>"))
}

pub(super) fn push(
    alice: &mut Client,
    contact: &str,
    state: &str,
    ask: Option<&str>,
    approved: bool,
) -> TestResult {
    let stanza = alice.receive()?;
    acknowledge_push(alice, &stanza, contact, state, ask, approved)
}

fn assert_presence(stanza: &Element, namespace: &str, from: &str, to: &str, kind: Option<&str>) {
    stanza.assert_name(namespace, "presence");
    assert_eq!(stanza.attribute("from"), Some(from), "{stanza:?}");
    assert_eq!(stanza.attribute("to"), Some(to), "{stanza:?}");
    assert_eq!(stanza.attribute("type"), kind, "{stanza:?}");
}

fn component_presence(
    component: &mut ComponentClient,
    from: &str,
    contact: &str,
    kind: Option<&str>,
) -> TestResult<Element> {
    let stanza = component.receive()?;
    assert_presence(&stanza, NAMESPACE, from, contact, kind);
    Ok(stanza)
}

fn request_from_component(component: &mut ComponentClient, contact: &str, id: &str) -> TestResult {
    component.send(&format!(
        "<presence from='{contact}' to='{ALICE}' type='subscribe' id='{id}'/>"
    ))
}

fn client_receives(alice: &mut Client, contact: &str, kind: &str) -> TestResult<Element> {
    let stanza = alice.receive()?;
    assert_presence(&stanza, CLIENT, contact, ALICE, Some(kind));
    Ok(stanza)
}

fn follow(alice: &mut Client, component: &mut ComponentClient, contact: &str) -> TestResult {
    alice.send(&format!("<presence type='subscribe' to='{contact}'/>"))?;
    component_presence(component, ALICE, contact, Some("subscribe"))?;
    push(alice, contact, "none", Some("subscribe"), false)?;
    component.send(&format!(
        "<presence type='subscribed' from='{contact}' to='{ALICE}'/>"
    ))?;
    client_receives(alice, contact, "subscribed")?;
    push(alice, contact, "to", None, false)
}

macro_rules! subscription_scenarios {
    ($($scenario:ident),+ $(,)?) => {
        mod gateway {
            $(#[test] fn $scenario() -> super::TestResult { super::$scenario(super::DOMAIN) })+
        }
        mod irc_server {
            $(#[test] fn $scenario() -> super::TestResult { super::$scenario(super::SERVER) })+
        }
    };
}

subscription_scenarios!(
    client_subscription_to_component_contact_is_approved_and_pushes_to,
    component_subscription_request_is_stored_and_approval_grants_from,
    repeated_component_request_under_a_grant_is_answered_without_a_prompt,
    client_preapproval_completes_a_later_component_request_without_a_prompt,
    client_denial_and_revocation_reach_the_component,
    component_cancellation_and_unsubscribe_update_the_client_roster,
    client_unsubscribe_from_component_contact_clears_to,
    subscriptions_to_a_disconnected_component_bounce_and_keep_roster_state,
    component_subscriptions_to_full_jids_are_processed_as_bare,
    component_requests_over_the_pending_limit_get_resource_constraint,
    component_subscriptions_to_missing_accounts_are_silent_and_keep_the_stream_usable,
    initial_presence_probes_only_component_contacts_the_user_follows,
    blocked_component_contacts_receive_no_probe_or_broadcast,
    presence_updates_and_unavailable_reach_component_subscribers,
    session_end_sends_one_unavailable_to_each_component_subscriber,
    revocation_stops_presence_delivery_to_the_component,
    component_probes_are_answered_only_under_a_grant,
    component_contact_presence_reaches_the_client,
    component_restart_recovers_presence_through_probes,
    removing_a_component_contact_notifies_the_component,
    removing_a_requested_component_contact_withdraws_the_request,
    deleting_an_account_notifies_its_component_contacts,
    unsubscribe_stops_component_status_updates,
    requested_component_contacts_show_presence_only_after_approval,
    unavailable_and_full_jid_presence_from_unfollowed_contacts_is_delivered,
    presence_from_component_jids_outside_the_roster_is_delivered,
    hosts_without_roster_deliver_component_presence_unfiltered,
);

fn client_subscription_to_component_contact_is_approved_and_pushes_to(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    alice.send(&format!(
        "<presence type='subscribe' to='{contact}/console' id='outbound'/>"
    ))?;
    let request = component_presence(&mut component, ALICE, contact, Some("subscribe"))?;
    assert_eq!(request.attribute("id"), Some("outbound"));
    push(&mut alice, contact, "none", Some("subscribe"), false)?;

    component.send(&format!(
        "<presence type='subscribed' from='{contact}' to='{ALICE}' id='approved'/>"
    ))?;
    let approval = client_receives(&mut alice, contact, "subscribed")?;
    assert_eq!(approval.attribute("id"), Some("approved"));
    push(&mut alice, contact, "to", None, false)?;
    assert_item(&get_roster(&mut alice)?, contact, "to", None, false)?;
    traffic(&suite, "presence", 1, 1)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn component_subscription_request_is_stored_and_approval_grants_from(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    request_from_component(&mut component, contact, "online")?;
    assert_eq!(
        client_receives(&mut alice, contact, "subscribe")?.attribute("id"),
        Some("online")
    );
    alice.send(&format!("<presence type='unsubscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    alice.close()?;
    request_from_component(&mut component, contact, "offline")?;
    component_barrier(&mut component)?;
    let mut alice = available_alice(&suite)?;
    assert_eq!(
        client_receives(&mut alice, contact, "subscribe")?.attribute("id"),
        Some("offline")
    );

    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    component_presence(&mut component, DESK, contact, None)?;
    push(&mut alice, contact, "from", None, false)?;
    traffic(&suite, "presence", 2, 3)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn repeated_component_request_under_a_grant_is_answered_without_a_prompt(
    contact: &str,
) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    request_from_component(&mut component, contact, "first")?;
    client_receives(&mut alice, contact, "subscribe")?;
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    component_presence(&mut component, DESK, contact, None)?;
    push(&mut alice, contact, "from", None, false)?;

    request_from_component(&mut component, contact, "repeat")?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    component_barrier(&mut component)?;
    barrier(&mut alice)?;
    assert_item(&get_roster(&mut alice)?, contact, "from", None, false)?;
    traffic(&suite, "presence", 2, 3)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn client_preapproval_completes_a_later_component_request_without_a_prompt(
    contact: &str,
) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    request_roster(&mut alice)?;
    let first = alice.receive()?;
    if first.attribute("type") == Some("set") {
        acknowledge_push(&mut alice, &first, contact, "none", None, true)?;
        let stored = alice.receive()?;
        assert_roster_result(&stored)?;
        assert_item(&stored, contact, "none", None, true)?;
    } else {
        assert_roster_result(&first)?;
        assert_item(&first, contact, "none", None, true)?;
        push(&mut alice, contact, "none", None, true)?;
    }
    component_barrier(&mut component)?;

    request_from_component(&mut component, contact, "preapproved")?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    component_presence(&mut component, DESK, contact, None)?;
    push(&mut alice, contact, "from", None, false)?;
    component_barrier(&mut component)?;
    barrier(&mut alice)?;
    traffic(&suite, "presence", 1, 2)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn expect_resource_pair(
    component: &mut ComponentClient,
    contact: &str,
    kind: Option<&str>,
) -> TestResult {
    let mut receive_resource = || -> TestResult<Element> {
        let stanza = component.receive()?;
        stanza.assert_name(NAMESPACE, "presence");
        assert_eq!(stanza.attribute("type"), kind);
        assert_eq!(stanza.attribute("to"), Some(contact));
        Ok(stanza)
    };
    let pair = [receive_resource()?, receive_resource()?];
    let mut resources = pair.each_ref().map(|stanza| stanza.attribute("from"));
    resources.sort_unstable();
    assert_eq!(resources, [Some(DESK), Some(PHONE)]);
    Ok(())
}

fn client_denial_and_revocation_reach_the_component(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    request_from_component(&mut component, contact, "denied")?;
    client_receives(&mut alice, contact, "subscribe")?;
    alice.send(&format!("<presence type='unsubscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    barrier(&mut alice)?;

    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    phone.send("<presence/>")?;
    phone.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' from='{DESK}' to='{ALICE}'/>"
    ))?;
    for client in [&mut phone, &mut alice] {
        client.expect_xml(&format!(
            "<presence xmlns='{CLIENT}' from='{PHONE}' to='{ALICE}'/>"
        ))?;
    }
    request_from_component(&mut component, contact, "grant")?;
    client_receives(&mut alice, contact, "subscribe")?;
    client_receives(&mut phone, contact, "subscribe")?;
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    expect_resource_pair(&mut component, contact, None)?;
    push(&mut alice, contact, "from", None, false)?;

    alice.send(&format!("<presence type='unsubscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    expect_resource_pair(&mut component, contact, Some("unavailable"))?;
    push(&mut alice, contact, "none", None, false)?;
    traffic(&suite, "presence", 2, 7)?;
    component.close()?;
    phone.close()?;
    alice.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' type='unavailable' from='{PHONE}' to='{ALICE}'/>"
    ))?;
    alice.close()?;
    suite.stop()
}

fn component_cancellation_and_unsubscribe_update_the_client_roster(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, contact)?;
    request_from_component(&mut component, contact, "mutual")?;
    client_receives(&mut alice, contact, "subscribe")?;
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    component_presence(&mut component, DESK, contact, None)?;
    push(&mut alice, contact, "both", None, false)?;

    component.send(&format!(
        "<presence type='unsubscribed' from='{contact}' to='{ALICE}'/>"
    ))?;
    client_receives(&mut alice, contact, "unsubscribed")?;
    push(&mut alice, contact, "from", None, false)?;
    component.send(&format!(
        "<presence type='unsubscribe' from='{contact}' to='{ALICE}'/>"
    ))?;
    client_receives(&mut alice, contact, "unsubscribe")?;
    push(&mut alice, contact, "none", None, false)?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    component_presence(&mut component, DESK, contact, Some("unavailable"))?;
    traffic(&suite, "presence", 4, 5)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn client_unsubscribe_from_component_contact_clears_to(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, contact)?;

    alice.send(&format!("<presence type='unsubscribe' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribe"))?;
    push(&mut alice, contact, "none", None, false)?;
    assert_item(&get_roster(&mut alice)?, contact, "none", None, false)?;
    traffic(&suite, "presence", 1, 2)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn subscriptions_to_a_disconnected_component_bounce_and_keep_roster_state(
    contact: &str,
) -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = available_alice(&suite)?;
    alice.send(&format!(
        "<presence type='subscribe' to='{contact}' id='disconnected'/>"
    ))?;
    request_roster(&mut alice)?;
    let mut stored = false;
    let mut pushed = false;
    let mut bounced = false;
    for _ in 0..3 {
        let stanza = alice.receive()?;
        match (stanza.name.as_str(), stanza.attribute("type")) {
            ("iq", Some("set")) => {
                acknowledge_push(
                    &mut alice,
                    &stanza,
                    contact,
                    "none",
                    Some("subscribe"),
                    false,
                )?;
                pushed = true;
            }
            ("iq", Some("result")) => {
                assert_roster_result(&stanza)?;
                assert_item(&stanza, contact, "none", Some("subscribe"), false)?;
                stored = true;
            }
            ("presence", Some("error")) => {
                assert_presence(&stanza, CLIENT, contact, ALICE, Some("error"));
                assert_eq!(stanza.attribute("id"), Some("disconnected"));
                let error = stanza.child(CLIENT, "error")?;
                assert_eq!(error.attribute("type"), Some("wait"));
                error.child(ERRORS, "remote-server-timeout")?;
                assert_eq!(
                    error.child(ERRORS, "text")?.text,
                    "The service at this domain is not connected. Try again later."
                );
                bounced = true;
            }
            _ => return Err(format!("unexpected stanza {stanza:?}").into()),
        }
    }
    assert!(stored && pushed && bounced);
    suite.wait_for_metric(
        "lonewolf_component_admission_rejections_total{reason=\"not_connected\"} 1",
    )?;
    traffic(&suite, "presence", 0, 0)?;
    alice.close()?;
    suite.stop()
}

fn component_subscriptions_to_full_jids_are_processed_as_bare(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    component.send(&format!(
        "<presence from='{contact}/console' to='{DESK}' type='subscribe' id='full'/>"
    ))?;
    assert_eq!(
        client_receives(&mut alice, contact, "subscribe")?.attribute("id"),
        Some("full")
    );
    alice.close()?;
    let mut alice = available_alice(&suite)?;
    assert_eq!(
        client_receives(&mut alice, contact, "subscribe")?.attribute("id"),
        Some("full")
    );
    traffic(&suite, "presence", 1, 0)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn component_requests_over_the_pending_limit_get_resource_constraint(contact: &str) -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\nmax_connections = 2\n[hosts.localhost]\nextensions = ['roster', 'ping']\n[hosts.localhost.roster]\nmax_pending_subscription_requests = 1"
    ))?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = available_alice(&suite)?;
    let mut first = attach(&suite)?;
    let mut second = attach(&suite)?;
    let other = if contact == DOMAIN { SERVER } else { DOMAIN };
    request_from_component(&mut first, other, "first")?;
    client_receives(&mut alice, other, "subscribe")?;
    request_from_component(&mut second, contact, "over-limit")?;
    send_component_ping(&mut second)?;
    let rejection = second.receive()?;
    assert_presence(&rejection, NAMESPACE, ALICE, contact, Some("error"));
    assert_eq!(rejection.attribute("id"), Some("over-limit"));
    let error = rejection.child(NAMESPACE, "error")?;
    assert_eq!(error.attribute("type"), Some("wait"));
    error.child(ERRORS, "resource-constraint")?;
    assert_eq!(
        error.child(ERRORS, "text")?.text,
        "The recipient's pending subscription request limit has been reached. Retry after the recipient handles pending requests."
    );
    expect_component_pong(&mut second)?;
    component_barrier(&mut first)?;
    barrier(&mut alice)?;
    traffic(&suite, "presence", 2, 1)?;
    second.close()?;
    first.close()?;
    alice.close()?;
    suite.stop()
}

fn component_subscriptions_to_missing_accounts_are_silent_and_keep_the_stream_usable(
    contact: &str,
) -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut component = attach(&suite)?;
    for recipient in ["missing@localhost", "missing@localhost/desk"] {
        for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
            component.send(&format!(
                "<presence from='{contact}' to='{recipient}' type='{kind}'/>"
            ))?;
            component_barrier(&mut component)?;
        }
    }
    traffic(&suite, "presence", 8, 0)?;
    traffic(&suite, "iq", 8, 8)?;
    component.close()?;
    suite.stop()
}

const OTHER: &str = "other.example.test@irc.example.test";
const FOURTH: &str = "fourth.example.test@irc.example.test";

fn other_contact(contact: &str) -> &'static str {
    if contact == DOMAIN { SERVER } else { DOMAIN }
}

pub(super) fn unavailable_setup(config: &str) -> TestResult<(C2sSuite, Client, ComponentClient)> {
    let suite = C2sSuite::with_components(config)?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    get_roster(&mut alice)?;
    let component = attach(&suite)?;
    Ok((suite, alice, component))
}

pub(super) fn grant(
    alice: &mut Client,
    component: &mut ComponentClient,
    contact: &str,
    follows: bool,
    available: bool,
) -> TestResult {
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    push(
        alice,
        contact,
        if follows { "to" } else { "none" },
        None,
        true,
    )?;
    request_from_component(component, contact, "grant")?;
    component_presence(component, ALICE, contact, Some("subscribed"))?;
    if available {
        component_presence(component, DESK, contact, None)?;
    }
    push(
        alice,
        contact,
        if follows { "both" } else { "from" },
        None,
        false,
    )
}

fn roster_audience(
    alice: &mut Client,
    component: &mut ComponentClient,
    both: &str,
    available: bool,
) -> TestResult {
    follow(alice, component, OTHER)?;
    follow(alice, component, both)?;
    grant(alice, component, both, true, available)?;
    grant(alice, component, other_contact(both), false, available)?;
    alice.send(&format!("<presence type='subscribe' to='{FOURTH}'/>"))?;
    component_presence(component, ALICE, FOURTH, Some("subscribe"))?;
    push(alice, FOURTH, "none", Some("subscribe"), false)
}

pub(super) fn publish(alice: &mut Client, kind: Option<&str>, status: &str) -> TestResult {
    let ty = kind.map_or(String::new(), |kind| format!(" type='{kind}'"));
    alice.send(&format!(
        "<presence{ty}><status>{status}</status></presence>"
    ))?;
    let echo = alice.receive()?;
    assert_presence(&echo, CLIENT, DESK, ALICE, kind);
    assert_eq!(echo.child(CLIENT, "status")?.text, status);
    barrier(alice)
}

pub(super) fn expect_audience(
    component: &mut ComponentClient,
    probes: &[&str],
    broadcasts: &[&str],
    kind: Option<&str>,
    status: Option<&str>,
) -> TestResult {
    let mut expected_probes = probes.to_vec();
    let mut expected_broadcasts = broadcasts.to_vec();
    send_component_ping(component)?;
    loop {
        let stanza = component.receive()?;
        if stanza.name == "iq" {
            stanza.assert_xml(&format!("<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='{DOMAIN}' id='barrier'/>"))?;
            break;
        }
        let to = stanza.attribute("to").ok_or("missing presence recipient")?;
        let recipients = if stanza.attribute("type") == Some("probe") {
            assert_presence(&stanza, NAMESPACE, ALICE, to, Some("probe"));
            &mut expected_probes
        } else {
            assert_presence(&stanza, NAMESPACE, DESK, to, kind);
            assert_eq!(
                stanza
                    .child(NAMESPACE, "status")
                    .ok()
                    .map(|child| child.text.as_str()),
                status,
                "{stanza:?}"
            );
            &mut expected_broadcasts
        };
        let index = recipients
            .iter()
            .position(|recipient| *recipient == to)
            .ok_or_else(|| format!("unexpected or duplicate presence: {stanza:?}"))?;
        recipients.swap_remove(index);
    }
    assert!(
        expected_probes.is_empty() && expected_broadcasts.is_empty(),
        "missing probes to {expected_probes:?}, missing broadcasts to {expected_broadcasts:?}"
    );
    Ok(())
}

fn initial_presence_probes_only_component_contacts_the_user_follows(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(CONFIG)?;
    roster_audience(&mut alice, &mut component, contact, false)?;
    publish(&mut alice, None, "initial")?;
    expect_audience(
        &mut component,
        &[OTHER, contact],
        &[contact, other_contact(contact)],
        None,
        Some("initial"),
    )?;
    traffic(&suite, "presence", 4, 9)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn blocked_component_contacts_receive_no_probe_or_broadcast(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['test-policy','roster','ping']"
    ))?;
    let allowed = other_contact(contact);
    for jid in [contact, allowed] {
        follow(&mut alice, &mut component, jid)?;
        grant(&mut alice, &mut component, jid, true, false)?;
    }
    alice.send(&format!("<iq type='set' to='localhost' id='block'><toggle xmlns='urn:lonewolf:test:policy' enabled='true' peer='{contact}'/></iq>"))?;
    let result = alice.receive()?;
    result.assert_name(CLIENT, "iq");
    assert_eq!(result.attribute("type"), Some("result"));
    assert_eq!(result.attribute("id"), Some("block"));
    publish(&mut alice, None, "initial")?;
    expect_audience(
        &mut component,
        &[allowed],
        &[allowed],
        None,
        Some("initial"),
    )?;
    traffic(&suite, "presence", 4, 6)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn generated_presence_denial_is_silent() -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    for contact in [SERVER, OTHER] {
        follow(&mut alice, &mut component, contact)?;
        grant(&mut alice, &mut component, contact, true, false)?;
    }
    alice.send(&format!("<iq type='set' id='rule'><block xmlns='urn:xmpp:blocking'><item jid='{SERVER}'/><item jid='{OTHER}/console'/></block></iq>"))?;
    let result = alice.receive()?;
    result.assert_name(CLIENT, "iq");
    assert_eq!(result.attribute("type"), Some("result"));
    assert_eq!(result.attribute("id"), Some("rule"));

    publish(&mut alice, None, "initial")?;
    expect_audience(&mut component, &[OTHER], &[OTHER], None, Some("initial"))?;
    publish(&mut alice, None, "update")?;
    expect_audience(&mut component, &[], &[OTHER], None, Some("update"))?;
    publish(&mut alice, Some("unavailable"), "gone")?;
    expect_audience(
        &mut component,
        &[],
        &[OTHER],
        Some("unavailable"),
        Some("gone"),
    )?;
    alice.close()?;
    component.close()?;
    suite.stop()
}

#[test]
fn component_subscription_receives_block_transitions_at_its_wire_address() -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    grant(&mut alice, &mut component, SERVER, false, false)?;
    publish(&mut alice, None, "ready")?;
    expect_audience(&mut component, &[], &[SERVER], None, Some("ready"))?;
    crate::blocking::change_rule(&mut alice, "block", DOMAIN)?;
    expect_audience(&mut component, &[], &[SERVER], Some("unavailable"), None)?;
    crate::blocking::change_rule(&mut alice, "block", SERVER)?;
    component_barrier(&mut component)?;
    crate::blocking::change_rule(&mut alice, "unblock", DOMAIN)?;
    component_barrier(&mut component)?;
    crate::blocking::change_rule(&mut alice, "unblock", "")?;
    expect_audience(&mut component, &[], &[SERVER], None, Some("ready"))?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn domain_resource_rules_change_presence_only_at_the_exact_component_address() -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    for contact in [DOMAIN, SERVER] {
        grant(&mut alice, &mut component, contact, false, false)?;
    }
    publish(&mut alice, None, "current")?;
    expect_audience(
        &mut component,
        &[],
        &[DOMAIN, SERVER],
        None,
        Some("current"),
    )?;
    let exact = format!("{DOMAIN}/watch");
    let user = format!("{SERVER}/watch");
    for target in [&exact, &user] {
        alice.send(&format!("<presence to='{target}'/>"))?;
        component_presence(&mut component, DESK, target, None)?;
    }
    crate::blocking::change_rule(&mut alice, "block", &exact)?;
    expect_audience(&mut component, &[], &[&exact], Some("unavailable"), None)?;
    crate::blocking::change_rule(&mut alice, "unblock", &exact)?;
    expect_audience(&mut component, &[], &[&exact], None, Some("current"))?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn overlapping_component_rules_restore_only_known_eligible_full_addresses() -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    let excluded = format!("{SERVER}/phone");
    let known = format!("{SERVER}/console");
    publish(&mut alice, None, "current")?;
    alice.send(&format!("<presence to='{known}' id='directed'/>"))?;
    let directed = component_presence(&mut component, DESK, &known, None)?;
    assert_eq!(directed.attribute("id"), Some("directed"));
    component.send(&format!(
        "<presence type='probe' from='{known}' to='{DESK}'/>"
    ))?;
    component_presence(&mut component, DESK, &known, None)?;
    grant(&mut alice, &mut component, SERVER, false, true)?;
    component_barrier(&mut component)?;

    let hidden = Some("unavailable");
    let current = Some("current");
    let phone = excluded.as_str();
    for (command, item, destination, kind, status) in [
        ("block", phone, Some(phone), hidden, None),
        ("block", SERVER, Some(SERVER), hidden, None),
        ("unblock", SERVER, Some(known.as_str()), None, current),
        ("unblock", phone, Some(phone), None, current),
        ("block", DOMAIN, Some(SERVER), hidden, None),
        ("block", phone, None, None, None),
        ("unblock", phone, None, None, None),
        ("unblock", DOMAIN, Some(SERVER), None, current),
    ] {
        crate::blocking::change_rule(&mut alice, command, item)?;
        expect_audience(&mut component, &[], destination.as_slice(), kind, status)?;
    }
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn clearing_broad_and_full_component_rules_restores_the_bare_subscriber_once() -> TestResult {
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    grant(&mut alice, &mut component, SERVER, false, false)?;
    crate::blocking::change_rule(&mut alice, "block", &format!("{SERVER}/phone"))?;
    crate::blocking::change_rule(&mut alice, "block", SERVER)?;
    publish(&mut alice, None, "current")?;
    component_barrier(&mut component)?;
    crate::blocking::change_rule(&mut alice, "unblock", "")?;
    expect_audience(&mut component, &[], &[SERVER], None, Some("current"))?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn presence_updates_and_unavailable_reach_component_subscribers(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    roster_audience(&mut alice, &mut component, contact, true)?;
    let subscribers = [contact, other_contact(contact)];
    for (kind, status) in [(None, "away"), (Some("unavailable"), "leaving")] {
        publish(&mut alice, kind, status)?;
        expect_audience(&mut component, &[], &subscribers, kind, Some(status))?;
    }
    traffic(&suite, "presence", 4, 11)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn session_end_sends_one_unavailable_to_each_component_subscriber(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    roster_audience(&mut alice, &mut component, contact, true)?;
    alice.send(&format!("<presence to='{contact}'/>"))?;
    component_presence(&mut component, DESK, contact, None)?;
    alice.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 1")?;
    expect_audience(
        &mut component,
        &[],
        &[contact, other_contact(contact)],
        Some("unavailable"),
        None,
    )?;
    traffic(&suite, "presence", 4, 10)?;
    component.close()?;
    suite.stop()
}

fn revocation_stops_presence_delivery_to_the_component(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    grant(&mut alice, &mut component, contact, false, true)?;
    publish(&mut alice, None, "before")?;
    expect_audience(&mut component, &[], &[contact], None, Some("before"))?;
    alice.send(&format!("<presence type='unsubscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    component_presence(&mut component, DESK, contact, Some("unavailable"))?;
    push(&mut alice, contact, "none", None, false)?;
    publish(&mut alice, None, "after")?;
    component_barrier(&mut component)?;
    traffic(&suite, "presence", 1, 5)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn probe(component: &mut ComponentClient, contact: &str, status: Option<&str>) -> TestResult {
    component.send(&format!(
        "<presence type='probe' from='{contact}' to='{ALICE}'/>"
    ))?;
    if let Some(status) = status {
        let reply = component_presence(component, DESK, contact, None)?;
        assert_eq!(reply.child(NAMESPACE, "status")?.text, status);
    } else {
        component_presence(component, ALICE, contact, Some("unsubscribed"))?;
    }
    component_barrier(component)
}

fn component_probes_are_answered_only_under_a_grant(contact: &str) -> TestResult {
    for (follows, grants) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut suite, mut alice, mut first) =
            unavailable_setup(&format!("{CONFIG}\nmax_connections=2"))?;
        publish(&mut alice, None, "at desk")?;
        if follows {
            follow(&mut alice, &mut first, contact)?;
        }
        if grants {
            grant(&mut alice, &mut first, contact, follows, true)?;
        }
        let mut second = attach(&suite)?;
        for component in [&mut second, &mut first] {
            probe(component, contact, grants.then_some("at desk"))?;
        }
        traffic(
            &suite,
            "presence",
            2 + u64::from(follows) + u64::from(grants),
            2 + u64::from(follows) + 2 * u64::from(grants),
        )?;
        second.close()?;
        first.close()?;
        alice.close()?;
        suite.stop()?;
    }
    Ok(())
}

fn contact_status(
    component: &mut ComponentClient,
    contact: &str,
    kind: Option<&str>,
    status: &str,
) -> TestResult {
    let ty = kind.map_or(String::new(), |kind| format!(" type='{kind}'"));
    component.send(&format!(
        "<presence{ty} from='{contact}' to='{ALICE}'><status>{status}</status></presence>"
    ))
}

fn expect_contact_status(
    alice: &mut Client,
    contact: &str,
    kind: Option<&str>,
    status: &str,
) -> TestResult {
    let presence = alice.receive()?;
    assert_presence(&presence, CLIENT, contact, ALICE, kind);
    assert_eq!(presence.child(CLIENT, "status")?.text, status);
    Ok(())
}

fn component_contact_presence_reaches_the_client(contact: &str) -> TestResult {
    let (mut suite, mut desk, mut component) = online()?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    phone.send("<presence/>")?;
    assert_presence(&phone.receive()?, CLIENT, DESK, ALICE, None);
    for client in [&mut desk, &mut phone] {
        assert_presence(&client.receive()?, CLIENT, PHONE, ALICE, None);
    }
    follow(&mut desk, &mut component, contact)?;
    for (kind, status) in [(None, "connected"), (Some("unavailable"), "disconnected")] {
        contact_status(&mut component, contact, kind, status)?;
        for client in [&mut desk, &mut phone] {
            expect_contact_status(client, contact, kind, status)?;
        }
    }
    traffic(&suite, "presence", 3, 1)?;
    component.close()?;
    phone.close()?;
    assert_presence(&desk.receive()?, CLIENT, PHONE, ALICE, Some("unavailable"));
    desk.close()?;
    suite.stop()
}

fn component_restart_recovers_presence_through_probes(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, contact)?;
    grant(&mut alice, &mut component, contact, true, true)?;
    contact_status(&mut component, contact, None, "connected")?;
    expect_contact_status(&mut alice, contact, None, "connected")?;
    component.close()?;
    suite.wait_for_metric("lonewolf_component_streams 0")?;
    barrier(&mut alice)?;
    for (kind, status, count) in [
        (None, "away", 1),
        (Some("unavailable"), "leaving", 2),
        (None, "back", 4),
    ] {
        publish(&mut alice, kind, status)?;
        let expected = format!(
            "lonewolf_component_admission_rejections_total{{reason=\"not_connected\"}} {count}"
        );
        assert!(
            suite.scrape_metrics()?.lines().any(|line| line == expected),
            "missing {expected} after {status}"
        );
    }
    let mut component = attach(&suite)?;
    component_barrier(&mut component)?;
    barrier(&mut alice)?;
    probe(&mut component, contact, Some("back"))?;
    publish(&mut alice, None, "after restart")?;
    expect_audience(&mut component, &[], &[contact], None, Some("after restart"))?;
    traffic(&suite, "presence", 4, 5)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

#[test]
fn gateway_workflow_with_domain_and_server_contacts() -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, DOMAIN)?;
    contact_status(&mut component, DOMAIN, None, "gateway online")?;
    expect_contact_status(&mut alice, DOMAIN, None, "gateway online")?;
    request_from_component(&mut component, DOMAIN, "gateway-request")?;
    client_receives(&mut alice, DOMAIN, "subscribe")?;
    alice.send(&format!("<presence type='subscribed' to='{DOMAIN}'/>"))?;
    component_presence(&mut component, ALICE, DOMAIN, Some("subscribed"))?;
    component_presence(&mut component, DESK, DOMAIN, None)?;
    push(&mut alice, DOMAIN, "both", None, false)?;

    follow(&mut alice, &mut component, SERVER)?;
    contact_status(&mut component, SERVER, None, "IRC connected")?;
    expect_contact_status(&mut alice, SERVER, None, "IRC connected")?;
    alice.close()?;
    suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"stream_end\"} 1")?;
    expect_audience(&mut component, &[], &[DOMAIN], Some("unavailable"), None)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    get_roster(&mut alice)?;
    publish(&mut alice, None, "logged in again")?;
    expect_audience(
        &mut component,
        &[DOMAIN, SERVER],
        &[DOMAIN],
        None,
        Some("logged in again"),
    )?;
    for (jid, status) in [(DOMAIN, "gateway online"), (SERVER, "IRC connected")] {
        contact_status(&mut component, jid, None, status)?;
        expect_contact_status(&mut alice, jid, None, status)?;
    }
    contact_status(
        &mut component,
        SERVER,
        Some("unavailable"),
        "IRC disconnected",
    )?;
    expect_contact_status(&mut alice, SERVER, Some("unavailable"), "IRC disconnected")?;
    const OCCUPANT: &str = "#lonewolf%irc-server.example.test@irc.example.test/nick";
    component.send(&format!("<presence from='{OCCUPANT}' to='{DESK}'><status>joined</status></presence><message from='{OCCUPANT}' to='{DESK}' type='groupchat'><body>hello</body></message>"))?;
    alice.expect_xml(&format!("<presence xmlns='{CLIENT}' from='{OCCUPANT}' to='{DESK}'><status>joined</status></presence>"))?;
    alice.expect_xml(&format!("<message xmlns='{CLIENT}' from='{OCCUPANT}' to='{DESK}' type='groupchat'><body>hello</body></message>"))?;
    barrier(&mut alice)?;
    traffic(&suite, "presence", 9, 8)?;
    traffic(&suite, "message", 1, 0)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn remove_contact(alice: &mut Client, contact: &str) -> TestResult {
    alice.send(&format!(
        "<iq type='set' id='remove'><query xmlns='{ROSTER}'><item jid='{contact}' subscription='remove'/></query></iq>"
    ))?;
    alice.expect_xml(&format!(
        "<iq xmlns='{CLIENT}' type='result' id='remove' to='{DESK}'/>"
    ))?;
    push(alice, contact, "remove", None, false)?;
    barrier(alice)
}

fn removing_a_component_contact_notifies_the_component(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, contact)?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    phone.send("<presence/>")?;
    phone.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' from='{DESK}' to='{ALICE}'/>"
    ))?;
    for client in [&mut phone, &mut alice] {
        client.expect_xml(&format!(
            "<presence xmlns='{CLIENT}' from='{PHONE}' to='{ALICE}'/>"
        ))?;
    }
    component_presence(&mut component, ALICE, contact, Some("probe"))?;

    request_from_component(&mut component, contact, "mutual")?;
    client_receives(&mut alice, contact, "subscribe")?;
    client_receives(&mut phone, contact, "subscribe")?;
    alice.send(&format!("<presence type='subscribed' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribed"))?;
    expect_resource_pair(&mut component, contact, None)?;
    push(&mut alice, contact, "both", None, false)?;

    remove_contact(&mut alice, contact)?;
    send_component_ping(&mut component)?;
    expect_resource_pair(&mut component, contact, Some("unavailable"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribe"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    expect_component_pong(&mut component)?;
    traffic(&suite, "presence", 2, 9)?;
    component.close()?;
    phone.close()?;
    alice.expect_xml(&format!(
        "<presence xmlns='{CLIENT}' type='unavailable' from='{PHONE}' to='{ALICE}'/>"
    ))?;
    alice.close()?;
    suite.stop()
}

fn removing_a_requested_component_contact_withdraws_the_request(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    alice.send(&format!("<presence type='subscribe' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribe"))?;
    push(&mut alice, contact, "none", Some("subscribe"), false)?;

    remove_contact(&mut alice, contact)?;
    send_component_ping(&mut component)?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribe"))?;
    expect_component_pong(&mut component)?;
    traffic(&suite, "presence", 0, 2)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn deleting_an_account_notifies_its_component_contacts(both: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    follow(&mut alice, &mut component, both)?;
    grant(&mut alice, &mut component, both, true, true)?;
    follow(&mut alice, &mut component, other_contact(both))?;
    request_from_component(&mut component, OTHER, "pending")?;
    client_receives(&mut alice, OTHER, "subscribe")?;
    component_barrier(&mut component)?;
    traffic(&suite, "presence", 4, 4)?;

    suite.delete_account("alice")?;
    alice.expect_stream_error("not-authorized")?;
    send_component_ping(&mut component)?;
    for contact in [SERVER, DOMAIN] {
        if contact == both {
            component_presence(&mut component, DESK, contact, Some("unavailable"))?;
        }
        component_presence(&mut component, ALICE, contact, Some("unsubscribe"))?;
        if contact == both {
            component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
        }
    }
    component_presence(&mut component, ALICE, OTHER, Some("unsubscribed"))?;
    expect_component_pong(&mut component)?;
    traffic(&suite, "presence", 4, 9)?;
    component.close()?;
    suite.stop()
}

const NOT_SUBSCRIBED: &str =
    "lonewolf_component_dropped_stanzas_total{reason=\"presence_not_subscribed\"}";

fn unsubscribe_stops_component_status_updates(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    let followed = other_contact(contact);
    follow(&mut alice, &mut component, followed)?;
    follow(&mut alice, &mut component, contact)?;
    grant(&mut alice, &mut component, contact, true, true)?;

    alice.send(&format!("<presence type='unsubscribe' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribe"))?;
    push(&mut alice, contact, "from", None, false)?;
    contact_status(&mut component, contact, Some("unavailable"), "disconnected")?;
    component.send(&format!("<presence type='unsubscribed' from='{contact}' to='{ALICE}'/><presence type='unsubscribe' from='{contact}' to='{ALICE}'/>"))?;
    expect_contact_status(&mut alice, contact, Some("unavailable"), "disconnected")?;
    client_receives(&mut alice, contact, "unsubscribe")?;
    push(&mut alice, contact, "none", None, false)?;
    component_presence(&mut component, ALICE, contact, Some("unsubscribed"))?;
    component_presence(&mut component, DESK, contact, Some("unavailable"))?;

    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 0)?;
    contact_status(&mut component, contact, None, "reconnected")?;
    contact_status(&mut component, followed, None, "online")?;
    traffic(&suite, "presence", 8, 7)?;
    expect_contact_status(&mut alice, followed, None, "online")?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 1)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn requested_component_contacts_show_presence_only_after_approval(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    alice.send(&format!("<presence type='subscribe' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribe"))?;
    push(&mut alice, contact, "none", Some("subscribe"), false)?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 0)?;

    contact_status(&mut component, contact, None, "before approval")?;
    component.send(&format!("<presence type='subscribed' from='{contact}' to='{ALICE}'/><presence from='{contact}' to='{ALICE}'><status>after approval</status></presence>"))?;
    traffic(&suite, "presence", 3, 1)?;
    client_receives(&mut alice, contact, "subscribed")?;
    push(&mut alice, contact, "to", None, false)?;
    expect_contact_status(&mut alice, contact, None, "after approval")?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 1)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn unavailable_and_full_jid_presence_from_unfollowed_contacts_is_delivered(
    contact: &str,
) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    grant(&mut alice, &mut component, contact, false, true)?;
    contact_status(&mut component, contact, Some("unavailable"), "disconnected")?;
    expect_contact_status(&mut alice, contact, Some("unavailable"), "disconnected")?;
    for sender in [
        contact,
        "#room%irc-server.example.test@irc.example.test/nick",
    ] {
        component.send(&format!("<presence from='{sender}' to='{DESK}'/>"))?;
        assert_presence(&alice.receive()?, CLIENT, sender, DESK, None);
    }
    traffic(&suite, "presence", 4, 2)?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 0)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn presence_from_component_jids_outside_the_roster_is_delivered(contact: &str) -> TestResult {
    let (mut suite, mut alice, mut component) = online()?;
    for sender in [contact, "bot@irc.example.test"] {
        contact_status(&mut component, sender, None, "online")?;
        expect_contact_status(&mut alice, sender, None, "online")?;
    }
    traffic(&suite, "presence", 2, 0)?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 0)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}

fn hosts_without_roster_deliver_component_presence_unfiltered(contact: &str) -> TestResult {
    use std::fs::OpenOptions;
    use std::io::Write;

    let (mut suite, mut alice, mut component) = unavailable_setup(CONFIG)?;
    alice.send(&format!("<presence type='subscribe' to='{contact}'/>"))?;
    component_presence(&mut component, ALICE, contact, Some("subscribe"))?;
    push(&mut alice, contact, "none", Some("subscribe"), false)?;
    component.close()?;
    alice.close()?;
    suite.stop()?;
    writeln!(
        OpenOptions::new()
            .append(true)
            .open(suite.fixture_path().join("lonewolf.toml"))?,
        "\n[hosts.localhost]\nextensions = ['ping']"
    )?;
    suite.restart()?;

    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<presence/>")?;
    assert_presence(&alice.receive()?, CLIENT, DESK, ALICE, None);
    let mut component = attach(&suite)?;
    contact_status(&mut component, contact, None, "online")?;
    expect_contact_status(&mut alice, contact, None, "online")?;
    traffic(&suite, "presence", 1, 0)?;
    assert_counter(&suite.scrape_metrics()?, NOT_SUBSCRIBED, 0)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}
