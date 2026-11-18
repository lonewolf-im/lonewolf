// SPDX-License-Identifier: Apache-2.0

use super::routing::traffic;
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

fn get_roster(alice: &mut Client) -> TestResult<Element> {
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

fn push(
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
    client_preapproval_completes_a_later_component_request_without_a_prompt,
    client_denial_and_revocation_reach_the_component,
    component_cancellation_and_unsubscribe_update_the_client_roster,
    client_unsubscribe_from_component_contact_clears_to,
    subscriptions_to_a_disconnected_component_bounce_and_keep_roster_state,
    component_subscriptions_to_full_jids_are_processed_as_bare,
    component_requests_over_the_pending_limit_get_resource_constraint,
    component_subscriptions_to_missing_accounts_are_silent_and_keep_the_stream_usable,
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
    let pair = [component.receive()?, component.receive()?];
    for stanza in &pair {
        stanza.assert_name(NAMESPACE, "presence");
        assert_eq!(stanza.attribute("type"), kind);
        assert_eq!(stanza.attribute("to"), Some(contact));
    }
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
