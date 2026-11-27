// SPDX-License-Identifier: Apache-2.0

use crate::blocking::{change_rule, external};
use crate::roster::component::{
    CLIENT, CONFIG, DESK, DOMAIN, OTHER, SERVER, component_barrier, component_presence,
    expect_audience, follow, get_roster, grant, publish, push, unavailable_setup,
};
use crate::support::{TestResult, barrier};

#[test]
fn owner_authority_and_route_matrix() -> TestResult {
    const OWNER: &str = "alice@localhost";
    const DESK: &str = "alice@localhost/desk";
    const PEER: &str = "irc-server.example.test@irc.example.test/phone";
    let (mut suite, mut alice, mut component) = unavailable_setup(&format!(
        "{CONFIG}\n[hosts.localhost]\nextensions=['blocking','roster','ping']"
    ))?;
    change_rule(&mut alice, "block", "private.example")?;
    external::foreign_commands(&mut component, PEER, OWNER, "missing@localhost")?;
    grant(&mut alice, &mut component, SERVER, false, false)?;
    publish(&mut alice, None, "ready")?;
    expect_audience(&mut component, &[], &[SERVER], None, Some("ready"))?;
    external::chats(&mut alice, &mut component, DESK, PEER, true)?;

    change_rule(&mut alice, "block", SERVER)?;
    expect_audience(&mut component, &[], &[SERVER], Some("unavailable"), None)?;
    external::blocked_matrix(&mut alice, &mut component, DESK, PEER)?;
    external::chats(
        &mut alice,
        &mut component,
        DESK,
        "other@irc.example.test/phone",
        true,
    )?;
    component_barrier(&mut component)?;
    barrier(&mut alice)?;
    let roster = get_roster(&mut alice)?;
    let query = roster.child("jabber:iq:roster", "query")?;
    assert_eq!(query.children.len(), 1, "{query:?}");
    query.children[0].assert_xml(&format!(
        "<item xmlns='jabber:iq:roster' jid='{SERVER}' subscription='from'/>"
    ))?;

    change_rule(&mut alice, "unblock", SERVER)?;
    expect_audience(&mut component, &[], &[SERVER], None, Some("ready"))?;
    external::restored_traffic(&mut alice, &mut component, DESK, PEER)?;

    alice.send(&format!("<presence type='subscribe' to='{SERVER}'/>"))?;
    external::envelope(
        &component.receive()?,
        crate::support::component::NAMESPACE,
        "presence",
        OWNER,
        SERVER,
        Some("subscribe"),
    );
    push(&mut alice, SERVER, "from", Some("subscribe"), false)?;
    component.send(&format!(
        "<presence type='subscribed' from='{SERVER}' to='{OWNER}'/>"
    ))?;
    external::envelope(
        &alice.receive()?,
        "jabber:client",
        "presence",
        SERVER,
        OWNER,
        Some("subscribed"),
    );
    push(&mut alice, SERVER, "both", None, false)?;
    external::verify_owner_list(&mut alice)?;
    component_barrier(&mut component)?;
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
