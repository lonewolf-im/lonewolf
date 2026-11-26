// SPDX-License-Identifier: Apache-2.0

use super::roster::{
    CONFIG, SERVER, component_barrier, expect_audience, get_roster, grant, publish,
    unavailable_setup,
};
use crate::blocking::{change_rule, external};
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
    super::roster::push(&mut alice, SERVER, "from", Some("subscribe"), false)?;
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
    super::roster::push(&mut alice, SERVER, "both", None, false)?;
    external::verify_owner_list(&mut alice)?;
    component_barrier(&mut component)?;
    component.close()?;
    alice.close()?;
    suite.stop()
}
