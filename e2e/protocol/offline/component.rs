// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{
    ComponentClient, NAMESPACE,
    room::{
        CLIENT, CONFIG, DOMAIN, ROOM, SECRET, TWO_COMPONENTS, client, connect, numbered, ping,
        ping_result, through_ping,
    },
    traffic,
};
use crate::support::{C2sSuite, PASSWORD, TestResult, barrier};

#[test]
fn component_chat_is_stored_offline_and_replayed_with_delay_at_next_available_login() -> TestResult
{
    let mut suite = C2sSuite::with_components(TWO_COMPONENTS)?;
    suite.create_account("bob", PASSWORD)?;
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<message type='chat' from='room@muc.localhost/nick' to='bob@localhost' id='offline'><body>saved message</body></message>")?;
    ping(&mut component, "stored")?;
    ping_result(&mut component, "stored")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/desk' to='bob@localhost'/>",
    )?;
    let mut saved = bob.receive()?;
    let delay = saved.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some("localhost"));
    let stamp = delay.attribute("stamp").ok_or("missing delay timestamp")?;
    assert_eq!(stamp.len(), 20);
    assert!(stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T');
    saved
        .children
        .retain(|child| child.namespace != "urn:xmpp:delay" || child.name != "delay");
    saved.assert_xml("<message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='bob@localhost' id='offline'><body>saved message</body></message>")?;
    barrier(&mut bob)?;
    traffic(&suite, "message", 1, 0)?;
    traffic(&suite, "iq", 1, 1)?;
    component.close()?;
    bob.close()?;
    suite.stop()
}

#[test]
fn room_chat_sent_while_offline_reaches_the_next_available_login_with_delay() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut bob = client(&suite, "bob", "phone")?;
    bob.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    let mut room = connect(&suite)?;
    room.send(&numbered(NAMESPACE, ROOM, "bob@localhost", "offline"))?;
    ping(&mut room, "stored")?;
    assert!(through_ping(&mut room, "stored")?.is_empty());
    let mut bob = suite.connect("bob", PASSWORD, "next")?;
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/next' to='bob@localhost'/>",
    )?;
    let mut stanza = bob.receive()?;
    let delay = stanza.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some("localhost"));
    time::OffsetDateTime::parse(
        delay.attribute("stamp").ok_or("missing delay stamp")?,
        &time::format_description::well_known::Rfc3339,
    )?;
    assert_eq!(
        stanza
            .children
            .iter()
            .filter(|child| child.namespace == "urn:xmpp:delay" && child.name == "delay")
            .count(),
        1
    );
    stanza
        .children
        .retain(|child| child.namespace != "urn:xmpp:delay" || child.name != "delay");
    stanza.assert_xml(&numbered(CLIENT, ROOM, "bob@localhost", "offline"))?;
    barrier(&mut bob)?;
    traffic(&suite, "message", 1, 0)?;
    room.close()?;
    bob.close()?;
    suite.stop()
}
