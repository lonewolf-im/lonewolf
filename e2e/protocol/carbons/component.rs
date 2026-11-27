// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{
    ComponentClient,
    room::{DOMAIN, SECRET, TWO_COMPONENTS as CONFIG, ping, ping_result},
    traffic,
};
use crate::support::{C2sSuite, PASSWORD, TestResult};

#[test]
fn component_chat_delivers_received_carbons_to_the_other_enabled_resource() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    for (client, resource) in [(&mut desk, "desk"), (&mut phone, "phone")] {
        client.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='enable' to='alice@localhost/{resource}'/>"
        ))?;
    }
    let mut component = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    component.send("<message type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message>")?;
    desk.expect_xml("<message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    phone.expect_xml("<message xmlns='jabber:client' type='chat' from='alice@localhost' to='alice@localhost/phone'><received xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' type='chat' from='room@muc.localhost/nick' to='alice@localhost/desk' id='carbon'><body>copied</body></message></forwarded></received></message>").map_err(|error| crate::support::xml::context("component stanza delivery", error))?;
    ping(&mut component, "done")?;
    ping_result(&mut component, "done")?;
    traffic(&suite, "message", 1, 0)?;
    component.close()?;
    desk.close()?;
    phone.close()?;
    suite.stop()
}
