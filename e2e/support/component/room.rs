// SPDX-License-Identifier: Apache-2.0

use super::{ComponentClient, NAMESPACE};
use crate::support::{C2sSuite, Client, PASSWORD, TestResult, xml::Element};

pub(crate) const DOMAIN: &str = "muc.localhost";
pub(crate) const SECRET: &str = "component-test-secret-0001";
pub(crate) const TWO_COMPONENTS: &str = "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'\n[components.domains.'pubsub.localhost']\nsecret='component-test-secret-0001'";
pub(crate) const CONFIG: &str =
    "[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'";
pub(crate) const ROOM: &str = "room@muc.localhost";
pub(crate) const CLIENT: &str = "jabber:client";

pub(crate) fn connect(suite: &C2sSuite) -> TestResult<ComponentClient> {
    ComponentClient::authenticated(suite, DOMAIN, SECRET)
}

pub(crate) fn client(suite: &C2sSuite, name: &str, resource: &str) -> TestResult<Client> {
    suite.create_account(name, PASSWORD)?;
    suite.connect(name, PASSWORD, resource)
}

pub(crate) fn numbered(ns: &str, from: &str, to: &str, id: &str) -> String {
    format!(
        "<message xmlns='{ns}' type='chat' from='{from}' to='{to}' id='{id}'><body>{id}</body></message>"
    )
}

pub(crate) fn ping(component: &mut ComponentClient, id: &str) -> TestResult {
    component.send(&format!("<iq type='get' from='muc.localhost' to='localhost' id='{id}'><ping xmlns='urn:xmpp:ping'/></iq>"))
}

pub(crate) fn ping_result(component: &mut ComponentClient, id: &str) -> TestResult {
    component.expect_xml(&format!(
        "<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='muc.localhost' id='{id}'/>"
    ))
}

pub(crate) fn through_ping(component: &mut ComponentClient, id: &str) -> TestResult<Vec<Element>> {
    let mut stanzas = Vec::new();
    loop {
        let stanza = component.receive()?;
        if stanza.name == "iq" && stanza.attribute("id") == Some(id) {
            stanza.assert_xml(&format!("<iq xmlns='{NAMESPACE}' type='result' from='localhost' to='muc.localhost' id='{id}'/>"))?;
            return Ok(stanzas);
        }
        stanzas.push(stanza);
    }
}
