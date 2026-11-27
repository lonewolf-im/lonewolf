// SPDX-License-Identifier: Apache-2.0

use crate::support::component::{SECRET_FILE_DOMAIN, write_secret};
use crate::support::{C2sSuite, PASSWORD, TestResult};

#[test]
fn component_discovery_follows_the_discoverable_setting() -> TestResult {
    for discoverable in [true, false] {
        let mut suite = C2sSuite::with_components_and_setup(
            &format!("{SECRET_FILE_DOMAIN}\ndiscoverable={discoverable}"),
            "",
            write_secret,
        )?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send("<iq type='get' to='localhost' id='items'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
        if discoverable {
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'><item jid='muc.localhost'/></query></iq>")?;
        } else {
            alice.expect_xml("<iq xmlns='jabber:client' type='result' id='items' from='localhost' to='alice@localhost/desk'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")?;
        }
        alice.close()?;
        suite.stop()?;
    }
    Ok(())
}
