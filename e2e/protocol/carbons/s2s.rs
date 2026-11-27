// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::FederatedPair;
use crate::support::federation::workflow::{ACCOUNTS, traffic, workflow_options};
use crate::support::{PASSWORD, TestResult};

#[test]
fn carbons_copy_federated_messages() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    let mut a2 = pair.a.connect(an, PASSWORD, "tablet")?;
    let mut b2 = pair.b.connect(bn, PASSWORD, "tablet")?;
    for (client, full) in [
        (&mut a, format!("{aj}/desk")),
        (&mut a2, format!("{aj}/tablet")),
        (&mut b, format!("{bj}/phone")),
        (&mut b2, format!("{bj}/tablet")),
    ] {
        client.send("<iq type='set' id='enable'><enable xmlns='urn:xmpp:carbons:2'/></iq>")?;
        client.expect_xml(&format!(
            "<iq xmlns='jabber:client' type='result' id='enable' to='{full}'/>"
        ))?;
    }
    a.send(&format!("<message type='chat' id='carbon' to='{bj}/phone'><body>Carbon across domains</body></message>"))?;
    let inner = format!(
        "<message xmlns='jabber:client' type='chat' id='carbon' from='{aj}/desk' to='{bj}/phone'><body>Carbon across domains</body></message>"
    );
    let received_inner = inner.replace("type='chat'", "type='chat' xml:lang='en'");
    b.receive()?.assert_xml(&received_inner)?;
    for (client, bare, full, direction) in [
        (&mut a2, &aj, format!("{aj}/tablet"), "sent"),
        (&mut b2, &bj, format!("{bj}/tablet"), "received"),
    ] {
        let copy = client.receive()?;
        copy.assert_name("jabber:client", "message");
        assert_eq!(copy.attribute("from"), Some(bare.as_str()));
        assert_eq!(copy.attribute("to"), Some(full.as_str()));
        copy.child("urn:xmpp:carbons:2", direction)?
            .child("urn:xmpp:forward:0", "forwarded")?
            .child("jabber:client", "message")?
            .assert_xml(if direction == "sent" {
                &inner
            } else {
                &received_inner
            })?;
    }
    a2.close()?;
    b2.close()?;
    traffic(
        &pair,
        "carbons_copy_federated_messages",
        [1, 0, 0],
        [0, 0, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
