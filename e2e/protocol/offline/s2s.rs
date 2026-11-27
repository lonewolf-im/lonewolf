// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::FederatedPair;
use crate::support::federation::workflow::{
    ACCOUNTS, available, iq_reply, stanza_error, traffic, workflow_options,
};
use crate::support::{PASSWORD, TestResult};

#[test]
fn message_to_offline_recipient_is_stored_and_replayed() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    a.send(&format!(
        "<message type='chat' id='stored' to='{bj}'><body>Stored across domains</body></message>"
    ))?;
    a.send(&format!(
        "<iq type='get' id='stored-fence' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(&mut a, "stored-fence", "error", &bj, &format!("{aj}/desk"))?,
        "service-unavailable",
    )?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    available(&mut b, &bj, "phone")?;
    let reply = b.receive()?;
    reply.assert_name("jabber:client", "message");
    assert_eq!(reply.attribute("type"), Some("chat"));
    assert_eq!(reply.attribute("id"), Some("stored"));
    assert_eq!(reply.attribute("from"), Some(format!("{aj}/desk").as_str()));
    assert_eq!(reply.attribute("to"), Some(bj.as_str()));
    assert_eq!(
        reply.child("jabber:client", "body")?.text,
        "Stored across domains"
    );
    let delay = reply.child("urn:xmpp:delay", "delay")?;
    assert_eq!(delay.attribute("from"), Some(bd));
    let stamp = delay.attribute("stamp").ok_or("missing replay timestamp")?;
    assert_eq!(stamp.len(), 20);
    assert!(stamp.ends_with('Z') && stamp.as_bytes()[10] == b'T');
    crate::support::barrier(&mut b)?;
    traffic(
        &pair,
        "message_to_offline_recipient_is_stored_and_replayed",
        [1, 1, 0],
        [0, 1, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
