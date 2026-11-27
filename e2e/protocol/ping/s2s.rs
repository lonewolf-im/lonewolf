// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::workflow::{
    ACCOUNTS, iq_reply, presence, stanza_error, traffic, workflow_options,
};
use crate::support::federation::{FederatedPair, subscribe_mutually};
use crate::support::{PASSWORD, TestResult};

#[test]
fn ping_remote_account_requires_subscription() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    a.send(&format!(
        "<iq type='get' id='private-ping' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
    ))?;
    stanza_error(
        &iq_reply(&mut a, "private-ping", "error", &bj, &format!("{aj}/desk"))?,
        "service-unavailable",
    )?;
    subscribe_mutually(&mut a, &aj, &mut b, &bj)?;
    a.send(&format!(
        "<iq type='get' id='authorized-ping' to='{bj}'><ping xmlns='urn:xmpp:ping'/></iq>"
    ))?;
    assert!(
        iq_reply(
            &mut a,
            "authorized-ping",
            "result",
            &bj,
            &format!("{aj}/desk")
        )?
        .children
        .is_empty()
    );
    traffic(
        &pair,
        "ping_remote_account_requires_subscription",
        [0, 2, 3],
        [0, 2, 3],
    )?;
    a.close()?;
    presence(&mut b, &format!("{aj}/desk"), &bj, Some("unavailable"))?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
