// SPDX-License-Identifier: Apache-2.0

use crate::support::federation::FederatedPair;
use crate::support::federation::workflow::{
    ACCOUNTS, iq_reply, stanza_error, traffic, workflow_options,
};
use crate::support::{PASSWORD, TestResult};

#[test]
fn vcard_of_remote_account_is_public() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut pair = FederatedPair::start(ad, bd, workflow_options())?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    b.send("<iq type='set' id='publish'><vCard xmlns='vcard-temp'><FN>Public remote name</FN></vCard></iq>")?;
    b.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='publish' to='{bj}/phone'/>"
    ))?;
    a.send(&format!(
        "<iq type='get' id='public-card' to='{bj}'><vCard xmlns='vcard-temp'/></iq>"
    ))?;
    let reply = iq_reply(&mut a, "public-card", "result", &bj, &format!("{aj}/desk"))?;
    assert_eq!(
        reply
            .child("vcard-temp", "vCard")?
            .child("vcard-temp", "FN")?
            .text,
        "Public remote name"
    );
    traffic(
        &pair,
        "vcard_of_remote_account_is_public",
        [0, 1, 0],
        [0, 1, 0],
    )?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}

#[test]
fn remote_vcard_set_is_forbidden() -> TestResult {
    let (ad, an, bd, bn) = ACCOUNTS;
    let mut options = workflow_options();
    // Disable the source vCard handler so the remote server must reject this SET.
    options.a_extensions = "'roster'".into();
    let mut pair = FederatedPair::start(ad, bd, options)?;
    pair.a.create_account(an, PASSWORD)?;
    pair.b.create_account(bn, PASSWORD)?;
    let aj = format!("{an}@{ad}");
    let bj = format!("{bn}@{bd}");
    let mut a = pair.a.connect(an, PASSWORD, "desk")?;
    let mut b = pair.b.connect(bn, PASSWORD, "phone")?;
    b.send("<iq type='set' id='original-card'><vCard xmlns='vcard-temp'><FN>Original name</FN></vCard></iq>")?;
    b.expect_xml(&format!(
        "<iq xmlns='jabber:client' type='result' id='original-card' to='{bj}/phone'/>"
    ))?;
    a.send(&format!("<iq type='set' id='forbidden-card' to='{bj}'><vCard xmlns='vcard-temp'><FN>Unwanted change</FN></vCard></iq>"))?;
    stanza_error(
        &iq_reply(
            &mut a,
            "forbidden-card",
            "error",
            &bj,
            &format!("{aj}/desk"),
        )?,
        "forbidden",
    )?;
    b.send("<iq type='get' id='own-card'><vCard xmlns='vcard-temp'/></iq>")?;
    let reply = b.receive()?;
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some("own-card"));
    assert_eq!(
        reply
            .child("vcard-temp", "vCard")?
            .child("vcard-temp", "FN")?
            .text,
        "Original name"
    );
    traffic(&pair, "remote_vcard_set_is_forbidden", [0, 1, 0], [0, 1, 0])?;
    a.close()?;
    b.close()?;
    pair.stop()?;
    Ok(())
}
