// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::net::Shutdown;

use crate::support::xml::Element;
use crate::support::{C2sSuite, Client, OPEN, PASSWORD, TestResult, barrier};

#[path = "../support/vcard.rs"]
mod fixtures;

const VCARD: &str = "vcard-temp";
const XML: &str = "http://www.w3.org/XML/1998/namespace";
const MARKER: &str = "PRIVATE-VCARD-MARKER-469";

fn result(client: &mut Client, id: &str, from: Option<&str>, to: &str) -> TestResult<Element> {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some(id));
    assert_eq!(reply.attribute("from"), from);
    assert_eq!(reply.attribute("to"), Some(to));
    Ok(reply)
}

fn omitted_error(
    client: &mut Client,
    id: &str,
    condition: &str,
    kind: &str,
) -> TestResult<Element> {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("id"), Some(id));
    assert_eq!(reply.children.len(), 1);
    let error = reply.child("jabber:client", "error")?;
    assert_eq!(error.attribute("type"), Some(kind));
    assert_eq!(error.children.len(), 2);
    let text = error.child("urn:ietf:params:xml:ns:xmpp-stanzas", "text")?;
    assert_eq!(text.attribute_in("lang", XML)?, Some("en"));
    assert!(!text.text.is_empty());
    error.child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
    assert!(!format!("{reply:?}").contains(MARKER));
    Ok(reply)
}

fn publish(client: &mut Client, resource: &str, payload: &str) -> TestResult {
    client.send(&format!("<iq type='set' id='write'>{payload}</iq>"))?;
    assert!(
        result(
            client,
            "write",
            None,
            &format!("alice@localhost/{resource}")
        )?
        .children
        .is_empty()
    );
    Ok(())
}

fn own_card(client: &mut Client, resource: &str) -> TestResult<Element> {
    client.send("<iq type='get' id='read'><vCard xmlns='vcard-temp'/></iq>")?;
    let mut reply = result(client, "read", None, &format!("alice@localhost/{resource}"))?;
    assert_eq!(reply.children.len(), 1);
    reply.children[0].assert_name(VCARD, "vCard");
    Ok(reply.children.remove(0))
}

fn drain_presence(client: &mut Client) -> TestResult {
    client.send("<iq type='get' id='drain'><query xmlns='urn:test:barrier'/></iq>")?;
    for _ in 0..16 {
        let reply = client.receive()?;
        if reply.name == "iq" {
            assert_eq!(reply.attribute("id"), Some("drain"));
            assert_eq!(reply.attribute("type"), Some("error"));
            return Ok(());
        }
        reply.assert_name("jabber:client", "presence");
    }
    Err("presence queue exceeded fixture bound".into())
}

#[test]
fn vcard_owner_two_resources_public_offline_whole_replacement_and_empty_publication() -> TestResult
{
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "reader")?;
    for destination in ["", " to='ALICE@LOCALHOST'"] {
        for id in ["", "&lt;&amp;&quot;&apos;&gt;", "reused", "reused"] {
            desk.send(&format!("<iq type='set'{destination} from='bob@localhost/reader' id='{id}'><vCard xmlns='vcard-temp'><FN>Alice é é</FN><NICKNAME>old</NICKNAME></vCard></iq>"))?;
            let from = if destination.is_empty() {
                ""
            } else {
                " from='alice@localhost'"
            };
            desk.expect_xml(&format!("<iq xmlns='jabber:client' type='result'{from} to='alice@localhost/desk' id='{id}'/>"))?;
            desk.send(&format!(
                "<iq type='get'{destination} id='{id}'><vCard xmlns='vcard-temp'/></iq>"
            ))?;
            let read = desk.receive()?;
            assert_eq!(read.attribute("type"), Some("result"));
            assert_eq!(
                read.attribute("id"),
                Some(if id.starts_with("&lt;") { "<&\"'>" } else { id })
            );
            assert_eq!(read.attribute("to"), Some("alice@localhost/desk"));
            assert_eq!(read.children.len(), 1);
            assert_eq!(
                read.attribute("from"),
                if destination.is_empty() {
                    None
                } else {
                    Some("alice@localhost")
                }
            );
            assert_eq!(
                read.child(VCARD, "vCard")?.child(VCARD, "FN")?.text,
                "Alice é é"
            );
        }
    }
    assert_eq!(
        own_card(&mut phone, "phone")?
            .child(VCARD, "NICKNAME")?
            .text,
        "old"
    );
    publish(
        &mut phone,
        "phone",
        "<vCard xmlns='vcard-temp'><FN>Replacement</FN><JABBERID>bob@localhost</JABBERID><CLASS><PRIVATE/><CONFIDENTIAL/></CLASS><owner xmlns='urn:foreign'>bob</owner><PHOTO><TYPE>image/unknown</TYPE><BINVAL>AQID</BINVAL><EXTVAL>https://invalid.example/not-fetched</EXTVAL></PHOTO><KEY><CRED>synthetic opaque value</CRED></KEY><SOUND><EXTVAL>../inert</EXTVAL></SOUND><LOGO><EXTVAL>urn:inert</EXTVAL></LOGO></vCard>",
    )?;
    let card = own_card(&mut desk, "desk")?;
    assert_eq!(card.child(VCARD, "FN")?.text, "Replacement");
    assert!(card.child(VCARD, "NICKNAME").is_err());
    bob.send("<iq type='get' id='inert-owner'><vCard xmlns='vcard-temp'/></iq>")?;
    omitted_error(&mut bob, "inert-owner", "item-not-found", "cancel")?;
    for offline in [false, true] {
        if offline {
            desk.close()?;
            phone.close()?;
        }
        bob.send("<iq type='get' to='alice@localhost' id='public'><vCard xmlns='vcard-temp' xml:space='invalid'>ignored<field xmlns='urn:foreign'/></vCard></iq>")?;
        let read = result(
            &mut bob,
            "public",
            Some("alice@localhost"),
            "bob@localhost/reader",
        )?;
        assert_eq!(read.children.len(), 1);
        assert_eq!(read.child(VCARD, "vCard")?, &card);
        if !offline {
            barrier(&mut desk)?;
            barrier(&mut phone)?;
        }
    }
    let mut desk = suite.connect("alice", PASSWORD, "again")?;
    for empty in [
        "<vCard xmlns='vcard-temp'/>",
        "<vCard xmlns='vcard-temp' version='anything'> \n </vCard>",
    ] {
        publish(&mut desk, "again", empty)?;
        let card = own_card(&mut desk, "again")?;
        assert!(card.children.is_empty());
        assert_eq!(
            card.attribute("version"),
            if empty.contains("version=") {
                Some("anything")
            } else {
                None
            }
        );
        assert!(card.text.trim().is_empty());
        barrier(&mut bob)?;
    }
    desk.close()?;
    bob.close()
}

#[test]
fn vcard_missing_owner_public_absence_and_ignored_selectors_keep_storage_and_stream_usable()
-> TestResult {
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for payload in [
        "<vCard xmlns='vcard-temp'/>",
        "<vCard xmlns='vcard-temp' xml:space='' xmlns:f='urn:foreign' f:owner='secret'>text<FN>filter</FN></vCard>",
    ] {
        for (target, condition) in [
            ("", "item-not-found"),
            (" to='alice@localhost'", "item-not-found"),
            (" to='bob@localhost'", "service-unavailable"),
            (" to='missing@localhost'", "service-unavailable"),
        ] {
            alice.send(&format!(
                "<iq type='get'{target} id='absent'>{payload}</iq>"
            ))?;
            omitted_error(&mut alice, "absent", condition, "cancel")?;
            barrier(&mut alice)?;
        }
    }
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>unchanged</FN></vCard>",
    )?;
    for payload in [
        "<vCard xmlns='vcard-temp'>PRIVATE-VCARD-MARKER-469</vCard>",
        "<vCard xmlns='vcard-temp' xml:space='bad'/>",
        "<vCard xmlns='vcard-temp' xml:space=''/>",
        "<vCard xmlns='vcard-temp'><FN xml:space='bad'>private</FN></vCard>",
        "<vCard xmlns='vcard-temp'><FN xml:space=''>private</FN></vCard>",
    ] {
        alice.send(&format!("<iq type='set' id='invalid'>{payload}</iq>"))?;
        omitted_error(&mut alice, "invalid", "bad-request", "modify")?;
        assert_eq!(
            own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
            "unchanged"
        );
    }
    let logs = fs::read_to_string(suite.fixture_path().join("server.log"))?;
    assert!(!logs.contains(MARKER));
    alice.close()
}

#[test]
fn vcard_wrong_set_destinations_never_deliver_or_replace_cards() -> TestResult {
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", PASSWORD, "visible")?;
    let mut hidden = suite.connect("bob", PASSWORD, "hidden")?;
    let mut carol = suite.connect("carol", PASSWORD, "hidden")?;
    carol.send("<iq type='set' id='victim'><vCard xmlns='vcard-temp'><FN>victim original</FN></vCard></iq>")?;
    result(&mut carol, "victim", None, "carol@localhost/hidden")?;
    bob.send("<presence to='alice@localhost/desk'/>")?;
    alice.receive()?.assert_name("jabber:client", "presence");
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>original</FN></vCard>",
    )?;
    for target in [
        "bob@localhost",
        "carol@localhost",
        "carol@localhost/hidden",
        "missing@localhost",
        "alice@localhost/desk",
        "alice@localhost/phone",
        "alice@localhost/absent",
        "alice@localhost/Phone",
        "bob@localhost/visible",
        "bob@localhost/hidden",
        "missing@localhost/resource",
        "localhost",
        "localhost/resource",
        "remote.example",
        "bob@remote.example",
        "bob@remote.example/resource",
    ] {
        alice.send(&format!("<iq type='set' id='forbidden' to='{target}'><vCard xmlns='vcard-temp'><FN>{MARKER}</FN></vCard></iq>"))?;
        let reply = omitted_error(&mut alice, "forbidden", "forbidden", "auth")?;
        assert_eq!(reply.attribute("from"), Some(target));
        assert_eq!(reply.attribute("to"), Some("alice@localhost/desk"));
        assert_eq!(
            own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
            "original"
        );
        barrier(&mut phone)?;
        barrier(&mut bob)?;
        barrier(&mut hidden)?;
        carol.send("<iq type='get' id='victim'><vCard xmlns='vcard-temp'/></iq>")?;
        assert_eq!(
            result(&mut carol, "victim", None, "carol@localhost/hidden")?
                .child(VCARD, "vCard")?
                .child(VCARD, "FN")?
                .text,
            "victim original"
        );
    }
    bob.send("<iq type='get' id='empty'><vCard xmlns='vcard-temp'/></iq>")?;
    omitted_error(&mut bob, "empty", "item-not-found", "cancel")?;
    let logs = fs::read_to_string(suite.fixture_path().join("server.log"))?;
    assert!(!logs.contains(MARKER));
    carol.close()?;
    hidden.close()?;
    bob.close()?;
    drain_presence(&mut alice)?;
    alice.close()?;
    phone.close()
}

#[test]
fn vcard_pipelined_set_get_and_truncated_stanza_preserve_commit_order() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='write'><vCard xmlns='vcard-temp'><FN>committed</FN></vCard></iq><iq type='get' id='read'><vCard xmlns='vcard-temp'/></iq>")?;
    assert!(
        result(&mut alice, "write", None, "alice@localhost/desk")?
            .children
            .is_empty()
    );
    assert_eq!(
        result(&mut alice, "read", None, "alice@localhost/desk")?
            .child(VCARD, "vCard")?
            .child(VCARD, "FN")?
            .text,
        "committed"
    );
    alice
        .send("<iq type='set' id='truncated'><vCard xmlns='vcard-temp'><FN>never committed</FN>")?;
    alice.transport().sock.shutdown(Shutdown::Both)?;
    drop(alice);
    let mut other = suite.connect("alice", PASSWORD, "other")?;
    assert_eq!(
        own_card(&mut other, "other")?.child(VCARD, "FN")?.text,
        "committed"
    );
    other.close()
}

#[test]
fn vcard_restart_retains_database_tls_accounts_and_reads_above_reduced_write_quota() -> TestResult {
    let mut suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions=['disco','vcard']\n[hosts.localhost.vcard]\nmax_bytes=2048",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    publish(
        &mut alice,
        "desk",
        &format!(
            "<vCard xmlns='vcard-temp'><FN>{}</FN></vCard>",
            "é".repeat(300)
        ),
    )?;
    let before = own_card(&mut alice, "desk")?;
    alice.close()?;
    let directory = suite.fixture_path().to_owned();
    let certificate = fs::read(directory.join("certificate.pem"))?;
    suite.restart()?;
    assert_eq!(suite.fixture_path(), directory);
    assert_eq!(fs::read(directory.join("certificate.pem"))?, certificate);
    let mut alice = suite.connect("alice", PASSWORD, "after")?;
    assert_eq!(own_card(&mut alice, "after")?, before);
    alice.close()?;
    let config = directory.join("lonewolf.toml");
    fs::write(
        &config,
        fs::read_to_string(&config)?.replace("max_bytes=2048", "max_bytes=256"),
    )?;
    suite.restart()?;
    let mut alice = suite.connect("alice", PASSWORD, "reduced")?;
    assert_eq!(own_card(&mut alice, "reduced")?, before);
    alice.send(&format!(
        "<iq type='set' id='large'><vCard xmlns='vcard-temp'><FN>{}</FN></vCard></iq>",
        "x".repeat(300)
    ))?;
    omitted_error(&mut alice, "large", "resource-constraint", "wait")?;
    assert_eq!(own_card(&mut alice, "reduced")?, before);
    publish(
        &mut alice,
        "reduced",
        "<vCard xmlns='vcard-temp'><FN>small</FN></vCard>",
    )?;
    assert_eq!(
        own_card(&mut alice, "reduced")?.child(VCARD, "FN")?.text,
        "small"
    );
    alice.close()
}

#[test]
fn vcard_semantics_namespace_qnames_and_xml_normalization_survive_repeated_storage() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = Client::secure(&suite)?;
    alice.authenticate("alice", PASSWORD)?;
    let mut alice = alice.restart();
    alice.open_with(
        &OPEN
            .replace("stream:stream", "s:stream")
            .replace("xmlns:stream=", "xmlns:s="),
    )?;
    alice.features()?;
    alice.bind(Some("desk"))?;
    let payload = "<vCard xmlns='vcard-temp' version='3.0' xml:base='../inert'><FN>é é &amp; &lt;</FN><NOTE>before<b xmlns='urn:foreign'>bold</b>after</NOTE><TEL><NUMBER/></TEL><TEL><NUMBER>123</NUMBER></TEL><EMAIL><USERID>a@example.test</USERID></EMAIL><ADR><CTRY>España</CTRY></ADR><AGENT><vCard><FN>Nested</FN></vCard></AGENT><f:data xmlns:f='urn:foreign' q='s:Type' i='i:Type' literal='a\t\nb\rc' referenced='a&#9;&#10;b&#13;c'>s:Text<reset xmlns=''/><i:child xmlns:i='urn:rebound'/></f:data><NOTE>literal\r\nnext\rlast&#13;ref</NOTE></vCard>";
    alice.send(&format!(
        "<iq type='set' id='semantic' xmlns:i='urn:iq-qname' not_stored='yes'>{payload}</iq>"
    ))?;
    assert!(
        result(&mut alice, "semantic", None, "alice@localhost/desk")?
            .children
            .is_empty()
    );
    let card = own_card(&mut alice, "desk")?;
    assert_eq!(card.attribute("not_stored"), None);
    assert_eq!(card.attribute_in("base", XML)?, Some("../inert"));
    assert_eq!(card.child(VCARD, "FN")?.text, "é é & <");
    let notes: Vec<_> = card.children.iter().filter(|c| c.name == "NOTE").collect();
    assert_eq!(notes[0].text, "beforeafter");
    assert_eq!(notes[0].children[0].text, "bold");
    assert_eq!(notes[1].text, "literal\nnext\nlast\rref");
    let foreign = card.child("urn:foreign", "data")?;
    assert_eq!(
        foreign.resolve_qname(foreign.attribute("q").ok_or("missing q")?)?,
        ("http://etherx.jabber.org/streams", "Type")
    );
    assert_eq!(
        foreign.resolve_qname(foreign.attribute("i").ok_or("missing i")?)?,
        ("urn:iq-qname", "Type")
    );
    assert_eq!(foreign.attribute("literal"), Some("a  b c"));
    assert_eq!(foreign.attribute("referenced"), Some("a\t\nb\rc"));
    foreign.child("", "reset")?;
    foreign.child("urn:rebound", "child")?;
    assert_eq!(own_card(&mut alice, "desk")?, card);
    alice.close_with_footer("</s:stream>")
}

#[test]
fn vcard_language_space_context_is_detached_from_later_retrieval_stream() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut reader = Client::secure(&suite)?;
    reader.authenticate("alice", PASSWORD)?;
    let mut reader = reader.restart();
    reader.open_with(&OPEN.replace('>', " xml:lang='de' xml:space='preserve'>"))?;
    reader.features()?;
    reader.bind(Some("reader"))?;
    for (stream, iq, root, lang, space) in [
        ("", "", "", "", "default"),
        (
            " xml:lang='es' xml:space='preserve'",
            "",
            "",
            "es",
            "preserve",
        ),
        (
            " xml:lang='es' xml:space='default'",
            "",
            "",
            "es",
            "default",
        ),
        (
            " xml:lang='es' xml:space='preserve'",
            " xml:lang='fr' xml:space='default'",
            "",
            "fr",
            "default",
        ),
        (
            " xml:space='default'",
            " xml:space='preserve'",
            "",
            "",
            "preserve",
        ),
        (
            " xml:lang='es' xml:space='preserve'",
            " xml:lang='fr' xml:space='default'",
            " xml:lang='de' xml:space='preserve'",
            "de",
            "preserve",
        ),
        (
            " xml:lang='es' xml:space='preserve'",
            "",
            " xml:lang='' xml:space='default'",
            "",
            "default",
        ),
        (
            " xml:space='invalid'",
            "",
            " xml:space='default'",
            "",
            "default",
        ),
        ("", " xml:space=''", " xml:space='preserve'", "", "preserve"),
    ] {
        let mut writer = Client::secure(&suite)?;
        writer.authenticate("alice", PASSWORD)?;
        let mut writer = writer.restart();
        writer.open_with(&OPEN.replace('>', &format!("{stream}>")))?;
        writer.features()?;
        writer.bind(Some("writer"))?;
        writer.send(&format!("<iq type='set' id='context'{iq}><vCard xmlns='vcard-temp'{root}><FN xml:lang='it' xml:space='preserve'>  nested  </FN></vCard></iq>"))?;
        assert!(
            result(&mut writer, "context", None, "alice@localhost/writer")?
                .children
                .is_empty()
        );
        let card = own_card(&mut reader, "reader")?;
        assert_eq!(card.attribute_in("lang", XML)?, Some(lang));
        assert_eq!(card.attribute_in("space", XML)?, Some(space));
        let field = card.child(VCARD, "FN")?;
        assert_eq!(field.attribute_in("lang", XML)?, Some("it"));
        assert_eq!(field.attribute_in("space", XML)?, Some("preserve"));
        assert_eq!(field.text, "  nested  ");
        writer.close()?;
    }
    for (stream, iq) in [
        (" xml:space='invalid'", ""),
        (" xml:space=''", ""),
        ("", " xml:space='invalid'"),
        ("", " xml:space='' "),
    ] {
        let before = own_card(&mut reader, "reader")?;
        let mut writer = Client::secure(&suite)?;
        writer.authenticate("alice", PASSWORD)?;
        let mut writer = writer.restart();
        writer.open_with(&OPEN.replace('>', &format!("{stream}>")))?;
        writer.features()?;
        writer.bind(Some("writer"))?;
        writer.send(&format!("<iq type='set' id='invalid'{iq}><vCard xmlns='vcard-temp'><FN>{MARKER}</FN></vCard></iq>"))?;
        omitted_error(&mut writer, "invalid", "bad-request", "modify")?;
        assert_eq!(own_card(&mut reader, "reader")?, before);
        writer.send("<iq type='get' id='selector'><vCard xmlns='vcard-temp' xml:space='invalid'>ignored</vCard></iq>")?;
        assert_eq!(
            result(&mut writer, "selector", None, "alice@localhost/writer")?
                .child(VCARD, "vCard")?,
            &before
        );
        writer.close()?;
    }
    reader.close()
}

#[test]
fn vcard_envelopes_and_invalid_responses_preserve_storage_and_no_reply_loops() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>retained</FN></vCard>",
    )?;
    for (attributes, payload, id) in [
        ("type='set'", "<vCard xmlns='vcard-temp'/>", ""),
        (
            "id='missing-type'",
            "<vCard xmlns='vcard-temp'/>",
            "missing-type",
        ),
        (
            "type='' id='empty-type'",
            "<vCard xmlns='vcard-temp'/>",
            "empty-type",
        ),
        (
            "type='invalid' id='type'",
            "<vCard xmlns='vcard-temp'/>",
            "type",
        ),
        ("type='get' id='zero'", "", "zero"),
        (
            "type='set' id='two'",
            "<vCard xmlns='vcard-temp'/><extra/>",
            "two",
        ),
    ] {
        alice.send(&format!("<iq {attributes}>{payload}</iq>"))?;
        omitted_error(&mut alice, id, "bad-request", "modify")?;
        assert_eq!(
            own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
            "retained"
        );
    }
    for target in [
        "localhost",
        "alice@localhost",
        "missing@localhost",
        "alice@localhost/desk",
        "remote.example",
    ] {
        alice.send(&format!("<iq type='result' to='{target}' id='malformed'><vCard xmlns='vcard-temp'/><extra/></iq><iq type='error' to='{target}' id='malformed'><vCard xmlns='vcard-temp'/></iq>"))?;
        barrier(&mut alice)?;
        assert_eq!(
            own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
            "retained"
        );
    }
    alice.close()
}

#[test]
fn vcard_tls_authentication_sasl_and_prebind_gates_never_publish() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    for payload in [
        "<vCard xmlns='vcard-temp'/>",
        "<ping xmlns='urn:xmpp:ping'/>",
    ] {
        let mut plain = suite.tcp_client()?;
        plain.open()?;
        plain.send(&format!("<iq type='set' id='plain'>{payload}</iq>"))?;
        plain.expect_stream_error("not-authorized")?;
        let mut unauth = Client::secure(&suite)?;
        unauth.send(&format!("<iq type='set' id='unauth'>{payload}</iq>"))?;
        unauth.expect_stream_error("not-authorized")?;
        let mut sasl = Client::secure(&suite)?;
        sasl.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=preauthfixednonce")?;
        sasl.receive()?
            .assert_name(crate::support::SASL_NAMESPACE, "challenge");
        sasl.send(&format!("<iq type='set' id='during'>{payload}</iq>"))?;
        sasl.expect_stream_error("not-authorized")?;
        let mut prebind = suite.authenticated_client("alice", PASSWORD)?;
        prebind.send(&format!("<iq type='set' id='prebind'>{payload}</iq>"))?;
        let reply = prebind.receive()?;
        assert_eq!(reply.attribute("type"), Some("error"));
        reply
            .child("jabber:client", "error")?
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
        prebind.bind(Some("after"))?;
        prebind.send("<iq type='get' id='empty'><vCard xmlns='vcard-temp'/></iq>")?;
        omitted_error(&mut prebind, "empty", "item-not-found", "cancel")?;
        prebind.close()?;
    }
    Ok(())
}

#[test]
fn vcard_exact_encoded_quota_counts_context_namespaces_unicode_escaping_and_attributes()
-> TestResult {
    let suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions=['disco','vcard']\n[hosts.localhost.vcard]\nmax_bytes=256",
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let base = "<vCard xmlns='vcard-temp' xmlns:stream='http://etherx.jabber.org/streams' xmlns:q='urn:quota' xml:lang='es' xml:space='preserve' q:a='&amp;&quot;'><FN>é&amp;</FN></vCard>";
    let padding = 256 - base.len();
    let exact = base.replace("é&amp;", &format!("é&amp;{}", "x".repeat(padding)));
    assert_eq!(exact.len(), 256);
    publish(&mut alice, "desk", &exact)?;
    let before = own_card(&mut alice, "desk")?;
    alice.send(&format!(
        "<iq type='set' id='over' xml:lang='es'>{}</iq>",
        exact.replace("</FN>", "x</FN>")
    ))?;
    let error = omitted_error(&mut alice, "over", "resource-constraint", "wait")?;
    assert_eq!(
        error
            .child("jabber:client", "error")?
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "text")?
            .text,
        "vCard exceeds the 256-byte limit, including XML and Base64 data. Use a smaller avatar or reduce profile data."
    );
    assert_eq!(own_card(&mut alice, "desk")?, before);
    alice.close()
}

#[test]
fn vcard_whole_stanza_and_namespace_amplification_keep_ingress_stream_outcomes() -> TestResult {
    let suite = C2sSuite::with_limits("max_stanza_bytes=32768")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>old</FN></vCard>",
    )?;
    alice.send(&format!(
        "<iq type='set' id='ingress'><vCard xmlns='vcard-temp'><FN>{}</FN></vCard></iq>",
        "x".repeat(33000)
    ))?;
    alice.expect_stream_error("policy-violation")?;
    let mut alice = suite.connect("alice", PASSWORD, "again")?;
    assert_eq!(
        own_card(&mut alice, "again")?.child(VCARD, "FN")?.text,
        "old"
    );
    let uri = format!("urn:{}", "n".repeat(10000));
    let xml = format!(
        "<iq type='set' id='amplification'><vCard xmlns='vcard-temp' xmlns:q='{uri}'>{}</vCard></iq>",
        "<q:X/>".repeat(1000)
    );
    assert!(xml.len() < 32768);
    alice.send(&xml)?;
    alice.expect_stream_error("policy-violation")?;
    let mut alice = suite.connect("alice", PASSWORD, "final")?;
    assert_eq!(
        own_card(&mut alice, "final")?.child(VCARD, "FN")?.text,
        "old"
    );
    alice.close()
}

#[test]
fn vcard_corrupt_retained_records_produce_sanitized_payload_free_internal_errors() -> TestResult {
    let oversized = vec![b'x'; lonewolf_storage::vcard::MAX_VCARD_BYTES + 1];
    for bytes in [
        format!("<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>{MARKER}</FN>").into_bytes(),
        vec![0xff,0xfe],oversized,
        b"<vCard xmlns='vcard-temp' xml:space='default'/>".to_vec(),
        b"<vCard xmlns='vcard-temp' xml:lang=''/>".to_vec(),
        b"<vCard xmlns='vcard-temp' xml:lang='' xml:space='invalid'/>".to_vec(),
        b"<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN xml:space='invalid'/></vCard>".to_vec(),
        format!("<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'>{MARKER}</vCard>").into_bytes(),
    ] {
        let mut suite=C2sSuite::with_extensions_and_setup("'disco','vcard'",|path|fixtures::seed(path,&[("alice@localhost",&bytes)]))?;
        let mut alice=suite.connect("alice",PASSWORD,"desk")?;
        alice.send("<iq type='get' id='corrupt'><vCard xmlns='vcard-temp'/></iq>")?;
        omitted_error(&mut alice,"corrupt","internal-server-error","cancel")?;
        barrier(&mut alice)?;
        let logs=suite.wait_for_log("internal operation failed")?;
        assert!(!logs.contains(MARKER));assert!(!logs.contains("<vCard"));
        assert_eq!(logs.lines().filter(|line|line.contains("internal operation failed")).count(),1);
        alice.close()?;
        suite.stop()?;
        fixtures::assert_raw(suite.fixture_path(),"alice@localhost",&bytes)?;

    }
    Ok(())
}

#[test]
fn vcard_deletion_while_enabled_or_disabled_clears_corrupt_oversized_and_valid_rows() -> TestResult
{
    for enabled in [false, true] {
        let huge = vec![b'x'; lonewolf_storage::vcard::MAX_VCARD_BYTES + 1];
        for bytes in [
            b"<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN>retained</FN></vCard>"
                .as_slice(),
            b"\xff PRIVATE-VCARD-MARKER-469",
            huge.as_slice(),
        ] {
            let mut suite = C2sSuite::with_extensions_and_setup(
                if enabled {
                    "'disco','vcard'"
                } else {
                    "'disco'"
                },
                |path| fixtures::seed(path, &[("alice@localhost", bytes)]),
            )?;
            suite.delete_account("alice")?;
            suite.create_account("alice", PASSWORD)?;
            let mut alice = suite.connect("alice", PASSWORD, "new")?;
            barrier(&mut alice)?;
            alice.close()?;
            if !enabled {
                let path = suite.fixture_path().join("lonewolf.toml");
                fs::write(
                    &path,
                    fs::read_to_string(&path)?
                        .replace("extensions = ['disco']", "extensions = ['disco','vcard']"),
                )?;
                suite.restart()?;
            }
            let mut alice = suite.connect("alice", PASSWORD, "enabled")?;
            alice.send("<iq type='get' id='gone'><vCard xmlns='vcard-temp'/></iq>")?;
            omitted_error(&mut alice, "gone", "item-not-found", "cancel")?;
            publish(&mut alice, "enabled", "<vCard xmlns='vcard-temp'/>")?;
            alice.close()?;
            suite.delete_account("alice")?;
            suite.stop()?;
            fixtures::assert_absent(suite.fixture_path(), "alice@localhost")?;
        }
    }
    Ok(())
}

#[test]
fn vcard_full_get_uses_exact_case_sensitive_resources_without_account_fallback() -> TestResult {
    for extensions in ["'roster','disco','vcard'", "'roster','disco'"] {
        let suite = C2sSuite::with_extensions(extensions)?;
        for name in ["alice", "bob"] {
            suite.create_account(name, PASSWORD)?;
        }
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        let mut phone = suite.connect("alice", PASSWORD, "Phone")?;
        let mut space = suite.connect("alice", PASSWORD, " Phone")?;
        let mut bob = suite.connect("bob", PASSWORD, "reader")?;
        if extensions.contains("vcard") {
            publish(
                &mut alice,
                "desk",
                "<vCard xmlns='vcard-temp'><FN>account</FN></vCard>",
            )?;
        }
        alice.send("<iq type='get' to='alice@localhost/desk' id='self-full'><vCard xmlns='vcard-temp'/></iq>")?;
        let request = alice.receive()?;
        assert_eq!(request.attribute("type"), Some("get"));
        assert_eq!(request.attribute("from"), Some("alice@localhost/desk"));
        request.child(VCARD, "vCard")?;
        alice.send("<iq type='result' to='alice@localhost/desk' id='self-full'/>")?;
        result(
            &mut alice,
            "self-full",
            Some("alice@localhost/desk"),
            "alice@localhost/desk",
        )?;
        crate::support::mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
        for presence in [
            None,
            Some("<presence><priority>-1</priority></presence>"),
            Some("<presence type='unavailable'/>"),
        ] {
            if let Some(presence) = presence {
                phone.send(presence)?;
                drain_presence(&mut phone)?;
                drain_presence(&mut alice)?;
                drain_presence(&mut space)?;
                drain_presence(&mut bob)?;
            }
            for (target, recipient) in [
                ("alice@localhost/desk", &mut alice),
                ("alice@localhost/Phone", &mut phone),
                ("alice@localhost/ Phone", &mut space),
            ] {
                bob.send(&format!("<iq type='get' to='{target}' from='forged@remote/x' id='resource'><vCard xmlns='vcard-temp'/></iq>"))?;
                recipient.expect_xml(&format!("<iq xmlns='jabber:client' type='get' to='{target}' from='bob@localhost/reader' id='resource'><vCard xmlns='vcard-temp'/></iq>"))?;
                recipient.send("<iq type='result' to='bob@localhost/reader' id='resource'><chosen xmlns='urn:client-answer'/></iq>")?;
                let reply = bob.receive()?;
                assert_eq!(reply.attribute("from"), Some(target));
                reply.child("urn:client-answer", "chosen")?;
            }
        }
        for target in [
            "alice@localhost/phone",
            "alice@localhost/missing",
            "missing@localhost/Phone",
        ] {
            bob.send(&format!(
                "<iq type='get' to='{target}' id='missing'><vCard xmlns='vcard-temp'/></iq>"
            ))?;
            let reply = bob.receive()?;
            assert_eq!(reply.attribute("type"), Some("error"));
            reply
                .child("jabber:client", "error")?
                .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
            barrier(&mut bob)?;
        }
        if extensions.contains("vcard") {
            assert_eq!(
                own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
                "account"
            );
        }
        barrier(&mut alice)?;
        barrier(&mut phone)?;
        barrier(&mut space)?;
        space.close()?;
        phone.close()?;
        alice.close()?;
        bob.close()?;
    }
    Ok(())
}

#[test]
fn vcard_exact_qname_host_enablement_guard_and_generic_routes_are_independent() -> TestResult {
    for (source, target) in [(true, false), (false, true), (false, false)] {
        let suite = C2sSuite::with_hosts(&format!(
            "[hosts.localhost]\nextensions=['disco','test-service'{}]\n[hosts.'other.localhost']\nextensions=['disco'{}]\n[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate.pem'\nprivate_key_path='private-key.pem'",
            if source { ",'vcard'" } else { "" },
            if target { ",'vcard'" } else { "" }
        ))?;
        suite.create_account("alice", PASSWORD)?;
        suite.create_account_jid("alice@other.localhost", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        if source {
            publish(
                &mut alice,
                "desk",
                "<vCard xmlns='vcard-temp'><FN>original</FN></vCard>",
            )?;
        }
        for destination in [
            "alice@other.localhost",
            "alice@other.localhost/resource",
            "other.localhost",
            "other.localhost/resource",
            "missing@other.localhost",
        ] {
            alice.send(&format!("<iq type='set' to='{destination}' id='cross'><vCard xmlns='vcard-temp'><FN>{MARKER}</FN></vCard></iq>"))?;
            if source || target {
                omitted_error(&mut alice, "cross", "forbidden", "auth")?;
            } else {
                let reply = alice.receive()?;
                reply
                    .child("jabber:client", "error")?
                    .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
            }
            barrier(&mut alice)?;
        }
        for destination in [
            "remote.example",
            "alice@remote.example/resource",
            "echo.localhost",
        ] {
            alice.send(&format!(
                "<iq type='set' to='{destination}' id='external'><vCard xmlns='vcard-temp'/></iq>"
            ))?;
            if source {
                omitted_error(&mut alice, "external", "forbidden", "auth")?;
            } else {
                let reply = alice.receive()?;
                let condition = if destination == "echo.localhost" {
                    "bad-request"
                } else {
                    "remote-server-not-found"
                };
                reply
                    .child("jabber:client", "error")?
                    .child("urn:ietf:params:xml:ns:xmpp-stanzas", condition)?;
            }
        }
        if !source && !target {
            alice.send("<iq type='set' to='alice@localhost/desk' id='disabled-full'><vCard xmlns='vcard-temp'/></iq>")?;
            let request = alice.receive()?;
            assert_eq!(request.attribute("type"), Some("set"));
            assert_eq!(request.attribute("id"), Some("disabled-full"));
            assert_eq!(request.attribute("from"), Some("alice@localhost/desk"));
            request.child(VCARD, "vCard")?;
            alice.send("<iq type='get' id='disabled-own'><vCard xmlns='vcard-temp'/></iq>")?;
            let reply = alice.receive()?;
            reply
                .child("jabber:client", "error")?
                .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
        }
        for payload in ["<vcard xmlns='vcard-temp'/>", "<vCard xmlns='urn:wrong'/>"] {
            alice.send(&format!(
                "<iq type='set' to='alice@localhost/desk' id='unmatched'>{payload}</iq>"
            ))?;
            let routed = alice.receive()?;
            assert_eq!(routed.attribute("type"), Some("set"));
            assert_eq!(routed.attribute("from"), Some("alice@localhost/desk"));
            alice.send(&format!(
                "<iq type='get' to='alice@localhost' id='wrong'>{payload}</iq>"
            ))?;
            let reply = alice.receive()?;
            reply
                .child("jabber:client", "error")?
                .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
        }
        for destination in ["localhost", "localhost/resource", "remote.example"] {
            alice.send(&format!(
                "<iq type='get' to='{destination}' id='domain'><vCard xmlns='vcard-temp'/></iq>"
            ))?;
            let reply = alice.receive()?;
            reply.child("jabber:client", "error")?.child(
                "urn:ietf:params:xml:ns:xmpp-stanzas",
                if destination == "remote.example" {
                    "remote-server-not-found"
                } else {
                    "service-unavailable"
                },
            )?;
        }
        if source {
            assert_eq!(
                own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
                "original"
            );
        }
        alice.close()?;
    }
    Ok(())
}

#[test]
fn vcard_full_get_hidden_disconnected_and_directed_visibility_never_fall_back_to_bare() -> TestResult
{
    let suite = C2sSuite::start()?;
    for name in ["alice", "bob"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "reader")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>account card</FN></vCard>",
    )?;
    for offline in [false, true] {
        if offline {
            alice.close()?;
        }
        bob.send(
            "<iq type='get' to='alice@localhost/desk' id='hidden'><vCard xmlns='vcard-temp'/></iq>",
        )?;
        let reply = bob.receive()?;
        reply
            .child("jabber:client", "error")?
            .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
        barrier(&mut bob)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "new")?;
    alice.send("<presence to='bob@localhost/reader'/>")?;
    bob.receive()?.assert_name("jabber:client", "presence");
    bob.send(
        "<iq type='get' to='alice@localhost/new' id='directed'><vCard xmlns='vcard-temp'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' from='bob@localhost/reader' to='alice@localhost/new' id='directed'><vCard xmlns='vcard-temp'/></iq>")?;
    alice.send("<iq type='result' to='bob@localhost/reader' id='directed'/>")?;
    result(
        &mut bob,
        "directed",
        Some("alice@localhost/new"),
        "bob@localhost/reader",
    )?;
    assert_eq!(
        own_card(&mut alice, "new")?.child(VCARD, "FN")?.text,
        "account card"
    );
    alice.close()?;
    drain_presence(&mut bob)?;
    bob.close()
}

#[test]
fn vcard_concurrent_resource_writers_expose_only_complete_documents() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut left = suite.connect("alice", PASSWORD, "left")?;
    let mut right = suite.connect("alice", PASSWORD, "right")?;
    let mut reader = suite.connect("alice", PASSWORD, "reader")?;
    publish(
        &mut left,
        "left",
        "<vCard xmlns='vcard-temp'><FN>old</FN><NICKNAME>old</NICKNAME></vCard>",
    )?;
    let start = std::sync::Barrier::new(3);
    std::thread::scope(|scope| -> TestResult {
        let a = scope.spawn(|| -> Result<(), String> {
            start.wait();
            publish(
                &mut left,
                "left",
                "<vCard xmlns='vcard-temp'><FN>A</FN><NICKNAME>A</NICKNAME></vCard>",
            )
            .map_err(|e| e.to_string())
        });
        let b = scope.spawn(|| -> Result<(), String> {
            start.wait();
            publish(
                &mut right,
                "right",
                "<vCard xmlns='vcard-temp'><FN>B</FN><NICKNAME>B</NICKNAME></vCard>",
            )
            .map_err(|e| e.to_string())
        });
        start.wait();
        for _ in 0..8 {
            let card = own_card(&mut reader, "reader")?;
            let name = &card.child(VCARD, "FN")?.text;
            assert!(matches!(name.as_str(), "old" | "A" | "B"));
            assert_eq!(&card.child(VCARD, "NICKNAME")?.text, name);
        }
        a.join().map_err(|_| "writer A panicked")??;
        b.join().map_err(|_| "writer B panicked")??;
        Ok(())
    })?;
    let card = own_card(&mut reader, "reader")?;
    assert!(matches!(card.child(VCARD, "FN")?.text.as_str(), "A" | "B"));
    left.close()?;
    right.close()?;
    reader.close()
}

#[test]
fn vcard_canonical_owner_case_and_composed_localparts_do_not_normalize_profile_fields() -> TestResult
{
    let suite = C2sSuite::start()?;
    suite.create_account("élice", PASSWORD)?;
    let mut alice = suite.authenticated_client("ÉLICE", PASSWORD)?;
    assert_eq!(alice.bind(Some("desk"))?, "élice@localhost/desk");
    alice.send("<iq type='set' to='ÉLICE@LOCALHOST' id='canonical'><vCard xmlns='vcard-temp'><FN>É é</FN></vCard></iq>")?;
    result(
        &mut alice,
        "canonical",
        Some("élice@localhost"),
        "élice@localhost/desk",
    )?;
    alice.send(
        "<iq type='get' to='ÉLICE@LOCALHOST' id='canonical'><vCard xmlns='vcard-temp'/></iq>",
    )?;
    let read = result(
        &mut alice,
        "canonical",
        Some("élice@localhost"),
        "élice@localhost/desk",
    )?;
    assert_eq!(read.child(VCARD, "vCard")?.child(VCARD, "FN")?.text, "É é");
    assert_eq!(
        fixtures::key("ÉLICE@BÜCHER.example")?,
        fixtures::key("élice@xn--bcher-kva.example")?
    );
    alice.close()
}

#[test]
fn vcard_result_error_policy_and_recipient_budget_variants_never_persist_or_reflect() -> TestResult
{
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'disco','vcard','ping','test-policy'",
        "incoming_stanzas_per_connection={per_second=1000,burst=1000}\nnew_recipients_per_connection={per_second=1,burst=1}",
        |_| Ok(()),
    )?;
    for name in ["alice", "bob", "blocked"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    let mut blocked = suite.connect("blocked", PASSWORD, "phone")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>kept</FN></vCard>",
    )?;
    alice.send("<message to='bob@localhost/phone' id='budget'/>")?;
    bob.receive()?.assert_name("jabber:client", "message");
    crate::support::toggle(&mut alice, true)?;
    for destination in [
        "",
        " to='localhost'",
        " to='alice@localhost'",
        " to='bob@localhost'",
        " to='missing@localhost'",
        " to='bob@localhost/missing'",
        " to='blocked@localhost'",
        " to='blocked@localhost/phone'",
        " to='remote.example'",
        " to='user@remote.example/resource'",
    ] {
        for response in [
            format!(
                "<iq type='result'{destination} id='response'><vCard xmlns='vcard-temp'><FN>{MARKER}</FN></vCard></iq>"
            ),
            format!(
                "<iq type='error'{destination} id='response'><vCard xmlns='vcard-temp'><FN>{MARKER}</FN></vCard><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
            ),
        ] {
            alice.send(&response)?;
            alice.send(
                "<iq type='get' to='localhost' id='sentinel'><ping xmlns='urn:xmpp:ping'/></iq>",
            )?;
            result(
                &mut alice,
                "sentinel",
                Some("localhost"),
                "alice@localhost/desk",
            )?;
        }
    }
    for kind in ["result", "error"] {
        let error = if kind == "error" {
            "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"
        } else {
            ""
        };
        alice.send(&format!("<iq type='{kind}' to='bob@localhost/phone' id='delivered'><vCard xmlns='vcard-temp'/>{error}</iq>"))?;
        let reply = bob.receive()?;
        assert_eq!(reply.attribute("type"), Some(kind));
        assert_eq!(reply.attribute("from"), Some("alice@localhost/desk"));
        barrier(&mut alice)?;
    }
    assert_eq!(
        own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
        "kept"
    );
    bob.send("<iq type='get' id='absent'><vCard xmlns='vcard-temp'/></iq>")?;
    omitted_error(&mut bob, "absent", "item-not-found", "cancel")?;
    barrier(&mut blocked)?;
    alice.close()?;
    bob.close()?;
    blocked.close()
}

#[test]
fn vcard_idn_domain_and_composed_owner_aliases_use_one_canonical_card() -> TestResult {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    let mut config = None;
    let suite = C2sSuite::with_hosts_and_setup(
        "[hosts.'bücher.example']\nextensions=['disco','vcard']\n[hosts.'bücher.example'.tls]\ncertificate_chain_path='certificate-idn.pem'\nprivate_key_path='private-key-idn.pem'",
        |directory| {
            let roots =
                crate::support::tls::configure_host(directory, "-idn", &["xn--bcher-kva.example"])?;
            config = Some(Arc::new(crate::support::tls::client_config(
                roots,
                rustls::DEFAULT_VERSIONS,
            )?));
            Ok(())
        },
    )?;
    suite.create_account_jid("élice@bücher.example", PASSWORD)?;
    let opening = OPEN.replace("to='localhost'", "to='BÜCHER.example'");
    let mut plain = suite.tcp_client()?;
    plain.open_with(&opening)?;
    plain.features()?;
    let mut alice = plain.start_tls_with_identity(
        config.ok_or("missing IDN TLS config")?,
        ServerName::try_from("xn--bcher-kva.example")?,
    )?;
    alice.open_with(&opening)?;
    alice.features()?;
    alice.authenticate("ÉLICE", PASSWORD)?;
    let mut alice = alice.restart();
    alice.open_with(&opening)?;
    alice.features()?;
    assert_eq!(alice.bind(Some("desk"))?, "élice@bücher.example/desk");
    alice.send("<iq type='set' to='ÉLICE@BÜCHER.example' id='idn'><vCard xmlns='vcard-temp'><FN>É é unchanged</FN></vCard></iq>")?;
    result(
        &mut alice,
        "idn",
        Some("élice@bücher.example"),
        "élice@bücher.example/desk",
    )?;
    alice.send(
        "<iq type='get' to='élice@bücher.example' id='idn'><vCard xmlns='vcard-temp'/></iq>",
    )?;
    let read = result(
        &mut alice,
        "idn",
        Some("élice@bücher.example"),
        "élice@bücher.example/desk",
    )?;
    assert_eq!(
        read.child(VCARD, "vCard")?.child(VCARD, "FN")?.text,
        "É é unchanged"
    );
    alice.close()
}

#[test]
fn vcard_same_username_on_two_hosts_keeps_distinct_cards_and_disabled_host_retains_no_handler()
-> TestResult {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    let mut suite = C2sSuite::with_hosts(
        "[hosts.localhost]\nextensions=['disco','vcard']\n[hosts.'other.localhost']\nextensions=['disco','vcard']\n[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate.pem'\nprivate_key_path='private-key.pem'",
    )?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account_jid("alice@other.localhost", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let opening = OPEN.replace("to='localhost'", "to='other.localhost'");
    let mut plain = suite.tcp_client()?;
    plain.open_with(&opening)?;
    plain.features()?;
    let mut other = plain.start_tls_with_identity(
        Arc::clone(&suite.tls),
        ServerName::try_from("other.localhost")?,
    )?;
    other.open_with(&opening)?;
    other.features()?;
    other.authenticate("alice", PASSWORD)?;
    let mut other = other.restart();
    other.open_with(&opening)?;
    other.features()?;
    other.bind(Some("desk"))?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>first host</FN></vCard>",
    )?;
    other.send(
        "<iq type='set' id='other'><vCard xmlns='vcard-temp'><FN>second host</FN></vCard></iq>",
    )?;
    result(&mut other, "other", None, "alice@other.localhost/desk")?;
    for (target, expected) in [
        ("alice@localhost", "first host"),
        ("alice@other.localhost", "second host"),
    ] {
        alice.send(&format!(
            "<iq type='get' to='{target}' id='host'><vCard xmlns='vcard-temp'/></iq>"
        ))?;
        assert_eq!(
            result(&mut alice, "host", Some(target), "alice@localhost/desk")?
                .child(VCARD, "vCard")?
                .child(VCARD, "FN")?
                .text,
            expected
        );
    }
    alice.close()?;
    other.close()?;
    let path = suite.fixture_path().join("lonewolf.toml");
    fs::write(
        &path,
        fs::read_to_string(&path)?.replace(
            "[hosts.'other.localhost']\nextensions=['disco','vcard']",
            "[hosts.'other.localhost']\nextensions=['disco']",
        ),
    )?;
    suite.restart()?;
    let mut alice = suite.connect("alice", PASSWORD, "after")?;
    alice.send(
        "<iq type='get' to='alice@other.localhost' id='disabled'><vCard xmlns='vcard-temp'/></iq>",
    )?;
    let reply = alice.receive()?;
    reply
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    assert_eq!(
        own_card(&mut alice, "after")?.child(VCARD, "FN")?.text,
        "first host"
    );
    alice.close()
}

#[test]
fn vcard_detached_root_attribute_growth_rejects_before_replacement() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>retained</FN></vCard>",
    )?;
    let declarations = (0..120)
        .map(|n| format!(" xmlns:p{n}='urn:{n}'"))
        .collect::<String>();
    let attributes = (0..134)
        .map(|n| format!(" a{n}='{MARKER}'"))
        .collect::<String>();
    alice.send(&format!("<iq type='set' id='attribute-limit'{declarations}><vCard xmlns='vcard-temp'{attributes}/></iq>"))?;
    omitted_error(&mut alice, "attribute-limit", "resource-constraint", "wait")?;
    assert_eq!(
        own_card(&mut alice, "desk")?.child(VCARD, "FN")?.text,
        "retained"
    );
    let logs = fs::read_to_string(suite.fixture_path().join("server.log"))?;
    assert!(!logs.contains(MARKER));
    alice.close()
}

#[test]
fn vcard_structural_rejection_has_english_text_without_profile_or_quota_claim() -> TestResult {
    let suite = C2sSuite::with_hosts("[hosts.localhost]\nextensions=['disco','vcard']")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    publish(
        &mut alice,
        "desk",
        "<vCard xmlns='vcard-temp'><FN>old</FN></vCard>",
    )?;
    let before = own_card(&mut alice, "desk")?;
    let declarations = (0..120)
        .map(|index| format!(" xmlns:p{index}='urn:{index}'"))
        .collect::<String>();
    let attributes = (0..134)
        .map(|index| format!(" a{index}='{MARKER}'"))
        .collect::<String>();
    alice.send(&format!("<iq type='set' id='structure' xml:lang='es'{declarations}><vCard xmlns='vcard-temp'{attributes}/></iq>"))?;
    let reply = omitted_error(&mut alice, "structure", "resource-constraint", "wait")?;
    assert_eq!(reply.attribute_in("lang", XML)?, Some("es"));
    let text = &reply
        .child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "text")?
        .text;
    assert_eq!(
        text,
        "vCard has too many XML attributes. Reduce the profile's XML attributes."
    );
    assert_eq!(own_card(&mut alice, "desk")?, before);
    alice.close()
}
