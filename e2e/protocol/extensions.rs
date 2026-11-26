// SPDX-License-Identifier: Apache-2.0

use crate::support::PASSWORD;

use std::time::{Duration, Instant};

use crate::support::{C2sSuite, Client, Signal, TestResult, mutually_subscribe};

fn requester_outcome(client: &mut Client) -> TestResult<Option<String>> {
    client.send("<iq type='get' to='localhost' id='outcome'><outcome xmlns='urn:lonewolf:test:requester'/></iq>")?;
    let reply = client.receive()?;
    assert_eq!(reply.attribute("type"), Some("result"));
    assert_eq!(reply.attribute("id"), Some("outcome"));
    match reply.children.first() {
        Some(outcome) => {
            outcome.assert_name("urn:lonewolf:test:requester", "outcome");
            Ok(Some(
                outcome
                    .attribute("value")
                    .ok_or("missing outcome value")?
                    .into(),
            ))
        }
        None => Ok(None),
    }
}

fn wait_for_requester_outcome(client: &mut Client, expected: &str) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(outcome) = requester_outcome(client)? {
            assert_eq!(outcome, expected);
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("server IQ request remained pending".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn detached_requests_receive_the_addressed_resources_answer() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-requester'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='ask'><ask xmlns='urn:lonewolf:test:requester' jid='bob@localhost/desk' timeout='5'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='ask' to='alice@localhost/desk'/>",
    )?;
    let request = bob.receive()?;
    assert_eq!(request.attribute("type"), Some("get"));
    assert_eq!(request.attribute("from"), Some("localhost"));
    assert_eq!(request.attribute("to"), Some("bob@localhost/desk"));
    request.child("urn:xmpp:ping", "ping")?;
    let id = request.attribute("id").ok_or("missing request ID")?;
    assert!(id.starts_with("lw-iq-"));
    bob.send(&format!("<iq type='result' to='localhost' id='{id}'/>"))?;
    wait_for_requester_outcome(&mut alice, "answered:result")?;
    alice.close()?;
    bob.close()
}

#[test]
fn responses_from_other_entities_are_ignored() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-requester'")?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='ask'><ask xmlns='urn:lonewolf:test:requester' jid='bob@localhost/desk' timeout='5'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='ask' to='alice@localhost/desk'/>",
    )?;
    let request = bob.receive()?;
    let id = request.attribute("id").ok_or("missing request ID")?;
    carol.send(&format!(
        "<iq type='result' from='bob@localhost/desk' to='localhost' id='{id}'/>"
    ))?;
    carol.send("<message to='carol@localhost/desk' id='processed'/>")?;
    carol.expect_xml("<message xmlns='jabber:client' from='carol@localhost/desk' to='carol@localhost/desk' id='processed'/>")?;
    assert_eq!(requester_outcome(&mut alice)?, None);
    bob.send(&format!("<iq type='result' to='localhost' id='{id}'/>"))?;
    wait_for_requester_outcome(&mut alice, "answered:result")?;
    alice.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn unanswered_requests_time_out() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-requester'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='ask'><ask xmlns='urn:lonewolf:test:requester' jid='bob@localhost/desk' timeout='1'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='ask' to='alice@localhost/desk'/>",
    )?;
    assert_eq!(bob.receive()?.attribute("type"), Some("get"));
    wait_for_requester_outcome(&mut alice, "failed")?;
    alice.close()?;
    bob.close()
}

#[test]
fn requests_to_absent_resources_fail() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-requester'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='ask'><ask xmlns='urn:lonewolf:test:requester' jid='bob@localhost/absent' timeout='5'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='ask' to='alice@localhost/desk'/>",
    )?;
    wait_for_requester_outcome(&mut alice, "failed")?;
    alice.close()
}

#[test]
fn detached_requests_to_the_initiating_resource_do_not_deadlock() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-requester'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='ask'><ask xmlns='urn:lonewolf:test:requester' jid='alice@localhost/desk' timeout='5'/></iq>")?;
    let first = alice.receive()?;
    let second = alice.receive()?;
    let (reply, request) = if first.attribute("type") == Some("result") {
        (first, second)
    } else {
        (second, first)
    };
    reply.assert_xml(
        "<iq xmlns='jabber:client' type='result' id='ask' to='alice@localhost/desk'/>",
    )?;
    assert_eq!(request.attribute("type"), Some("get"));
    assert_eq!(request.attribute("from"), Some("localhost"));
    assert_eq!(request.attribute("to"), Some("alice@localhost/desk"));
    request.child("urn:xmpp:ping", "ping")?;
    let id = request.attribute("id").ok_or("missing request ID")?;
    assert!(id.starts_with("lw-iq-"));
    alice.send(&format!("<iq type='result' to='localhost' id='{id}'/>"))?;
    wait_for_requester_outcome(&mut alice, "answered:result")?;
    alice.close()
}

#[test]
fn iq_results_arrive_in_order_before_the_reply() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-results'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    alice.send(
        "<iq type='get' id='results'><query xmlns='urn:lonewolf:test:results' count='3'/></iq>",
    )?;
    for index in 0..3 {
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='localhost' to='alice@localhost/desk'><result xmlns='urn:lonewolf:test:results' index='{index}'/></message>"))?;
    }
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='results' to='alice@localhost/desk'/>",
    )?;
    alice.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;
    alice.close()
}

#[test]
fn misaddressed_iq_results_become_an_internal_error() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq-results'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    alice.send("<iq type='get' id='misaddressed'><query xmlns='urn:lonewolf:test:results' misaddressed='true'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='misaddressed' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:results' misaddressed='true'/><error type='cancel'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server could not complete the request. Try again later.</text></error></iq>")?;
    alice.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;
    alice.close()
}

#[test]
fn iq_handlers_read_their_hosts_discovery_data() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-discovery', 'test-service'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' to='localhost' id='discovery'><query xmlns='urn:lonewolf:test:discovery'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='discovery' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:discovery'><feature var='urn:lonewolf:test:a'/><feature var='urn:lonewolf:test:b'/><service jid='echo.localhost'/></query></iq>")?;
    alice.close()
}

#[test]
fn precommit_handler_wait_keeps_healthy_outbound_delivery_progressing() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-precommit-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<iq type='set' id='stalled'><stall xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    suite.wait_for_signal(Signal::PrecommitHandlerWaiting, 1)?;

    for index in 0..96 {
        bob.send(&format!(
            "<message to='alice@localhost/desk' type='chat' id='delivery-{index}'/>"
        ))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='chat' id='delivery-{index}'/>"))?;
    }
    alice.send("<message to='bob@localhost/phone' type='chat' id='after-handler'/>")?;
    bob.send("<iq type='get' to='localhost' id='release'><release xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='release' from='localhost' to='bob@localhost/phone'/>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='stalled' to='alice@localhost/desk'/>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone' type='chat' id='after-handler'/>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn precommit_writer_admission_keeps_healthy_outbound_delivery_progressing() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-precommit-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    suite.create_account("charlie", PASSWORD)?;
    let mut blocker = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    let mut sender = suite.connect("charlie", PASSWORD, "desk")?;
    blocker.send(
        "<iq type='set' id='holding-writer'><stall xmlns='urn:lonewolf:test:precommit'/></iq>",
    )?;
    suite.wait_for_signal(Signal::PrecommitHandlerWaiting, 1)?;
    bob.send(
        "<iq type='set' id='waiting-writer'><write xmlns='urn:lonewolf:test:precommit'/></iq>",
    )?;

    for index in 0..96 {
        sender.send(&format!(
            "<message to='bob@localhost/phone' type='chat' id='delivery-{index}'/>"
        ))?;
        bob.expect_xml(&format!("<message xmlns='jabber:client' from='charlie@localhost/desk' to='bob@localhost/phone' type='chat' id='delivery-{index}'/>"))?;
    }
    sender.send("<iq type='get' to='localhost' id='release'><release xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    sender.expect_xml("<iq xmlns='jabber:client' type='result' id='release' from='localhost' to='charlie@localhost/desk'/>")?;
    blocker.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='holding-writer' to='alice@localhost/desk'/>",
    )?;
    bob.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='waiting-writer' to='bob@localhost/phone'/>",
    )?;
    blocker.close()?;
    bob.close()?;
    sender.close()
}

#[test]
fn precommit_offline_store_keeps_healthy_outbound_delivery_progressing() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-slow-offline'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<message to='bob@localhost' type='chat' id='stored'/>")?;
    suite.wait_for_signal(Signal::OfflineStoreWaiting, 1)?;
    for index in 0..96 {
        bob.send(&format!(
            "<message to='alice@localhost/desk' type='chat' id='delivery-{index}'/>"
        ))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='chat' id='delivery-{index}'/>"))?;
    }
    bob.send("<presence/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost'/>",
    )?;
    bob.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost' type='chat' id='stored'/>")?;
    alice.send("<message to='alice@localhost/desk' type='chat' id='after-store'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='after-store'/>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn precommit_snapshot_preparation_keeps_delivery_ahead_of_the_presence_echo() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-precommit-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<presence id='initial'/>")?;
    for (phase, waiting) in [
        ("audience", Signal::PrecommitAudienceWaiting),
        ("backlog", Signal::PrecommitBacklogWaiting),
    ] {
        suite.wait_for_signal(waiting, 1)?;
        for index in 0..96 {
            bob.send(&format!(
                "<message to='alice@localhost/desk' type='chat' id='{phase}-{index}'/>"
            ))?;
            alice.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='chat' id='{phase}-{index}'/>"))?;
        }
        bob.send(&format!("<iq type='get' to='localhost' id='{phase}'><release xmlns='urn:lonewolf:test:precommit'/></iq>"))?;
        bob.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='{phase}' from='localhost' to='bob@localhost/phone'/>"))?;
    }
    alice.expect_xml("<presence xmlns='jabber:client' id='initial' from='alice@localhost/desk' to='alice@localhost'/>")?;
    alice.close()?;
    bob.close()
}

#[test]
fn shutdown_cancels_precommit_handler_without_committing_staged_writes() -> TestResult {
    use compio::runtime::Runtime;
    use lonewolf_storage::account::AccountKey;
    use lonewolf_storage::offline::OfflineReads;
    use lonewolf_storage::{RedbStorage, Storage};
    use lonewolf_util::arena::{Arena, ArenaConfig};
    use lonewolf_xmpp::jid::Jid;

    let mut database = std::path::PathBuf::new();
    let mut suite = C2sSuite::with_extensions_and_setup("'test-precommit-iq'", |directory| {
        database = directory.join("data/lonewolf.dat");
        Ok(())
    })?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice
        .send("<iq type='set' id='cancelled'><stall xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    suite.wait_for_signal(Signal::PrecommitHandlerWaiting, 1)?;
    suite.stop()?;
    assert_eq!(suite.signal_count(Signal::PrecommitHandlerCancelled)?, 1);
    assert_eq!(suite.signal_count(Signal::PrecommitHandlerCompleted)?, 0);
    assert_eq!(suite.signal_count(Signal::PrecommitEffectsDelivered)?, 0);

    let storage = RedbStorage::open(database)?;
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let account =
        AccountKey::try_from(Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?)?;
    Runtime::new()?.block_on(async {
        assert_eq!(
            storage.begin_read().await?.offline_count(&account).await?,
            0
        );
        Ok(())
    })
}

#[test]
fn unknown_extensions_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'missing-extension'")
        .err()
        .ok_or("server started with an unknown extension")?;
    let message = error.to_string();
    assert!(
        message.contains("unknown extension") && message.contains("missing-extension"),
        "{message}"
    );
    Ok(())
}

#[test]
fn conflicting_enabled_handlers_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-iq', 'test-conflicting-iq'")
        .err()
        .ok_or("server started with conflicting handlers")?;
    assert!(
        error.to_string().contains("conflicting IQ route"),
        "{error}"
    );
    Ok(())
}

#[test]
fn conflicting_presence_handlers_prevent_server_startup() -> TestResult {
    let error = C2sSuite::with_extensions("'test-presence', 'test-conflicting-presence'")
        .err()
        .ok_or("server started with conflicting presence handlers")?;
    assert!(
        error.to_string().contains("conflicting presence route"),
        "{error}"
    );
    Ok(())
}

#[test]
fn requests_to_another_local_host_use_its_enabled_handlers() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts."other.localhost"]
extensions = ["test-server-iq"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other-host' from='other.localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='other.localhost'/></iq>")?;
    alice.close()
}

#[test]
fn enabled_account_handler_receives_an_iq_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='extension-1'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='extension-1' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()
}

#[test]
fn missing_account_requests_skip_registered_get_and_set_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for kind in ["get", "set"] {
        for namespace in ["urn:lonewolf:test:iq", "urn:lonewolf:test:unknown"] {
            alice.send(&format!("<iq type='{kind}' id='missing-{kind}' to='missing@localhost'><query xmlns='{namespace}'/></iq>"))?;
            let recipient = if namespace == "urn:lonewolf:test:iq" {
                " to='alice@localhost/desk'"
            } else {
                ""
            };
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='missing-{kind}' from='missing@localhost'{recipient}><query xmlns='{namespace}'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>"))?;
        }
    }
    alice.send("<iq type='result' id='missing-result' to='missing@localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.send("<iq type='error' id='missing-error' to='missing@localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send(
        "<iq type='get' id='calls'><query xmlns='urn:lonewolf:test:iq' calls='true'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='calls' to='alice@localhost/desk'><calls xmlns='urn:lonewolf:test:iq' gets='0' sets='0'/></iq>")?;
    alice.close()
}

#[test]
fn own_account_get_and_set_accept_omitted_and_explicit_targets() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for (address, reply_address) in [
        ("", ""),
        (" to='alice@localhost'", " from='alice@localhost'"),
    ] {
        alice.send(&format!(
            "<iq type='get' id='own-get'{address}><query xmlns='urn:lonewolf:test:iq'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='own-get'{reply_address} to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>"))?;
        alice.send(&format!(
            "<iq type='set' id='own-set'{address}><query xmlns='urn:lonewolf:test:iq'/></iq>"
        ))?;
        alice.expect_xml(&format!("<iq xmlns='jabber:client' type='result' id='own-set'{reply_address} to='alice@localhost/desk'/>"))?;
    }
    alice.send(
        "<iq type='get' id='calls'><query xmlns='urn:lonewolf:test:iq' calls='true'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='calls' to='alice@localhost/desk'><calls xmlns='urn:lonewolf:test:iq' gets='2' sets='2'/></iq>")?;
    alice.close()
}

#[test]
fn subscription_presence_handlers_receive_authenticated_directed_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        for target in [
            "bob@localhost",
            "bob@remote.example",
            "bob@remote.example/phone",
            "remote.example",
            "remote.example/phone",
        ] {
            alice.send(&format!("<presence type='{kind}' id='{kind}' from='mallory@localhost/spy' to='{target}'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick></presence>"))?;
            alice.expect_xml(&format!("<presence xmlns='jabber:client' type='error' id='{kind}' from='{target}' to='alice@localhost/desk'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>This operation is not allowed for the requested target.</text></error></presence>"))?;
        }
    }

    alice.close()
}

#[test]
fn outbound_presence_uses_the_sender_hosts_extensions() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["test-presence"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    alice.send("<presence type='subscribe' id='other-host' to='bob@other.localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='error' id='other-host' from='bob@other.localhost' to='alice@localhost/desk'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>This operation is not allowed for the requested target.</text></error></presence>")?;

    alice.close()
}

#[test]
fn undirected_subscription_presence_does_not_enter_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    alice.send("<presence type='subscribe' id='undirected'/>")?;
    alice.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;

    alice.close()
}

#[test]
fn presence_extensions_do_not_intercept_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;

    alice.send("<presence/>")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost' type='unavailable'/>")?;

    alice.close()
}

#[test]
fn get_and_set_with_the_same_payload_select_different_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='get'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='get' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.send("<iq type='set' id='set'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml(
        "<iq xmlns='jabber:client' type='result' id='set' to='alice@localhost/desk'/>",
    )?;
    alice.close()
}

#[test]
fn disabled_extension_returns_service_unavailable() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='disabled'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='disabled'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn unknown_payload_namespace_does_not_match_a_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn only_the_direct_payload_element_selects_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<iq type='get' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn qualified_payload_and_authenticated_identity_reach_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='a&amp;b' from='mallory@localhost/spy' to='bob@localhost'><t:query xmlns:t='urn:lonewolf:test:iq' value='one &amp; two'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='a&amp;b' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='bob@localhost' value='one &amp; two'/></iq>")?;
    alice.close()
}

#[test]
fn handler_errors_preserve_the_request_payload_and_address_the_bound_resource() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-error-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='set' id='denied' from='mallory@localhost/spy' to='alice@localhost'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='denied' from='alice@localhost' to='alice@localhost/desk'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>This operation is not allowed for the requested target.</text></error></iq>")?;
    alice.close()
}

#[test]
fn server_scope_does_not_handle_account_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-server-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='account'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='account'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='server' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='localhost'/></iq>")?;
    alice.close()
}

#[test]
fn account_scope_does_not_handle_server_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='server' from='localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.close()
}

#[test]
fn full_jid_requests_are_not_consumed_by_account_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='resource' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' id='resource' from='alice@localhost/desk' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.close()
}

#[test]
fn remote_requests_are_not_consumed_by_local_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq', 'test-server-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    for kind in ["get", "set"] {
        for target in [
            "bob@remote.example",
            "bob@remote.example/phone",
            "remote.example",
            "remote.example/phone",
        ] {
            alice.send(&format!("<iq type='{kind}' from='mallory@localhost/spy' id='remote' to='{target}'><query xmlns='urn:lonewolf:test:iq'/></iq>"))?;
            alice.expect_xml(&format!("<iq xmlns='jabber:client' type='error' id='remote' from='{target}'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server cannot deliver this request to a remote domain.</text></error></iq>"))?;
        }
    }
    alice.close()
}

#[test]
fn iq_results_and_errors_do_not_enter_request_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='result' id='result'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.send("<iq type='error' id='error'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' id='request'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='request' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()
}

#[test]
fn extension_activation_is_scoped_to_the_destination_host() -> TestResult {
    let suite = C2sSuite::with_hosts(
        r#"
[hosts.localhost]
extensions = ["test-server-iq"]
[hosts."other.localhost".tls]
certificate_chain_path = "certificate.pem"
private_key_path = "private-key.pem"
"#,
    )?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-host' from='other.localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.send("<iq type='get' id='enabled-host' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='enabled-host' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='localhost'/></iq>")?;
    alice.close()
}

#[test]
fn internal_handler_errors_keep_iq_wire_replies_and_log_safe_diagnostics_once() -> TestResult {
    for (kind, category, operation) in [
        ("get", "storage_corrupt_data", "roster_read"),
        ("set", "storage_unavailable", "roster_write"),
    ] {
        let mut suite = C2sSuite::with_extensions("'test-failure-iq'")?;
        suite.create_account("alice", PASSWORD)?;
        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
        alice.send(&format!("<iq type='{kind}' id='private-stanza-id' xml:lang='fr'><fail xmlns='urn:lonewolf:test:failure'><detail>private-payload</detail></fail></iq>"))?;
        alice.expect_xml("<iq xmlns='jabber:client' type='error' to='alice@localhost/desk' id='private-stanza-id' xml:lang='fr'><fail xmlns='urn:lonewolf:test:failure'><detail>private-payload</detail></fail><error type='cancel'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The server could not complete the request. Try again later.</text></error></iq>")?;
        alice.send("<message to='alice@localhost/desk' id='still-open'/>")?;
        alice.expect_xml("<message xmlns='jabber:client' to='alice@localhost/desk' from='alice@localhost/desk' id='still-open'/>")?;
        alice.close()?;
        let logs = suite.stop_with_logs()?;
        let diagnostics: Vec<_> = logs
            .lines()
            .filter(|line| line.contains("internal operation failed"))
            .collect();
        assert_eq!(diagnostics.len(), 1, "{logs}");
        assert!(
            diagnostics[0].contains(&format!("failure_kind=\"{category}\"")),
            "{logs}"
        );
        assert!(
            diagnostics[0].contains(&format!("operation=\"{operation}\"")),
            "{logs}"
        );
        for sensitive in [
            "sensitive-seeded-storage-source",
            "private-stanza-id",
            "private-payload",
        ] {
            assert!(!logs.contains(sensitive), "{logs}");
        }
    }
    Ok(())
}

#[test]
fn shared_router_panic_stops_serving_and_reports_one_private_failure() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'roster', 'test-router-failure'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send("<iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.receive()?;
    alice
        .send("<iq type='set' id='crash'><crash xmlns='urn:lonewolf:test:router-failure'/></iq>")?;
    alice.expect_stream_error("internal-server-error")?;
    bob.expect_stream_error("internal-server-error")?;
    let logs = suite.wait_for_failure()?;
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("router service failed"))
            .count(),
        1,
        "{logs}"
    );
    let failure = logs
        .lines()
        .find(|line| line.contains("router service failed"))
        .ok_or("missing failure event")?;
    assert!(
        failure.contains("component=\"router\"")
            && failure.contains("shard_id=")
            && failure.contains("reason=\"panicked\""),
        "{failure}"
    );
    assert!(
        logs.contains("router shard") && logs.contains("panicked"),
        "{logs}"
    );
    assert!(!logs.contains("seeded-sensitive-router-payload"), "{logs}");
    assert!(std::net::TcpStream::connect(suite.address).is_err());
    Ok(())
}

#[test]
fn ordinary_connection_panic_leaves_router_and_other_connections_serving() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'test-router-failure'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "phone")?;
    alice.send(
        "<iq type='set' id='crash'><connection xmlns='urn:lonewolf:test:router-failure'/></iq>",
    )?;
    alice.drain()?;
    bob.send("<message to='bob@localhost/phone' type='chat' id='still-serving'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost/phone' type='chat' id='still-serving'/>")?;
    let mut replacement = suite.connect("alice", PASSWORD, "desk")?;
    replacement.close()?;
    bob.close()?;
    suite.wait_for_metric("lonewolf_c2s_connection_panics_total{listener=\"0\"} 1")?;
    let logs = suite.stop_with_logs()?;
    assert!(
        !logs.contains("seeded-sensitive-connection-payload"),
        "{logs}"
    );
    Ok(())
}

#[test]
fn account_gets_learn_whether_the_requester_may_see_presence() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-account-access'")?;
    for user in ["alice", "bob", "carol"] {
        suite.create_account(user, PASSWORD)?;
    }
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", PASSWORD, "desk")?;
    let mut carol = suite.connect("carol", PASSWORD, "desk")?;

    alice.send("<iq type='get' id='own'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='own' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='owner'/></iq>")?;
    alice.send("<iq type='get' id='explicit-own' to='alice@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='explicit-own' from='alice@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='owner'/></iq>")?;
    alice.send("<iq type='get' id='other' to='bob@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='other'/></iq>")?;

    mutually_subscribe(&mut alice, "alice", &mut bob, "bob")?;
    alice.send(
        "<iq type='get' id='bob' to='bob@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='bob' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='presence-authorized'/></iq>")?;
    bob.send("<iq type='get' id='alice' to='alice@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    bob.expect_xml("<iq xmlns='jabber:client' type='result' id='alice' from='alice@localhost' to='bob@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='presence-authorized'/></iq>")?;
    carol.send("<iq type='get' id='carol' to='bob@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    carol.expect_xml("<iq xmlns='jabber:client' type='result' id='carol' from='bob@localhost' to='carol@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='other'/></iq>")?;
    alice.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn account_gets_can_list_live_resources() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-account-access'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut desk = suite.connect("alice", PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", PASSWORD, "phone")?;
    desk.send("<presence id='avail'/>")?;
    let presence = desk.receive()?;
    presence.assert_name("jabber:client", "presence");
    assert_eq!(presence.attribute("id"), Some("avail"));
    desk.send("<iq type='get' id='resources'><query xmlns='urn:lonewolf:test:access' resources='true'/></iq>")?;
    desk.expect_xml("<iq xmlns='jabber:client' type='result' id='resources' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='owner'><resource name='desk' available='true'/><resource name='phone' available='false'/></query></iq>")?;
    phone.close()?;
    suite.wait_for_closed("stream_end", 1)?;
    desk.send("<iq type='get' id='remaining'><query xmlns='urn:lonewolf:test:access' resources='true'/></iq>")?;
    desk.expect_xml("<iq xmlns='jabber:client' type='result' id='remaining' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='owner'><resource name='desk' available='true'/></query></iq>")?;
    desk.close()
}

#[test]
fn account_gets_answer_for_missing_accounts_through_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'roster', 'test-account-access'")?;
    suite.create_account("alice", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='missing' to='missing@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='missing' from='missing@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' missing='true'/></iq>")?;
    alice.send("<iq type='set' id='missing-set' to='missing@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='missing-set' from='missing@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")?;
    alice.send("<iq type='set' id='set'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='set' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='none'/></iq>")?;
    alice.close()
}

#[test]
fn without_a_presence_handler_only_the_owner_is_authorized() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-account-access'")?;
    suite.create_account("alice", PASSWORD)?;
    suite.create_account("bob", PASSWORD)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<iq type='get' id='own'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='own' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='owner'/></iq>")?;
    alice.send("<iq type='get' id='other' to='bob@localhost'><query xmlns='urn:lonewolf:test:access'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:access' requester='other'/></iq>")?;
    alice.close()
}
