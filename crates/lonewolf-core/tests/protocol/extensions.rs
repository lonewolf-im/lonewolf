// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, TestResult};

#[test]
fn precommit_handler_wait_keeps_healthy_outbound_delivery_progressing() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-precommit-iq'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    alice.send("<iq type='set' id='stalled'><stall xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    suite.wait_for_log("test precommit handler waiting")?;

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
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    suite.create_account("charlie", "password")?;
    let mut blocker = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    let mut sender = suite.connect("charlie", "password", "desk")?;
    blocker.send(
        "<iq type='set' id='holding-writer'><stall xmlns='urn:lonewolf:test:precommit'/></iq>",
    )?;
    suite.wait_for_log("test precommit handler waiting")?;
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
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    alice.send("<message to='bob@localhost' type='chat' id='stored'/>")?;
    suite.wait_for_log("test offline store waiting")?;
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
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    alice.send("<presence id='initial'/>")?;
    for (phase, waiting) in [
        ("audience", "test precommit audience waiting"),
        ("backlog", "test precommit backlog waiting"),
    ] {
        suite.wait_for_log(waiting)?;
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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice
        .send("<iq type='set' id='cancelled'><stall xmlns='urn:lonewolf:test:precommit'/></iq>")?;
    suite.wait_for_log("test precommit handler waiting")?;
    suite.stop()?;
    let logs = suite.wait_for_log("test precommit handler cancelled")?;
    assert!(!logs.contains("test precommit handler completed"), "{logs}");
    assert!(!logs.contains("test precommit effects delivered"), "{logs}");

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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='other-host' from='other.localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='other.localhost'/></iq>")?;
    alice.close()
}

#[test]
fn enabled_account_handler_receives_an_iq_request() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='extension-1'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='extension-1' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='alice@localhost'/></iq>")?;
    alice.close()
}

#[test]
fn subscription_presence_handlers_receive_authenticated_directed_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        alice.send(&format!("<presence type='{kind}' id='{kind}' from='mallory@localhost/spy' to='bob@localhost'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick></presence>"))?;
        alice.expect_xml(&format!("<presence xmlns='jabber:client' type='error' id='{kind}' from='bob@localhost' to='alice@localhost/desk'><nick xmlns='http://jabber.org/protocol/nick'>Robert</nick><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>"))?;
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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='other-host' to='bob@other.localhost'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' type='error' id='other-host' from='bob@other.localhost' to='alice@localhost/desk'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")?;

    alice.close()
}

#[test]
fn undirected_subscription_presence_does_not_enter_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

    alice.send("<presence type='subscribe' id='undirected'/>")?;
    alice.send("<message to='alice@localhost/desk' id='sentinel'/>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' id='sentinel'/>")?;

    alice.close()
}

#[test]
fn presence_extensions_do_not_intercept_availability() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-presence'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;

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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='disabled'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='disabled'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn unknown_payload_namespace_does_not_match_a_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='unknown'><query xmlns='urn:lonewolf:test:unknown'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn only_the_direct_payload_element_selects_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send(
        "<iq type='get' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='nested'><other xmlns='urn:lonewolf:test:iq'><query/></other><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn qualified_payload_and_authenticated_identity_reach_the_handler() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='a&amp;b' from='mallory@localhost/spy' to='bob@localhost'><t:query xmlns:t='urn:lonewolf:test:iq' value='one &amp; two'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='a&amp;b' from='bob@localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='bob@localhost' value='one &amp; two'/></iq>")?;
    alice.close()
}

#[test]
fn handler_errors_preserve_the_request_payload_and_address_the_bound_resource() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-error-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='set' id='denied' from='mallory@localhost/spy' to='alice@localhost'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='denied' from='alice@localhost' to='alice@localhost/desk'><deny xmlns='urn:lonewolf:test:iq'><detail>Keep &amp; escape</detail></deny><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn server_scope_does_not_handle_account_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-server-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='account'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='account'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='server' from='localhost' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq' sender='alice@localhost/desk' target='localhost'/></iq>")?;
    alice.close()
}

#[test]
fn account_scope_does_not_handle_server_requests() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send(
        "<iq type='get' id='server' to='localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='server' from='localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn full_jid_requests_are_not_consumed_by_account_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='resource' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='get' id='resource' from='alice@localhost/desk' to='alice@localhost/desk'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.close()
}

#[test]
fn remote_requests_are_not_consumed_by_local_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq', 'test-server-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='remote' to='bob@remote.example'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='remote' from='bob@remote.example'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='get' id='remote-server' to='remote.example'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='remote-server' from='remote.example'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.close()
}

#[test]
fn iq_results_and_errors_do_not_enter_request_handlers() -> TestResult {
    let suite = C2sSuite::with_extensions("'test-iq'")?;
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
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
    suite.create_account("alice", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    alice.send("<iq type='get' id='other-host' to='other.localhost'><query xmlns='urn:lonewolf:test:iq'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='other-host' from='other.localhost'><query xmlns='urn:lonewolf:test:iq'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
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
        let suite = C2sSuite::with_extensions("'test-failure-iq'")?;
        suite.create_account("alice", "password")?;
        let mut alice = suite.connect("alice", "password", "desk")?;
        alice.send(&format!("<iq type='{kind}' id='private-stanza-id' xml:lang='fr'><fail xmlns='urn:lonewolf:test:failure'><detail>private-payload</detail></fail></iq>"))?;
        alice.expect_xml("<iq xmlns='jabber:client' type='error' to='alice@localhost/desk' id='private-stanza-id' xml:lang='fr'><fail xmlns='urn:lonewolf:test:failure'><detail>private-payload</detail></fail><error type='wait'><internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
        alice.send("<message to='alice@localhost/desk' id='still-open'/>")?;
        alice.expect_xml("<message xmlns='jabber:client' to='alice@localhost/desk' from='alice@localhost/desk' id='still-open'/>")?;
        let logs = suite.wait_for_log("internal operation failed")?;
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
        alice.close()?;
    }
    Ok(())
}

#[test]
fn shared_router_panic_stops_serving_and_reports_one_private_failure() -> TestResult {
    let mut suite = C2sSuite::with_extensions("'roster', 'test-router-failure'")?;
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
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
    suite.create_account("alice", "password")?;
    suite.create_account("bob", "password")?;
    let mut alice = suite.connect("alice", "password", "desk")?;
    let mut bob = suite.connect("bob", "password", "phone")?;
    alice.send(
        "<iq type='set' id='crash'><connection xmlns='urn:lonewolf:test:router-failure'/></iq>",
    )?;
    alice.drain()?;
    bob.send("<message to='bob@localhost/phone' type='chat' id='still-serving'/>")?;
    bob.expect_xml("<message xmlns='jabber:client' from='bob@localhost/phone' to='bob@localhost/phone' type='chat' id='still-serving'/>")?;
    let mut replacement = suite.connect("alice", "password", "desk")?;
    replacement.close()?;
    bob.close()?;
    let logs = suite.wait_for_log("connection task panicked")?;
    assert!(!logs.contains("router service failed"), "{logs}");
    assert!(
        !logs.contains("seeded-sensitive-connection-payload"),
        "{logs}"
    );
    suite.stop()
}
