// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use crate::support::{C2sSuite, Client, TestResult};

const STRICT: &str = "incoming_stanzas_per_connection = { per_second = 1, burst = 1 }";
fn expect_self_message(client: &mut Client, resource: &str, id: &str) -> TestResult {
    client.expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/{resource}' to='alice@localhost/{resource}' type='chat' id='{id}'/>"))
}

#[test]
fn message_presence_and_iq_share_one_burst_then_resume_in_order() -> TestResult {
    let suite =
        C2sSuite::with_limits("incoming_stanzas_per_connection = { per_second = 1, burst = 4 }")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send("<message to='alice@localhost/desk' type='chat' id='first'/><presence/><iq type='get' id='roster'><query xmlns='jabber:iq:roster'/></iq><message to='alice@localhost/desk' type='chat' id='last'/>")?;
    expect_self_message(&mut alice, "desk", "first")?;
    alice.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost'/>",
    )?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='roster' to='alice@localhost/desk'><query xmlns='jabber:iq:roster'/></iq>")?;
    alice.expect_no_tls_input()?;
    expect_self_message(&mut alice, "desk", "last")?;
    alice.close()
}

#[test]
fn iq_results_and_errors_consume_allowance_before_the_next_request() -> TestResult {
    let suite =
        C2sSuite::with_limits("incoming_stanzas_per_connection = { per_second = 1, burst = 3 }")?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;

    alice.send("<iq type='result' id='ignored-result'/><iq type='error' id='ignored-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq><message to='alice@localhost/desk' type='chat' id='after'/>")?;
    alice.expect_no_tls_input()?;
    expect_self_message(&mut alice, "desk", "after")?;
    alice.close()
}

#[test]
fn rejected_binding_and_bound_stanzas_preserve_the_connection_allowance() -> TestResult {
    let suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.authenticated_client("alice", "pencil")?;

    alice.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    alice.expect_no_tls_input()?;
    alice.expect_xml("<iq xmlns='jabber:client' type='result' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>alice@localhost/desk</jid></bind></iq>")?;
    alice.send(" \t\r\n<message to='alice@localhost/desk' type='chat' id='bound'/>")?;
    alice.expect_no_tls_input()?;
    expect_self_message(&mut alice, "desk", "bound")?;
    alice.close()
}

#[test]
fn connections_have_independent_stanza_allowances() -> TestResult {
    let suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", "pencil")?;
    let mut desk = suite.authenticated_client("alice", "pencil")?;
    let mut phone = suite.authenticated_client("alice", "pencil")?;
    assert_eq!(desk.bind(Some("desk"))?, "alice@localhost/desk");
    desk.send("<message to='alice@localhost/desk' type='chat' id='desk'/>")?;
    desk.expect_no_tls_input()?;

    let started = Instant::now();
    assert_eq!(phone.bind(Some("phone"))?, "alice@localhost/phone");
    assert!(started.elapsed() < Duration::from_millis(500));
    expect_self_message(&mut desk, "desk", "desk")?;
    desk.close()?;
    phone.close()
}

#[test]
fn listeners_apply_default_and_selected_stanza_profiles() -> TestResult {
    let suite = C2sSuite::with_profile_settings(
        "default",
        &format!(
            "{STRICT}\n[limits.c2s.profiles.selected]\nincoming_stanzas_per_connection = {{ per_second = 1, burst = 3 }}\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'selected'",
        ),
    )?;
    suite.create_account("alice", "pencil")?;
    let mut strict = suite.connect("alice", "pencil", "desk")?;
    strict.send("<message to='alice@localhost/desk' type='chat' id='strict'/>")?;
    strict.expect_no_tls_input()?;

    let mut selected = Client::connect_at(
        &suite,
        suite.listener_address(1)?,
        "alice",
        "pencil",
        "phone",
    )?;
    let started = Instant::now();
    selected.send("<message to='alice@localhost/phone' type='chat' id='first'/><message to='alice@localhost/phone' type='chat' id='second'/><message to='alice@localhost/phone' type='chat' id='last'/>")?;
    expect_self_message(&mut selected, "phone", "first")?;
    expect_self_message(&mut selected, "phone", "second")?;
    assert!(started.elapsed() < Duration::from_millis(500));
    selected.expect_no_tls_input()?;
    expect_self_message(&mut strict, "desk", "strict")?;
    expect_self_message(&mut selected, "phone", "last")?;
    strict.close()?;
    selected.close()
}

#[test]
fn a_shaped_reader_keeps_delivering_more_than_a_mailbox_of_live_stanzas() -> TestResult {
    let suite = C2sSuite::with_profile_settings(
        "default",
        &format!(
            "{STRICT}\n[limits.c2s.profiles.fast]\nincoming_stanzas_per_connection = {{ per_second = 100_000, burst = 100_000 }}\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'fast'",
        ),
    )?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "secret")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    let mut bob = Client::connect_at(&suite, suite.listener_address(1)?, "bob", "secret", "phone")?;

    alice.send("<message to='alice@localhost/desk' type='chat' id='pending'/>")?;
    alice.expect_no_tls_input()?;
    for index in 0..80 {
        bob.send(&format!(
            "<message to='alice@localhost/desk' type='chat' id='live-{index}'/>"
        ))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='bob@localhost/phone' to='alice@localhost/desk' type='chat' id='live-{index}'/>"))?;
    }
    expect_self_message(&mut alice, "desk", "pending")?;
    alice.close()?;
    bob.close()
}

#[test]
fn deleting_an_account_cancels_its_token_wait_and_releases_its_resource() -> TestResult {
    let suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='alice@localhost/desk' type='chat' id='pending'/>")?;
    alice.expect_no_tls_input()?;

    suite.delete_account("alice")?;
    alice.expect_stream_error("not-authorized")?;
    suite.create_account("alice", "pencil")?;
    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}

#[test]
fn shutdown_cancels_a_stanza_token_wait() -> TestResult {
    let mut suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.connect("alice", "pencil", "desk")?;
    alice.send("<message to='alice@localhost/desk' type='chat' id='pending'/>")?;
    alice.expect_no_tls_input()?;

    let started = Instant::now();
    std::thread::scope(|scope| -> TestResult {
        let stopped = scope.spawn(|| suite.stop().map_err(|error| error.to_string()));
        alice.expect_stream_error("system-shutdown")?;
        stopped.join().map_err(|_| "shutdown thread panicked")??;
        Ok(())
    })?;
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn stanza_shaping_does_not_extend_the_resource_binding_deadline() -> TestResult {
    let suite = C2sSuite::with_limits(&format!("{STRICT}\nresource_binding_timeout_secs = 1",))?;
    suite.create_account("alice", "pencil")?;
    let mut alice = suite.authenticated_client("alice", "pencil")?;
    alice.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/></bind></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    alice.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    alice.expect_eof()?;
    let mut replacement = suite.connect("alice", "pencil", "desk")?;
    replacement.close()
}
