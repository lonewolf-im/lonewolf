// SPDX-License-Identifier: Apache-2.0

use crate::support::{ALTERNATE_PASSWORD, OTHER_PASSWORD};

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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;

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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;

    alice.send("<iq type='result' id='ignored-result'/><iq type='error' id='ignored-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq><message to='alice@localhost/desk' type='chat' id='after'/>")?;
    alice.expect_no_tls_input()?;
    expect_self_message(&mut alice, "desk", "after")?;
    alice.close()
}

#[test]
fn rejected_binding_and_bound_stanzas_preserve_the_connection_allowance() -> TestResult {
    let suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;

    alice.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut desk = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let mut phone = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut strict = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    strict.send("<message to='alice@localhost/desk' type='chat' id='strict'/>")?;
    strict.expect_no_tls_input()?;

    let mut selected = Client::connect_at(
        &suite,
        suite.listener_address(1)?,
        "alice",
        ALTERNATE_PASSWORD,
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    suite.create_account("bob", OTHER_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut bob = Client::connect_at(
        &suite,
        suite.listener_address(1)?,
        "bob",
        OTHER_PASSWORD,
        "phone",
    )?;

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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    alice.send("<message to='alice@localhost/desk' type='chat' id='pending'/>")?;
    alice.expect_no_tls_input()?;

    suite.delete_account("alice")?;
    alice.expect_stream_error("not-authorized")?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn shutdown_cancels_a_stanza_token_wait() -> TestResult {
    let mut suite = C2sSuite::with_limits(STRICT)?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
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
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.authenticated_client("alice", ALTERNATE_PASSWORD)?;
    let started = Instant::now();
    alice.send("<iq type='set' id='bad'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource attr='1'/></bind></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' type='error' id='bad'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Resource binding requires one bind element and a valid optional resource name.</text></error></iq>")?;
    alice.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
    alice
        .receive()?
        .child("urn:ietf:params:xml:ns:xmpp-streams", "policy-violation")?;
    assert!(started.elapsed() < Duration::from_secs(2));
    alice.expect_footer()?;
    alice.send("</stream:stream>")?;
    alice.expect_tls_close()?;
    alice.send_tls_close()?;
    alice.expect_tcp_eof()?;
    let mut replacement = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    replacement.close()
}

#[test]
fn new_recipient_budget_rejects_fourth_without_poisoning_recent_recipients() -> TestResult {
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'roster'",
        "new_recipients_per_connection = { per_second = 1, burst = 3 }",
        |directory| {
            let path = directory.join("lonewolf.toml");
            let mut config = std::fs::read_to_string(&path)?;
            config.push_str("\n[logging]\nlevel = 'debug'\n");
            std::fs::write(path, config)?;
            Ok(())
        },
    )?;
    suite.create_account("alice", ALTERNATE_PASSWORD)?;
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut recipients = Vec::new();
    for name in ["bob", "carol", "dave", "erin"] {
        suite.create_account(name, OTHER_PASSWORD)?;
        recipients.push(suite.connect(name, OTHER_PASSWORD, "phone")?);
    }
    for (index, name) in ["bob", "carol", "dave"].into_iter().enumerate() {
        alice.send(&format!(
            "<message to='{name}@localhost/phone' type='chat' id='first'/>"
        ))?;
        recipients[index].expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='{name}@localhost/phone' type='chat' id='first'/>"))?;
    }
    for id in ["fourth", "retry"] {
        alice.send(&format!(
            "<message to='erin@localhost/phone' type='chat' id='{id}'/>"
        ))?;
        alice.expect_xml(&format!("<message xmlns='jabber:client' from='erin@localhost/phone' to='alice@localhost/desk' type='error' id='{id}'><error type='wait'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>Too many distinct recipients were contacted. Wait before contacting additional recipients.</text></error></message>"))?;
    }
    for (index, name) in ["bob", "carol", "dave"].into_iter().enumerate() {
        alice.send(&format!(
            "<message to='{name}@localhost/phone' type='chat' id='repeat'/>"
        ))?;
        recipients[index].expect_xml(&format!("<message xmlns='jabber:client' from='alice@localhost/desk' to='{name}@localhost/phone' type='chat' id='repeat'/>"))?;
    }
    recipients[3].expect_no_tls_input()?;
    let logs = suite.wait_for_log("recipient_rate")?;
    let rejections: Vec<_> = logs
        .lines()
        .filter(|line| line.contains("recipient_rate"))
        .collect();
    assert_eq!(rejections.len(), 2, "{logs}");
    for event in rejections {
        assert!(event.contains("DEBUG"), "{event}");
        assert!(event.contains("rejected"), "{event}");
        assert!(!event.contains("erin"), "{event}");
        assert!(
            !event.contains("fourth") && !event.contains("retry"),
            "{event}"
        );
    }
    alice.close()?;
    for recipient in &mut recipients {
        recipient.close()?;
    }
    Ok(())
}

const RECIPIENT_STRICT: &str = "new_recipients_per_connection = { per_second = 1, burst = 1 }";

fn expect_policy_error(client: &mut Client, name: &str, target: &str, id: &str) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name("jabber:client", name);
    assert_eq!(reply.attribute("type"), Some("error"));
    assert_eq!(reply.attribute("from"), Some(target));
    assert_eq!(reply.attribute("to"), Some("alice@localhost/desk"));
    assert_eq!(reply.attribute("id"), Some(id));
    let error = reply.child("jabber:client", "error")?;
    assert_eq!(error.attribute("type"), Some("wait"));
    error.child("urn:ietf:params:xml:ns:xmpp-stanzas", "policy-violation")?;
    Ok(())
}

#[test]
fn recipient_budget_rejects_iq_and_every_subscription_without_roster_changes() -> TestResult {
    let suite = C2sSuite::with_limits(RECIPIENT_STRICT)?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, ALTERNATE_PASSWORD)?;
    }
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", ALTERNATE_PASSWORD, "phone")?;
    let mut carol = suite.connect("carol", ALTERNATE_PASSWORD, "phone")?;
    alice.send("<message to='bob@localhost/phone' id='burn'/><iq type='get' id='before'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("burn"));
    let before = alice.receive()?;
    let before = before.child("jabber:iq:roster", "query")?;
    for kind in ["get", "set"] {
        alice.send(&format!("<iq to='carol@localhost/phone' from='mallory@localhost/spy' type='{kind}' id='{kind}'><query xmlns='urn:test'/></iq>"))?;
        expect_policy_error(&mut alice, "iq", "carol@localhost/phone", kind)?;
    }
    for kind in ["subscribe", "subscribed", "unsubscribe", "unsubscribed"] {
        alice.send(&format!(
            "<presence to='carol@localhost/phone' from='mallory@localhost/spy' type='{kind}' id='{kind}'/>"
        ))?;
        expect_policy_error(&mut alice, "presence", "carol@localhost/phone", kind)?;
    }
    alice.send("<iq type='get' id='after'><query xmlns='jabber:iq:roster' ver=''/></iq>")?;
    let after = alice.receive()?;
    assert_eq!(after.child("jabber:iq:roster", "query")?, before);
    carol.expect_no_tls_input()?;
    alice.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn recipient_budget_exempts_own_account_server_services_and_responses() -> TestResult {
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'roster', 'test-service'",
        RECIPIENT_STRICT,
        |_| Ok(()),
    )?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, ALTERNATE_PASSWORD)?;
    }
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.connect("alice", ALTERNATE_PASSWORD, "phone")?;
    let mut bob = suite.connect("bob", ALTERNATE_PASSWORD, "phone")?;
    let mut carol = suite.connect("carol", ALTERNATE_PASSWORD, "phone")?;
    alice.send("<message to='bob@localhost/phone' id='burn'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("burn"));
    alice.send("<message to='alice@localhost/desk' type='chat' id='own-full'/><iq type='get' to='alice@localhost' id='own-bare'><query xmlns='jabber:iq:roster'/></iq><message type='chat' to='alice@localhost' id='own-bare-message'/><message type='chat' id='no-to-message'/><iq type='get' id='no-to'><query xmlns='jabber:iq:roster'/></iq><iq type='get' to='localhost' id='server'><ping xmlns='urn:xmpp:ping'/></iq><iq type='get' to='localhost/resource' id='server-resource'><ping xmlns='urn:xmpp:ping'/></iq><message type='chat' to='room@echo.localhost' id='service'><body>echo</body></message>")?;
    for id in [
        "own-full",
        "own-bare",
        "own-bare-message",
        "no-to-message",
        "no-to",
        "server",
        "server-resource",
        "service",
    ] {
        let reply = alice.receive()?;
        assert_eq!(reply.attribute("id"), Some(id), "{reply:?}");
        if reply.attribute("type") == Some("error") {
            assert!(
                reply
                    .child("jabber:client", "error")?
                    .children
                    .iter()
                    .all(|child| child.name != "policy-violation")
            );
        }
    }
    alice.send("<message to='alice@localhost/phone' id='own-other-resource'/><message type='error' to='carol@localhost/phone' id='message-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message><presence type='error' to='carol@localhost/phone' id='presence-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence><iq type='result' to='carol@localhost/phone' id='iq-result'/><iq type='error' to='carol@localhost/phone' id='iq-error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")?;
    assert_eq!(phone.receive()?.attribute("id"), Some("own-other-resource"));
    for id in ["message-error", "presence-error", "iq-result", "iq-error"] {
        assert_eq!(carol.receive()?.attribute("id"), Some(id));
    }
    alice.send("<message to='carol@localhost/phone' id='still-limited'/>")?;
    expect_policy_error(
        &mut alice,
        "message",
        "carol@localhost/phone",
        "still-limited",
    )?;
    phone.send("<message to='carol@localhost/phone' id='independent'/>")?;
    assert_eq!(carol.receive()?.attribute("id"), Some("independent"));
    alice.close()?;
    phone.close()?;
    bob.close()?;
    carol.close()
}

#[test]
fn recipient_budget_counts_bare_identity_across_resources() -> TestResult {
    let suite = C2sSuite::with_limits(RECIPIENT_STRICT)?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, ALTERNATE_PASSWORD)?;
    }
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut desk = suite.connect("bob", ALTERNATE_PASSWORD, "desk")?;
    let mut phone = suite.connect("bob", ALTERNATE_PASSWORD, "phone")?;
    alice.send("<message to='bob@localhost/desk' id='first'/><message to='bob@localhost/phone' id='second'/><iq to='bob@localhost' type='get' id='bare'><query xmlns='urn:test'/></iq><message to='carol@localhost/phone' id='denied'/>")?;
    assert_eq!(desk.receive()?.attribute("id"), Some("first"));
    assert_eq!(phone.receive()?.attribute("id"), Some("second"));
    let bare = alice.receive()?;
    assert_eq!(bare.attribute("id"), Some("bare"));
    bare.child("jabber:client", "error")?
        .child("urn:ietf:params:xml:ns:xmpp-stanzas", "service-unavailable")?;
    expect_policy_error(&mut alice, "message", "carol@localhost/phone", "denied")?;
    alice.close()?;
    desk.close()?;
    phone.close()
}

#[test]
fn recipient_budget_quietly_drops_directed_presence_without_grant_changes() -> TestResult {
    let suite =
        C2sSuite::with_limits("new_recipients_per_connection = { per_second = 1, burst = 65 }")?;
    for name in ["alice", "bob", "carol"] {
        suite.create_account(name, ALTERNATE_PASSWORD)?;
    }
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", ALTERNATE_PASSWORD, "phone")?;
    let mut carol = suite.connect("carol", ALTERNATE_PASSWORD, "phone")?;
    alice.send("<presence to='bob@localhost/phone' id='grant'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("grant"));
    let mut fill = String::new();
    for index in 0..64 {
        fill.push_str(&format!(
            "<message to='user{index}@remote.example' id='fill-{index}'/>"
        ));
    }
    alice.send(&fill)?;
    for index in 0..64 {
        assert_eq!(
            alice.receive()?.attribute("id"),
            Some(format!("fill-{index}").as_str())
        );
    }
    alice.send("<presence to='carol@localhost/phone' id='available'/><presence to='bob@localhost/phone' type='unavailable' id='withdrawal'/><presence to='carol@localhost/phone' type='probe' id='probe'/><message to='alice@localhost/desk' id='barrier'/>")?;
    let barrier = alice.receive()?;
    assert_eq!(barrier.attribute("id"), Some("barrier"), "{barrier:?}");
    bob.send("<presence to='alice@localhost/desk' type='probe' id='existing-grant'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/desk' to='bob@localhost/phone' id='existing-grant'/>")?;
    carol.send("<presence to='alice@localhost/desk' type='probe' id='no-grant'/>")?;
    carol.expect_xml("<presence xmlns='jabber:client' type='unsubscribed' from='alice@localhost' to='carol@localhost/phone' id='no-grant'/>")?;
    alice.close()?;
    assert_eq!(bob.receive()?.attribute("type"), Some("unavailable"));
    carol.expect_no_tls_input()?;
    bob.close()?;
    carol.close()
}

#[test]
fn recipient_budget_precedes_policy_and_archive_processing() -> TestResult {
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "'test-policy', 'test-archive'",
        RECIPIENT_STRICT,
        |_| Ok(()),
    )?;
    for name in ["alice", "bob", "blocked", "carol"] {
        suite.create_account(name, ALTERNATE_PASSWORD)?;
    }
    let mut alice = suite.connect("alice", ALTERNATE_PASSWORD, "desk")?;
    let mut bob = suite.connect("bob", ALTERNATE_PASSWORD, "phone")?;
    let mut blocked = suite.connect("blocked", ALTERNATE_PASSWORD, "phone")?;
    let mut carol = suite.connect("carol", ALTERNATE_PASSWORD, "phone")?;
    alice.send("<message type='chat' to='bob@localhost/phone' id='burn'/>")?;
    assert_eq!(bob.receive()?.attribute("id"), Some("burn"));
    for target in ["blocked@localhost/phone", "carol@localhost/phone"] {
        alice.send(&format!("<message type='chat' to='{target}' id='denied'/>"))?;
        expect_policy_error(&mut alice, "message", target, "denied")?;
    }
    alice.send("<iq type='get' to='localhost' id='entries'><entries xmlns='urn:lonewolf:test:archive'/></iq>")?;
    alice.expect_xml("<iq xmlns='jabber:client' from='localhost' to='alice@localhost/desk' type='result' id='entries'><entries xmlns='urn:lonewolf:test:archive'><entry owner='alice@localhost' direction='sent' id='1'/><entry owner='bob@localhost' direction='received' id='2'/></entries></iq>")?;
    blocked.expect_no_tls_input()?;
    carol.expect_no_tls_input()?;
    alice.close()?;
    bob.close()?;
    blocked.close()?;
    carol.close()
}
