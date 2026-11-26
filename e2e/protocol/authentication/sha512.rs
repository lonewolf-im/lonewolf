// SPDX-License-Identifier: Apache-2.0

use super::*;

const MECHANISMS: &[(&str, Option<&str>)] = &[
    ("SCRAM-SHA-512", None),
    ("SCRAM-SHA-512-PLUS", Some("tls-server-end-point")),
];

fn enable_sha512(directory: &std::path::Path) -> TestResult {
    let path = directory.join("lonewolf.toml");
    let config = std::fs::read_to_string(&path)?.replace("[[c2s.listeners]]", "[[c2s.listeners]]\nauth_mechanisms = ['SCRAM-SHA-512-PLUS', 'SCRAM-SHA-512', 'SCRAM-SHA-256-PLUS', 'SCRAM-SHA-256', 'SCRAM-SHA-1-PLUS', 'SCRAM-SHA-1']");
    Ok(std::fs::write(path, config)?)
}

#[test]
fn default_listener_omits_and_rejects_sha512() -> TestResult {
    let mut suite = C2sSuite::start()?;
    let mut plain = super::super::support::PlainClient::tcp(&suite)?;
    let features = plain.open()?;
    assert!(
        features
            .children
            .iter()
            .all(|child| child.name != "mechanisms")
    );
    let mut client = plain.start_tls(&suite)?;
    let features = client.open()?;
    let names: Vec<_> = features
        .child(SASL_NAMESPACE, "mechanisms")?
        .children
        .iter()
        .map(|child| child.text.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "SCRAM-SHA-256-PLUS",
            "SCRAM-SHA-256",
            "SCRAM-SHA-1-PLUS",
            "SCRAM-SHA-1"
        ]
    );
    for (mechanism, _) in MECHANISMS {
        client.send_sasl_auth(mechanism, "n,,n=alice,r=nonce")?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
        )?;
    }
    client.close()?;
    suite.stop()
}

#[test]
fn each_sha512_mechanism_can_be_the_only_offer_and_complete_a_session() -> TestResult {
    for (mechanism, binding) in MECHANISMS {
        let mut suite = C2sSuite::with_auth_mechanisms(&[mechanism])?;
        suite.create_account("alice", PASSWORD)?;
        let mut client = suite.tls_client()?;
        let features = client.open()?;
        let names: Vec<_> = features
            .child(SASL_NAMESPACE, "mechanisms")?
            .children
            .iter()
            .map(|child| child.text.as_str())
            .collect();
        assert_eq!(names, [*mechanism]);
        assert_eq!(
            features
                .children
                .iter()
                .any(|child| child.name == "sasl-channel-binding"),
            binding.is_some()
        );
        if binding.is_some() {
            features.child("urn:xmpp:sasl-cb:0", "sasl-channel-binding")?.assert_xml("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding>")?;
        }
        let disabled = if binding.is_some() {
            "SCRAM-SHA-512"
        } else {
            "SCRAM-SHA-512-PLUS"
        };
        client.send_sasl_auth(disabled, "n,,n=alice,r=nonce")?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
        )?;
        client
            .scram("alice", PASSWORD, mechanism, *binding)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.send("<message to='alice@localhost/desk' type='chat' id='sha512'><body>Ready</body></message>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='sha512'><body>Ready</body></message>")?;
        client.close()?;
        suite.stop()?;
    }
    Ok(())
}

#[test]
fn legacy_credentials_use_decoy_until_admin_password_replacement() -> TestResult {
    let mut suite = C2sSuite::with_extensions_and_setup("", |directory| {
        seed_legacy_short_password_credentials(directory)?;
        enable_sha512(directory)
    })?;
    for username in ["legacy", "missing"] {
        for (mechanism, binding) in MECHANISMS {
            let mut client = suite.unauthenticated_client()?;
            client
                .scram(username, "a", mechanism, *binding)?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
            client.close()?;
        }
    }
    suite.reject_weak_password_change("legacy", "a")?;
    for mechanism in ["SCRAM-SHA-1", "SCRAM-SHA-256"] {
        let mut client = suite.unauthenticated_client()?;
        client
            .scram("legacy", "a", mechanism, None)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        client.bind(Some("desk"))?;
        client.close()?;
    }
    suite.change_password("legacy", PASSWORD)?;
    for (mechanism, binding) in MECHANISMS {
        let mut client = suite.unauthenticated_client()?;
        client
            .scram("legacy", PASSWORD, mechanism, *binding)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        client.bind(Some("desk"))?;
        client.close()?;
    }
    suite.stop()
}

#[test]
fn sha512_revalidates_credentials_and_authorization_before_success() -> TestResult {
    let mut suite = C2sSuite::with_auth_mechanisms(ALL_SCRAM_MECHANISMS)?;
    suite.create_account("alice", PASSWORD)?;
    for (mechanism, binding) in MECHANISMS {
        for authzid in [None, Some("bob@localhost")] {
            suite.change_password("alice", PASSWORD)?;
            let mut client = suite.unauthenticated_client()?;
            let exchange = client.begin_scram("alice", PASSWORD, mechanism, *binding, authzid)?;
            suite.change_password("alice", NEW_PASSWORD)?;
            client.finish_scram(exchange)?.assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
            let exchange = client.begin_scram(
                "alice",
                NEW_PASSWORD,
                mechanism,
                *binding,
                Some("bob@localhost"),
            )?;
            client.finish_scram(exchange)?.assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
            )?;
            let exchange = client.begin_scram(
                "alice",
                NEW_PASSWORD,
                mechanism,
                *binding,
                Some("Alice@LOCALHOST"),
            )?;
            client
                .finish_scram(exchange)?
                .assert_name(SASL_NAMESPACE, "success");
            let mut client = client.restart();
            client.open()?;
            client.bind(Some("desk"))?;
            client.close()?;
        }
        let mut client = suite.unauthenticated_client()?;
        let exchange = client.begin_scram(
            "alice",
            NEW_PASSWORD,
            mechanism,
            *binding,
            Some("bob@localhost"),
        )?;
        suite.delete_account("alice")?;
        client.finish_scram(exchange)?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;
        client.close()?;
        suite.create_account("alice", PASSWORD)?;
        let mut client = suite.unauthenticated_client()?;
        client
            .scram("alice", PASSWORD, mechanism, *binding)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        suite.delete_account("alice")?;
        client.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
        client.expect_stream_error("not-authorized")?;
        suite.create_account("alice", PASSWORD)?;
    }
    suite.stop()
}

#[test]
fn sha512_failed_proofs_and_aborts_share_the_attempt_budget() -> TestResult {
    let mut suite = C2sSuite::with_auth_mechanisms(ALL_SCRAM_MECHANISMS)?;
    suite.create_account("alice", PASSWORD)?;
    for (mechanism, binding) in MECHANISMS {
        let mut client = suite.unauthenticated_client()?;
        let _exchange = client.begin_scram("alice", PASSWORD, mechanism, *binding, None)?;
        client.abort_sasl()?;
        client
            .expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
        for password in ["wrong", "wrong again"] {
            client
                .scram("alice", password, mechanism, *binding)?
                .assert_xml(
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
                )?;
        }
        client.expect_stream_error("policy-violation")?;
        let mut client = suite.unauthenticated_client()?;
        for _ in 0..3 {
            let _exchange = client.begin_scram("alice", PASSWORD, mechanism, *binding, None)?;
        }
        client.send_sasl_auth(mechanism, "n,,n=alice,r=fourth")?;
        client.expect_stream_error("policy-violation")?;
    }
    suite.stop()
}

#[test]
fn sha512_pending_proofs_obey_authentication_deadline_and_shutdown() -> TestResult {
    let mut suite = C2sSuite::with_extensions_limits_and_setup(
        "",
        "authentication_timeout_secs = 1",
        enable_sha512,
    )?;
    for (index, (mechanism, binding)) in MECHANISMS.iter().enumerate() {
        let mut client = suite.unauthenticated_client()?;
        let _exchange = client.begin_scram("missing", PASSWORD, mechanism, *binding, None)?;
        client.expect_stream_error("policy-violation")?;
        suite.wait_for_closed("authentication_timeout", (index + 1) as u64)?;
    }
    suite.stop()?;
    let mut suite = C2sSuite::with_auth_mechanisms(ALL_SCRAM_MECHANISMS)?;
    let mut normal = suite.unauthenticated_client()?;
    let mut plus = suite.unauthenticated_client()?;
    let _normal = normal.begin_scram("missing", PASSWORD, "SCRAM-SHA-512", None, None)?;
    let _plus = plus.begin_scram(
        "missing",
        PASSWORD,
        "SCRAM-SHA-512-PLUS",
        Some("tls-exporter"),
        None,
    )?;
    std::thread::scope(|scope| -> TestResult {
        let stopped = scope.spawn(|| suite.stop().map_err(|error| error.to_string()));
        normal.expect_stream_error("system-shutdown")?;
        plus.expect_stream_error("system-shutdown")?;
        stopped.join().map_err(|_| "shutdown worker panicked")??;
        Ok(())
    })
}
