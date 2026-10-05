// SPDX-License-Identifier: Apache-2.0

use super::support::xml::STREAM_NAMESPACE;
use rustls::{ProtocolVersion, SupportedProtocolVersion, version};

use super::support::{C2sSuite, Client, OPEN, SASL_NAMESPACE, STREAM_ERRORS, TestResult};

#[test]
fn scram_sha256_authenticates() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client
        .scram("Alice", "pencil", "SCRAM-SHA-256", None)?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    let header = client.open_with(OPEN)?;
    assert_eq!(header.attribute("from"), Some("localhost"));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
    </stream:features>",
    )?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn tls12_exporter_authenticates_both_plus_mechanisms() -> TestResult {
    exporter_authenticates_both_plus_mechanisms(&version::TLS12)
}

#[test]
fn tls13_exporter_authenticates_both_plus_mechanisms() -> TestResult {
    exporter_authenticates_both_plus_mechanisms(&version::TLS13)
}

fn exporter_authenticates_both_plus_mechanisms(
    version: &'static SupportedProtocolVersion,
) -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
        let mut client = Client::secure_with_versions(&suite, &[version])?;
        assert_eq!(
            client.transport().conn.protocol_version(),
            Some(version.version)
        );
        client
            .scram("Alice", "pencil", mechanism, Some("tls-exporter"))?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.send("<message to='alice@localhost/desk' type='chat' id='bound'><body>Ready</body></message>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='bound'><body>Ready</body></message>")?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn tls12_absent_exporter_context_rejects_both_plus_mechanisms() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
        let mut client = Client::secure_with_versions(&suite, &[&version::TLS12])?;
        assert_eq!(
            client.transport().conn.protocol_version(),
            Some(ProtocolVersion::TLSv1_2)
        );
        let mut absent = [0; 32];
        let mut empty = [0; 32];
        client.transport().conn.export_keying_material(
            &mut absent,
            b"EXPORTER-Channel-Binding",
            None,
        )?;
        client.transport().conn.export_keying_material(
            &mut empty,
            b"EXPORTER-Channel-Binding",
            Some(&[]),
        )?;
        assert_ne!(absent, empty);
        let exchange = client.begin_scram_with_channel_binding(
            "alice",
            "pencil",
            mechanism,
            "tls-exporter",
            &absent,
        )?;
        client.finish_scram(exchange)?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;
        client.expect_end()?;
    }
    Ok(())
}

#[test]
fn wrong_exporter_data_rejects_both_plus_mechanisms_on_each_tls_version() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    for version in [&version::TLS12, &version::TLS13] {
        for mechanism in ["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS"] {
            let mut client = Client::secure_with_versions(&suite, &[version])?;
            assert_eq!(
                client.transport().conn.protocol_version(),
                Some(version.version)
            );
            let mut wrong = [0; 32];
            client.transport().conn.export_keying_material(
                &mut wrong,
                b"EXPORTER-Channel-Binding",
                Some(&[]),
            )?;
            wrong[0] ^= 1;
            let exchange = client.begin_scram_with_channel_binding(
                "alice",
                "pencil",
                mechanism,
                "tls-exporter",
                &wrong,
            )?;
            client.finish_scram(exchange)?.assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
            client.expect_end()?;
        }
    }
    Ok(())
}

#[test]
fn scram_sha256_plus_with_tls_server_end_point_authenticates() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client
        .scram(
            "Alice",
            "pencil",
            "SCRAM-SHA-256-PLUS",
            Some("tls-server-end-point"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    let header = client.open_with(OPEN)?;
    assert_eq!(header.attribute("from"), Some("localhost"));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
    </stream:features>",
    )?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn scram_sha1_authenticates() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client
        .scram("Alice", "pencil", "SCRAM-SHA-1", None)?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    let header = client.open_with(OPEN)?;
    assert_eq!(header.attribute("from"), Some("localhost"));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
    </stream:features>",
    )?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn scram_sha1_plus_with_tls_server_end_point_authenticates() -> TestResult {
    let suite = C2sSuite::with_extensions("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client
        .scram(
            "Alice",
            "pencil",
            "SCRAM-SHA-1-PLUS",
            Some("tls-server-end-point"),
        )?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    let header = client.open_with(OPEN)?;
    assert_eq!(header.attribute("from"), Some("localhost"));

    client.features()?.assert_xml(
        "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
    </stream:features>",
    )?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn non_plus_listener_rejects_disabled_plus_mechanism() -> TestResult {
    let suite = C2sSuite::with_auth_mechanisms(&["SCRAM-SHA-256"])?;
    let mut client = suite.tls_client()?;
    client.open()?.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism></mechanisms>
    </stream:features>")?;

    client.send_sasl_auth("SCRAM-SHA-256-PLUS", "n,,n=alice,r=nonce")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    client.close()
}

#[test]
fn plus_only_listener_rejects_non_plus_authentication() -> TestResult {
    let suite = C2sSuite::with_auth_mechanisms(&["SCRAM-SHA-1-PLUS"])?;
    let mut client = suite.tls_client()?;
    client.open()?.assert_xml("<stream:features xmlns:stream='http://etherx.jabber.org/streams'>
        <sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding>
        <mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1-PLUS</mechanism></mechanisms>
    </stream:features>")?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    client.close()
}

#[test]
fn non_plus_listener_accepts_the_scram_y_flag() -> TestResult {
    let suite = C2sSuite::with_auth_mechanisms(&["SCRAM-SHA-256"])?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "y,,n=alice,r=nonce")?;
    let challenge = client.receive_sasl_challenge()?;
    assert!(challenge.starts_with("r=nonce"));

    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client.close()
}

#[test]
fn missing_mechanism_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn unsupported_mechanism_returns_invalid_mechanism() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'/>")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    client.close()
}

#[test]
fn extra_attribute_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256' extra='1'/>",
    )?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn child_element_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'><child/></auth>",
    )?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn invalid_base64_returns_incorrect_encoding() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>!</auth>",
    )?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><incorrect-encoding/></failure>",
    )?;
    client.close()
}

#[test]
fn abort_without_challenge_returns_aborted() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client.close()
}

#[test]
fn unknown_channel_binding_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256-PLUS", "p=unknown-binding,,n=alice,r=nonce")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn malformed_scram_initial_message_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "invalid")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn wrong_password_closes_after_three_failed_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        let reply = client.scram("alice", "wrong", "SCRAM-SHA-256", None)?;
        reply.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn malformed_final_for_known_account_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=nonce")?;
    client.receive_sasl_challenge()?;

    client.send_sasl_response("x=1")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn known_account_uses_normalized_scram_challenge_parameters() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=Alice,r=firstnonce")?;
    let uppercase = client.receive_sasl_challenge()?;
    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=alice,r=secondnonce")?;
    let lowercase = client.receive_sasl_challenge()?;
    assert_eq!(
        uppercase
            .split_once(",s=")
            .ok_or("missing uppercase salt")?
            .1,
        lowercase
            .split_once(",s=")
            .ok_or("missing lowercase salt")?
            .1
    );
    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client.close()
}

#[test]
fn unknown_account_closes_after_three_failed_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        let reply = client.scram("missing", "wrong", "SCRAM-SHA-256", None)?;
        reply.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn malformed_final_for_unknown_account_returns_malformed_request() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=nonce")?;
    client.receive_sasl_challenge()?;

    client.send_sasl_response("x=1")?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><malformed-request/></failure>",
    )?;
    client.close()
}

#[test]
fn unknown_account_uses_normalized_scram_challenge_parameters() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=Missing,r=firstnonce")?;
    let uppercase = client.receive_sasl_challenge()?;
    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=secondnonce")?;
    let lowercase = client.receive_sasl_challenge()?;
    assert_eq!(
        uppercase
            .split_once(",s=")
            .ok_or("missing uppercase salt")?
            .1,
        lowercase
            .split_once(",s=")
            .ok_or("missing lowercase salt")?
            .1
    );
    client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client.close()
}

#[test]
fn scram_proof_challenge_counts_aborted_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=nonce")?;
        let challenge = client.receive_sasl_challenge()?;
        assert!(challenge.starts_with("r=nonce"));

        client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        client
            .expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn scram_proof_challenge_counts_incorrect_encoding_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=nonce")?;
        let challenge = client.receive_sasl_challenge()?;
        assert!(challenge.starts_with("r=nonce"));

        client.send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>!</response>")?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><incorrect-encoding/></failure>",
        )?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn replacement_auth_discards_the_scram_proof_challenge() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=discarded,r=first")?;
    client.receive_sasl_challenge()?;

    for nonce in ["second", "third"] {
        client.send_sasl_auth("SCRAM-SHA-256", &format!("n,,n=missing,r={nonce}"))?;
        assert!(
            client
                .receive_sasl_challenge()?
                .starts_with(&format!("r={nonce}"))
        );
    }
    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=fourth")?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn empty_initial_challenge_counts_aborted_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        client.send_sasl_auth("SCRAM-SHA-256", "")?;
        let challenge = client.receive_sasl_challenge()?;
        assert!(challenge.is_empty());

        client.send("<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        client
            .expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn empty_initial_challenge_counts_incorrect_encoding_attempts() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    for _ in 0..3 {
        client.send_sasl_auth("SCRAM-SHA-256", "")?;
        let challenge = client.receive_sasl_challenge()?;
        assert!(challenge.is_empty());

        client.send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>!</response>")?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><incorrect-encoding/></failure>",
        )?;
    }
    client.expect_stream_error("policy-violation")
}

#[test]
fn replacement_auth_discards_the_empty_initial_challenge() -> TestResult {
    let suite = C2sSuite::start()?;
    let mut client = suite.unauthenticated_client()?;

    client.send_sasl_auth("SCRAM-SHA-256", "")?;
    client.receive_sasl_challenge()?;

    for nonce in ["second", "third"] {
        client.send_sasl_auth("SCRAM-SHA-256", &format!("n,,n=missing,r={nonce}"))?;
        assert!(
            client
                .receive_sasl_challenge()?
                .starts_with(&format!("r={nonce}"))
        );
    }
    client.send_sasl_auth("SCRAM-SHA-256", "n,,n=missing,r=fourth")?;
    client.expect_stream_error("policy-violation")
}

#[test]
fn valid_proof_with_unauthorized_authzid_can_retry_after_invalid_authzid() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "other password")?;

    for authzid in [
        "bob@localhost",
        "alice@other.example",
        "alice@localhost/desk",
        "localhost",
        "not a jid",
        "",
    ] {
        let mut client = suite.unauthenticated_client()?;
        let exchange =
            client.begin_scram("alice", "pencil", "SCRAM-SHA-256", None, Some(authzid))?;
        client.finish_scram(exchange)?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
        )?;

        client.authenticate("alice", "pencil")?;
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn normalized_same_account_authzid_authenticates_with_channel_binding() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    let exchange = client.begin_scram(
        "Alice",
        "pencil",
        "SCRAM-SHA-256-PLUS",
        Some("tls-server-end-point"),
        Some("ALICE@LOCALHOST."),
    )?;
    client
        .finish_scram(exchange)?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn unknown_account_and_wrong_proof_hide_authzid_outcomes() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;

    for username in ["alice", "missing"] {
        let mut client = suite.unauthenticated_client()?;
        for authzid in [None, Some("bob@localhost"), Some("alice@localhost")] {
            let exchange = client.begin_scram(username, "wrong", "SCRAM-SHA-256", None, authzid)?;
            client.finish_scram(exchange)?.assert_xml(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
            )?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}

#[test]
fn password_rotation_rejects_old_proof_before_authzid_validation() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;

    for authzid in [None, Some("bob@localhost")] {
        suite.change_password("alice", "pencil")?;
        let mut client = suite.unauthenticated_client()?;
        let exchange = client.begin_scram("alice", "pencil", "SCRAM-SHA-256", None, authzid)?;
        suite.change_password("alice", "replacement")?;
        client.finish_scram(exchange)?.assert_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )?;

        client.authenticate("alice", "replacement")?;
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn account_deletion_rejects_old_proof_before_authzid_validation() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.unauthenticated_client()?;
    let exchange = client.begin_scram(
        "alice",
        "pencil",
        "SCRAM-SHA-256",
        None,
        Some("bob@localhost"),
    )?;
    suite.delete_account("alice")?;
    client.finish_scram(exchange)?.assert_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
    )?;
    client.close()
}

#[test]
fn protected_from_must_match_the_authenticated_account() -> TestResult {
    let suite = C2sSuite::start()?;
    suite.create_account("alice", "pencil")?;
    let mut client = suite.tls_client()?;
    client.open_with(&OPEN.replace("to='localhost'", "from='bob@localhost' to='localhost'"))?;
    client.features()?;
    let reply = client.scram("alice", "pencil", "SCRAM-SHA-256", None)?;
    reply.assert_name(STREAM_NAMESPACE, "error");
    reply.child(STREAM_ERRORS, "invalid-from")?;
    client.expect_end()
}

#[test]
fn optional_client_certificates_keep_no_certificate_and_trusted_certificate_scram_working()
-> TestResult {
    use super::support::tls::{ClientCertificates, with_client_certificate};
    let mut certificates = None;
    let suite = C2sSuite::with_extensions_and_setup("", |directory| {
        certificates = Some(ClientCertificates::configure(directory)?);
        Ok(())
    })?;
    let certificates = certificates.ok_or("missing client certificate fixtures")?;
    suite.create_account("alice", "pencil")?;
    for key in [
        None,
        Some(certificates.trusted),
        Some(certificates.without_xmpp_addr),
        Some(certificates.absent_key_usage),
    ] {
        let mut plain = super::support::PlainClient::tcp(&suite)?;
        plain.open()?;
        let config = key.map_or_else(
            || std::sync::Arc::clone(&suite.tls),
            |key| with_client_certificate(&suite.tls, key),
        );
        let mut client = plain.start_tls_with_config(config)?;
        client.open()?.child(SASL_NAMESPACE, "mechanisms")?;
        client
            .scram("alice", "pencil", "SCRAM-SHA-256", None)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    Ok(())
}

#[test]
fn optional_client_certificates_reject_invalid_presented_certificates() -> TestResult {
    use super::support::tls::{ClientCertificates, with_client_certificate};
    let mut certificates = None;
    let suite = C2sSuite::with_extensions_and_setup("", |directory| {
        certificates = Some(ClientCertificates::configure(directory)?);
        Ok(())
    })?;
    let mut certificates = certificates.ok_or("missing client certificate fixtures")?;
    certificates.rejected.push((
        "resource-bearing XmppAddr",
        certificates.malformed_xmpp_addr,
    ));
    for (scenario, key) in certificates.rejected {
        for version in [&version::TLS12, &version::TLS13] {
            let mut plain = super::support::PlainClient::tcp(&suite)?;
            plain.open()?;
            let config = suite.tls_with_versions(&[version])?;
            let mut client = plain.start_tls_with_config(with_client_certificate(
                &config,
                std::sync::Arc::clone(&key),
            ))?;
            assert!(
                client.open_with(OPEN).is_err(),
                "accepted {scenario} with {:?}",
                version.version
            );
        }
    }
    let logs = suite.wait_for_log("outcome=\"tls_failure\"")?;
    assert!(!logs.contains("alice@localhost"));
    Ok(())
}

#[test]
fn client_certificate_handshakes_use_replaced_crls_without_restarting() -> TestResult {
    use super::support::tls::{ClientCertificates, with_client_certificate};
    let mut certificates = None;
    let suite = C2sSuite::with_extensions_and_setup("", |directory| {
        certificates = Some(ClientCertificates::configure(directory)?);
        Ok(())
    })?;
    let certificates = certificates.ok_or("missing client certificate fixtures")?;
    suite.create_account("alice", "pencil")?;
    let config = with_client_certificate(&suite.tls, std::sync::Arc::clone(&certificates.trusted));
    for replace in [false, true] {
        if replace {
            certificates.replace_crl(
                false,
                time::OffsetDateTime::now_utc() + time::Duration::days(2),
            )?;
        }
        let mut plain = super::support::PlainClient::tcp(&suite)?;
        plain.open()?;
        let mut client = plain.start_tls_with_config(std::sync::Arc::clone(&config))?;
        client.open()?.child(SASL_NAMESPACE, "mechanisms")?;
        client
            .scram("alice", "pencil", "SCRAM-SHA-256", None)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    certificates.replace_crl(
        true,
        time::OffsetDateTime::now_utc() + time::Duration::days(2),
    )?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client = plain.start_tls_with_config(config)?;
    assert!(client.open_with(OPEN).is_err());
    Ok(())
}

#[test]
fn runtime_crl_failures_reject_certificates_and_keep_no_certificate_scram_working() -> TestResult {
    use super::support::tls::{ClientCertificates, with_client_certificate};
    let mut certificates = None;
    let mut crls_path = None;
    let suite = C2sSuite::with_extensions_and_setup("", |directory| {
        certificates = Some(ClientCertificates::configure(directory)?);
        crls_path = Some(directory.join("client-crls.pem"));
        Ok(())
    })?;
    let certificates = certificates.ok_or("missing client certificate fixtures")?;
    let crls_path = crls_path.ok_or("missing CRL path")?;
    suite.create_account("alice", "pencil")?;
    for material in [
        None,
        Some(b"".as_slice()),
        Some(b"-----BEGIN X509 CRL-----\n!\n-----END X509 CRL-----\n".as_slice()),
    ] {
        match material {
            None => std::fs::remove_file(&crls_path)?,
            Some(bytes) => std::fs::write(&crls_path, bytes)?,
        }
        let mut plain = super::support::PlainClient::tcp(&suite)?;
        plain.open()?;
        let mut client = plain.start_tls_with_config(with_client_certificate(
            &suite.tls,
            std::sync::Arc::clone(&certificates.trusted),
        ))?;
        assert!(client.open_with(OPEN).is_err());
        let mut client = suite.unauthenticated_client()?;
        client
            .scram("alice", "pencil", "SCRAM-SHA-256", None)?
            .assert_name(SASL_NAMESPACE, "success");
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.close()?;
    }
    certificates.replace_crl(
        false,
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    )?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client =
        plain.start_tls_with_config(with_client_certificate(&suite.tls, certificates.trusted))?;
    assert!(client.open_with(OPEN).is_err());
    let mut client = suite.unauthenticated_client()?;
    client
        .scram("alice", "pencil", "SCRAM-SHA-256", None)?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn blocked_handshake_crl_reload_obeys_establishment_timeout_and_late_results_are_isolated()
-> TestResult {
    use super::support::tls::{
        ClientCertificates, block_crl_reads, wait_for_crl_reader, with_client_certificate,
    };
    use std::io::Write as _;
    let mut certificates = None;
    let mut crls_path = None;
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "",
        "connection_establishment_timeout_secs = 1",
        |directory| {
            certificates = Some(ClientCertificates::configure(directory)?);
            crls_path = Some(directory.join("client-crls.pem"));
            Ok(())
        },
    )?;
    let certificates = certificates.ok_or("missing client certificate fixtures")?;
    let crls_path = crls_path.ok_or("missing CRL path")?;
    suite.create_account("alice", "pencil")?;
    let material = block_crl_reads(&crls_path)?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client = plain.start_tls_with_config(std::sync::Arc::clone(&suite.tls))?;
    let mut release = wait_for_crl_reader(&crls_path)?;
    assert!(client.open_with(OPEN).is_err());
    suite.wait_for_log("outcome=\"establishment_timeout\"")?;
    release.write_all(&material)?;
    drop(release);
    std::fs::remove_file(&crls_path)?;
    std::fs::write(&crls_path, &material)?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client =
        plain.start_tls_with_config(with_client_certificate(&suite.tls, certificates.trusted))?;
    client.open()?.child(SASL_NAMESPACE, "mechanisms")?;
    client
        .scram("alice", "pencil", "SCRAM-SHA-256", None)?
        .assert_name(SASL_NAMESPACE, "success");
    let mut client = client.restart();
    client.open()?;
    assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
    client.close()
}

#[test]
fn blocked_handshake_crl_reload_obeys_shutdown() -> TestResult {
    use super::support::tls::{ClientCertificates, block_crl_reads, wait_for_crl_reader};
    let mut crls_path = None;
    let mut suite = C2sSuite::with_extensions_and_setup("", |directory| {
        ClientCertificates::configure(directory)?;
        crls_path = Some(directory.join("client-crls.pem"));
        Ok(())
    })?;
    let crls_path = crls_path.ok_or("missing CRL path")?;
    block_crl_reads(&crls_path)?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client = plain.start_tls_with_config(std::sync::Arc::clone(&suite.tls))?;
    let _release = wait_for_crl_reader(&crls_path)?;
    suite.stop()?;
    assert!(client.open_with(OPEN).is_err());
    suite.wait_for_log("outcome=\"system_shutdown\"")?;
    Ok(())
}

fn external_suite(
    extensions: &str,
) -> TestResult<(
    C2sSuite,
    super::support::tls::ClientCertificates,
    std::path::PathBuf,
)> {
    let mut certificates = None;
    let mut path = None;
    let suite = C2sSuite::with_extensions_and_setup(extensions, |directory| {
        certificates = Some(super::support::tls::ClientCertificates::configure(
            directory,
        )?);
        path = Some(directory.join("client-crls.pem"));
        Ok(())
    })?;
    Ok((
        suite,
        certificates.ok_or("missing certificate fixtures")?,
        path.ok_or("missing CRL path")?,
    ))
}

fn certificate_client(
    suite: &C2sSuite,
    key: std::sync::Arc<rustls::sign::CertifiedKey>,
    from: Option<&str>,
) -> TestResult<Client> {
    let mut plain = super::support::PlainClient::tcp(suite)?;
    plain.open()?;
    let mut client = plain.start_tls_with_config(super::support::tls::with_client_certificate(
        &suite.tls, key,
    ))?;
    let open =
        from.map(|from| OPEN.replace("to='localhost'", &format!("from='{from}' to='localhost'")));
    client.open_with(open.as_deref().unwrap_or(OPEN))?;
    let features = client.features()?;
    let mechanisms = features.child(SASL_NAMESPACE, "mechanisms")?;
    assert_eq!(
        mechanisms
            .children
            .first()
            .map(|mechanism| mechanism.text.as_str()),
        Some("EXTERNAL")
    );
    Ok(client)
}

#[test]
fn external_explicit_empty_and_omitted_responses_bind_and_route() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    for authzid in [Some("Alice@LOCALHOST"), Some(""), None] {
        let mut client =
            certificate_client(&suite, std::sync::Arc::clone(&certificates.trusted), None)?;
        client.send_external_auth(authzid)?;
        if authzid.is_none() {
            client.expect_xml("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
            client.send_sasl_response("")?;
        }
        client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        let mut client = client.restart();
        client.open()?;
        assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
        client.send("<message to='alice@localhost/desk' type='chat' id='external'><body>Ready</body></message>")?;
        client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='external'><body>Ready</body></message>")?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn external_multiple_candidates_require_explicit_or_protected_identity() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "pencil")?;
    let key = certificates.identity_key(
        &["alice@localhost", "bob@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    for (from, authzid, account) in [
        (None, Some("bob@localhost"), "bob"),
        (Some("alice@localhost"), Some(""), "alice"),
    ] {
        let mut client = certificate_client(&suite, std::sync::Arc::clone(&key), from)?;
        client.send_external_auth(authzid)?;
        client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        let mut client = client.restart();
        client.open()?;
        assert_eq!(
            client.bind(Some("desk"))?,
            format!("{account}@localhost/desk")
        );
        client.close()?;
    }
    let mut client = certificate_client(&suite, key, None)?;
    client.send_external_auth(Some(""))?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure>",
    )?;
    client.close()
}

#[test]
fn external_rejects_unprovisioned_unauthorized_and_malformed_identities() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    for (response, condition) in [
        ("=", "not-authorized"),
        ("Ym9iQGxvY2FsaG9zdA==", "invalid-authzid"),
        ("YWxpY2VAbG9jYWxob3N0L3Bob25l", "invalid-authzid"),
        ("YWxpY2VAb3RoZXIubG9jYWxob3N0", "invalid-authzid"),
        ("/w==", "malformed-request"),
        ("!", "incorrect-encoding"),
    ] {
        let mut client =
            certificate_client(&suite, std::sync::Arc::clone(&certificates.trusted), None)?;
        client.send(&format!(
            "<auth xmlns='{SASL_NAMESPACE}' mechanism='EXTERNAL'>{response}</auth>"
        ))?;
        client.expect_xml(&format!(
            "<failure xmlns='{SASL_NAMESPACE}'><{condition}/></failure>"
        ))?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn external_protected_from_mismatch_uses_invalid_from() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = certificate_client(&suite, certificates.trusted, Some("bob@localhost"))?;
    client.send_external_auth(Some("alice@localhost"))?;
    client.receive()?.child(STREAM_ERRORS, "invalid-from")?;
    client.expect_end()
}

#[test]
fn external_absent_for_no_certificate_no_candidates_and_disabled_policy() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    for key in [
        None,
        Some(std::sync::Arc::clone(&certificates.without_xmpp_addr)),
        Some(certificates.identity_key(
            &["alice@other.localhost"],
            time::OffsetDateTime::now_utc() + time::Duration::days(1),
        )?),
    ] {
        let mut plain = super::support::PlainClient::tcp(&suite)?;
        assert!(
            !plain
                .open()?
                .children
                .iter()
                .any(|feature| feature.namespace == SASL_NAMESPACE)
        );
        let config = key.map_or_else(
            || std::sync::Arc::clone(&suite.tls),
            |key| super::support::tls::with_client_certificate(&suite.tls, key),
        );
        let mut client = plain.start_tls_with_config(config)?;
        let features = client.open()?;
        assert!(
            !features
                .child(SASL_NAMESPACE, "mechanisms")?
                .children
                .iter()
                .any(|mechanism| mechanism.text == "EXTERNAL")
        );
        client.send_external_auth(Some(""))?;
        client.expect_xml(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
        )?;
        client.close()?;
    }
    let mut material = None;
    let suite = C2sSuite::with_extensions_and_setup("", |directory| {
        material = Some(super::support::tls::ClientCertificates::configure(
            directory,
        )?);
        let mut config = std::fs::read_to_string(directory.join("lonewolf.toml"))?;
        config = config.replace(
            "[[c2s.listeners]]",
            "[[c2s.listeners]]\nauth_mechanisms = ['SCRAM-SHA-256']",
        );
        std::fs::write(directory.join("lonewolf.toml"), config)?;
        Ok(())
    })?;
    let mut plain = super::support::PlainClient::tcp(&suite)?;
    plain.open()?;
    let mut client = plain.start_tls_with_config(super::support::tls::with_client_certificate(
        &suite.tls,
        material.ok_or("missing certificates")?.trusted,
    ))?;
    let features = client.open()?;
    assert!(
        !features
            .child(SASL_NAMESPACE, "mechanisms")?
            .children
            .iter()
            .any(|mechanism| mechanism.text == "EXTERNAL")
    );
    client.send_external_auth(Some(""))?;
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
    )?;
    client.close()
}

#[test]
fn external_abort_replacement_and_attempt_budget_match_scram() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let mut client =
        certificate_client(&suite, std::sync::Arc::clone(&certificates.trusted), None)?;
    client.send_external_auth(None)?;
    assert_eq!(client.receive_sasl_challenge()?, "");
    client.abort_sasl()?;
    client.expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    client.send_external_auth(None)?;
    assert_eq!(client.receive_sasl_challenge()?, "");
    client.send_external_auth(Some(""))?;
    client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut client = client.restart();
    client.open()?;
    client.bind(Some("desk"))?;
    client.close()?;
    let mut client = certificate_client(&suite, certificates.trusted, None)?;
    for _ in 0..3 {
        client.send_external_auth(None)?;
        assert_eq!(client.receive_sasl_challenge()?, "");
        client.abort_sasl()?;
        client
            .expect_xml("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")?;
    }
    client.receive()?.child(STREAM_ERRORS, "policy-violation")?;
    client.expect_end()
}

#[test]
fn external_revalidates_revocation_before_success() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let mut client =
        certificate_client(&suite, std::sync::Arc::clone(&certificates.trusted), None)?;
    certificates.replace_crl(
        true,
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    client.send_external_auth(Some(""))?;
    client.receive()?.child(STREAM_ERRORS, "reset")?;
    client.expect_end()
}

#[test]
fn external_account_deletion_during_revalidation_prevents_success() -> TestResult {
    use super::support::tls::{block_crl_reads, wait_for_crl_reader};
    use std::io::Write as _;
    let (suite, certificates, path) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = certificate_client(&suite, certificates.trusted, None)?;
    let material = block_crl_reads(&path)?;
    client.send_external_auth(Some(""))?;
    let mut release = wait_for_crl_reader(&path)?;
    suite.delete_account("alice")?;
    std::fs::remove_file(&path)?;
    std::fs::write(&path, &material)?;
    release.write_all(&material)?;
    drop(release);
    client.expect_xml(
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
    )?;
    client.close()
}

#[test]
fn external_expiry_during_binding_uses_reset() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let key = certificates.identity_key(
        &["alice@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::seconds(3),
    )?;
    let mut client = certificate_client(&suite, key, None)?;
    client.send_external_auth(Some(""))?;
    client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut client = client.restart();
    client.open()?;
    client.receive()?.child(STREAM_ERRORS, "reset")?;
    client.expect_end()
}

#[test]
fn external_expiry_after_binding_sends_directed_unavailable() -> TestResult {
    let (suite, certificates, _) = external_suite("'roster'")?;
    suite.create_account("alice", "pencil")?;
    suite.create_account("bob", "pencil")?;
    let mut bob = Client::authenticated(&suite, "bob", "pencil")?;
    bob.bind(Some("desk"))?;
    let key = certificates.identity_key(
        &["alice@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::seconds(3),
    )?;
    let mut alice = certificate_client(&suite, key, None)?;
    alice.send_external_auth(Some(""))?;
    alice.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut alice = alice.restart();
    alice.open()?;
    alice.bind(Some("phone"))?;
    alice.send("<presence to='bob@localhost/desk'/>")?;
    bob.expect_xml(
        "<presence xmlns='jabber:client' from='alice@localhost/phone' to='bob@localhost/desk'/>",
    )?;
    alice.receive()?.child(STREAM_ERRORS, "reset")?;
    alice.expect_end()?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@localhost/phone' to='bob@localhost/desk' type='unavailable'/>")?;
    bob.close()
}

#[test]
fn external_account_deletion_before_and_after_binding_retires_only_its_session() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    for bound in [false, true] {
        suite.create_account("alice", "pencil")?;
        let mut client =
            certificate_client(&suite, std::sync::Arc::clone(&certificates.trusted), None)?;
        client.send_external_auth(Some(""))?;
        client.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
        let mut client = client.restart();
        client.open()?;
        if bound {
            client.bind(Some("desk"))?;
        }
        suite.delete_account("alice")?;
        if !bound {
            client.send("<iq type='set' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>desk</resource></bind></iq>")?;
        }
        client.receive()?.child(STREAM_ERRORS, "not-authorized")?;
        client.expect_end()?;
    }
    Ok(())
}

#[test]
fn scram_with_a_certificate_does_not_activate_certificate_expiry_monitoring() -> TestResult {
    let (suite, certificates, _) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let expires = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);
    let key = certificates.identity_key(&["alice@localhost"], expires)?;
    let mut client = certificate_client(&suite, key, None)?;
    client.authenticate("alice", "pencil")?;
    let mut client = client.restart();
    client.open()?;
    client.bind(Some("desk"))?;
    let remaining = (expires - time::OffsetDateTime::now_utc()).max(time::Duration::ZERO);
    std::thread::sleep(
        std::time::Duration::try_from(remaining)? + std::time::Duration::from_millis(50),
    );
    client.send("<message to='alice@localhost/desk' type='chat' id='scram'/>")?;
    client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='scram'/>")?;
    client.close()
}

#[test]
fn external_shutdown_cancels_blocked_revalidation() -> TestResult {
    use super::support::tls::{block_crl_reads, wait_for_crl_reader};
    use std::io::Write as _;
    let (mut suite, certificates, path) = external_suite("")?;
    suite.create_account("alice", "pencil")?;
    let mut client = certificate_client(&suite, certificates.trusted, None)?;
    let material = block_crl_reads(&path)?;
    client.send_external_auth(Some(""))?;
    let mut release = wait_for_crl_reader(&path)?;
    let stopped = std::thread::spawn(move || suite.stop().map_err(|error| error.to_string()));
    client.receive()?.child(STREAM_ERRORS, "system-shutdown")?;
    client.expect_end()?;
    release.write_all(&material)?;
    drop(release);
    stopped.join().map_err(|_| "shutdown worker panicked")??;
    Ok(())
}

#[test]
fn external_blocked_revalidation_obeys_authentication_deadline() -> TestResult {
    use super::support::tls::{block_crl_reads, wait_for_crl_reader};
    use std::io::Write as _;
    let mut material = None;
    let mut path = None;
    let suite = C2sSuite::with_extensions_limits_and_setup(
        "",
        "authentication_timeout_secs = 1",
        |directory| {
            material = Some(super::support::tls::ClientCertificates::configure(
                directory,
            )?);
            path = Some(directory.join("client-crls.pem"));
            Ok(())
        },
    )?;
    let certificates = material.ok_or("missing certificate fixtures")?;
    let path = path.ok_or("missing CRL path")?;
    suite.create_account("alice", "pencil")?;
    let mut client = certificate_client(&suite, certificates.trusted, None)?;
    let material = block_crl_reads(&path)?;
    client.send_external_auth(Some(""))?;
    let mut release = wait_for_crl_reader(&path)?;
    assert!(client.receive().is_err());
    suite.wait_for_log("outcome=\"authentication_timeout\"")?;
    std::fs::remove_file(&path)?;
    std::fs::write(&path, &material)?;
    release.write_all(&material)?;
    drop(release);
    let mut client = Client::authenticated(&suite, "alice", "pencil")?;
    client.bind(Some("desk"))?;
    client.send("<message to='alice@localhost/desk' type='chat' id='retry'/>")?;
    client.expect_xml("<message xmlns='jabber:client' from='alice@localhost/desk' to='alice@localhost/desk' type='chat' id='retry'/>")?;
    client.close()
}
