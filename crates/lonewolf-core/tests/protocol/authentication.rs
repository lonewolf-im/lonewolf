// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::support::xml::STREAM_NAMESPACE;
use super::support::{
    BIND_NAMESPACE, Client, OPEN, SASL_NAMESPACE, STREAM_ERRORS, Server, TestResult,
};

fn auth(client: &mut Client, mechanism: &str, first: &str) -> TestResult {
    client.send(&format!(
        "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{}</auth>",
        STANDARD.encode(first)
    ))
}

fn challenge(client: &mut Client) -> TestResult<String> {
    let reply = client.receive()?;
    reply.assert_name(SASL_NAMESPACE, "challenge");
    Ok(String::from_utf8(STANDARD.decode(reply.text)?)?)
}

fn response(client: &mut Client, value: &str) -> TestResult {
    client.send(&format!(
        "<response xmlns='{SASL_NAMESPACE}'>{}</response>",
        STANDARD.encode(value)
    ))
}

fn failure(client: &mut Client, condition: &str) -> TestResult {
    let reply = client.receive()?;
    reply.assert_name(SASL_NAMESPACE, "failure");
    reply.child(SASL_NAMESPACE, condition)?;
    Ok(())
}

#[test]
fn scram_hashes_and_both_channel_bindings_authenticate_and_allow_binding() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for hash in ["SCRAM-SHA-256", "SCRAM-SHA-1"] {
        for binding in [None, Some("tls-exporter"), Some("tls-server-end-point")] {
            let mechanism = if binding.is_some() {
                format!("{hash}-PLUS")
            } else {
                hash.into()
            };
            let mut client = Client::secure(&server)?;
            client
                .scram("Alice", "pencil", &mechanism, binding)?
                .assert_name(SASL_NAMESPACE, "success");
            let mut client = client.restart();
            let header = client.open_with(OPEN)?;
            assert_eq!(header.attribute("from"), Some("localhost"));
            let features = client.features()?;
            assert_eq!(features.children.len(), 1);
            features.child(BIND_NAMESPACE, "bind")?;
            assert_eq!(client.bind(Some("desk"))?, "alice@localhost/desk");
            client.barrier()?;
            client.close()?;
        }
    }
    Ok(())
}

#[test]
fn configured_mechanisms_control_the_offer_and_reject_disabled_mechanisms() -> TestResult {
    for (mechanism, plus) in [("SCRAM-SHA-256", false), ("SCRAM-SHA-1-PLUS", true)] {
        let server = Server::configured(&format!("auth_mechanisms = ['{mechanism}']"), "")?;
        let mut client = Client::encrypted(&server)?;
        let features = client.open()?;
        let mechanisms = features.child(SASL_NAMESPACE, "mechanisms")?;
        assert_eq!(mechanisms.children.len(), 1);
        assert_eq!(mechanisms.children[0].text, mechanism);
        assert_eq!(
            features
                .children
                .iter()
                .any(|child| child.name == "sasl-channel-binding"),
            plus
        );
        auth(
            &mut client,
            if plus {
                "SCRAM-SHA-256"
            } else {
                "SCRAM-SHA-256-PLUS"
            },
            "n,,n=alice,r=nonce",
        )?;
        failure(&mut client, "invalid-mechanism")?;
        if !plus {
            auth(&mut client, mechanism, "y,,n=alice,r=nonce")?;
            challenge(&mut client)?;
            client.send(&format!("<abort xmlns='{SASL_NAMESPACE}'/>"))?;
            failure(&mut client, "aborted")?;
        }
        client.close()?;
    }
    Ok(())
}

#[test]
fn malformed_sasl_requests_return_standard_conditions() -> TestResult {
    let server = Server::start()?;
    for (request, condition) in [
        (
            format!("<auth xmlns='{SASL_NAMESPACE}'/>"),
            "malformed-request",
        ),
        (
            format!("<auth xmlns='{SASL_NAMESPACE}' mechanism='PLAIN'/>"),
            "invalid-mechanism",
        ),
        (
            format!("<auth xmlns='{SASL_NAMESPACE}' mechanism='SCRAM-SHA-256' extra='1'/>"),
            "malformed-request",
        ),
        (
            format!("<auth xmlns='{SASL_NAMESPACE}' mechanism='SCRAM-SHA-256'><child/></auth>"),
            "malformed-request",
        ),
        (
            format!("<auth xmlns='{SASL_NAMESPACE}' mechanism='SCRAM-SHA-256'>!</auth>"),
            "incorrect-encoding",
        ),
        (format!("<abort xmlns='{SASL_NAMESPACE}'/>"), "aborted"),
    ] {
        let mut client = Client::secure(&server)?;
        client.send(&request)?;
        failure(&mut client, condition)?;
        client.close()?;
    }
    for (mechanism, initial) in [
        ("SCRAM-SHA-256-PLUS", "p=unknown-binding,,n=alice,r=nonce"),
        ("SCRAM-SHA-256", "invalid"),
    ] {
        let mut client = Client::secure(&server)?;
        auth(&mut client, mechanism, initial)?;
        failure(&mut client, "malformed-request")?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn wrong_password_and_missing_account_have_the_same_failure_and_attempt_limit() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for username in ["alice", "missing"] {
        let mut client = Client::secure(&server)?;
        for _ in 0..3 {
            let reply = client.scram(username, "wrong", "SCRAM-SHA-256", None)?;
            reply.assert_name(SASL_NAMESPACE, "failure");
            reply.child(SASL_NAMESPACE, "not-authorized")?;
        }
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}

#[test]
fn malformed_final_does_not_disclose_account_existence() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for username in ["alice", "missing"] {
        let mut client = Client::secure(&server)?;
        auth(
            &mut client,
            "SCRAM-SHA-256",
            &format!("n,,n={username},r=nonce"),
        )?;
        challenge(&mut client)?;
        response(&mut client, "x=1")?;
        failure(&mut client, "malformed-request")?;
        client.close()?;
    }
    Ok(())
}

#[test]
fn normalized_identities_have_stable_scram_challenge_parameters() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    for usernames in [["Alice", "alice"], ["Missing", "missing"]] {
        let mut client = Client::secure(&server)?;
        let mut parameters = None;
        for username in usernames {
            auth(
                &mut client,
                "SCRAM-SHA-256",
                &format!("n,,n={username},r=nonce"),
            )?;
            let challenge = challenge(&mut client)?;
            let current = challenge
                .split_once(",s=")
                .ok_or("missing challenge salt")?
                .1;
            if let Some(previous) = parameters.as_deref() {
                assert_eq!(current, previous);
            } else {
                parameters = Some(current.to_owned());
            }
            client.send(&format!("<abort xmlns='{SASL_NAMESPACE}'/>"))?;
            failure(&mut client, "aborted")?;
        }
        client.close()?;
    }
    Ok(())
}

#[test]
fn both_challenge_phases_allow_retries_until_three_failed_attempts() -> TestResult {
    let server = Server::start()?;
    for empty_initial in [false, true] {
        for (request, condition) in [
            (format!("<abort xmlns='{SASL_NAMESPACE}'/>"), "aborted"),
            (
                format!("<response xmlns='{SASL_NAMESPACE}'>!</response>"),
                "incorrect-encoding",
            ),
        ] {
            let mut client = Client::secure(&server)?;
            for _ in 0..3 {
                auth(
                    &mut client,
                    "SCRAM-SHA-256",
                    if empty_initial {
                        ""
                    } else {
                        "n,,n=missing,r=nonce"
                    },
                )?;
                let first = challenge(&mut client)?;
                assert_eq!(first.is_empty(), empty_initial);
                client.send(&request)?;
                failure(&mut client, condition)?;
            }
            client.expect_stream_error("policy-violation")?;
        }
    }
    Ok(())
}

#[test]
fn replacement_auth_discards_both_pending_challenges_and_counts_toward_the_cap() -> TestResult {
    let server = Server::start()?;
    for empty_initial in [false, true] {
        let mut client = Client::secure(&server)?;
        auth(
            &mut client,
            "SCRAM-SHA-256",
            if empty_initial {
                ""
            } else {
                "n,,n=discarded,r=first"
            },
        )?;
        challenge(&mut client)?;
        for nonce in ["second", "third"] {
            auth(
                &mut client,
                "SCRAM-SHA-256",
                &format!("n,,n=missing,r={nonce}"),
            )?;
            assert!(challenge(&mut client)?.starts_with(&format!("r={nonce}")));
        }
        auth(&mut client, "SCRAM-SHA-256", "n,,n=missing,r=fourth")?;
        client.expect_stream_error("policy-violation")?;
    }
    Ok(())
}

#[test]
fn protected_from_must_match_the_authenticated_account() -> TestResult {
    let server = Server::start()?;
    server.create_account("alice", "pencil")?;
    let mut client = Client::encrypted(&server)?;
    client.open_with(&OPEN.replace("to='localhost'", "from='bob@localhost' to='localhost'"))?;
    client.features()?;
    let reply = client.scram("alice", "pencil", "SCRAM-SHA-256", None)?;
    reply.assert_name(STREAM_NAMESPACE, "error");
    reply.child(STREAM_ERRORS, "invalid-from")?;
    client.expect_end()
}
