// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::tls::with_client_certificate;
use rustls::pki_types::ServerName;
use std::io::{self, Read};
use std::sync::Arc;

fn rejected(phase: &str, mut client: Client) -> TestResult {
    let error = match client.complete_tls() {
        Err(error) => error,
        Ok(()) => match client.transport().read(&mut [0; 1]) {
            Err(error) => error,
            Ok(count) => {
                return Err(
                    format!("{phase}: TLS read returned {count} bytes after handshake").into(),
                );
            }
        },
    };
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof, "{error:?}");
    Ok(())
}

#[test]
fn direct_tls_two_sni_policies_apply_crl_replacement_and_expiry_without_crossing_hosts()
-> TestResult {
    let mut fixture = super::hosts::fixture()?;
    fixture.suite.create_account("alice", PASSWORD)?;
    fixture
        .suite
        .create_account_jid("alice@bücher.example", PASSWORD)?;
    let short = fixture.first.identity_key(
        &["alice@localhost"],
        time::OffsetDateTime::now_utc() + time::Duration::seconds(8),
    )?;
    let second = fixture.second.identity_key(
        &["alice@bücher.example"],
        time::OffsetDateTime::now_utc() + time::Duration::days(1),
    )?;
    let mut a = Client::direct_tls_with_config(
        fixture.suite.address,
        with_client_certificate(&fixture.suite.tls, Arc::clone(&short)),
        ServerName::try_from("localhost")?,
    )?;
    a.open()?.assert_xml(EXTERNAL_FEATURES)?;
    a.send_external_auth(Some("alice@localhost"))?;
    a.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut a = a.restart();
    a.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(a.bind(Some("short"))?, "alice@localhost/short");
    let mut b = Client::direct_tls_with_config(
        fixture.suite.address,
        with_client_certificate(&fixture.idn_tls, Arc::clone(&second)),
        ServerName::try_from("XN--BCHER-KVA.EXAMPLE")?,
    )?;
    let header = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='bücher.example' version='1.0'>";
    assert_eq!(
        b.open_with(header)?.attribute("from"),
        Some("bücher.example")
    );
    b.features()?.assert_xml(EXTERNAL_FEATURES)?;
    b.send_external_auth(Some("alice@bücher.example"))?;
    b.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut b = b.restart();
    assert_eq!(
        b.open_with(header)?.attribute("from"),
        Some("bücher.example")
    );
    b.features()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(b.bind(Some("isolated"))?, "alice@bücher.example/isolated");
    fixture.first.replace_crl(
        false,
        time::OffsetDateTime::now_utc() + time::Duration::days(2),
    )?;
    let mut replacement = Client::direct_tls_with_config(
        fixture.suite.address,
        with_client_certificate(&fixture.suite.tls, Arc::clone(&fixture.first.trusted)),
        ServerName::try_from("localhost")?,
    )?;
    replacement.open()?.assert_xml(EXTERNAL_FEATURES)?;
    replacement.send_external_auth(Some("alice@localhost"))?;
    replacement.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut replacement = replacement.restart();
    replacement.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(
        replacement.bind(Some("replacement-crl"))?,
        "alice@localhost/replacement-crl"
    );
    replacement.close()?;
    fixture.first.replace_crl(
        true,
        time::OffsetDateTime::now_utc() + time::Duration::days(2),
    )?;
    rejected(
        "revoked",
        Client::direct_tls_with_config(
            fixture.suite.address,
            with_client_certificate(&fixture.suite.tls, Arc::clone(&fixture.first.trusted)),
            ServerName::try_from("localhost")?,
        )?,
    )?;
    b.send("<message to='alice@bücher.example/isolated' type='chat' id='other-policy'><body>Other policy stays valid</body></message>")?;
    b.expect_xml("<message xmlns='jabber:client' from='alice@bücher.example/isolated' to='alice@bücher.example/isolated' type='chat' id='other-policy'><body>Other policy stays valid</body></message>")?;
    a.expect_stream_error("reset")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"bound\",outcome=\"certificate_invalid\"} 1")?;
    fixture.first.replace_crl(
        false,
        time::OffsetDateTime::now_utc() + time::Duration::days(2),
    )?;
    let expired = fixture.first.identity_key(
        &["alice@localhost"],
        time::OffsetDateTime::now_utc() - time::Duration::minutes(1),
    )?;
    rejected(
        "expired",
        Client::direct_tls_with_config(
            fixture.suite.address,
            with_client_certificate(&fixture.suite.tls, expired),
            ServerName::try_from("localhost")?,
        )?,
    )?;
    let path = fixture.suite.fixture_path().join("client-crls.pem");
    for material in [None, Some(b"invalid CRL".as_slice()), Some(b"".as_slice())] {
        match material {
            None => std::fs::remove_file(&path)?,
            Some(bytes) => std::fs::write(&path, bytes)?,
        }
        rejected(
            "runtime",
            Client::direct_tls_with_config(
                fixture.suite.address,
                with_client_certificate(&fixture.suite.tls, Arc::clone(&fixture.first.trusted)),
                ServerName::try_from("localhost")?,
            )?,
        )?;
        let mut password = Client::direct_tls(&fixture.suite)?;
        password.open()?.assert_xml(DEFAULT_FEATURES)?;
        password.authenticate("alice", PASSWORD)?;
        let mut password = password.restart();
        password.open()?.assert_xml(BIND_FEATURES)?;
        assert_eq!(password.bind(Some("password"))?, "alice@localhost/password");
        password.close()?;
    }
    fixture.first.replace_crl(
        false,
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    )?;
    rejected(
        "stale",
        Client::direct_tls_with_config(
            fixture.suite.address,
            with_client_certificate(&fixture.suite.tls, Arc::clone(&fixture.first.trusted)),
            ServerName::try_from("localhost")?,
        )?,
    )?;
    let mut password = Client::direct_tls(&fixture.suite)?;
    password.open()?.assert_xml(DEFAULT_FEATURES)?;
    password.authenticate("alice", PASSWORD)?;
    let mut password = password.restart();
    password.open()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(
        password.bind(Some("after-stale"))?,
        "alice@localhost/after-stale"
    );
    password.close()?;
    b.send("<message to='alice@bücher.example/isolated' type='chat' id='after-stale'><body>Still isolated</body></message>")?;
    b.expect_xml("<message xmlns='jabber:client' from='alice@bücher.example/isolated' to='alice@bücher.example/isolated' type='chat' id='after-stale'><body>Still isolated</body></message>")?;
    let mut fresh_b = Client::direct_tls_with_config(
        fixture.suite.address,
        with_client_certificate(&fixture.idn_tls, second),
        ServerName::try_from("xn--bcher-kva.example")?,
    )?;
    assert_eq!(
        fresh_b.open_with(header)?.attribute("from"),
        Some("bücher.example")
    );
    fresh_b.features()?.assert_xml(EXTERNAL_FEATURES)?;
    fresh_b.send_external_auth(Some("alice@bücher.example"))?;
    fresh_b.expect_xml("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")?;
    let mut fresh_b = fresh_b.restart();
    fresh_b.open_with(header)?;
    fresh_b.features()?.assert_xml(BIND_FEATURES)?;
    assert_eq!(
        fresh_b.bind(Some("fresh-policy"))?,
        "alice@bücher.example/fresh-policy"
    );
    fresh_b.close()?;
    b.close()?;
    fixture.suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"EXTERNAL\",outcome=\"success\"} 4")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_authentications_total{listener=\"0\",mechanism=\"SCRAM-SHA-256\",outcome=\"success\"} 4")?;
    fixture.suite.wait_for_metric("lonewolf_c2s_connections_closed_total{listener=\"0\",phase=\"establishing\",outcome=\"tls_failure\"} 6")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_c2s_unauthenticated_connections 0")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_router_sessions 0")?;
    fixture.suite.stop()
}
