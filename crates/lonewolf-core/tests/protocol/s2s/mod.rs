// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, atomic::Ordering};
use std::thread;

use parking_lot::Mutex as PlMutex;

use super::support::federation::{FederatedPair, PairOptions, ProcessCompletions};
use super::support::{C2sSuite, PASSWORD, TestResult};

#[test]
fn two_servers_exchange_a_chat_message() -> TestResult {
    let completion = Arc::new(PlMutex::new(ProcessCompletions::default()));
    let dns_join = Arc::new(PlMutex::new(None));
    let failure = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            b_extra_toml: "[invalid-configuration]\nvalue=true".into(),
            completion: Some(Arc::clone(&completion)),
            dns_join: Some(Arc::clone(&dns_join)),
            ..PairOptions::default()
        },
    );
    failure
        .err()
        .ok_or("partial startup unexpectedly succeeded")?;
    {
        let receipt = completion.lock();
        assert_eq!(receipt.spawned.len(), 2, "{receipt:?}");
        assert_eq!(receipt.reaped.len(), 2, "{receipt:?}");
        assert_eq!(receipt.ready.len(), 1, "{receipt:?}");
        assert!(
            receipt
                .reaped
                .iter()
                .any(|(_, status)| status.code() == Some(101)),
            "{receipt:?}"
        );
        for pid in &receipt.spawned {
            assert!(
                receipt.reaped.iter().any(|(reaped, _)| reaped == pid),
                "{receipt:?}"
            );
        }
    }
    assert!(
        dns_join
            .lock()
            .as_ref()
            .ok_or("missing DNS receipt")?
            .load(Ordering::Acquire)
    );
    let mut pair = FederatedPair::start(
        "a.test",
        "b.test",
        PairOptions {
            a_extensions: "'roster'".into(),
            b_extensions: "'roster'".into(),
            ..PairOptions::default()
        },
    )?;
    pair.a.create_account("alice", PASSWORD)?;
    pair.b.create_account("bob", PASSWORD)?;
    let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
    let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
    alice
        .send("<message type='chat' to='bob@b.test/phone'><body>federated chat</body></message>")?;
    let message = bob.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
    assert_eq!(message.attribute("to"), Some("bob@b.test/phone"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "federated chat"
    );
    pair.a.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"success\"} 1",
    )?;
    pair.b.wait_for_metric(
        "lonewolf_s2s_authentications_total{direction=\"inbound\",outcome=\"success\"} 1",
    )?;
    pair.a
        .wait_for_metric("lonewolf_s2s_dns_resolutions_total{outcome=\"srv\"} 1")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_connections_accepted_total{listener=\"0\"} 1")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_outbound_queued_stanzas 0")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_outbound_queued_bytes 0")?;
    pair.a
        .wait_for_metric("lonewolf_s2s_outbound_links{state=\"ready\"} 1")?;
    for (suite, direction) in [(&pair.a, "outbound"), (&pair.b, "inbound")] {
        for metric in ["received_bytes_total", "sent_bytes_total"] {
            let name = format!("lonewolf_s2s_{metric}{{direction=\"{direction}\"}}");
            suite.wait_for_metrics(&name, |body| {
                sample(body, &name).is_ok_and(|value| value > 0)
            })?;
        }
    }
    assert_eq!(
        pair.dns.query_count(
            "_xmpp-server._tcp.b.test",
            hickory_proto::rr::RecordType::SRV
        ),
        1
    );
    validate_fixture_material(&pair.ca, &mut pair.dns, pair.a.fixture_path())?;
    super::support::federation::subscribe_mutually(
        &mut alice,
        "alice@a.test",
        &mut bob,
        "bob@b.test",
    )?;
    alice.send("<presence type='unavailable'/>")?;
    alice.expect_xml("<presence xmlns='jabber:client' from='alice@a.test/desk' to='alice@a.test' type='unavailable'/>")?;
    bob.expect_xml("<presence xmlns='jabber:client' from='alice@a.test/desk' to='bob@b.test' type='unavailable' xml:lang='en'/>")?;
    alice.close()?;
    bob.close()?;
    pair.a.stop()?;
    pair.b
        .wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    pair.b
        .wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    pair.b
        .wait_for_metrics("closed authenticated inbound stream", |body| {
            body.lines()
                .filter(|line| {
                    line.starts_with("lonewolf_s2s_streams_closed_total{direction=\"inbound\",")
                })
                .filter_map(|line| line.rsplit_once(' ')?.1.parse::<u64>().ok())
                .sum::<u64>()
                == 1
        })?;
    pair.stop()?;

    drop(pair);

    let outcomes = thread::scope(|scope| {
        let (start, ready) = async_channel::bounded::<()>(1);
        let mut workers = Vec::with_capacity(4);
        for index in 0..4 {
            let ready = ready.clone();
            workers.push(scope.spawn(move || {
                let _ = ready.recv_blocking();
                (|| -> TestResult {
                    if index % 2 == 0 {
                        let completion = Arc::new(PlMutex::new(ProcessCompletions::default()));
                        let dns_join = Arc::new(PlMutex::new(None));
                        let mut pair = FederatedPair::start("a.test", "b.test", PairOptions {
                            completion: Some(Arc::clone(&completion)),
                            dns_join: Some(Arc::clone(&dns_join)),
                            ..PairOptions::default()
                        })?;
                        pair.a.create_account("alice", PASSWORD)?;
                        pair.b.create_account("bob", PASSWORD)?;
                        let mut alice = pair.a.connect("alice", PASSWORD, "desk")?;
                        let mut bob = pair.b.connect("bob", PASSWORD, "phone")?;
                        alice.send("<message type='chat' to='bob@b.test/phone'><body>concurrent pair</body></message>")?;
                        let message = bob.receive()?;
                        message.assert_name("jabber:client", "message");
                        assert_eq!(message.attribute("from"), Some("alice@a.test/desk"));
                        assert_eq!(message.child("jabber:client", "body")?.text, "concurrent pair");
                        alice.close()?;
                        bob.close()?;
                        pair.stop()?;
                        drop(pair);
                        let receipt = completion.lock();
                        assert_eq!(receipt.spawned.len(), 2, "{receipt:?}");
                        assert_eq!(receipt.reaped.len(), 2, "{receipt:?}");
                        assert!(receipt.reaped.iter().all(|(_, status)| status.success()), "{receipt:?}");
                        assert!(dns_join.lock().as_ref().ok_or("missing DNS receipt")?.load(Ordering::Acquire));
                    } else {
                        let mut suite = C2sSuite::start()?;
                        suite.create_account("alice", PASSWORD)?;
                        suite.create_account("bob", PASSWORD)?;
                        let mut alice = suite.connect("alice", PASSWORD, "desk")?;
                        let mut bob = suite.connect("bob", PASSWORD, "phone")?;
                        alice.send("<message type='chat' to='bob@localhost/phone'><body>concurrent singleton</body></message>")?;
                        let message = bob.receive()?;
                        message.assert_name("jabber:client", "message");
                        assert_eq!(message.attribute("from"), Some("alice@localhost/desk"));
                        assert_eq!(message.child("jabber:client", "body")?.text, "concurrent singleton");
                        alice.close()?;
                        bob.close()?;
                        suite.stop()?;
                    }
                    Ok(())
                })().map_err(|error|error.to_string())
            }));
        }
        drop(start);
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    for outcome in outcomes {
        outcome.map_err(|_| "concurrent federation workflow panicked")??;
    }
    raw_peer_workflow()?;
    Ok(())
}

fn sample(body: &str, name: &str) -> TestResult<u64> {
    Ok(body
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .ok_or_else(|| format!("missing {name}: {body}"))?
        .parse()?)
}

fn raw_peer_workflow() -> TestResult {
    use super::support::federation::{
        FakeDns, FederatedHost, FederationCa,
        peer::{self, RawS2sListener, RawS2sPeer},
    };
    let directory = tempfile::tempdir()?;
    let ca = Arc::new(FederationCa::new(directory.path())?);
    let mut dns = FakeDns::start()?;
    let listener = RawS2sListener::bind()?;
    dns.srv(
        "peer.test",
        &[(0, 0, listener.address()?.port(), "server.peer.test")],
    );
    dns.a("server.peer.test", std::net::Ipv4Addr::LOCALHOST);
    dns.aaaa("server.peer.test", std::net::Ipv6Addr::LOCALHOST);
    let key = ca.server(directory.path(), "peer", &["peer.test"])?;
    let client_config = peer::client_config(&ca, Arc::clone(&key))?;
    let server_config = peer::server_config(&ca, key, "local.test")?;
    let mut suite = C2sSuite::federated(FederatedHost {
        domain: "local.test".into(),
        enabled: Some(true),
        federation: None,
        extensions: String::new(),
        extra_toml: String::new(),
        ca: Arc::clone(&ca),
        dns: dns.address(),
        completion: None,
    })?;
    suite.create_account("alice", PASSWORD)?;
    suite.change_password("alice", super::support::NEW_PASSWORD)?;
    let mut alice = suite.connect("alice", super::support::NEW_PASSWORD, "desk")?;
    let mut raw = RawS2sPeer::connect(suite.s2s_addresses()?[0], "peer.test", "local.test")?;
    raw.expect_starttls_features()?;
    let mut raw = raw.start_tls(Arc::clone(&client_config))?;
    raw.expect_external_offered()?;
    raw.auth_external(Some("peer.test"))?;
    raw.expect_sasl_success()?;
    let mut raw = raw.restart("peer.test", "local.test")?;
    raw.send("<message type='chat' from='bob@peer.test/phone' to='alice@local.test/desk'><body>scripted inbound</body></message>")?;
    let message = alice.receive()?;
    message.assert_name("jabber:client", "message");
    assert_eq!(message.attribute("from"), Some("bob@peer.test/phone"));
    assert_eq!(
        message.child("jabber:client", "body")?.text,
        "scripted inbound"
    );
    alice.send(
        "<message type='chat' to='bob@peer.test/phone'><body>scripted outbound</body></message>",
    )?;
    let mut receiving = listener.accept("peer.test", "local.test", server_config, true)?;
    let message = receiving.receive()?;
    message.assert_name("jabber:server", "message");
    assert_eq!(message.attribute("from"), Some("alice@local.test/desk"));
    assert_eq!(
        message.child("jabber:server", "body")?.text,
        "scripted outbound"
    );
    raw.close()?;
    raw.expect_eof()?;
    receiving.close()?;
    suite.wait_for_metric(
        "lonewolf_s2s_streams_closed_total{direction=\"inbound\",outcome=\"stream_end\"} 1",
    )?;
    suite.wait_for_metric("lonewolf_s2s_connections{direction=\"inbound\"} 0")?;
    suite.wait_for_metric("lonewolf_s2s_streams{direction=\"inbound\"} 0")?;
    let mut raw = RawS2sPeer::connect(suite.s2s_addresses()?[0], "peer.test", "local.test")?;
    raw.expect_starttls_features()?;
    raw.send("<message from='bob@peer.test' to='alice@local.test'/>")?;
    raw.expect_stream_error("not-authorized")?;
    alice.close()?;
    suite.delete_account("alice")?;
    suite.stop()?;
    dns.stop()?;
    Ok(())
}

fn validate_fixture_material(
    ca: &super::support::federation::FederationCa,
    dns: &mut super::support::federation::FakeDns,
    directory: &std::path::Path,
) -> TestResult {
    for key in [
        ca.client_auth_only(directory, "peer.test")?,
        ca.without_eku(directory, "peer.test")?,
        ca.wrong_name(directory, "peer.test")?,
        ca.expired(directory, "peer.test")?,
        ca.short_lived(directory, "peer.test", 60)?,
        ca.srv_id(directory, "peer.test")?,
        ca.xmpp_addr(directory, "peer.test")?,
    ] {
        assert_eq!(key.cert.len(), 1);
        key.keys_match()?;
    }
    let untrusted_directory = tempfile::tempdir()?;
    let untrusted = super::support::federation::FederationCa::new(untrusted_directory.path())?;
    assert_ne!(
        std::fs::read(ca.trust_anchors_path())?,
        std::fs::read(untrusted.trust_anchors_path())?
    );
    dns.nxdomain("missing.test");
    dns.servfail("failed.test");
    dns.no_service("unavailable.test");
    dns.drop_queries("dropped.test");
    dns.a("mutable.test", std::net::Ipv4Addr::LOCALHOST);
    for tcp in [false, true] {
        for (name, kind, code) in [
            (
                "missing.test",
                hickory_proto::rr::RecordType::A,
                hickory_proto::op::ResponseCode::NXDomain,
            ),
            (
                "failed.test",
                hickory_proto::rr::RecordType::AAAA,
                hickory_proto::op::ResponseCode::ServFail,
            ),
            (
                "_xmpp-server._tcp.unavailable.test",
                hickory_proto::rr::RecordType::SRV,
                hickory_proto::op::ResponseCode::NoError,
            ),
            (
                "mutable.test",
                hickory_proto::rr::RecordType::A,
                hickory_proto::op::ResponseCode::NoError,
            ),
        ] {
            let answer = dns_query(dns.address(), name, kind, tcp)?;
            assert_eq!(answer.metadata.response_code, code);
            if name.starts_with("_xmpp") {
                assert!(answer.answers.iter().any(|record|matches!(&record.data,hickory_proto::rr::RData::SRV(srv) if srv.target.is_root())));
            }
            assert_eq!(dns.query_count(name, kind), if tcp { 2 } else { 1 });
        }
    }
    dns.a("mutable.test", std::net::Ipv4Addr::new(127, 0, 0, 2));
    let answer = dns_query(
        dns.address(),
        "mutable.test",
        hickory_proto::rr::RecordType::A,
        false,
    )?;
    assert!(answer.answers.iter().any(|record|matches!(&record.data,hickory_proto::rr::RData::A(address) if address.0==std::net::Ipv4Addr::new(127,0,0,2))));
    Ok(())
}
fn dns_query(
    address: std::net::SocketAddr,
    name: &str,
    kind: hickory_proto::rr::RecordType,
    tcp: bool,
) -> TestResult<hickory_proto::op::Message> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use std::io::{Read, Write};
    let mut query = Message::new(123, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        hickory_proto::rr::Name::from_ascii(name)?,
        kind,
    ));
    let bytes = query.to_vec()?;
    let response = if tcp {
        let mut stream =
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(1)))?;
        stream.write_all(&(bytes.len() as u16).to_be_bytes())?;
        stream.write_all(&bytes)?;
        let mut length = [0; 2];
        stream.read_exact(&mut length)?;
        let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut response)?;
        response
    } else {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        socket.send_to(&bytes, address)?;
        let mut response = vec![0; 65535];
        let length = socket.recv(&mut response)?;
        response.truncate(length);
        response
    };
    Ok(Message::from_vec(&response)?)
}
