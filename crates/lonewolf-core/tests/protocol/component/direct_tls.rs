// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConnection, SupportedProtocolVersion};

use crate::support::component::{ComponentClient, NAMESPACE, TlsComponentClient, tcp};
use crate::support::tls::{self, ClientCertificates};
use crate::support::{C2sSuite, PASSWORD, TestResult};

const DOMAIN: &str = "muc.localhost";
const SECRET: &str = "component-test-secret-0001";
const CONFIG: &str =
    "tls_mode='direct'\n[components.domains.'muc.localhost']\nsecret='component-test-secret-0001'";

fn authenticate(component: &mut TlsComponentClient) -> TestResult {
    let header = component.open(DOMAIN, Some("1.0"))?;
    assert_eq!(header.from.as_deref(), Some(DOMAIN));
    assert_eq!(header.namespace, NAMESPACE);
    assert!(header.version.is_none());
    component.send_handshake_for(SECRET, &header.id)?;
    component.expect_handshake()
}

fn close_tls(component: &mut TlsComponentClient) -> TestResult {
    component.send("</stream:stream>")?;
    component.expect_footer()?;
    component.expect_tls_close()
}

fn socket_bytes(suite: &C2sSuite, component: &TlsComponentClient) -> TestResult {
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let bytes = component.counters.snapshot();
    suite.wait_for_metric(&format!(
        "lonewolf_component_received_bytes_total {}",
        bytes.written
    ))?;
    suite.wait_for_metric(&format!(
        "lonewolf_component_sent_bytes_total {}",
        bytes.read
    ))?;
    Ok(())
}

fn exchange(version: &'static SupportedProtocolVersion) -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    suite.create_account("alice", PASSWORD)?;
    let mut component = TlsComponentClient::connect_tls(
        suite.component_address(0)?,
        suite.tls_with_versions(&[version])?,
        ServerName::try_from("localhost")?,
    )?;
    assert_eq!(
        component.tls_connection().protocol_version(),
        Some(version.version)
    );
    authenticate(&mut component)?;
    let mut alice = suite.connect("alice", PASSWORD, "desk")?;
    alice.send("<message to='room@muc.localhost/member' type='chat' id='encrypted'><body>private component message</body></message>")?;
    component.expect_xml("<message xmlns='jabber:component:accept' from='alice@localhost/desk' to='room@muc.localhost/member' type='chat' id='encrypted'><body>private component message</body></message>")?;
    component.send("<message from='room@muc.localhost/member' to='alice@localhost/desk' type='chat' id='reply'><body>encrypted reply</body></message>")?;
    alice.expect_xml("<message xmlns='jabber:client' from='room@muc.localhost/member' to='alice@localhost/desk' type='chat' id='reply'><body>encrypted reply</body></message>")?;
    close_tls(&mut component)?;
    socket_bytes(&suite, &component)?;
    for sample in [
        "lonewolf_component_listener_info{listener=\"0\",tls_mode=\"direct\"} 1",
        "lonewolf_component_authentications_total{outcome=\"success\"} 1",
        "lonewolf_component_negotiation_duration_seconds_count 1",
        "lonewolf_component_streams_closed_total{outcome=\"stream_end\"} 1",
        "lonewolf_component_streams 0",
        "lonewolf_component_stanzas_sent_total{kind=\"message\"} 1",
        "lonewolf_component_stanzas_received_total{kind=\"message\"} 1",
    ] {
        suite.wait_for_metric(sample)?;
    }
    alice.close()?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing shutdown receipt")?;
    assert_eq!(state.connections, 0);
    assert_eq!(state.streams, 0);
    assert_eq!(state.authentication_success, 1);
    assert_eq!(state.authentication_total, 1);
    assert_eq!(state.streams_closed_total, 1);
    Ok(())
}

#[test]
fn tls13_authenticates_exchanges_stanzas_and_counts_encrypted_socket_bytes() -> TestResult {
    exchange(&rustls::version::TLS13)
}

#[test]
fn tls12_authenticates_exchanges_stanzas_and_counts_encrypted_socket_bytes() -> TestResult {
    exchange(&rustls::version::TLS12)
}

#[test]
fn absent_sni_uses_default_host_leaf_and_authenticates_the_component_domain() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let expected = CertificateDer::from_pem_file(suite.fixture_path().join("certificate.pem"))?;
    let mut config = (*suite.tls).clone();
    config.enable_sni = false;
    let mut component = TlsComponentClient::connect_tls(
        suite.component_address(0)?,
        Arc::new(config),
        ServerName::try_from("localhost")?,
    )?;
    assert_eq!(
        component
            .tls_connection()
            .peer_certificates()
            .ok_or("missing leaf")?[0],
        expected
    );
    authenticate(&mut component)?;
    close_tls(&mut component)?;
    socket_bytes(&suite, &component)?;
    suite.stop()
}

#[test]
fn sni_selects_another_host_leaf_independently_of_the_component_domain() -> TestResult {
    let mut roots = None;
    let mut suite = C2sSuite::with_components_and_setup(
        CONFIG,
        "[hosts.'other.localhost'.tls]\ncertificate_chain_path='certificate-other.pem'\nprivate_key_path='private-key-other.pem'",
        |directory| {
            roots = Some(tls::configure_host(
                directory,
                "-other",
                &["other.localhost"],
            )?);
            Ok(())
        },
    )?;
    let expected =
        CertificateDer::from_pem_file(suite.fixture_path().join("certificate-other.pem"))?;
    let default = CertificateDer::from_pem_file(suite.fixture_path().join("certificate.pem"))?;
    assert_ne!(expected, default);
    let config = tls::client_config(roots.ok_or("missing host roots")?, rustls::DEFAULT_VERSIONS)?;
    let mut component = TlsComponentClient::connect_tls(
        suite.component_address(0)?,
        Arc::new(config),
        ServerName::try_from("other.localhost")?,
    )?;
    assert_eq!(
        component
            .tls_connection()
            .peer_certificates()
            .ok_or("missing leaf")?[0],
        expected
    );
    authenticate(&mut component)?;
    close_tls(&mut component)?;
    suite.stop()
}

#[derive(Debug)]
struct CertificateRequests(Arc<AtomicUsize>);

impl rustls::client::ResolvesClientCert for CertificateRequests {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn direct_tls_ignores_offered_alpn_and_does_not_request_host_client_certificates() -> TestResult {
    let mut suite = C2sSuite::with_components_and_setup(CONFIG, "", |directory| {
        ClientCertificates::configure(directory)?;
        Ok(())
    })?;
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let requests = Arc::new(AtomicUsize::new(0));
        let mut config = (*suite.tls_with_versions(&[version])?).clone();
        config.alpn_protocols = vec![b"xmpp-client".to_vec(), b"xmpp-server".to_vec()];
        config.client_auth_cert_resolver = Arc::new(CertificateRequests(Arc::clone(&requests)));
        let mut component = TlsComponentClient::connect_tls(
            suite.component_address(0)?,
            Arc::new(config),
            ServerName::try_from("localhost")?,
        )?;
        assert_eq!(component.tls_connection().alpn_protocol(), None);
        authenticate(&mut component)?;
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        close_tls(&mut component)?;
        suite.wait_for_metric("lonewolf_component_connections 0")?;
    }
    suite.stop()
}

fn drain_without_xml(socket: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut reply = Vec::new();
    match socket.read_to_end(&mut reply) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => return Err(error.into()),
    }
    let mut records = reply.as_slice();
    while !records.is_empty() {
        assert!(records.len() >= 5, "incomplete TLS alert: {records:?}");
        assert_eq!(records[0], 21, "only TLS alerts may precede this failure");
        assert_eq!(records[1], 3);
        let length = usize::from(u16::from_be_bytes([records[3], records[4]]));
        assert!(length <= records.len() - 5);
        records = &records[5 + length..];
    }
    Ok(reply)
}

fn rejected_tls(suite: &C2sSuite, sni: &'static str) -> TestResult {
    let mut connection = ClientConnection::new(Arc::clone(&suite.tls), ServerName::try_from(sni)?)?;
    let mut socket = tcp(suite.component_address(0)?)?;
    while connection.wants_write() {
        connection.write_tls(&mut socket)?;
    }
    let reply = drain_without_xml(&mut socket)?;
    if !reply.is_empty() {
        connection.read_tls(&mut reply.as_slice())?;
        assert!(connection.process_new_packets().is_err());
    }
    assert!(connection.is_handshaking());
    Ok(())
}

#[test]
fn unknown_and_component_domain_sni_fail_tls_without_xml_or_authentication() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    for (index, sni) in ["unknown.example", DOMAIN].into_iter().enumerate() {
        rejected_tls(&suite, sni)?;
        suite.wait_for_metric(&format!(
            "lonewolf_component_authentications_total{{outcome=\"tls_failure\"}} {}",
            index + 1
        ))?;
        suite.wait_for_metric("lonewolf_component_connections 0")?;
    }
    suite.wait_for_metric("lonewolf_component_negotiation_duration_seconds_count 2")?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing shutdown receipt")?;
    assert_eq!(state.authentication_success, 0);
    assert_eq!(state.authentication_total, 2);
    assert_eq!(state.streams_closed_total, 0);
    assert_eq!(state.connections, 0);
    assert_eq!(state.streams, 0);
    Ok(())
}

#[test]
fn plaintext_xml_on_a_direct_listener_fails_tls_without_xml() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut socket = tcp(suite.component_address(0)?)?;
    socket.write_all(b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:component:accept' to='muc.localhost'>")?;
    drain_without_xml(&mut socket)?;
    suite.wait_for_metric("lonewolf_component_authentications_total{outcome=\"tls_failure\"} 1")?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    suite.wait_for_metric("lonewolf_component_negotiation_duration_seconds_count 1")?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing shutdown receipt")?;
    assert_eq!(state.authentication_total, 1);
    assert_eq!(state.authentication_success, 0);
    assert_eq!(state.streams_closed_total, 0);
    Ok(())
}

#[test]
fn mixed_listener_readiness_addresses_preserve_plain_then_direct_configuration_order() -> TestResult
{
    let mut suite = C2sSuite::with_components(&format!(
        "tls_mode='none'\n[[components.listeners]]\naddress='127.0.0.1:0'\n{CONFIG}"
    ))?;
    let plain_address = suite.component_address(0)?;
    let direct_address = suite.component_address(1)?;
    assert_ne!(plain_address, direct_address);
    assert_ne!(plain_address.port(), 0);
    assert_ne!(direct_address.port(), 0);
    let mut plain = ComponentClient::authenticated(&suite, DOMAIN, SECRET)?;
    plain.close()?;
    suite.wait_for_metric("lonewolf_component_connections 0")?;
    let mut direct = TlsComponentClient::connect_tls(
        direct_address,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    authenticate(&mut direct)?;
    close_tls(&mut direct)?;
    for sample in [
        "lonewolf_component_listener_info{listener=\"0\",tls_mode=\"none\"} 1",
        "lonewolf_component_listener_info{listener=\"1\",tls_mode=\"direct\"} 1",
        "lonewolf_component_authentications_total{outcome=\"success\"} 2",
        "lonewolf_component_connections 0",
    ] {
        suite.wait_for_metric(sample)?;
    }
    suite.stop()
}

fn incoming_xml_throttles(metrics: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "lonewolf_component_rate_limited_total{limit=\"incoming_xml_per_connection\"} ",
            )
            .and_then(|value| value.parse().ok())
        })
        .unwrap_or(0)
}

fn enter_xml_reader_without_a_header(
    suite: &C2sSuite,
    component: &mut TlsComponentClient,
) -> TestResult {
    let baseline = incoming_xml_throttles(&suite.scrape_metrics()?);
    component.send_raw(&" ".repeat(256))?;
    suite.wait_for_metrics(
        "the sole component entered the XML byte limiter",
        |metrics| incoming_xml_throttles(metrics) > baseline,
    )?;
    Ok(())
}

fn rejected_inside_tls(component: &mut TlsComponentClient, condition: &str) -> TestResult {
    component.expect_stream_error(condition)?;
    component.expect_footer()?;
    component.send("</stream:stream>")?;
    component.expect_tls_close()
}

fn timeout_accounting(suite: &C2sSuite) -> TestResult {
    for sample in [
        "lonewolf_component_authentications_total{outcome=\"timeout\"} 1",
        "lonewolf_component_negotiation_duration_seconds_count 1",
        "lonewolf_component_connections 0",
        "lonewolf_component_streams 0",
    ] {
        suite.wait_for_metric(sample)?;
    }
    Ok(())
}

#[test]
fn silent_direct_tcp_peer_times_out_without_tls_or_xml_and_records_one_authentication() -> TestResult
{
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nnegotiation_timeout_secs=1"
    ))?;
    let mut socket = tcp(suite.component_address(0)?)?;
    suite.wait_for_metric("lonewolf_component_connections 1")?;
    assert!(drain_without_xml(&mut socket)?.is_empty());
    timeout_accounting(&suite)?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing shutdown receipt")?;
    assert_eq!(
        state,
        lonewolf_core::test_support::ComponentShutdownState {
            connections: 0,
            streams: 0,
            authentication_success: 0,
            authentication_shutdown: 0,
            authentication_total: 1,
            streams_closed_shutdown: 0,
            streams_closed_total: 0,
        }
    );
    Ok(())
}

#[test]
fn tls_without_an_xml_header_times_out_inside_tls_and_sends_close_notify() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nnegotiation_timeout_secs=1\nincoming_xml_per_connection={{bytes_per_second=16,burst_bytes=256}}"
    ))?;
    let mut component = TlsComponentClient::connect_tls(
        suite.component_address(0)?,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    enter_xml_reader_without_a_header(&suite, &mut component)?;
    let header = component.open_with("")?;
    assert!(header.from.is_none());
    assert_eq!(header.namespace, NAMESPACE);
    assert!(header.version.is_none());
    rejected_inside_tls(&mut component, "connection-timeout")?;
    timeout_accounting(&suite)?;
    socket_bytes(&suite, &component)?;
    let state = suite
        .stop_with_component_state()?
        .ok_or("missing shutdown receipt")?;
    assert_eq!(
        state,
        lonewolf_core::test_support::ComponentShutdownState {
            connections: 0,
            streams: 0,
            authentication_success: 0,
            authentication_shutdown: 0,
            authentication_total: 1,
            streams_closed_shutdown: 0,
            streams_closed_total: 0,
        }
    );
    Ok(())
}

#[test]
fn shutdown_before_client_hello_aborts_without_xml_or_stream_accounting() -> TestResult {
    let mut suite = C2sSuite::with_components(CONFIG)?;
    let mut socket = tcp(suite.component_address(0)?)?;
    suite.wait_for_metric("lonewolf_component_connections 1")?;
    let state = std::thread::scope(|scope| -> TestResult<_> {
        let peer = scope.spawn(move || -> Result<(), String> {
            let reply = drain_without_xml(&mut socket).map_err(|error| error.to_string())?;
            assert!(reply.is_empty());
            Ok(())
        });
        let state = suite
            .stop_with_component_state()?
            .ok_or("missing shutdown receipt")?;
        peer.join()
            .map_err(|_| "TLS shutdown reader panicked")?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        Ok(state)
    })?;
    assert_eq!(
        state,
        lonewolf_core::test_support::ComponentShutdownState {
            connections: 0,
            streams: 0,
            authentication_success: 0,
            authentication_shutdown: 1,
            authentication_total: 1,
            streams_closed_shutdown: 0,
            streams_closed_total: 0,
        }
    );
    Ok(())
}

#[test]
fn shutdown_after_tls_preserves_xml_phase_and_closes_each_connection_once() -> TestResult {
    let mut suite = C2sSuite::with_components(&format!(
        "{CONFIG}\n[limits.components]\nincoming_xml_per_connection={{bytes_per_second=16,burst_bytes=256}}"
    ))?;
    let address = suite.component_address(0)?;
    let mut before_header = TlsComponentClient::connect_tls(
        address,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    enter_xml_reader_without_a_header(&suite, &mut before_header)?;
    let mut before_auth = TlsComponentClient::connect_tls(
        address,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    let header = before_auth.open(DOMAIN, None)?;
    assert_eq!(header.from.as_deref(), Some(DOMAIN));
    let mut authenticated = TlsComponentClient::connect_tls(
        address,
        Arc::clone(&suite.tls),
        ServerName::try_from("localhost")?,
    )?;
    authenticate(&mut authenticated)?;
    suite.wait_for_metric("lonewolf_component_connections 3")?;
    suite.wait_for_metric("lonewolf_component_streams 1")?;
    let state = std::thread::scope(|scope| -> TestResult<_> {
        let peers = scope.spawn(move || -> Result<(), String> {
            let header = before_header
                .open_with("")
                .map_err(|error| error.to_string())?;
            assert!(header.from.is_none());
            assert_eq!(header.namespace, NAMESPACE);
            assert!(header.version.is_none());
            for component in [&mut before_header, &mut before_auth, &mut authenticated] {
                rejected_inside_tls(component, "system-shutdown")
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        });
        let state = suite
            .stop_with_component_state()?
            .ok_or("missing shutdown receipt")?;
        peers
            .join()
            .map_err(|_| "TLS shutdown readers panicked")?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        Ok(state)
    })?;
    assert_eq!(
        state,
        lonewolf_core::test_support::ComponentShutdownState {
            connections: 0,
            streams: 0,
            authentication_success: 1,
            authentication_shutdown: 2,
            authentication_total: 3,
            streams_closed_shutdown: 1,
            streams_closed_total: 1,
        }
    );
    Ok(())
}
