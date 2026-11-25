// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, UNIX_EPOCH};

use super::*;

fn facts(connection_id: u64, remote: &str) -> ConnectionFacts {
    ConnectionFacts {
        connection_id,
        direction: Direction::Inbound,
        local: Arc::from("local.test"),
        remote: Arc::from(remote),
        remote_address: None,
        tls_mode: TlsMode::StartTls,
        tls: TlsSummary {
            version: "TLSv1.3",
            cipher_suite: "TLS13_AES_256_GCM_SHA384",
        },
        certificate_expires_at: UNIX_EPOCH + Duration::from_secs(2_000_000_000),
        traffic: Arc::default(),
    }
}

fn ids(page: &[S2sConnection]) -> Vec<u64> {
    page.iter().map(|entry| entry.connection_id).collect()
}

#[test]
fn pages_follow_connection_id_order_after_the_cursor() {
    let registry = Arc::new(ConnectionRegistry::default());
    let _third = registry.register(facts(30, "peer.test"), false);
    let _first = registry.register(facts(10, "peer.test"), false);
    let _second = registry.register(facts(20, "peer.test"), false);
    let two = NonZeroUsize::MIN.saturating_add(1);

    assert_eq!(ids(&registry.connections(None, None, two)), [10, 20]);
    assert_eq!(ids(&registry.connections(Some(20), None, two)), [30]);
    assert_eq!(ids(&registry.connections(Some(15), None, two)), [20, 30]);
    assert!(registry.connections(Some(u64::MAX), None, two).is_empty());
}

#[test]
fn remote_domain_filter_matches_exactly() {
    let registry = Arc::new(ConnectionRegistry::default());
    let _first = registry.register(facts(1, "peer.test"), false);
    let _child = registry.register(facts(2, "sub.peer.test"), false);
    let _second = registry.register(facts(3, "peer.test"), false);
    let two = NonZeroUsize::MIN.saturating_add(1);

    assert_eq!(
        ids(&registry.connections(None, Some("peer.test"), two)),
        [1, 3]
    );
    assert_eq!(
        ids(&registry.connections(Some(1), Some("peer.test"), NonZeroUsize::MIN)),
        [3]
    );
    assert!(
        registry
            .connections(None, Some("PEER.test"), two)
            .is_empty()
    );
}

#[test]
fn dropping_a_registration_removes_only_its_entry() {
    let registry = Arc::new(ConnectionRegistry::default());
    let first = registry.register(facts(1, "peer.test"), false);
    let _second = registry.register(facts(2, "peer.test"), false);
    let two = NonZeroUsize::MIN.saturating_add(1);

    drop(first);

    assert_eq!(ids(&registry.connections(None, None, two)), [2]);
}

#[test]
fn snapshots_report_traffic_and_uptime_from_the_given_instant() {
    let registry = Arc::new(ConnectionRegistry::default());
    let mut facts = facts(1, "peer.test");
    facts.tls_mode = TlsMode::Direct;
    facts.direction = Direction::Outbound;
    let traffic = Arc::clone(&facts.traffic);
    let _registration = registry.register(facts, true);
    let established = registry.entries.lock()[&1].established;
    traffic.received(73);
    traffic.sent(21);
    traffic.sent(34);

    let duration = Duration::from_secs(90);
    let page = registry.page_at(established + duration, None, None, NonZeroUsize::MIN);
    let entry = &page[0];
    assert_eq!(entry.uptime, duration);
    assert_eq!(entry.bytes_received, 73);
    assert_eq!(entry.bytes_sent, 55);
    assert_eq!(entry.direction, S2sDirection::Outbound);
    assert_eq!(entry.tls_mode, S2sTlsMode::Direct);
    assert!(entry.bidirectional);
}

#[test]
fn tls_summary_names_supported_versions() {
    assert_eq!(tls_version(Some(ProtocolVersion::TLSv1_2)), "TLSv1.2");
    assert_eq!(tls_version(Some(ProtocolVersion::TLSv1_3)), "TLSv1.3");
    assert_eq!(tls_version(Some(ProtocolVersion::TLSv1_1)), "unknown");
    assert_eq!(tls_version(None), "unknown");
}
