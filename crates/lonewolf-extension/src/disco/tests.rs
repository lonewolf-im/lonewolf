// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};

use super::*;
use crate::Extensions;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn server_info_lists_the_hosts_identities_and_features() -> TestResult {
    let mut discovery = Discovery::default();
    let store = Identity {
        category: "store",
        kind: "file",
        name: Some("Files"),
    };
    discovery.add_identity(DiscoScope::Server, store);
    discovery.add_identity(DiscoScope::Server, SERVER_IDENTITY);
    discovery.add_feature(DiscoScope::Server, ITEMS_NAMESPACE);
    discovery.add_feature(DiscoScope::Server, INFO_NAMESPACE);
    discovery.add_identity(DiscoScope::Account, store);
    discovery.add_feature(DiscoScope::Account, "urn:account-only");
    let mut arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
    let element = answer_server(
        Query {
            kind: QueryKind::Info,
            node: None,
        },
        &discovery,
        &mut arena,
    )
    .map_err(|condition| format!("{condition:?}"))?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#info\"><identity category=\"server\" type=\"im\"/><identity category=\"store\" type=\"file\" name=\"Files\"/><feature var=\"http://jabber.org/protocol/disco#info\"/><feature var=\"http://jabber.org/protocol/disco#items\"/></query>"
    );
    Ok(())
}

#[test]
fn server_items_list_service_domains_in_order() -> TestResult {
    let mut discovery = Discovery::default();
    discovery.add_service("b.example");
    discovery.add_service("a.example");
    let mut arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
    let element = answer_server(
        Query {
            kind: QueryKind::Items,
            node: None,
        },
        &discovery,
        &mut arena,
    )
    .map_err(|condition| format!("{condition:?}"))?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#items\"><item jid=\"a.example\"/><item jid=\"b.example\"/></query>"
    );
    Ok(())
}

#[test]
fn server_items_without_services_are_empty() -> TestResult {
    let mut arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
    let element = answer_server(
        Query {
            kind: QueryKind::Items,
            node: None,
        },
        &Discovery::default(),
        &mut arena,
    )
    .map_err(|condition| format!("{condition:?}"))?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#items\"/>"
    );
    Ok(())
}

#[test]
fn server_queries_for_any_node_are_item_not_found() -> TestResult {
    let discovery = Discovery::default();
    let mut arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
    for kind in [QueryKind::Info, QueryKind::Items] {
        for node in ["x", ""] {
            assert!(matches!(
                answer_server(
                    Query {
                        kind,
                        node: Some(node)
                    },
                    &discovery,
                    &mut arena
                ),
                Err(StanzaErrorCondition::ItemNotFound)
            ));
        }
    }
    Ok(())
}

#[test]
fn disco_registers_server_routes_identity_and_features() -> TestResult {
    let mut extensions = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    for factory in crate::builtin() {
        extensions.register_factory(factory)?;
    }
    let registry = extensions.enable_host("example.com", ["disco"])?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        assert!(
            registry
                .iq()
                .find(IqScope::Server, IqRequestType::Get, namespace, "query")
                .is_some()
        );
        assert!(
            registry
                .iq()
                .find(IqScope::Server, IqRequestType::Set, namespace, "query")
                .is_none()
        );
        assert!(
            registry
                .iq()
                .find(IqScope::Account, IqRequestType::Get, namespace, "query")
                .is_none()
        );
    }
    assert_eq!(
        registry.discovery().identities(DiscoScope::Server),
        [SERVER_IDENTITY]
    );
    assert_eq!(
        registry.discovery().features(DiscoScope::Server),
        [INFO_NAMESPACE, ITEMS_NAMESPACE]
    );
    assert!(
        registry
            .discovery()
            .identities(DiscoScope::Account)
            .is_empty()
    );
    assert!(
        registry
            .discovery()
            .features(DiscoScope::Account)
            .is_empty()
    );
    Ok(())
}
