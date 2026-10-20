// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use futures_executor::block_on;
use lonewolf_storage::RedbStorage;
use lonewolf_xmpp::jid::Jid;

use crate::ExtensionFuture;
use crate::delivery::{DeliveryError, SessionLookup};
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
fn disco_registers_routes_identities_and_features() -> TestResult {
    let mut extensions = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    for factory in crate::builtin() {
        extensions.register_factory(factory)?;
    }
    let registry = extensions.enable_host("example.com", ["disco"])?;
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        for scope in [IqScope::Server, IqScope::Account] {
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Get, namespace, "query")
                    .is_some()
            );
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Set, namespace, "query")
                    .is_none()
            );
        }
    }
    assert_eq!(
        registry.discovery().identities(DiscoScope::Server),
        [SERVER_IDENTITY]
    );
    assert_eq!(
        registry.discovery().features(DiscoScope::Server),
        [INFO_NAMESPACE, ITEMS_NAMESPACE]
    );
    assert_eq!(
        registry.discovery().identities(DiscoScope::Account),
        [ACCOUNT_IDENTITY]
    );
    assert_eq!(
        registry.discovery().features(DiscoScope::Account),
        [INFO_NAMESPACE, ITEMS_NAMESPACE]
    );
    Ok(())
}

#[test]
fn account_answers_follow_the_privacy_rules() {
    let cases = [
        (
            QueryKind::Info,
            Requester::Owner,
            [AccountAnswer::Info, AccountAnswer::ItemNotFound],
        ),
        (
            QueryKind::Info,
            Requester::PresenceAuthorized,
            [AccountAnswer::Info, AccountAnswer::ItemNotFound],
        ),
        (
            QueryKind::Info,
            Requester::Other,
            [
                AccountAnswer::ServiceUnavailable,
                AccountAnswer::ServiceUnavailable,
            ],
        ),
        (
            QueryKind::Items,
            Requester::Owner,
            [AccountAnswer::Resources, AccountAnswer::ItemNotFound],
        ),
        (
            QueryKind::Items,
            Requester::PresenceAuthorized,
            [AccountAnswer::Resources, AccountAnswer::ItemNotFound],
        ),
        (
            QueryKind::Items,
            Requester::Other,
            [AccountAnswer::EmptyItems, AccountAnswer::EmptyItems],
        ),
    ];
    for (kind, requester, expected) in cases {
        for (node, expected) in [None, Some("x")].into_iter().zip(expected) {
            assert_eq!(
                account_answer(kind, requester, node),
                expected,
                "{kind:?} {requester:?} {node:?}"
            );
        }
    }
}

#[test]
fn owners_see_every_live_resource_and_contacts_only_available_ones() -> TestResult {
    let resources = [
        BoundResource {
            resource: "desk".into(),
            available: true,
        },
        BoundResource {
            resource: "phone".into(),
            available: false,
        },
    ];
    for (requester, expected) in [
        (
            Requester::Owner,
            "<query xmlns=\"http://jabber.org/protocol/disco#items\"><item jid=\"alice@example.com/desk\"/><item jid=\"alice@example.com/phone\"/></query>",
        ),
        (
            Requester::PresenceAuthorized,
            "<query xmlns=\"http://jabber.org/protocol/disco#items\"><item jid=\"alice@example.com/desk\"/></query>",
        ),
    ] {
        let mut arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
        let element = resource_items("alice@example.com", requester, &resources, &mut arena)?;
        let mut xml = String::new();
        element.resolve(&arena)?.write_xml(&mut xml)?;
        assert_eq!(xml, expected);
    }
    Ok(())
}

struct UnexpectedSessions;

impl SessionLookup for UnexpectedSessions {
    fn resources<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("hidden and missing account queries must not inspect sessions")
    }
}

#[test]
fn missing_accounts_answer_like_hidden_ones() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    let discovery = Discovery::default();
    for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
        for node in [None, Some("x")] {
            let mut request_arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
            let sender = Jid::parse_in("bob@example.com/desk", &mut request_arena)?;
            let target = Jid::parse_in("alice@example.com", &mut request_arena)?;
            let mut builder = Element::builder_in("query", namespace, &mut request_arena)?;
            if let Some(node) = node {
                builder = builder.attribute("node", "", node)?;
            }
            let query = builder.build()?;
            let request = || -> Result<IqRequest<'_, GlobalChunkAllocator>, Box<dyn Error>> {
                Ok(IqRequest {
                    sender: sender.resolve(&request_arena)?,
                    target: target.resolve(&request_arena)?,
                    discovery: &discovery,
                    sessions: &UnexpectedSessions,
                    requester: Some(Requester::Other),
                    payload: query.resolve(&request_arena)?,
                })
            };
            let mut hidden_arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
            let mut missing_arena = Arena::<GlobalChunkAllocator>::try_new(ArenaConfig::default())?;
            let hidden = block_on(
                <Disco as IqHandler<GlobalChunkAllocator, RedbStorage>>::get(
                    &Disco,
                    request()?,
                    &transaction,
                    &mut hidden_arena,
                ),
            )
            .map(|reply| reply.payload);
            let missing =
                <Disco as IqHandler<GlobalChunkAllocator, RedbStorage>>::get_missing_account(
                    &Disco,
                    request()?,
                    &mut missing_arena,
                );
            match (hidden, missing) {
                (Ok(Some(hidden)), Ok(Some(missing))) => {
                    let mut hidden_xml = String::new();
                    hidden.resolve(&hidden_arena)?.write_xml(&mut hidden_xml)?;
                    let mut missing_xml = String::new();
                    missing
                        .resolve(&missing_arena)?
                        .write_xml(&mut missing_xml)?;
                    assert_eq!(hidden_xml, missing_xml);
                }
                (Err(hidden), Err(missing)) => {
                    assert_eq!(
                        hidden,
                        HandlerError::Stanza(StanzaErrorCondition::ServiceUnavailable)
                    );
                    assert_eq!(hidden, missing);
                }
                _ => panic!("hidden and missing answers must have the same shape"),
            }
        }
    }
    Ok(())
}
