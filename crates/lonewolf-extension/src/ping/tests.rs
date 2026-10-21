// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;

use futures_executor::block_on;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::Element;

use super::*;
use crate::delivery::{BoundResource, DeliveryError, SessionLookup};
use crate::discovery::{Discovery, INFO_NAMESPACE, ITEMS_NAMESPACE, Identity};
use crate::{EnableError, ExtensionFuture, ExtensionRegistry, Extensions, HostSelection};

type TestResult = Result<(), Box<dyn Error>>;
type TestArena = Arena<GlobalChunkAllocator>;
type TestExtensions = Extensions<GlobalChunkAllocator, RedbStorage>;

fn builtin_catalog() -> Result<TestExtensions, RegistrationError> {
    let mut catalog = TestExtensions::default();
    let factories = crate::builtin();
    assert_eq!(
        factories.each_ref().map(|factory| factory.name()),
        [
            crate::roster::NAME,
            crate::offline::NAME,
            crate::disco::NAME,
            NAME
        ]
    );
    for factory in factories {
        catalog.register_factory(factory)?;
    }
    Ok(catalog)
}

fn assert_selection(
    registry: &ExtensionRegistry<GlobalChunkAllocator, RedbStorage>,
    names: &[&str],
) {
    let has_ping = names.contains(&NAME);
    let has_disco = names.contains(&crate::disco::NAME);
    assert_eq!(registry.enabled(), names);
    for (scope, discovery_scope, category, kind) in [
        (IqScope::Server, DiscoScope::Server, "server", "im"),
        (
            IqScope::Account,
            DiscoScope::Account,
            "account",
            "registered",
        ),
    ] {
        for (namespace, name, enabled) in [
            (NAMESPACE, "ping", has_ping),
            (INFO_NAMESPACE, "query", has_disco),
            (ITEMS_NAMESPACE, "query", has_disco),
        ] {
            assert_eq!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Get, namespace, name)
                    .is_some(),
                enabled,
                "{scope:?}: {namespace} {name} for {names:?}"
            );
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Set, namespace, name)
                    .is_none()
            );
        }
        for (namespace, name) in [(NAMESPACE, "pong"), ("urn:wrong", "ping")] {
            for request_type in [IqRequestType::Get, IqRequestType::Set] {
                assert!(
                    registry
                        .iq()
                        .find(scope, request_type, namespace, name)
                        .is_none()
                );
            }
        }
        let mut expected_features = Vec::new();
        if has_disco {
            expected_features.extend([INFO_NAMESPACE, ITEMS_NAMESPACE]);
        }
        if has_ping {
            expected_features.push(NAMESPACE);
        }
        expected_features.sort_unstable();
        let features = registry.discovery().features(discovery_scope);
        assert_eq!(features, expected_features);
        assert_eq!(
            features
                .iter()
                .filter(|&&feature| feature == NAMESPACE)
                .count(),
            usize::from(has_ping)
        );
        let identity = Identity {
            category,
            kind,
            name: None,
        };
        let expected_identities = if has_disco {
            std::slice::from_ref(&identity)
        } else {
            &[]
        };
        assert_eq!(
            registry.discovery().identities(discovery_scope),
            expected_identities
        );
    }
    for kind in crate::presence::PresenceRequestType::ALL {
        assert!(registry.presence().find(kind).is_none());
    }
    assert!(registry.discovery().services().is_empty());
    assert!(registry.services().is_empty());
    assert!(registry.stream_features().is_empty());
    assert!(registry.account_handlers().is_empty());
    assert!(registry.message_observers().is_empty());
    assert!(registry.session_observers().is_empty());
    assert!(registry.presence_decorations().is_empty());
    assert!(registry.policies().is_empty());
    assert!(registry.archive().is_none());
    assert!(registry.messages().is_none());
}

#[test]
fn builtin_ping_routes_and_features_follow_each_hosts_selection() -> TestResult {
    let catalog = builtin_catalog()?;
    let options = BTreeMap::new();
    for enabled in [
        &[NAME][..],
        &[NAME, crate::disco::NAME][..],
        &[crate::disco::NAME, NAME][..],
    ] {
        let names: Vec<_> = enabled.iter().copied().map(String::from).collect();
        for disabled in [&[][..], &[String::from(crate::disco::NAME)][..]] {
            for reverse in [false, true] {
                let mut selections = [
                    HostSelection {
                        domain: "enabled.example",
                        extensions: &names,
                        options: &options,
                    },
                    HostSelection {
                        domain: "disabled.example",
                        extensions: disabled,
                        options: &options,
                    },
                ];
                if reverse {
                    selections.reverse();
                }
                let registries = catalog.enable(&selections)?;
                for selection in &selections {
                    let expected: Vec<_> =
                        selection.extensions.iter().map(String::as_str).collect();
                    assert_selection(&registries[selection.domain], &expected);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn builtin_ping_and_disco_selections_are_isolated_between_hosts() -> TestResult {
    let catalog = builtin_catalog()?;
    let options = BTreeMap::new();
    let names = [NAME.into()];
    let disco = [crate::disco::NAME.into()];
    for reverse in [false, true] {
        let mut selections = [
            HostSelection {
                domain: "ping-only.example",
                extensions: &names,
                options: &options,
            },
            HostSelection {
                domain: "disco-only.example",
                extensions: &disco,
                options: &options,
            },
        ];
        if reverse {
            selections.reverse();
        }
        let registries = catalog.enable(&selections)?;
        assert_eq!(registries.len(), 2);
        assert_selection(&registries["ping-only.example"], &[NAME]);
        assert_selection(&registries["disco-only.example"], &[crate::disco::NAME]);
    }
    let registries = catalog.enable(&[HostSelection {
        domain: "ping-only.example",
        extensions: &names,
        options: &options,
    }])?;
    assert_eq!(registries.len(), 1);
    assert_selection(&registries["ping-only.example"], &[NAME]);
    Ok(())
}

#[test]
fn builtin_ping_rejects_duplicate_and_misspelled_selections() -> TestResult {
    let catalog = builtin_catalog()?;
    for (names, expected) in [
        (
            vec![NAME.into(), crate::disco::NAME.into(), NAME.into()],
            RegistrationError::DuplicateExtension(NAME),
        ),
        (
            vec!["pign".into(), crate::disco::NAME.into()],
            RegistrationError::UnknownExtension("pign".into()),
        ),
    ] {
        let error = catalog
            .enable(&[HostSelection {
                domain: "invalid.example",
                extensions: &names,
                options: &BTreeMap::new(),
            }])
            .err()
            .ok_or("invalid selection accepted")?;
        assert_eq!(
            error,
            EnableError {
                host: "invalid.example".into(),
                source: expected
            }
        );
    }
    Ok(())
}

struct UnexpectedSessions;

impl SessionLookup for UnexpectedSessions {
    fn resources<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("ping must not inspect sessions")
    }
}

#[test]
fn ping_registers_only_get_routes_and_features_without_disco() -> TestResult {
    let mut extensions = TestExtensions::default();
    extensions.register(Arc::new(Ping))?;
    let ping = extensions.enable_host("example.com", [NAME])?;
    assert_selection(&ping, &[NAME]);
    extensions.register(Arc::new(crate::disco::Disco))?;
    for names in [
        &[][..],
        &[NAME][..],
        &[crate::disco::NAME][..],
        &[NAME, crate::disco::NAME][..],
        &[crate::disco::NAME, NAME][..],
    ] {
        let registry = extensions.enable_host("example.com", names.iter().copied())?;
        assert_selection(&registry, names);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Content {
    Empty,
    Text(&'static str),
    Element,
    Mixed,
}

struct PayloadCase {
    name: &'static str,
    attributes: &'static [(&'static str, &'static str, &'static str)],
    content: Content,
    valid: bool,
}

fn payload_cases() -> [PayloadCase; 15] {
    [
        PayloadCase {
            name: "empty",
            attributes: &[],
            content: Content::Empty,
            valid: true,
        },
        PayloadCase {
            name: "language",
            attributes: &[("lang", XML_NAMESPACE, "es")],
            content: Content::Empty,
            valid: true,
        },
        PayloadCase {
            name: "empty language",
            attributes: &[("lang", XML_NAMESPACE, "")],
            content: Content::Empty,
            valid: true,
        },
        PayloadCase {
            name: "inert language",
            attributes: &[("lang", XML_NAMESPACE, "not a language tag!")],
            content: Content::Empty,
            valid: true,
        },
        PayloadCase {
            name: "unqualified attribute",
            attributes: &[("id", "", "x")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "foreign attribute",
            attributes: &[("id", "urn:foreign", "x")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "unqualified language",
            attributes: &[("lang", "", "es")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "foreign language",
            attributes: &[("lang", "urn:foreign", "es")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "xml space",
            attributes: &[("space", XML_NAMESPACE, "preserve")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "xml base",
            attributes: &[("base", XML_NAMESPACE, "https://example.com")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "language and rejected attribute",
            attributes: &[("lang", XML_NAMESPACE, "es"), ("id", "", "x")],
            content: Content::Empty,
            valid: false,
        },
        PayloadCase {
            name: "element",
            attributes: &[],
            content: Content::Element,
            valid: false,
        },
        PayloadCase {
            name: "text",
            attributes: &[],
            content: Content::Text("x"),
            valid: false,
        },
        PayloadCase {
            name: "whitespace",
            attributes: &[],
            content: Content::Text(" \n\t"),
            valid: false,
        },
        PayloadCase {
            name: "mixed content",
            attributes: &[],
            content: Content::Mixed,
            valid: false,
        },
    ]
}

fn payload_in(case: &PayloadCase, arena: &mut TestArena) -> Result<Element, Box<dyn Error>> {
    let child = if matches!(case.content, Content::Element | Content::Mixed) {
        Some(Element::builder_in("child", NAMESPACE, arena)?.build()?)
    } else {
        None
    };
    let mut builder = Element::builder_in("ping", NAMESPACE, arena)?;
    for &(name, namespace, value) in case.attributes {
        builder = builder.attribute(name, namespace, value)?;
    }
    if let Content::Text(text) = case.content {
        builder = builder.text(text)?;
    }
    if matches!(case.content, Content::Mixed) {
        builder = builder.text("before")?;
    }
    if let Some(child) = child {
        builder = builder.child(child)?;
    }
    if matches!(case.content, Content::Mixed) {
        builder = builder.text("after")?;
    }
    Ok(builder.build()?)
}

fn request<'a>(
    arena: &'a TestArena,
    sender: Jid,
    target: Jid,
    payload: Element,
    discovery: &'a Discovery,
    requester: Option<Requester>,
) -> Result<IqRequest<'a, GlobalChunkAllocator>, Box<dyn Error>> {
    Ok(IqRequest {
        sender: sender.resolve(arena)?,
        target: target.resolve(arena)?,
        payload: payload.resolve(arena)?,
        discovery,
        sessions: &UnexpectedSessions,
        requester,
    })
}

#[test]
fn allowed_ping_requests_validate_payloads_and_return_empty_replies() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    let discovery = Discovery::default();
    for (target, requester, sender) in [
        ("example.com", None, "bob@example.com/desk"),
        (
            "alice@example.com",
            Some(Requester::Owner),
            "alice@example.com/desk",
        ),
        (
            "alice@example.com",
            Some(Requester::PresenceAuthorized),
            "bob@example.com/desk",
        ),
    ] {
        for case in payload_cases() {
            for with_language in [false, true] {
                let mut arena = TestArena::try_new(ArenaConfig::default())?;
                let sender = Jid::parse_in(sender, &mut arena)?;
                let target_jid = Jid::parse_in(target, &mut arena)?;
                let payload = payload_in(&case, &mut arena)?;
                let payload = if with_language {
                    payload
                        .derive_in(&mut arena)?
                        .attribute("lang", XML_NAMESPACE, "es")?
                        .build()?
                } else {
                    payload
                };
                let mut response = TestArena::try_new(ArenaConfig::default())?;
                let result = block_on(<Ping as IqHandler<GlobalChunkAllocator, RedbStorage>>::get(
                    &Ping,
                    request(&arena, sender, target_jid, payload, &discovery, requester)?,
                    &transaction,
                    &mut response,
                ));
                if case.valid {
                    let reply =
                        result.map_err(|error| format!("{target} {}: {error:?}", case.name))?;
                    assert!(reply.payload.is_none(), "{target} {}", case.name);
                    assert!(reply.results.is_empty(), "{target} {}", case.name);
                    assert!(reply.effects.accounts.is_empty(), "{target} {}", case.name);
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(HandlerError::Stanza(StanzaErrorCondition::BadRequest))
                        ),
                        "{target} {}",
                        case.name
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn account_authorization_precedes_payload_validation() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    let discovery = Discovery::default();
    for (requester, condition) in [
        (
            Some(Requester::Other),
            StanzaErrorCondition::ServiceUnavailable,
        ),
        (None, StanzaErrorCondition::InternalServerError),
    ] {
        for case in payload_cases() {
            let mut arena = TestArena::try_new(ArenaConfig::default())?;
            let sender = Jid::parse_in("bob@example.com/desk", &mut arena)?;
            let target = Jid::parse_in("alice@example.com", &mut arena)?;
            let payload = payload_in(&case, &mut arena)?;
            let mut response = TestArena::try_new(ArenaConfig::default())?;
            let result = block_on(<Ping as IqHandler<GlobalChunkAllocator, RedbStorage>>::get(
                &Ping,
                request(&arena, sender, target, payload, &discovery, requester)?,
                &transaction,
                &mut response,
            ));
            assert!(
                matches!(result, Err(error) if error == HandlerError::Stanza(condition)),
                "{requester:?} {}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn missing_accounts_always_use_the_default_service_unavailable_reply() -> TestResult {
    let discovery = Discovery::default();
    for requester in [
        None,
        Some(Requester::Owner),
        Some(Requester::PresenceAuthorized),
        Some(Requester::Other),
    ] {
        for case in payload_cases() {
            let mut arena = TestArena::try_new(ArenaConfig::default())?;
            let sender = Jid::parse_in(
                if requester == Some(Requester::Owner) {
                    "alice@example.com/desk"
                } else {
                    "bob@example.com/desk"
                },
                &mut arena,
            )?;
            let target = Jid::parse_in("alice@example.com", &mut arena)?;
            let payload = payload_in(&case, &mut arena)?;
            let mut response = TestArena::try_new(ArenaConfig::default())?;
            let result =
                <Ping as IqHandler<GlobalChunkAllocator, RedbStorage>>::get_missing_account(
                    &Ping,
                    request(&arena, sender, target, payload, &discovery, requester)?,
                    &mut response,
                );
            assert!(
                matches!(
                    result,
                    Err(HandlerError::Stanza(
                        StanzaErrorCondition::ServiceUnavailable
                    ))
                ),
                "{requester:?} {}",
                case.name
            );
        }
    }
    Ok(())
}

#[test]
fn ping_validator_rejects_wrong_resolved_qnames() -> TestResult {
    let mut arena = TestArena::try_new(ArenaConfig::default())?;
    for (name, namespace) in [("pong", NAMESPACE), ("ping", "urn:wrong"), ("ping", "")] {
        let payload = Element::builder_in(name, namespace, &mut arena)?.build()?;
        assert_eq!(
            validate_payload(payload.resolve(&arena)?),
            Err(HandlerError::Stanza(StanzaErrorCondition::BadRequest))
        );
    }
    Ok(())
}
