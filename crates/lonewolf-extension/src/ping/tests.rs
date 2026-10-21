// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use futures_executor::block_on;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::Element;

use super::*;
use crate::delivery::{BoundResource, DeliveryError, SessionLookup};
use crate::discovery::Discovery;
use crate::{ExtensionFuture, Extensions};

type TestResult = Result<(), Box<dyn Error>>;
type TestArena = Arena<GlobalChunkAllocator>;

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
fn ping_requires_disco_and_registers_only_get_routes_and_features() -> TestResult {
    let mut extensions = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    extensions.register(Arc::new(Ping))?;
    extensions.register(Arc::new(crate::disco::Disco))?;
    assert!(matches!(
        extensions.enable_host("example.com", [NAME]),
        Err(RegistrationError::MissingDependency {
            extension: NAME,
            dependency: crate::disco::NAME,
        })
    ));
    let disco = extensions.enable_host("example.com", [crate::disco::NAME])?;
    for names in [&[][..], &[crate::disco::NAME][..]] {
        let registry = extensions.enable_host("example.com", names.iter().copied())?;
        assert_eq!(registry.enabled(), names);
        for (scope, discovery_scope) in [
            (IqScope::Server, DiscoScope::Server),
            (IqScope::Account, DiscoScope::Account),
        ] {
            for kind in [IqRequestType::Get, IqRequestType::Set] {
                assert!(registry.iq().find(scope, kind, NAMESPACE, "ping").is_none());
            }
            assert!(
                !registry
                    .discovery()
                    .features(discovery_scope)
                    .contains(&NAMESPACE)
            );
        }
    }
    for names in [[NAME, crate::disco::NAME], [crate::disco::NAME, NAME]] {
        let registry = extensions.enable_host("example.com", names)?;
        assert_eq!(registry.enabled(), names);
        for (scope, discovery_scope) in [
            (IqScope::Server, DiscoScope::Server),
            (IqScope::Account, DiscoScope::Account),
        ] {
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Get, NAMESPACE, "ping")
                    .is_some()
            );
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Set, NAMESPACE, "ping")
                    .is_none()
            );
            for (namespace, name) in [(NAMESPACE, "pong"), ("urn:wrong", "ping")] {
                for kind in [IqRequestType::Get, IqRequestType::Set] {
                    assert!(registry.iq().find(scope, kind, namespace, name).is_none());
                }
            }
            let features = registry.discovery().features(discovery_scope);
            assert_eq!(
                features
                    .iter()
                    .filter(|&&feature| feature == NAMESPACE)
                    .count(),
                1
            );
            let mut expected = disco.discovery().features(discovery_scope).to_vec();
            expected.push(NAMESPACE);
            expected.sort_unstable();
            assert_eq!(features, expected);
            assert_eq!(
                registry.discovery().identities(discovery_scope),
                disco.discovery().identities(discovery_scope)
            );
        }
        assert_eq!(
            registry.discovery().services(),
            disco.discovery().services()
        );
        assert_eq!(registry.services().len(), disco.services().len());
        assert_eq!(registry.stream_features(), disco.stream_features());
        assert!(registry.account_handlers().is_empty());
        assert!(registry.message_observers().is_empty());
        assert!(registry.session_observers().is_empty());
        assert!(registry.presence_decorations().is_empty());
        assert!(registry.policies().is_empty());
        assert!(registry.archive().is_none());
        assert!(registry.messages().is_none());
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
