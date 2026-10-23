// SPDX-License-Identifier: Apache-2.0

use lonewolf_storage::RedbStorage;
use lonewolf_xmpp::stanza::{StanzaErrorCondition, StanzaErrorText};

use super::*;
use crate::carbons::{NAME, NAMESPACE, RULES_FEATURE};
use crate::delivery::{BoundResource, DeliveryError, SessionLookup, SessionTag, TagChange};
use crate::discovery::{DiscoScope, INFO_NAMESPACE, ITEMS_NAMESPACE};
use crate::iq::{IqErrorPayload, IqRequest, IqRequestType, IqScope};
use crate::{ExtensionFuture, ExtensionRegistry, Extensions, HostSelection};

type Registry = ExtensionRegistry<GlobalChunkAllocator, RedbStorage>;

pub(super) fn catalog() -> TestResult<Extensions<GlobalChunkAllocator, RedbStorage>> {
    let mut catalog = Extensions::default();
    for factory in crate::builtin() {
        catalog.register_factory(factory)?;
    }
    Ok(catalog)
}

pub(super) fn registry() -> TestResult<Registry> {
    Ok(catalog()?.enable_host("localhost", [NAME])?)
}

fn assert_selection(registry: &Registry, names: &[&str]) {
    let carbons = names.contains(&NAME);
    let disco = names.contains(&crate::disco::NAME);
    assert_eq!(registry.enabled(), names);
    for name in [
        "enable", "disable", "private", "sent", "received", "unknown",
    ] {
        assert_eq!(
            registry.iq().find_session(NAMESPACE, name).is_some(),
            carbons && matches!(name, "enable" | "disable")
        );
        for scope in [IqScope::Server, IqScope::Account] {
            for kind in [IqRequestType::Get, IqRequestType::Set] {
                assert!(registry.iq().find(scope, kind, NAMESPACE, name).is_none());
            }
        }
    }
    for scope in [IqScope::Server, IqScope::Account] {
        for namespace in [INFO_NAMESPACE, ITEMS_NAMESPACE] {
            assert_eq!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Get, namespace, "query")
                    .is_some(),
                disco
            );
            assert!(
                registry
                    .iq()
                    .find(scope, IqRequestType::Set, namespace, "query")
                    .is_none()
            );
        }
    }
    for scope in [DiscoScope::Server, DiscoScope::Account] {
        let mut features = Vec::new();
        if disco {
            features.extend([INFO_NAMESPACE, ITEMS_NAMESPACE]);
        }
        if carbons && scope == DiscoScope::Server {
            features.extend([NAMESPACE, RULES_FEATURE]);
        }
        features.sort_unstable();
        assert_eq!(registry.discovery().features(scope), features);
    }
    assert_eq!(
        registry
            .message_observers()
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        if carbons { vec![NAME] } else { vec![] }
    );
    assert!(registry.stream_features().is_empty());
    assert!(registry.account_handlers().is_empty());
    assert!(registry.session_observers().is_empty());
    assert!(registry.services().is_empty());
    assert!(registry.discovery().services().is_empty());
    assert!(registry.policies().is_empty());
    assert!(registry.archive().is_none());
    assert!(registry.messages().is_none());
    assert!(registry.presence_decorations().is_empty());
    for kind in crate::presence::PresenceRequestType::ALL {
        assert!(registry.presence().find(kind).is_none());
    }
}

#[test]
fn carbons_registers_session_routes_discovery_and_one_observer() -> TestResult {
    assert_selection(&registry()?, &[NAME]);
    Ok(())
}

#[test]
fn carbons_and_disco_are_independently_selectable() -> TestResult {
    let catalog = catalog()?;
    let options = std::collections::BTreeMap::new();
    let selections = [
        vec![],
        vec![NAME.into()],
        vec!["disco".into()],
        vec!["disco".into(), NAME.into()],
        vec![NAME.into(), "disco".into()],
    ];
    let hosts = [
        "empty.example",
        "carbons.example",
        "disco.example",
        "both.example",
        "reverse.example",
    ];
    let mut selections: Vec<_> = hosts
        .iter()
        .zip(&selections)
        .map(|(domain, extensions)| HostSelection {
            domain,
            extensions,
            options: &options,
        })
        .collect();
    for _ in 0..2 {
        let registries = catalog.enable(&selections)?;
        assert_eq!(registries.len(), selections.len());
        for host in &selections {
            let names: Vec<_> = host.extensions.iter().map(String::as_str).collect();
            assert_selection(&registries[host.domain], &names);
        }
        selections.reverse();
    }
    assert_selection(&catalog.enable_host("localhost", [NAME])?, &[NAME]);
    Ok(())
}

struct UnexpectedSessions;

impl SessionLookup for UnexpectedSessions {
    fn resources<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("Carbons controls must not query sessions")
    }
}

#[test]
fn enable_and_disable_change_only_the_requesting_session() -> TestResult {
    let registry = registry()?;
    for name in [
        "enable", "enable", "disable", "disable", "enable", "disable",
    ] {
        for target in [
            None,
            Some("alice@localhost"),
            Some("bob@localhost"),
            Some("alice@foreign.example"),
            Some("alice@localhost/desk"),
            Some("localhost"),
        ] {
            let destination = target
                .map(|target| format!(" to='{target}'"))
                .unwrap_or_default();
            let request = parse(&format!(
                "<iq type='set' id='control'{destination}><{name} xmlns='{NAMESPACE}' extra='ignored'><anything xmlns='urn:ignored'>ignored</anything></{name}></iq>"
            ))?;
            let view = request.resolve()?;
            let mut response = arena()?;
            let sender = Jid::parse_in("alice@localhost/desk", &mut response)?;
            let payload = view
                .children()?
                .next()
                .transpose()?
                .ok_or("missing payload")?
                .clone_in(&mut response)?;
            let sender = sender.resolve(&response)?;
            let reply = registry
                .iq()
                .find_session(NAMESPACE, name)
                .ok_or("missing handler")?
                .set(
                    IqRequest {
                        sender,
                        target: view.to()?.unwrap_or_else(|| sender.bare()),
                        payload: payload.resolve(&response)?,
                        discovery: registry.discovery(),
                        sessions: &UnexpectedSessions,
                        requester: None,
                        lang: None,
                        space: None,
                    },
                    &mut arena()?,
                );
            if target.is_none() || target == Some("alice@localhost") {
                let reply = reply.map_err(|error| format!("control failed: {error:?}"))?;
                assert!(reply.payload.is_none());
                assert_eq!(
                    reply.change,
                    Some(if name == "enable" {
                        TagChange::Insert(SessionTag::Carbons)
                    } else {
                        TagChange::Remove(SessionTag::Carbons)
                    })
                );
            } else {
                let error = reply.err().ok_or("unauthorized target accepted")?;
                assert_eq!(error.condition(), StanzaErrorCondition::NotAllowed);
                assert_eq!(error.condition().error_type(), "cancel");
                assert_eq!(error.payload(), IqErrorPayload::Include);
                assert_eq!(
                    error.handler_error().text(),
                    StanzaErrorText::Static(
                        "Carbons can be changed only for your own session. Omit the destination or use your bare JID."
                    )
                );
            }
        }
    }
    Ok(())
}
