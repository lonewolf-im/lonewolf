// SPDX-License-Identifier: Apache-2.0

mod options;
use std::error::Error;
use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbStorage, RedbWrite};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::stanza::{Element, RoutedStanza};
use parking_lot::Mutex as PlMutex;

use super::account::AccountHandler;
use super::delivery::{HandlerError, HostLookup};
use super::discovery::{
    DiscoScope, Discovery, INFO_NAMESPACE, ITEMS_NAMESPACE, Identity, Query, QueryKind, info_in,
    item_in, items_in,
};
use super::iq::{IqDestinationRule, IqHandler, IqRequestKey, IqRequestType, IqRoute, IqScope};
use super::message::MessageHandler;
use super::presence::{PresenceHandler, PresenceRequestType};
use super::service::{ServiceContext, ServiceHandler};
use super::{Effects, Extension, ExtensionFuture, Extensions, RegistrationError, Slots};

type TestExtensions = Extensions<GlobalChunkAllocator, RedbStorage>;

const ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:test:iq",
    name: "query",
};

#[derive(Default)]
struct Fake {
    name: &'static str,
    iq: &'static [IqRoute],
    destinations: &'static [IqRequestKey],
    presence: &'static [PresenceRequestType],
    features: &'static [&'static str],
    disco_features: &'static [(DiscoScope, &'static str)],
    disco_identities: &'static [(DiscoScope, Identity)],
    services: &'static [&'static str],
    messages: bool,
    hosts: PlMutex<Vec<String>>,
    dependencies: &'static [&'static str],
    accounts: bool,
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

impl MessageHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

impl ServiceHandler<GlobalChunkAllocator, RedbStorage> for Fake {
    fn route<'a>(
        &'a self,
        _stanza: RoutedStanza<GlobalChunkAllocator>,
        _context: ServiceContext<'a, GlobalChunkAllocator, RedbStorage>,
    ) -> ExtensionFuture<'a, Result<(), HandlerError>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn service_domains_must_be_normalized_and_unique() -> Result<(), RegistrationError> {
    let mut registry = super::ExtensionRegistry::default();
    let mut slots = Slots::new(&mut registry, "service");
    let handler = Arc::new(Fake::default());
    assert_eq!(
        slots.service("Example.com", handler.clone()),
        Err(RegistrationError::InvalidServiceDomain(
            "Example.com".into()
        ))
    );
    slots.service("svc.example.com", handler.clone())?;
    assert_eq!(
        slots.service("svc.example.com", handler),
        Err(RegistrationError::DuplicateService(
            "svc.example.com".into()
        ))
    );
    assert_eq!(registry.services().len(), 1);
    assert_eq!(registry.services()[0].0, "svc.example.com");
    assert_eq!(registry.discovery().services(), ["svc.example.com"]);
    Ok(())
}

impl Extension<GlobalChunkAllocator, RedbStorage> for Fake {
    fn name(&self) -> &'static str {
        self.name
    }

    fn depends(&self) -> &'static [&'static str] {
        self.dependencies
    }

    fn register(
        self: Arc<Self>,
        host: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        self.hosts.lock().push(host.into());
        for route in self.iq {
            slots.iq(*route, self.clone())?;
        }
        for key in self.destinations {
            slots.iq_destination(*key, IqDestinationRule::SenderBare)?;
        }
        for kind in self.presence {
            slots.presence(*kind, self.clone())?;
        }
        for feature in self.features {
            slots.stream_feature(feature);
        }
        for &(scope, feature) in self.disco_features {
            slots.disco_feature(scope, feature);
        }
        for &(scope, identity) in self.disco_identities {
            slots.disco_identity(scope, identity);
        }
        for domain in self.services {
            slots.service(domain, self.clone())?;
        }
        if self.accounts {
            slots.account(self.clone());
        }
        if self.messages {
            slots.offline(self)?;
        }
        Ok(())
    }
}

impl AccountHandler<GlobalChunkAllocator, RedbStorage> for Fake {
    fn forget_account<'a>(
        &'a self,
        _transaction: &'a mut RedbWrite,
        _account: &'a AccountKey,
        _before: Arc<lonewolf_storage::RedbRead>,
        _hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<crate::Deliver<GlobalChunkAllocator>, HandlerError>> {
        Box::pin(async { Ok(Effects::none().deliver) })
    }
}

fn extension(
    name: &'static str,
    iq: &'static [IqRoute],
    presence: &'static [PresenceRequestType],
) -> Arc<Fake> {
    Arc::new(Fake {
        name,
        iq,
        presence,
        ..Fake::default()
    })
}

fn featured(name: &'static str, features: &'static [&'static str]) -> Arc<Fake> {
    Arc::new(Fake {
        name,
        features,
        ..Fake::default()
    })
}

#[test]
fn discovery_merges_features_and_identities_per_scope() -> Result<(), RegistrationError> {
    const SERVER: Identity = Identity {
        category: "server",
        kind: "im",
        name: None,
    };
    const NAMED_SERVER: Identity = Identity {
        name: Some("Example"),
        ..SERVER
    };
    const ACCOUNT: Identity = Identity {
        category: "account",
        kind: "registered",
        name: None,
    };
    const NAMED_ACCOUNT: Identity = Identity {
        name: Some("Example"),
        ..ACCOUNT
    };
    let mut extensions = TestExtensions::default();
    extensions.register(Arc::new(Fake {
        name: "first",
        disco_features: &[
            (DiscoScope::Server, "urn:test:b"),
            (DiscoScope::Server, "urn:test:a"),
            (DiscoScope::Account, "urn:test:c"),
            (DiscoScope::Account, "urn:test:a"),
        ],
        disco_identities: &[
            (DiscoScope::Server, NAMED_SERVER),
            (DiscoScope::Server, SERVER),
            (DiscoScope::Account, NAMED_ACCOUNT),
            (DiscoScope::Account, ACCOUNT),
        ],
        ..Fake::default()
    }))?;
    extensions.register(Arc::new(Fake {
        name: "second",
        disco_features: &[
            (DiscoScope::Account, "urn:test:a"),
            (DiscoScope::Account, "urn:test:c"),
            (DiscoScope::Server, "urn:test:a"),
            (DiscoScope::Server, "urn:test:b"),
        ],
        disco_identities: &[
            (DiscoScope::Account, ACCOUNT),
            (DiscoScope::Account, NAMED_ACCOUNT),
            (DiscoScope::Server, SERVER),
            (DiscoScope::Server, NAMED_SERVER),
        ],
        ..Fake::default()
    }))?;
    for names in [["first", "second"], ["second", "first"]] {
        let enabled = extensions.enable_host("example.com", names)?;
        let discovery = enabled.discovery();
        assert_eq!(
            discovery.features(DiscoScope::Server),
            ["urn:test:a", "urn:test:b"]
        );
        assert_eq!(
            discovery.features(DiscoScope::Account),
            ["urn:test:a", "urn:test:c"]
        );
        assert_eq!(
            discovery.identities(DiscoScope::Server),
            [SERVER, NAMED_SERVER]
        );
        assert_eq!(
            discovery.identities(DiscoScope::Account),
            [ACCOUNT, NAMED_ACCOUNT]
        );
        assert!(discovery.services().is_empty());
    }
    let disabled = extensions.enable_host("other.example", [])?;
    assert_eq!(disabled.discovery().as_ref(), &Discovery::default());
    Ok(())
}

#[test]
fn discovery_lists_registered_services() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(Arc::new(Fake {
        name: "services",
        services: &["b.example", "a.example"],
        ..Fake::default()
    }))?;
    let enabled = extensions.enable_host("example", ["services"])?;
    assert_eq!(enabled.discovery().services(), ["a.example", "b.example"]);
    Ok(())
}

#[test]
fn builtin_extensions_declare_their_discovery_features() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    for factory in super::builtin() {
        extensions.register_factory(factory)?;
    }

    let enabled = extensions.enable_host("example.com", ["roster", "offline"])?;
    assert_eq!(
        enabled.discovery().features(DiscoScope::Server),
        ["jabber:iq:roster", "msgoffline"]
    );
    assert!(enabled.discovery().features(DiscoScope::Account).is_empty());

    let carbons_only = extensions.enable_host("example.com", ["carbons"])?;
    assert_eq!(
        carbons_only.discovery().features(DiscoScope::Server),
        [crate::carbons::NAMESPACE, crate::carbons::RULES_FEATURE]
    );
    assert!(
        carbons_only
            .discovery()
            .features(DiscoScope::Account)
            .is_empty()
    );

    let roster_only = extensions.enable_host("example.com", ["roster"])?;
    assert_eq!(
        roster_only.discovery().features(DiscoScope::Server),
        ["jabber:iq:roster"]
    );
    Ok(())
}

#[test]
fn discovery_info_lists_identities_then_features() -> Result<(), Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let element = info_in(
        None,
        &[
            Identity {
                category: "server",
                kind: "im",
                name: None,
            },
            Identity {
                category: "store",
                kind: "file",
                name: Some("Files"),
            },
        ],
        &[INFO_NAMESPACE, "urn:example"],
        &mut arena,
    )?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#info\"><identity category=\"server\" type=\"im\"/><identity category=\"store\" type=\"file\" name=\"Files\"/><feature var=\"http://jabber.org/protocol/disco#info\"/><feature var=\"urn:example\"/></query>"
    );
    Ok(())
}

#[test]
fn discovery_info_repeats_the_requested_node() -> Result<(), Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let element = info_in(Some("n"), &[], &[], &mut arena)?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#info\" node=\"n\"/>"
    );
    Ok(())
}

#[test]
fn discovery_items_keep_item_order_and_optional_attributes() -> Result<(), Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let first = item_in("a.example", None, None, &mut arena)?;
    let second = item_in("b.example", Some("x"), Some("B"), &mut arena)?;
    let element = items_in(None, &[first, second], &mut arena)?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#items\"><item jid=\"a.example\"/><item jid=\"b.example\" node=\"x\" name=\"B\"/></query>"
    );
    Ok(())
}

#[test]
fn discovery_items_without_entries_are_empty() -> Result<(), Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let element = items_in(Some("n"), &[], &mut arena)?;
    let mut xml = String::new();
    element.resolve(&arena)?.write_xml(&mut xml)?;
    assert_eq!(
        xml,
        "<query xmlns=\"http://jabber.org/protocol/disco#items\" node=\"n\"/>"
    );
    Ok(())
}

#[test]
fn discovery_queries_parse_kind_and_node() -> Result<(), Box<dyn Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let info = Element::builder_in("query", INFO_NAMESPACE, &mut arena)?.build()?;
    let items = Element::builder_in("query", ITEMS_NAMESPACE, &mut arena)?
        .attribute("node", "", "n")?
        .build()?;
    let empty_node = Element::builder_in("query", ITEMS_NAMESPACE, &mut arena)?
        .attribute("node", "", "")?
        .build()?;
    let child = Element::builder_in("child", INFO_NAMESPACE, &mut arena)?.build()?;
    let nested = Element::builder_in("query", INFO_NAMESPACE, &mut arena)?
        .child(child)?
        .build()?;
    let wrong_namespace = Element::builder_in("query", "jabber:iq:roster", &mut arena)?.build()?;
    let wrong_name = Element::builder_in("other", INFO_NAMESPACE, &mut arena)?.build()?;

    assert_eq!(
        Query::parse(info.resolve(&arena)?)?,
        Some(Query {
            kind: QueryKind::Info,
            node: None,
        })
    );
    assert_eq!(
        Query::parse(items.resolve(&arena)?)?,
        Some(Query {
            kind: QueryKind::Items,
            node: Some("n"),
        })
    );
    assert_eq!(
        Query::parse(empty_node.resolve(&arena)?)?.map(|query| query.node),
        Some(Some(""))
    );
    assert_eq!(
        Query::parse(nested.resolve(&arena)?)?,
        Some(Query {
            kind: QueryKind::Info,
            node: None,
        })
    );
    assert_eq!(Query::parse(wrong_namespace.resolve(&arena)?)?, None);
    assert_eq!(Query::parse(wrong_name.resolve(&arena)?)?, None);
    Ok(())
}

fn message_extension(name: &'static str) -> Arc<Fake> {
    Arc::new(Fake {
        name,
        messages: true,
        ..Fake::default()
    })
}

#[test]
fn message_handler_is_selected_only_when_enabled() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    let message = message_extension("messages");
    let handler: Arc<dyn MessageHandler<GlobalChunkAllocator, RedbStorage>> = message.clone();
    extensions.register(message)?;
    extensions.register(extension("plain", &[], &[]))?;
    let enabled = extensions.enable_host("example.com", ["plain", "messages"])?;
    assert!(
        enabled
            .messages()
            .is_some_and(|selected| Arc::ptr_eq(selected, &handler))
    );
    assert!(
        extensions
            .enable_host("example.com", ["plain"])?
            .messages()
            .is_none()
    );
    assert!(
        extensions
            .enable_host("example.com", [])?
            .messages()
            .is_none()
    );
    assert_eq!(enabled.enabled(), ["plain", "messages"]);
    assert_eq!(enabled.stream_features(), "");
    Ok(())
}

#[test]
fn conflicting_message_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(message_extension("first"))?;
    extensions.register(message_extension("second"))?;
    for names in [["first", "second"], ["second", "first"]] {
        assert!(matches!(
            extensions.enable_host("example.com", names),
            Err(RegistrationError::DuplicateMessageHandler)
        ));
    }
    assert!(
        extensions
            .enable_host("example.com", ["first"])?
            .messages()
            .is_some()
    );
    assert!(
        extensions
            .enable_host("example.com", ["second"])?
            .messages()
            .is_some()
    );
    Ok(())
}

#[test]
fn enabled_extensions_contribute_their_stream_features_in_order() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(featured("first", &["<a xmlns='urn:test:a'/>"]))?;
    extensions.register(featured(
        "second",
        &["<b xmlns='urn:test:b'/>", "<c xmlns='urn:test:c'/>"],
    ))?;
    extensions.register(extension("plain", &[], &[]))?;
    let enabled = extensions.enable_host("example.com", ["second", "plain", "first"])?;
    assert_eq!(
        enabled.stream_features(),
        "<b xmlns='urn:test:b'/><c xmlns='urn:test:c'/><a xmlns='urn:test:a'/>"
    );
    assert_eq!(
        extensions
            .enable_host("example.com", ["plain"])?
            .stream_features(),
        ""
    );
    Ok(())
}

#[test]
fn conflicting_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension("first", &[ROUTE], &[]))?;
    extensions.register(extension("second", &[ROUTE], &[]))?;
    assert!(extensions.enable_host("example.com", ["first"]).is_ok());
    assert!(extensions.enable_host("example.com", ["second"]).is_ok());
    assert!(matches!(
        extensions.enable_host("example.com", ["first", "second"]),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    ));
    assert!(matches!(
        extensions.enable_host("example.com", ["second", "first"]),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    ));
    Ok(())
}

#[test]
fn enabling_an_extension_with_conflicting_routes_fails() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension("example", &[ROUTE, ROUTE], &[]))?;
    assert!(matches!(
        extensions.enable_host("example.com", ["example"]),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    ));
    Ok(())
}

#[test]
fn duplicate_extension_names_cannot_replace_handlers() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension("example", &[ROUTE], &[]))?;
    assert_eq!(
        extensions.register(extension("example", &[], &[])),
        Err(RegistrationError::DuplicateExtension("example"))
    );
    let enabled = extensions.enable_host("example.com", ["example"])?;
    assert!(
        enabled
            .iq()
            .find(ROUTE.scope, ROUTE.kind, ROUTE.namespace, ROUTE.name)
            .is_some()
    );
    Ok(())
}

#[test]
fn unknown_enabled_names_are_rejected() {
    let extensions = TestExtensions::default();
    assert!(
        matches!(extensions.enable_host("example.com", ["missing"]), Err(RegistrationError::UnknownExtension(name)) if name == "missing")
    );
}

#[test]
fn extension_names_must_be_nonempty_and_trimmed() {
    let mut extensions = TestExtensions::default();
    for name in ["", " ", " leading", "trailing "] {
        assert_eq!(
            extensions.register(extension(name, &[], &[])),
            Err(RegistrationError::InvalidExtensionName)
        );
    }
}

#[test]
fn repeated_activation_is_rejected_even_without_iq_handlers() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension("example", &[], &[]))?;
    assert!(matches!(
        extensions.enable_host("example.com", ["example", "example"]),
        Err(RegistrationError::DuplicateExtension("example"))
    ));
    Ok(())
}

#[test]
fn conflicting_presence_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension("first", &[], &[PresenceRequestType::Subscribe]))?;
    extensions.register(extension("second", &[], &[PresenceRequestType::Subscribe]))?;
    assert!(matches!(
        extensions.enable_host("example.com", ["first", "second"]),
        Err(RegistrationError::DuplicatePresenceRoute(
            PresenceRequestType::Subscribe
        ))
    ));
    assert!(matches!(
        extensions.enable_host("example.com", ["second", "first"]),
        Err(RegistrationError::DuplicatePresenceRoute(
            PresenceRequestType::Subscribe
        ))
    ));
    Ok(())
}

#[test]
fn presence_kinds_select_distinct_handlers() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    extensions.register(extension(
        "example",
        &[],
        &[
            PresenceRequestType::Subscribe,
            PresenceRequestType::Subscribed,
        ],
    ))?;
    let enabled = extensions.enable_host("example.com", ["example"])?;
    assert!(
        enabled
            .presence()
            .find(PresenceRequestType::Subscribe)
            .is_some()
    );
    assert!(
        enabled
            .presence()
            .find(PresenceRequestType::Subscribed)
            .is_some()
    );
    assert!(
        enabled
            .presence()
            .find(PresenceRequestType::Unsubscribe)
            .is_none()
    );
    Ok(())
}

#[test]
fn enable_registers_each_extension_once_per_host() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    let handler = extension("example", &[ROUTE], &[]);
    extensions.register(handler.clone())?;
    assert!(handler.hosts.lock().is_empty());
    let first = extensions.enable_host("a.example", ["example"])?;
    let second = extensions.enable_host("b.example", ["example"])?;
    assert_eq!(*handler.hosts.lock(), ["a.example", "b.example"]);
    let iq: Arc<dyn IqHandler<GlobalChunkAllocator, RedbStorage>> = handler;
    for registry in [first, second] {
        assert_eq!(registry.enabled(), ["example"]);
        assert!(
            registry
                .iq()
                .find(ROUTE.scope, ROUTE.kind, ROUTE.namespace, ROUTE.name)
                .is_some_and(|registered| Arc::ptr_eq(registered, &iq))
        );
    }
    Ok(())
}

#[test]
fn missing_dependencies_prevent_enabling() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    let a = extension("a", &[], &[]);
    let b = Arc::new(Fake {
        name: "b",
        dependencies: &["a"],
        ..Fake::default()
    });
    extensions.register(a.clone())?;
    extensions.register(b.clone())?;
    assert!(matches!(
        extensions.enable_host("example.com", ["b"]),
        Err(RegistrationError::MissingDependency {
            extension: "b",
            dependency: "a",
        })
    ));
    assert!(a.hosts.lock().is_empty());
    assert!(b.hosts.lock().is_empty());
    assert_eq!(
        RegistrationError::MissingDependency {
            extension: "b",
            dependency: "a"
        }
        .to_string(),
        "extension \"b\" requires extension \"a\""
    );
    for names in [["b", "a"], ["a", "b"]] {
        assert_eq!(
            extensions.enable_host("example.com", names)?.enabled(),
            names
        );
    }
    Ok(())
}

#[test]
fn account_handlers_follow_enable_order() -> Result<(), RegistrationError> {
    let mut extensions = TestExtensions::default();
    let first = Arc::new(Fake {
        name: "first",
        accounts: true,
        ..Fake::default()
    });
    let second = Arc::new(Fake {
        name: "second",
        accounts: true,
        ..Fake::default()
    });
    extensions.register(first.clone())?;
    extensions.register(second.clone())?;
    extensions.register(extension("plain", &[], &[]))?;
    let enabled = extensions.enable_host("example.com", ["second", "plain", "first"])?;
    let handlers = enabled.account_handlers();
    assert_eq!(
        handlers.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["second", "first"]
    );
    let first: Arc<dyn AccountHandler<GlobalChunkAllocator, RedbStorage>> = first;
    let second: Arc<dyn AccountHandler<GlobalChunkAllocator, RedbStorage>> = second;
    assert!(Arc::ptr_eq(&handlers[0].1, &second));
    assert!(Arc::ptr_eq(&handlers[1].1, &first));
    assert!(
        extensions
            .enable_host("example.com", ["plain"])?
            .account_handlers()
            .is_empty()
    );
    Ok(())
}

#[test]
fn iq_destination_rules_match_exact_keys_independently_of_handler_routes()
-> Result<(), RegistrationError> {
    const KEYS: [IqRequestKey; 4] = [
        IqRequestKey {
            kind: IqRequestType::Set,
            namespace: "urn:test:guard",
            name: "query",
        },
        IqRequestKey {
            kind: IqRequestType::Get,
            namespace: "urn:test:guard",
            name: "query",
        },
        IqRequestKey {
            kind: IqRequestType::Set,
            namespace: "urn:test:guard",
            name: "other",
        },
        IqRequestKey {
            kind: IqRequestType::Set,
            namespace: "urn:test:other",
            name: "query",
        },
    ];
    let mut extensions = TestExtensions::default();
    extensions.register(Arc::new(Fake {
        name: "guard",
        destinations: &KEYS,
        ..Fake::default()
    }))?;
    let enabled = extensions.enable_host("a.example", ["guard"])?;
    let disabled = extensions.enable_host("b.example", [])?;
    assert!(!enabled.iq().is_empty());
    assert!(disabled.iq().is_empty());
    for key in KEYS {
        assert_eq!(
            enabled
                .iq()
                .destination_rule(key.kind, key.namespace, key.name),
            Some(IqDestinationRule::SenderBare)
        );
        assert_eq!(
            disabled
                .iq()
                .destination_rule(key.kind, key.namespace, key.name),
            None
        );
        assert!(
            enabled
                .iq()
                .find(IqScope::Account, key.kind, key.namespace, key.name)
                .is_none()
        );
    }
    for (kind, namespace, name) in [
        (IqRequestType::Get, "urn:test:other", "query"),
        (IqRequestType::Set, "urn:test:guard", "Query"),
        (IqRequestType::Set, "URN:test:guard", "query"),
        (IqRequestType::Set, "urn:test:guard", ""),
    ] {
        assert_eq!(enabled.iq().destination_rule(kind, namespace, name), None);
    }
    Ok(())
}

#[test]
fn duplicate_iq_destination_rules_fail_in_every_registration_order() -> Result<(), RegistrationError>
{
    const KEY: IqRequestKey = IqRequestKey {
        kind: IqRequestType::Set,
        namespace: "urn:test:guard",
        name: "query",
    };
    let mut extensions = TestExtensions::default();
    for name in ["first", "second"] {
        extensions.register(Arc::new(Fake {
            name,
            destinations: &[KEY],
            ..Fake::default()
        }))?;
    }
    extensions.register(Arc::new(Fake {
        name: "repeated",
        destinations: &[KEY, KEY],
        ..Fake::default()
    }))?;
    for names in [["first", "second"], ["second", "first"]] {
        assert!(matches!(
            extensions.enable_host("a.example", names),
            Err(RegistrationError::DuplicateIqDestinationRule(KEY))
        ));
    }
    assert!(matches!(
        extensions.enable_host("a.example", ["repeated"]),
        Err(RegistrationError::DuplicateIqDestinationRule(KEY))
    ));
    for name in ["first", "second"] {
        let enabled = extensions.enable_host("a.example", [name])?;
        assert_eq!(
            enabled
                .iq()
                .destination_rule(KEY.kind, KEY.namespace, KEY.name),
            Some(IqDestinationRule::SenderBare)
        );
    }
    assert_eq!(
        RegistrationError::DuplicateIqDestinationRule(KEY).to_string(),
        format!("conflicting IQ destination rule {KEY:?}")
    );
    Ok(())
}

impl super::iq::SessionIqHandler<GlobalChunkAllocator> for Fake {
    fn set(
        &self,
        _: super::iq::IqRequest<'_, GlobalChunkAllocator>,
        _: &mut Arena<GlobalChunkAllocator>,
    ) -> Result<super::iq::SessionIqReply, super::iq::IqError> {
        Ok(super::iq::SessionIqReply {
            payload: None,
            change: None,
        })
    }
}

#[test]
fn session_iq_routes_conflict_with_account_set_routes_in_both_orders()
-> Result<(), RegistrationError> {
    let route = IqRoute {
        kind: IqRequestType::Set,
        ..ROUTE
    };
    for session_first in [true, false] {
        let mut registry = super::ExtensionRegistry::default();
        let mut slots = Slots::new(&mut registry, "session");
        let handler = Arc::new(Fake::default());
        let result = if session_first {
            slots.session_iq(route.namespace, route.name, handler.clone())?;
            slots.iq(route, handler)
        } else {
            slots.iq(route, handler.clone())?;
            slots.session_iq(route.namespace, route.name, handler)
        };
        assert_eq!(result, Err(RegistrationError::DuplicateRoute(route)));
    }
    Ok(())
}

#[test]
fn session_iq_routes_conflict_with_each_other() -> Result<(), RegistrationError> {
    let mut registry = super::ExtensionRegistry::<GlobalChunkAllocator, RedbStorage>::default();
    let mut slots = Slots::new(&mut registry, "session");
    let handler = Arc::new(Fake::default());
    slots.session_iq(ROUTE.namespace, ROUTE.name, handler.clone())?;
    assert_eq!(
        slots.session_iq(ROUTE.namespace, ROUTE.name, handler),
        Err(RegistrationError::DuplicateRoute(IqRoute {
            kind: IqRequestType::Set,
            ..ROUTE
        }))
    );
    assert!(!registry.iq.is_empty());
    Ok(())
}

#[test]
fn session_iq_lookup_matches_only_exact_expanded_names() -> Result<(), RegistrationError> {
    let mut registry = super::ExtensionRegistry::default();
    let handler: Arc<dyn super::iq::SessionIqHandler<GlobalChunkAllocator>> =
        Arc::new(Fake::default());
    for (namespace, name) in [("urn:z", "a"), ("urn:a", "z"), ("urn:a", "a")] {
        let mut slots = Slots::new(&mut registry, "session");
        slots.session_iq(namespace, name, handler.clone())?;
        for (scope, kind) in [
            (IqScope::Server, IqRequestType::Set),
            (IqScope::Account, IqRequestType::Get),
        ] {
            slots.iq(
                IqRoute {
                    scope,
                    kind,
                    namespace,
                    name,
                },
                Arc::new(Fake::default()),
            )?;
        }
    }
    for (namespace, name) in [("urn:z", "a"), ("urn:a", "z"), ("urn:a", "a")] {
        assert!(
            registry
                .iq
                .find_session(namespace, name)
                .is_some_and(|found| Arc::ptr_eq(found, &handler))
        );
    }
    for (namespace, name) in [
        ("urn:z", "z"),
        ("urn:A", "a"),
        ("urn:a", "A"),
        ("", "a"),
        ("urn:a", ""),
    ] {
        assert!(registry.iq.find_session(namespace, name).is_none());
    }
    Ok(())
}
