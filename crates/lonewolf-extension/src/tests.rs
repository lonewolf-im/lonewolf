// SPDX-License-Identifier: Apache-2.0

mod options;
use std::sync::Arc;

use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbStorage, RedbWrite};
use lonewolf_util::arena::GlobalChunkAllocator;
use parking_lot::Mutex as PlMutex;

use super::account::AccountHandler;
use super::delivery::{HandlerError, HostLookup};
use super::iq::{IqHandler, IqRequestType, IqRoute, IqScope};
use super::message::MessageHandler;
use super::presence::{PresenceHandler, PresenceRequestType};
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
    presence: &'static [PresenceRequestType],
    features: &'static [&'static str],
    messages: bool,
    hosts: PlMutex<Vec<String>>,
    dependencies: &'static [&'static str],
    accounts: bool,
}

impl IqHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

impl MessageHandler<GlobalChunkAllocator, RedbStorage> for Fake {}

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
        for kind in self.presence {
            slots.presence(*kind, self.clone())?;
        }
        for feature in self.features {
            slots.stream_feature(feature);
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
        _hosts: &'a dyn HostLookup,
    ) -> ExtensionFuture<'a, Result<Effects<GlobalChunkAllocator>, HandlerError>> {
        Box::pin(async { Ok(Effects::none()) })
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
