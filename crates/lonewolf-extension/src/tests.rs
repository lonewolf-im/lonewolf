// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_util::arena::GlobalChunkAllocator;

use super::iq::{IqHandler, IqRequestType, IqRoute, IqScope};
use super::presence::{PresenceHandler, PresenceRequestType};
use super::{Extension, Extensions, RegistrationError};

const ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:test:iq",
    name: "query",
};

struct Fake {
    name: &'static str,
    iq: &'static [IqRoute],
    presence: &'static [PresenceRequestType],
}

impl IqHandler<GlobalChunkAllocator> for Fake {}

impl PresenceHandler<GlobalChunkAllocator> for Fake {}

impl Extension<GlobalChunkAllocator> for Fake {
    fn name(&self) -> &'static str {
        self.name
    }

    fn iq_routes(&self) -> &'static [IqRoute] {
        self.iq
    }

    fn presence_kinds(&self) -> &'static [PresenceRequestType] {
        self.presence
    }
}

fn extension(
    name: &'static str,
    iq: &'static [IqRoute],
    presence: &'static [PresenceRequestType],
) -> Arc<dyn Extension<GlobalChunkAllocator>> {
    Arc::new(Fake { name, iq, presence })
}

#[test]
fn conflicting_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register(extension("first", &[ROUTE], &[]))?;
    extensions.register(extension("second", &[ROUTE], &[]))?;
    assert!(extensions.enable(["first"]).is_ok());
    assert!(extensions.enable(["second"]).is_ok());
    assert!(matches!(
        extensions.enable(["first", "second"]),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    ));
    assert!(matches!(
        extensions.enable(["second", "first"]),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    ));
    Ok(())
}

#[test]
fn failed_registration_does_not_reserve_an_extension_name() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    assert_eq!(
        extensions.register(extension("example", &[ROUTE, ROUTE], &[])),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    );
    extensions.register(extension("example", &[ROUTE], &[]))?;
    assert!(extensions.enable(["example"]).is_ok());
    Ok(())
}

#[test]
fn duplicate_extension_names_cannot_replace_handlers() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register(extension("example", &[ROUTE], &[]))?;
    assert_eq!(
        extensions.register(extension("example", &[], &[])),
        Err(RegistrationError::DuplicateExtension("example"))
    );
    let enabled = extensions.enable(["example"])?;
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
    let extensions = Extensions::<GlobalChunkAllocator>::default();
    assert!(
        matches!(extensions.enable(["missing"]), Err(RegistrationError::UnknownExtension(name)) if name == "missing")
    );
}

#[test]
fn extension_names_must_be_nonempty_and_trimmed() {
    let mut extensions = Extensions::default();
    for name in ["", " ", " leading", "trailing "] {
        assert_eq!(
            extensions.register(extension(name, &[], &[])),
            Err(RegistrationError::InvalidExtensionName)
        );
    }
}

#[test]
fn repeated_activation_is_rejected_even_without_iq_handlers() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register(extension("example", &[], &[]))?;
    assert!(matches!(
        extensions.enable(["example", "example"]),
        Err(RegistrationError::DuplicateExtension("example"))
    ));
    Ok(())
}

#[test]
fn conflicting_presence_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register(extension("first", &[], &[PresenceRequestType::Subscribe]))?;
    extensions.register(extension("second", &[], &[PresenceRequestType::Subscribe]))?;
    assert!(matches!(
        extensions.enable(["first", "second"]),
        Err(RegistrationError::DuplicatePresenceRoute(
            PresenceRequestType::Subscribe
        ))
    ));
    assert!(matches!(
        extensions.enable(["second", "first"]),
        Err(RegistrationError::DuplicatePresenceRoute(
            PresenceRequestType::Subscribe
        ))
    ));
    Ok(())
}

#[test]
fn presence_kinds_select_distinct_handlers() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register(extension(
        "example",
        &[],
        &[
            PresenceRequestType::Subscribe,
            PresenceRequestType::Subscribed,
        ],
    ))?;
    let enabled = extensions.enable(["example"])?;
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
