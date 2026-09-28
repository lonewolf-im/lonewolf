// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_util::arena::{Arena, GlobalChunkAllocator};

use super::iq::{
    IqFuture, IqHandler, IqRegistration, IqRequest, IqRequestType, IqResponse, IqRoute, IqScope,
};
use super::presence::{
    PresenceDirection, PresenceEffect, PresenceFuture, PresenceHandler, PresenceRegistration,
    PresenceRequest, PresenceRequestType, PresenceRoute,
};
use super::{Extensions, RegistrationError};

const ROUTE: IqRoute = IqRoute {
    scope: IqScope::Account,
    kind: IqRequestType::Get,
    namespace: "urn:test:iq",
    name: "query",
};

const PRESENCE_ROUTE: PresenceRoute = PresenceRoute {
    direction: PresenceDirection::Outbound,
    kind: PresenceRequestType::Subscribe,
};

struct Empty;

struct EmptyPresence;

impl IqHandler<GlobalChunkAllocator> for Empty {
    fn handle<'a>(
        &'a self,
        _: IqRequest<'a, GlobalChunkAllocator>,
        _: &'a mut Arena<GlobalChunkAllocator>,
    ) -> IqFuture<'a> {
        Box::pin(async { Ok(IqResponse::new(None)) })
    }
}

fn handler() -> IqRegistration<GlobalChunkAllocator> {
    IqRegistration::new(ROUTE, Arc::new(Empty))
}

fn presence_handler(route: PresenceRoute) -> PresenceRegistration<GlobalChunkAllocator> {
    PresenceRegistration::new(route, Arc::new(EmptyPresence))
}

impl PresenceHandler<GlobalChunkAllocator> for EmptyPresence {
    fn handle<'a>(&'a self, _: PresenceRequest<'a, GlobalChunkAllocator>) -> PresenceFuture<'a> {
        Box::pin(async { Ok(PresenceEffect::None) })
    }
}

#[test]
fn conflicting_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register("first", [handler()], [])?;
    extensions.register("second", [handler()], [])?;
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
        extensions.register("example", [handler(), handler()], []),
        Err(RegistrationError::DuplicateRoute(ROUTE))
    );
    extensions.register("example", [handler()], [])?;
    assert!(extensions.enable(["example"]).is_ok());
    Ok(())
}

#[test]
fn duplicate_extension_names_cannot_replace_handlers() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register("example", [handler()], [])?;
    assert_eq!(
        extensions.register("example", [], []),
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
    let mut extensions = Extensions::<GlobalChunkAllocator>::default();
    for name in ["", " ", " leading", "trailing "] {
        assert_eq!(
            extensions.register(name, [], []),
            Err(RegistrationError::InvalidExtensionName)
        );
    }
}

#[test]
fn repeated_activation_is_rejected_even_without_iq_handlers() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::<GlobalChunkAllocator>::default();
    extensions.register("example", [], [])?;
    assert!(matches!(
        extensions.enable(["example", "example"]),
        Err(RegistrationError::DuplicateExtension("example"))
    ));
    Ok(())
}

#[test]
fn conflicting_presence_extensions_cannot_be_enabled_together() -> Result<(), RegistrationError> {
    let mut extensions = Extensions::default();
    extensions.register("first", [], [presence_handler(PRESENCE_ROUTE)])?;
    extensions.register("second", [], [presence_handler(PRESENCE_ROUTE)])?;
    assert!(matches!(
        extensions.enable(["first", "second"]),
        Err(RegistrationError::DuplicatePresenceRoute(PRESENCE_ROUTE))
    ));
    assert!(matches!(
        extensions.enable(["second", "first"]),
        Err(RegistrationError::DuplicatePresenceRoute(PRESENCE_ROUTE))
    ));
    Ok(())
}

#[test]
fn presence_direction_selects_a_distinct_handler() -> Result<(), RegistrationError> {
    let inbound = PresenceRoute {
        direction: PresenceDirection::Inbound,
        ..PRESENCE_ROUTE
    };
    let mut extensions = Extensions::default();
    extensions.register(
        "example",
        [],
        [presence_handler(PRESENCE_ROUTE), presence_handler(inbound)],
    )?;
    let enabled = extensions.enable(["example"])?;
    assert!(
        enabled
            .presence()
            .find(PRESENCE_ROUTE.direction, PRESENCE_ROUTE.kind)
            .is_some()
    );
    assert!(
        enabled
            .presence()
            .find(inbound.direction, inbound.kind)
            .is_some()
    );
    Ok(())
}
