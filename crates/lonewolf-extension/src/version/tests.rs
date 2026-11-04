// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;

use futures_executor::block_on;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;

use super::*;
use crate::delivery::{BoundResource, DeliveryError, SessionLookup};
use crate::discovery::Discovery;
use crate::presence::PresenceRequestType;
use crate::{EnableError, ExtensionFuture, Extensions, HostSelection};

type TestResult = Result<(), Box<dyn Error>>;
type TestArena = Arena<GlobalChunkAllocator>;
type TestExtensions = Extensions<GlobalChunkAllocator, RedbStorage>;

const SERVER_VERSION: &str = "1.2.3-test";
const REPLY: &str =
    "<query xmlns=\"jabber:iq:version\"><name>Lonewolf</name><version>1.2.3-test</version></query>";

fn catalog() -> Result<TestExtensions, RegistrationError> {
    let mut catalog = TestExtensions::default();
    catalog.register_factory(Box::new(VersionFactory::new(SERVER_VERSION)))?;
    Ok(catalog)
}

struct UnexpectedSessions;

impl SessionLookup for UnexpectedSessions {
    fn resources<'a>(
        &'a self,
        _: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("version must not inspect sessions")
    }
}

fn request<'a>(
    arena: &'a TestArena,
    sender: Jid,
    target: Jid,
    payload: Element,
    discovery: &'a Discovery,
) -> Result<IqRequest<'a, GlobalChunkAllocator>, Box<dyn Error>> {
    Ok(IqRequest {
        sender: sender.resolve(arena)?,
        target: target.resolve(arena)?,
        payload: payload.resolve(arena)?,
        discovery,
        sessions: &UnexpectedSessions,
        requester: None,
        lang: None,
        space: None,
    })
}

fn serialize(element: Element, arena: &TestArena) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    element.resolve(arena)?.write_xml(&mut output)?;
    Ok(output)
}

#[test]
fn version_registers_only_the_server_get_route_and_feature() -> TestResult {
    let registries = catalog()?.enable(&[HostSelection {
        domain: "example.com",
        extensions: &[NAME.into()],
        options: &BTreeMap::new(),
    }])?;
    let registry = &registries["example.com"];
    assert!(
        registry
            .iq()
            .find(IqScope::Server, IqRequestType::Get, NAMESPACE, "query")
            .is_some()
    );
    for (scope, kind, namespace, name) in [
        (IqScope::Server, IqRequestType::Set, NAMESPACE, "query"),
        (IqScope::Account, IqRequestType::Get, NAMESPACE, "query"),
        (IqScope::Account, IqRequestType::Set, NAMESPACE, "query"),
        (IqScope::Server, IqRequestType::Get, "urn:wrong", "query"),
        (IqScope::Server, IqRequestType::Get, NAMESPACE, "version"),
    ] {
        assert!(registry.iq().find(scope, kind, namespace, name).is_none());
    }
    assert_eq!(
        registry.discovery().features(DiscoScope::Server),
        [NAMESPACE]
    );
    assert!(
        registry
            .discovery()
            .features(DiscoScope::Account)
            .is_empty()
    );
    for scope in [DiscoScope::Server, DiscoScope::Account] {
        assert!(registry.discovery().identities(scope).is_empty());
    }
    assert!(registry.services().is_empty());
    assert_eq!(registry.enabled(), [NAME]);
    for kind in PresenceRequestType::ALL {
        assert!(registry.presence().find(kind).is_none());
    }
    assert!(registry.stream_features().is_empty());
    Ok(())
}

#[test]
fn replies_name_the_server_and_its_release_without_os_by_default() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    for setting in [None, Some(""), Some("show_os = false")] {
        let mut options = BTreeMap::new();
        if let Some(setting) = setting {
            options.insert(NAME.into(), toml::from_str(setting)?);
        }
        let registries = catalog()?.enable(&[HostSelection {
            domain: "example.com",
            extensions: &[NAME.into()],
            options: &options,
        }])?;
        let registry = &registries["example.com"];
        let handler = registry
            .iq()
            .find(IqScope::Server, IqRequestType::Get, NAMESPACE, "query")
            .ok_or("missing version route")?;
        let mut arena = TestArena::try_new(ArenaConfig::default())?;
        let sender = Jid::parse_in("alice@example.com/desk", &mut arena)?;
        let target = Jid::parse_in("example.com", &mut arena)?;
        let payload = Element::builder_in("query", NAMESPACE, &mut arena)?.build()?;
        let mut response = TestArena::try_new(ArenaConfig::default())?;
        let reply = block_on(handler.get(
            request(&arena, sender, target, payload, registry.discovery())?,
            &transaction,
            &mut response,
        ))
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            serialize(reply.payload.ok_or("missing reply")?, &response)?,
            REPLY
        );
        assert!(reply.results.is_empty());
        assert!(reply.effects.accounts.is_empty());
    }
    Ok(())
}

#[test]
fn os_is_shared_only_for_hosts_that_enable_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    let options = BTreeMap::from([(NAME.into(), toml::from_str("show_os = true")?)]);
    let registries = catalog()?.enable(&[
        HostSelection {
            domain: "os.example",
            extensions: &[NAME.into()],
            options: &options,
        },
        HostSelection {
            domain: "plain.example",
            extensions: &[NAME.into()],
            options: &BTreeMap::new(),
        },
    ])?;
    let os_reply = format!(
        "<query xmlns=\"jabber:iq:version\"><name>Lonewolf</name><version>1.2.3-test</version><os>{}</os></query>",
        std::env::consts::OS
    );
    for (domain, expected) in [("os.example", os_reply.as_str()), ("plain.example", REPLY)] {
        let registry = &registries[domain];
        let handler = registry
            .iq()
            .find(IqScope::Server, IqRequestType::Get, NAMESPACE, "query")
            .ok_or("missing version route")?;
        let mut arena = TestArena::try_new(ArenaConfig::default())?;
        let sender = Jid::parse_in("alice@plain.example/desk", &mut arena)?;
        let target = Jid::parse_in(domain, &mut arena)?;
        let payload = Element::builder_in("query", NAMESPACE, &mut arena)?.build()?;
        let mut response = TestArena::try_new(ArenaConfig::default())?;
        let reply = block_on(handler.get(
            request(&arena, sender, target, payload, registry.discovery())?,
            &transaction,
            &mut response,
        ))
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            serialize(reply.payload.ok_or("missing reply")?, &response)?,
            expected
        );
    }
    Ok(())
}

#[test]
fn request_contents_and_senders_do_not_change_the_reply() -> TestResult {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let transaction = block_on(storage.begin_read())?;
    let registries = catalog()?.enable(&[HostSelection {
        domain: "example.com",
        extensions: &[NAME.into()],
        options: &BTreeMap::new(),
    }])?;
    let registry = &registries["example.com"];
    let handler = registry
        .iq()
        .find(IqScope::Server, IqRequestType::Get, NAMESPACE, "query")
        .ok_or("missing version route")?;
    for sender in [
        "alice@example.com/desk",
        "remote.example",
        "bob@remote.example/phone",
    ] {
        let mut arena = TestArena::try_new(ArenaConfig::default())?;
        let sender = Jid::parse_in(sender, &mut arena)?;
        let target = Jid::parse_in("example.com", &mut arena)?;
        let name = Element::builder_in("name", NAMESPACE, &mut arena)?
            .text("Spoofed")?
            .build()?;
        let version = Element::builder_in("version", NAMESPACE, &mut arena)?
            .text("Spoofed")?
            .build()?;
        let os = Element::builder_in("os", NAMESPACE, &mut arena)?
            .text("Spoofed")?
            .build()?;
        let child = Element::builder_in("child", "urn:other", &mut arena)?.build()?;
        let payloads = [
            Element::builder_in("query", NAMESPACE, &mut arena)?.build()?,
            Element::builder_in("query", NAMESPACE, &mut arena)?
                .attribute("extra", "", "1")?
                .build()?,
            Element::builder_in("query", NAMESPACE, &mut arena)?
                .text("text")?
                .build()?,
            Element::builder_in("query", NAMESPACE, &mut arena)?
                .child(name)?
                .child(version)?
                .child(os)?
                .build()?,
            Element::builder_in("query", NAMESPACE, &mut arena)?
                .child(child)?
                .build()?,
        ];
        for payload in payloads {
            let mut response = TestArena::try_new(ArenaConfig::default())?;
            let reply = block_on(handler.get(
                request(&arena, sender, target, payload, registry.discovery())?,
                &transaction,
                &mut response,
            ))
            .map_err(|error| format!("{error:?}"))?;
            assert_eq!(
                serialize(reply.payload.ok_or("missing reply")?, &response)?,
                REPLY
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_options_identify_the_host_and_extension() -> TestResult {
    let catalog = catalog()?;
    for setting in [
        "show_os = 'yes'",
        "show_os = 1",
        "unknown = true",
        "show_os = true\nunknown = 1",
    ] {
        let options = BTreeMap::from([(NAME.into(), toml::from_str(setting)?)]);
        let error = catalog
            .enable(&[
                HostSelection {
                    domain: "valid.example",
                    extensions: &[NAME.into()],
                    options: &BTreeMap::new(),
                },
                HostSelection {
                    domain: "invalid.example",
                    extensions: &[NAME.into()],
                    options: &options,
                },
            ])
            .err()
            .ok_or("invalid options accepted")?;
        assert_eq!(error.host, "invalid.example");
        assert!(
            matches!(error.source, RegistrationError::InvalidOptions { extension: NAME, ref reason } if !reason.is_empty()),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn options_require_the_extension_to_be_enabled() -> TestResult {
    let options = BTreeMap::from([(NAME.into(), toml::from_str("show_os = true")?)]);
    assert!(matches!(catalog()?.enable(&[HostSelection {
        domain: "example.com",
        extensions: &[],
        options: &options,
    }]), Err(EnableError { source: RegistrationError::OptionsWithoutExtension(name), .. }) if name == NAME));
    Ok(())
}
