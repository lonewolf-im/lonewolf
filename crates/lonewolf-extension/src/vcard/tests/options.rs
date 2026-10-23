// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::*;
use crate::discovery::DiscoScope;
use crate::iq::{IqDestinationRule, IqRequestType, IqScope};
use crate::{ExtensionFactory, Extensions, HostOptions, HostSelection};

#[test]
fn strict_options_defaults_boundaries_and_host_quota_isolation() -> TestResult {
    let defaults: super::super::VCardOptions = toml::from_str("")?;
    assert_eq!(defaults.max_bytes.get(), 262_144);
    for valid in [1, 262_144, 1_048_576] {
        let options: super::super::VCardOptions = toml::from_str(&format!("max_bytes={valid}"))?;
        assert_eq!(options.max_bytes.get(), valid);
    }
    for invalid in [
        "max_bytes=0",
        "max_bytes=-1",
        "max_bytes=1.5",
        "max_bytes='4'",
        "max_bytes=true",
        "max_bytes=18446744073709551616",
        "unknown=1",
        "max_bytes=1048577",
    ] {
        let table: Result<toml::Table, _> = toml::from_str(invalid);
        if let Ok(table) = table {
            let factory: &dyn ExtensionFactory<GlobalChunkAllocator, RedbStorage> =
                &super::super::VCardFactory;
            assert!(
                factory
                    .build(&[HostOptions {
                        domain: "invalid.example",
                        options: Some(&table)
                    }])
                    .is_err(),
                "{invalid}"
            );
        }
    }
    let extension = VCard::new(BTreeMap::from([
        ("example.com".into(), quota(100)?),
        ("other.example".into(), quota(200)?),
    ]));
    assert_eq!(
        extension.quota(&key("alice@example.com")?).max_bytes.get(),
        100
    );
    assert_eq!(
        extension
            .quota(&key("alice@other.example")?)
            .max_bytes
            .get(),
        200
    );
    assert_eq!(
        extension.quota(&key("alice@default.example")?),
        VCardQuota::default()
    );
    Ok(())
}

#[test]
fn builtin_independent_selection_and_exact_route_constraint_and_discovery_inventory() -> TestResult
{
    let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    let factories = crate::builtin();
    assert_eq!(factories.len(), 6);
    assert_eq!(
        factories
            .iter()
            .filter(|factory| factory.name() == "vcard")
            .count(),
        1
    );
    for factory in factories {
        catalog.register_factory(factory)?;
    }
    for names in [
        ["vcard"].as_slice(),
        ["disco", "vcard"].as_slice(),
        ["vcard", "disco"].as_slice(),
    ] {
        let enabled = catalog.enable_host("example.com", names.iter().copied())?;
        let iq = enabled.iq();
        for kind in [IqRequestType::Get, IqRequestType::Set] {
            assert!(
                iq.find(IqScope::Account, kind, NAMESPACE, "vCard")
                    .is_some()
            );
            assert!(iq.find(IqScope::Server, kind, NAMESPACE, "vCard").is_none());
        }
        assert_eq!(
            iq.destination_rule(IqRequestType::Set, NAMESPACE, "vCard"),
            Some(IqDestinationRule::SenderBare)
        );
        assert_eq!(
            iq.destination_rule(IqRequestType::Get, NAMESPACE, "vCard"),
            None
        );
        for scope in [DiscoScope::Account, DiscoScope::Server] {
            assert_eq!(
                enabled
                    .discovery()
                    .features(scope)
                    .iter()
                    .filter(|feature| **feature == NAMESPACE)
                    .count(),
                1
            );
        }
        assert!(enabled.services().is_empty());
        assert!(enabled.account_handlers().is_empty());
        assert!(enabled.message_observers().is_empty());
        assert!(enabled.session_observers().is_empty());
        assert!(enabled.presence_decorations().is_empty());
        assert!(enabled.stream_features().is_empty());
    }
    let names = ["disco".into(), "vcard".into()];
    let tables = [
        BTreeMap::new(),
        BTreeMap::from([("vcard".into(), toml::from_str("max_bytes=100")?)]),
    ];
    let selections = [
        HostSelection {
            domain: "default.example",
            extensions: &names,
            options: &tables[0],
        },
        HostSelection {
            domain: "small.example",
            extensions: &names,
            options: &tables[1],
        },
    ];
    let enabled = catalog.enable(&selections)?;
    assert!(
        enabled["small.example"]
            .iq()
            .find(IqScope::Account, IqRequestType::Set, NAMESPACE, "vCard")
            .is_some()
    );
    Ok(())
}

fn configured_handler(domain: &str, kind: IqRequestType) -> TestResult<Arc<TestHandler>> {
    let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    for factory in crate::builtin() {
        catalog.register_factory(factory)?;
    }
    let names = ["disco".into(), "vcard".into()];
    let omitted = BTreeMap::new();
    let small = BTreeMap::from([("vcard".into(), toml::from_str("max_bytes=1")?)]);
    let enabled = catalog.enable(&[
        HostSelection {
            domain: "example.com",
            extensions: &names,
            options: &omitted,
        },
        HostSelection {
            domain: "other.example",
            extensions: &names,
            options: &small,
        },
    ])?;
    Ok(Arc::clone(
        enabled[domain]
            .iq()
            .find(IqScope::Account, kind, NAMESPACE, "vCard")
            .ok_or("missing configured handler")?,
    ))
}

#[test]
fn omitted_host_quota_publishes_the_complete_card() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        let handler = configured_handler("example.com", IqRequestType::Set)?;
        let call = Call::new("alice@example.com/desk", "alice@example.com", FIRST).await?;
        let mut response = arena()?;
        let mut transaction = test.storage.begin_write().await?;
        let reply = handler
            .set(
                call.request(None, None, None)?,
                &mut transaction,
                &NoLookups,
                &mut response,
            )
            .await
            .map_err(|error| format!("unexpected SET error: {error:?}"))?;
        assert!(reply.payload.is_none());
        assert!(reply.effects.accounts.is_empty());
        assert!(reply.results.is_empty());
        transaction.commit().await?;
        assert_eq!(
            test.stored("alice@example.com").await?,
            Some(
                r#"<vCard xmlns="vcard-temp" xml:lang="" xml:space="default"><FN>First</FN><NICKNAME>old</NICKNAME></vCard>"#.into()
            )
        );
        Ok(())
    })
}

#[test]
fn owner_host_quota_rejects_oversized_card_without_storing_it() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        let handler = configured_handler("other.example", IqRequestType::Set)?;
        let call = Call::new("alice@other.example/desk", "alice@other.example", FIRST).await?;
        let mut response = arena()?;
        let mut transaction = test.storage.begin_write().await?;
        condition(
            handler
                .set(
                    call.request(None, None, None)?,
                    &mut transaction,
                    &NoLookups,
                    &mut response,
                )
                .await,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        transaction.commit().await?;
        assert_eq!(test.stored("alice@other.example").await?, None);
        Ok(())
    })
}

#[test]
fn reader_host_quota_does_not_hide_another_hosts_complete_card() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let handler = configured_handler("example.com", IqRequestType::Get)?;
        let call = Call::new("alice@other.example/desk", "alice@example.com", EMPTY).await?;
        let mut response = arena()?;
        let snapshot = test.storage.begin_read().await?;
        let reply = handler
            .get(
                call.request(Some(Requester::Other), None, None)?,
                &snapshot,
                &mut response,
            )
            .await
            .map_err(|error| format!("unexpected GET error: {error:?}"))?;
        assert!(reply.effects.accounts.is_empty());
        assert!(reply.results.is_empty());
        assert_eq!(
            serialize(reply.payload.ok_or("missing card")?, &response)?,
            r#"<vCard xmlns="vcard-temp" xml:lang="" xml:space="default"><FN>First</FN><NICKNAME>old</NICKNAME></vCard>"#
        );
        Ok(())
    })
}
