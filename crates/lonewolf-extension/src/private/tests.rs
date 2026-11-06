// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;

use futures_executor::block_on;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::private::{PrivateXmlError, PrivateXmlReads};
use lonewolf_storage::{RedbStorage, Storage, StorageError, StorageErrorKind, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, ParserConfig, parse_element};
use lonewolf_xmpp::stanza::{Element, StanzaErrorCondition, StanzaErrorText};

use super::{NAME, NAMESPACE, PrivateFactory};
use crate::delivery::{
    BoundResource, DeliveryError, Failure, FailureKind, HostLookup, SessionLookup,
};
use crate::discovery::{DiscoScope, Discovery};
use crate::iq::{
    IqDestinationRule, IqError, IqErrorPayload, IqHandler, IqRequest, IqRequestType, IqScope,
    Requester, XmlSpace,
};
use crate::{EnableError, ExtensionFuture, ExtensionRegistry, Extensions, HostSelection};
use crate::{RegistrationError, presence::PresenceRequestType};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestHandler = dyn IqHandler<GlobalChunkAllocator, RedbStorage>;
type TestExtensions = Extensions<GlobalChunkAllocator, RedbStorage>;
type TestRegistry = ExtensionRegistry<GlobalChunkAllocator, RedbStorage>;

const ALICE: &str = "alice@example.com";
const DESK: &str = "alice@example.com/desk";
const EXODUS: &str = "<query xmlns='jabber:iq:private'><exodus xmlns='exodus:prefs'><defaultnick>Hamlet</defaultnick></exodus></query>";
const EXODUS_GET: &str = "<query xmlns='jabber:iq:private'><exodus xmlns='exodus:prefs'/></query>";

struct NoLookups;

impl HostLookup for NoLookups {
    fn is_local_host(&self, domain: &str) -> bool {
        matches!(domain, "example.com" | "other.example")
    }
}

impl SessionLookup for NoLookups {
    fn resources<'a>(
        &'a self,
        _account: &'a AccountKey,
    ) -> ExtensionFuture<'a, Result<Vec<BoundResource>, DeliveryError>> {
        panic!("private XML must not inspect sessions")
    }
}

fn arena() -> TestResult<Arena<GlobalChunkAllocator>> {
    Ok(Arena::try_new(ArenaConfig::default())?)
}

fn key(value: &str) -> TestResult<AccountKey> {
    let mut arena = arena()?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn parse(xml: &str) -> TestResult<Parsed<Element, GlobalChunkAllocator>> {
    Ok(parse_element(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4 * 1_048_576).ok_or("zero maximum")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    )
    .await?)
}

fn serialize(element: Element, arena: &Arena<GlobalChunkAllocator>) -> TestResult<String> {
    let mut output = String::new();
    element.resolve(arena)?.write_xml(&mut output)?;
    Ok(output)
}

fn catalog() -> TestResult<TestExtensions> {
    let mut catalog = TestExtensions::default();
    catalog.register_factory(Box::new(PrivateFactory))?;
    Ok(catalog)
}

fn enable(
    settings: &[(&str, Option<&str>)],
) -> Result<BTreeMap<String, TestRegistry>, EnableError> {
    let names = [NAME.to_owned()];
    let options = settings
        .iter()
        .map(|(_, setting)| match setting {
            Some(setting) => BTreeMap::from([(
                NAME.to_owned(),
                toml::from_str::<toml::Table>(setting).expect("valid TOML fixture"),
            )]),
            None => BTreeMap::new(),
        })
        .collect::<Vec<_>>();
    let selections = settings
        .iter()
        .zip(&options)
        .map(|((domain, _), options)| HostSelection {
            domain,
            extensions: &names,
            options,
        })
        .collect::<Vec<_>>();
    catalog().expect("catalog").enable(&selections)
}

struct Harness {
    storage: RedbStorage,
    registries: BTreeMap<String, TestRegistry>,
    _directory: tempfile::TempDir,
}

impl Harness {
    async fn new(settings: &[(&str, Option<&str>)]) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("private.redb"))?;
        let mut transaction = storage.begin_write().await?;
        for owner in [ALICE, "bob@example.com", "alice@other.example"] {
            transaction
                .create_account(NewAccount {
                    key: key(owner)?,
                    credentials: ScramCredentials::new(ScramVerifier::Sha1(
                        ScramSha1Verifier::new(
                            [11; 16],
                            SCRAM_POLICY_ITERATIONS,
                            [12; 20],
                            [13; 20],
                        ),
                    )),
                })
                .await?;
        }
        transaction.commit().await?;
        Ok(Self {
            storage,
            registries: enable(settings)?,
            _directory: directory,
        })
    }

    fn handler(&self, target: &str) -> TestResult<Arc<TestHandler>> {
        let domain = target.rsplit('@').next().ok_or("missing domain")?;
        let domain = domain.split('/').next().ok_or("missing domain")?;
        Ok(Arc::clone(
            self.registries
                .get(domain)
                .ok_or("host not enabled")?
                .iq()
                .find(IqScope::Account, IqRequestType::Get, NAMESPACE, "query")
                .ok_or("missing route")?,
        ))
    }

    async fn set(
        &self,
        sender: &str,
        target: &str,
        query: &str,
        lang: Option<&str>,
        space: Option<XmlSpace>,
    ) -> TestResult<Result<(), IqError>> {
        let mut identities = arena()?;
        let sender_jid = Jid::parse_in(sender, &mut identities)?;
        let target_jid = Jid::parse_in(target, &mut identities)?;
        let payload = parse(query).await?;
        let discovery = Discovery::default();
        let handler = self.handler(target)?;
        let mut transaction = self.storage.begin_write().await?;
        let mut response = arena()?;
        let result = handler
            .set(
                IqRequest {
                    sender: sender_jid.resolve(&identities)?,
                    target: target_jid.resolve(&identities)?,
                    discovery: &discovery,
                    sessions: &NoLookups,
                    requester: None,
                    lang,
                    space,
                    payload: payload.value().resolve(payload.arena())?,
                },
                &mut transaction,
                &NoLookups,
                &mut response,
            )
            .await;
        Ok(match result {
            Ok(reply) => {
                assert!(reply.payload.is_none());
                assert!(reply.effects.accounts.is_empty());
                assert!(reply.results.is_empty());
                transaction.commit().await?;
                Ok(())
            }
            Err(error) => Err(error),
        })
    }

    async fn get(
        &self,
        sender: &str,
        target: &str,
        query: &str,
    ) -> TestResult<Result<String, IqError>> {
        let mut identities = arena()?;
        let sender_jid = Jid::parse_in(sender, &mut identities)?;
        let target_jid = Jid::parse_in(target, &mut identities)?;
        let payload = parse(query).await?;
        let discovery = Discovery::default();
        let handler = self.handler(target)?;
        let transaction = self.storage.begin_read().await?;
        let mut response = arena()?;
        let result = handler
            .get(
                IqRequest {
                    sender: sender_jid.resolve(&identities)?,
                    target: target_jid.resolve(&identities)?,
                    discovery: &discovery,
                    sessions: &NoLookups,
                    requester: Some(Requester::Owner),
                    lang: Some("reader-language"),
                    space: Some(XmlSpace::Invalid),
                    payload: payload.value().resolve(payload.arena())?,
                },
                &transaction,
                &mut response,
            )
            .await;
        Ok(match result {
            Ok(reply) => {
                assert!(reply.effects.accounts.is_empty());
                assert!(reply.results.is_empty());
                Ok(serialize(
                    reply.payload.ok_or("missing payload")?,
                    &response,
                )?)
            }
            Err(error) => Err(error),
        })
    }
}

fn accepted<T>(result: Result<T, IqError>) -> TestResult<T> {
    result.map_err(|error| format!("unexpected error: {error:?}").into())
}

fn rejected<T>(result: Result<T, IqError>, condition: StanzaErrorCondition) -> TestResult<IqError> {
    let error = result.err().ok_or("unexpected success")?;
    assert_eq!(error.condition(), condition);
    assert_eq!(error.payload(), IqErrorPayload::Omit);
    Ok(error)
}

fn text(error: &IqError) -> StanzaErrorText {
    error.handler_error().text()
}

#[test]
fn private_registers_owner_routes_destination_rules_and_a_server_feature() -> TestResult {
    let registries = enable(&[("example.com", None)])?;
    let registry = &registries["example.com"];
    let iq = registry.iq();
    for kind in [IqRequestType::Get, IqRequestType::Set] {
        assert!(
            iq.find(IqScope::Account, kind, NAMESPACE, "query")
                .is_some()
        );
        assert!(iq.find(IqScope::Server, kind, NAMESPACE, "query").is_none());
        assert!(
            iq.find(IqScope::Account, kind, NAMESPACE, "storage")
                .is_none()
        );
        assert_eq!(
            iq.destination_rule(kind, NAMESPACE, "query"),
            Some(IqDestinationRule::SenderBare)
        );
        assert!(iq.find_session(NAMESPACE, "query").is_none());
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
    assert_eq!(registry.enabled(), [NAME]);
    assert!(registry.services().is_empty());
    assert!(registry.account_handlers().is_empty());
    assert!(registry.message_observers().is_empty());
    assert!(registry.session_observers().is_empty());
    assert!(registry.presence_decorations().is_empty());
    assert!(registry.policies().is_empty());
    assert!(registry.stream_features().is_empty());
    for kind in PresenceRequestType::ALL {
        assert!(registry.presence().find(kind).is_none());
    }
    Ok(())
}

#[test]
fn stored_elements_round_trip_with_materialized_language_and_space() -> TestResult {
    block_on(async {
        let test = Harness::new(&[("example.com", None)]).await?;
        test.set(DESK, ALICE, EXODUS, None, None)
            .await
            .and_then(accepted)?;
        assert_eq!(
            test.get("alice@example.com/phone", ALICE, EXODUS_GET)
                .await
                .and_then(accepted)?,
            "<query xmlns=\"jabber:iq:private\"><exodus xmlns=\"exodus:prefs\" xml:lang=\"\" xml:space=\"default\"><defaultnick>Hamlet</defaultnick></exodus></query>"
        );
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private' xml:lang='de'><a xmlns='urn:a'> x </a><b xmlns='urn:b' xml:lang='en' xml:space='default'>y</b></query>",
            Some("fr"),
            Some(XmlSpace::Preserve),
        )
        .await.and_then(accepted)?;
        assert_eq!(
            test.get(
                DESK,
                ALICE,
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/></query>"
            )
            .await
            .and_then(accepted)?,
            "<query xmlns=\"jabber:iq:private\"><a xmlns=\"urn:a\" xml:lang=\"de\" xml:space=\"preserve\"> x </a></query>"
        );
        assert_eq!(
            test.get(
                DESK,
                ALICE,
                "<query xmlns='jabber:iq:private'><b xmlns='urn:b'/></query>"
            )
            .await
            .and_then(accepted)?,
            "<query xmlns=\"jabber:iq:private\"><b xmlns=\"urn:b\" xml:lang=\"en\" xml:space=\"default\">y</b></query>"
        );
        Ok(())
    })
}

#[test]
fn missing_elements_return_only_the_requested_name_and_namespace() -> TestResult {
    block_on(async {
        let test = Harness::new(&[("example.com", None)]).await?;
        for query in [
            "<query xmlns='jabber:iq:private'><storage xmlns='storage:bookmarks'/></query>",
            "<query xmlns='jabber:iq:private'> <p:storage xmlns:p='storage:bookmarks' extra='1'><x/>text</p:storage> </query>",
        ] {
            assert_eq!(
                test.get(DESK, ALICE, query).await.and_then(accepted)?,
                "<query xmlns=\"jabber:iq:private\"><storage xmlns=\"storage:bookmarks\"/></query>"
            );
        }
        Ok(())
    })
}

#[test]
fn empty_elements_remove_data_and_the_last_change_wins() -> TestResult {
    block_on(async {
        let test = Harness::new(&[("example.com", None)]).await?;
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>1</a><b xmlns='urn:b'>1</b></query>",
            None,
            None,
        )
        .await
        .and_then(accepted)?;
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a' xmlns:unused='urn:unused'/><b xmlns='urn:b'>2</b><b xmlns='urn:b'>3</b></query>",
            None,
            None,
        )
        .await.and_then(accepted)?;
        assert_eq!(
            test.get(
                DESK,
                ALICE,
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/></query>"
            )
            .await
            .and_then(accepted)?,
            "<query xmlns=\"jabber:iq:private\"><a xmlns=\"urn:a\"/></query>"
        );
        assert_eq!(
            test.get(
                DESK,
                ALICE,
                "<query xmlns='jabber:iq:private'><b xmlns='urn:b'/></query>"
            )
            .await
            .and_then(accepted)?,
            "<query xmlns=\"jabber:iq:private\"><b xmlns=\"urn:b\" xml:lang=\"\" xml:space=\"default\">3</b></query>"
        );
        assert!(
            test.storage
                .begin_read()
                .await?
                .private_xml(&key(ALICE)?, "urn:a", "a")
                .await?
                .is_none()
        );
        Ok(())
    })
}

#[test]
fn query_content_is_validated_before_storage() -> TestResult {
    use StanzaErrorCondition::{BadRequest, NotAcceptable};
    block_on(async {
        let test = Harness::new(&[("example.com", None)]).await?;
        let none = "Include one child element with its own namespace in the private XML query.";
        let reserved = "Private XML cannot use an empty or reserved namespace, such as one that starts with jabber: or http://jabber.org/.";
        let content = "A private XML query can contain only child elements.";
        let space = "Private XML must use an xml:space value of default or preserve.";
        let cases: [(&str, bool, StanzaErrorCondition, &str); 16] = [
            (
                "<query xmlns='jabber:iq:private'/>",
                true,
                NotAcceptable,
                none,
            ),
            (
                "<query xmlns='jabber:iq:private'/>",
                false,
                NotAcceptable,
                none,
            ),
            (
                "<query xmlns='jabber:iq:private'> \n\t </query>",
                false,
                NotAcceptable,
                none,
            ),
            (
                "<query xmlns='jabber:iq:private'>text</query>",
                true,
                BadRequest,
                content,
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>1</a>text</query>",
                false,
                BadRequest,
                content,
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/><b xmlns='urn:b'/></query>",
                true,
                BadRequest,
                "Request one private XML element at a time.",
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/><a xmlns='urn:a'/></query>",
                true,
                BadRequest,
                "Request one private XML element at a time.",
            ),
            (
                "<query xmlns='jabber:iq:private'><a/></query>",
                false,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns=''>1</a></query>",
                false,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><x xmlns='jabber:x:oob'/></query>",
                true,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><query xmlns='http://jabber.org/protocol/muc'>1</query></query>",
                false,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><vCard xmlns='vcard-temp'><FN>x</FN></vCard></query>",
                false,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><features xmlns='http://etherx.jabber.org/streams'/></query>",
                true,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>1</a><message xmlns='jabber:client'/></query>",
                false,
                NotAcceptable,
                reserved,
            ),
            (
                "<query xmlns='jabber:iq:private'><a xmlns='urn:a' xml:space='keep'>1</a></query>",
                false,
                BadRequest,
                space,
            ),
            (
                "<query xmlns='jabber:iq:private' xml:space='keep'><a xmlns='urn:a'>1</a></query>",
                false,
                BadRequest,
                space,
            ),
        ];
        for (query, get, condition, expected) in cases {
            let result = if get {
                test.get(DESK, ALICE, query).await?.map(|_| ())
            } else {
                test.set(DESK, ALICE, query, None, None).await?
            };
            let error = rejected(result, condition)?;
            assert_eq!(text(&error), StanzaErrorText::Static(expected), "{query}");
        }
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private' xml:space='keep'><a xmlns='urn:a' xml:space='preserve'>1</a></query>",
            None,
            None,
        )
        .await.and_then(accepted)?;
        let read = test.storage.begin_read().await?;
        assert!(
            read.private_xml(&key(ALICE)?, "urn:b", "b")
                .await?
                .is_none()
        );
        Ok(())
    })
}

#[test]
fn targets_other_than_the_senders_bare_jid_are_forbidden() -> TestResult {
    block_on(async {
        let test = Harness::new(&[("example.com", None), ("other.example", None)]).await?;
        for target in [
            "bob@example.com",
            "alice@other.example",
            "missing@example.com",
            "alice@example.com/desk",
        ] {
            let error = rejected(
                test.set(DESK, target, EXODUS, None, None).await?,
                StanzaErrorCondition::Forbidden,
            )?;
            assert_eq!(text(&error), StanzaErrorCondition::Forbidden.default_text());
            rejected(
                test.get(DESK, target, EXODUS_GET).await?,
                StanzaErrorCondition::Forbidden,
            )?;
        }
        for owner in [ALICE, "bob@example.com", "alice@other.example"] {
            assert!(
                test.storage
                    .begin_read()
                    .await?
                    .private_xml(&key(owner)?, "exodus:prefs", "exodus")
                    .await?
                    .is_none()
            );
        }
        Ok(())
    })
}

#[test]
fn limits_follow_the_owners_host_and_report_exact_texts() -> TestResult {
    block_on(async {
        let test = Harness::new(&[
            ("example.com", Some("max_items = 1\nmax_bytes = 120")),
            ("other.example", None),
        ])
        .await?;
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>1</a></query>",
            None,
            None,
        )
        .await
        .and_then(accepted)?;
        let error = rejected(
            test.set(
                DESK,
                ALICE,
                "<query xmlns='jabber:iq:private'><b xmlns='urn:b'>1</b></query>",
                None,
                None,
            )
            .await?,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert_eq!(
            text(&error),
            StanzaErrorText::TwoLimits {
                parts: &[
                    "Private XML storage for this account is limited to ",
                    " elements and ",
                    " bytes. Remove stored elements or store less XML.",
                ],
                values: [1, 120],
            }
        );
        let large = format!(
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>{}</a></query>",
            "x".repeat(120)
        );
        let error = rejected(
            test.set(DESK, ALICE, &large, None, None).await?,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert_eq!(
            text(&error),
            StanzaErrorText::TwoLimits {
                parts: &[
                    "Private XML storage for this account is limited to ",
                    " elements and ",
                    " bytes. Remove stored elements or store less XML.",
                ],
                values: [1, 120],
            }
        );
        test.set(
            "alice@other.example/desk",
            "alice@other.example",
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a'>1</a><b xmlns='urn:b'>1</b></query>",
            None,
            None,
        )
        .await
        .and_then(accepted)?;
        test.set(
            DESK,
            ALICE,
            "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/><b xmlns='urn:b'>2</b></query>",
            None,
            None,
        )
        .await
        .and_then(accepted)?;

        let mut large_test = Harness::new(&[("example.com", None)]).await?;
        let large = "x".repeat(1_048_577);
        let same = "y".repeat(large.len());
        let smaller = "z".repeat(large.len() - 1);
        let stored_query = |value: &str| {
            format!("<query xmlns='jabber:iq:private'><a xmlns='urn:a'>{value}</a></query>")
        };
        large_test
            .set(DESK, ALICE, &stored_query(&large), None, None)
            .await
            .and_then(accepted)?;
        large_test.registries =
            enable(&[("example.com", Some("max_items = 50\nmax_bytes = 128"))])?;
        for value in [&same, &smaller] {
            large_test
                .set(DESK, ALICE, &stored_query(value), None, None)
                .await
                .and_then(accepted)?;
            assert_eq!(
                large_test
                    .get(
                        DESK,
                        ALICE,
                        "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/></query>"
                    )
                    .await
                    .and_then(accepted)?,
                format!(
                    "<query xmlns=\"jabber:iq:private\"><a xmlns=\"urn:a\" xml:lang=\"\" xml:space=\"default\">{value}</a></query>"
                )
            );
        }
        let error = rejected(
            large_test
                .set(DESK, ALICE, &stored_query(&large), None, None)
                .await?,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert_eq!(
            text(&error),
            StanzaErrorText::TwoLimits {
                parts: &[
                    "Private XML storage for this account is limited to ",
                    " elements and ",
                    " bytes. Remove stored elements or store less XML.",
                ],
                values: [50, 128],
            }
        );
        assert_eq!(
            large_test
                .get(
                    DESK,
                    ALICE,
                    "<query xmlns='jabber:iq:private'><a xmlns='urn:a'/></query>"
                )
                .await
                .and_then(accepted)?,
            format!(
                "<query xmlns=\"jabber:iq:private\"><a xmlns=\"urn:a\" xml:lang=\"\" xml:space=\"default\">{smaller}</a></query>"
            )
        );
        Ok(())
    })
}

#[test]
fn invalid_options_identify_the_host_and_extension() -> TestResult {
    for setting in [
        "max_items = 0",
        "max_bytes = 0",
        "max_items = -1",
        "max_bytes = 'large'",
        "max_items = 1.5",
        "unknown = 1",
    ] {
        let result = enable(&[("valid.example", None), ("invalid.example", Some(setting))]);
        assert!(
            matches!(
                &result,
                Err(EnableError {
                    host,
                    source: RegistrationError::InvalidOptions { extension: "private", .. },
                }) if host == "invalid.example"
            ),
            "{setting}"
        );
    }
    let defaults: super::PrivateOptions = toml::from_str("")?;
    assert_eq!(defaults.max_items.get(), 50);
    assert_eq!(defaults.max_bytes.get(), 2_097_152);
    Ok(())
}

#[test]
fn options_require_the_extension_to_be_enabled() -> TestResult {
    let options = BTreeMap::from([(
        NAME.to_owned(),
        toml::from_str::<toml::Table>("max_items = 5")?,
    )]);
    let result = catalog()?.enable(&[HostSelection {
        domain: "example.com",
        extensions: &[],
        options: &options,
    }]);
    assert!(matches!(
        result,
        Err(EnableError {
            source: RegistrationError::OptionsWithoutExtension(name),
            ..
        }) if name == NAME
    ));
    Ok(())
}

#[test]
fn corrupt_records_map_to_payload_free_internal_failures() -> TestResult {
    block_on(async {
        let requested = parse("<a xmlns='urn:a'/>").await?;
        let requested = requested.value().resolve(requested.arena())?;
        let mut response = arena()?;
        for xml in [
            "",
            "<a xmlns='urn:a' xml:space='default'>1</a>",
            "<a xmlns='urn:a' xml:lang=''>1</a>",
            "<a xmlns='urn:a' xml:lang='' xml:space='keep'>1</a>",
            "<b xmlns='urn:a' xml:lang='' xml:space='default'>1</b>",
            "<a xmlns='urn:b' xml:lang='' xml:space='default'>1</a>",
            "<a xmlns='urn:a' xml:lang='' xml:space='default'>",
            "<a xmlns='urn:a' xml:lang='' xml:space='default'/><a/>",
        ] {
            let error = super::decode(xml, &requested, &mut response)
                .await
                .err()
                .ok_or("corrupt record decoded")?;
            assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
            assert_eq!(
                error.failure(),
                Some(Failure {
                    kind: FailureKind::Storage(StorageErrorKind::CorruptData),
                    operation: "private_xml_decode",
                }),
                "{xml}"
            );
        }
        let decoded = super::decode(
            "<a xmlns='urn:a' xml:lang='' xml:space='default'>ok</a>",
            &requested,
            &mut response,
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            serialize(decoded, &response)?,
            "<a xmlns=\"urn:a\" xml:lang=\"\" xml:space=\"default\">ok</a>"
        );
        let error = super::storage_error(
            PrivateXmlError::Storage(StorageError::new(StorageErrorKind::CorruptData)),
            "private_xml_read",
        );
        assert_eq!(
            error.failure(),
            Some(Failure {
                kind: FailureKind::Storage(StorageErrorKind::CorruptData),
                operation: "private_xml_read",
            })
        );
        Ok(())
    })
}

#[test]
fn deleted_owner_accounts_answer_service_unavailable() -> TestResult {
    block_on(async {
        let test = Harness::new(&[("example.com", None)]).await?;
        let mut transaction = test.storage.begin_write().await?;
        transaction.delete_account(&key(ALICE)?).await?;
        transaction.commit().await?;
        rejected(
            test.set(DESK, ALICE, EXODUS, None, None).await?,
            StanzaErrorCondition::ServiceUnavailable,
        )?;
        let mut identities = arena()?;
        let sender = Jid::parse_in(DESK, &mut identities)?;
        let target = Jid::parse_in(ALICE, &mut identities)?;
        let payload = parse(EXODUS_GET).await?;
        let discovery = Discovery::default();
        let mut response = arena()?;
        rejected(
            test.handler(ALICE)?.get_missing_account(
                IqRequest {
                    sender: sender.resolve(&identities)?,
                    target: target.resolve(&identities)?,
                    discovery: &discovery,
                    sessions: &NoLookups,
                    requester: Some(Requester::Owner),
                    lang: None,
                    space: None,
                    payload: payload.value().resolve(payload.arena())?,
                },
                &mut response,
            ),
            StanzaErrorCondition::ServiceUnavailable,
        )?;
        Ok(())
    })
}
