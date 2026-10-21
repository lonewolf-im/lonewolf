// SPDX-License-Identifier: Apache-2.0

mod options;
mod xml;

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroUsize;

use futures_executor::block_on;
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_storage::account::{AccountKey, AccountWrites, NewAccount};
use lonewolf_storage::vcard::{VCardQuota, VCardReads, VCardWrites};
use lonewolf_storage::{RedbStorage, Storage, StorageError, StorageErrorKind, WriteTransaction};
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, ParserConfig, parse_element};
use lonewolf_xmpp::stanza::{Element, StanzaErrorCondition};

use super::{NAMESPACE, VCard};
use crate::ExtensionFuture;
use crate::delivery::{BoundResource, DeliveryError, HostLookup, SessionLookup};
use crate::discovery::Discovery;
use crate::iq::{IqError, IqErrorPayload, IqHandler, IqRequest, Requester, XmlSpace};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestHandler = dyn IqHandler<GlobalChunkAllocator, RedbStorage>;

const EMPTY: &str = "<vCard xmlns='vcard-temp'/>";
const FIRST: &str = "<vCard xmlns='vcard-temp'><FN>First</FN><NICKNAME>old</NICKNAME></vCard>";
const SECOND: &str = "<vCard xmlns='vcard-temp'><FN>Second</FN></vCard>";

fn quota(bytes: usize) -> TestResult<VCardQuota> {
    Ok(VCardQuota {
        max_bytes: NonZeroUsize::new(bytes).ok_or("zero quota")?,
    })
}

fn arena() -> TestResult<Arena<GlobalChunkAllocator>> {
    Ok(Arena::try_new(ArenaConfig::default())?)
}

fn key(value: &str) -> TestResult<AccountKey> {
    let mut arena = arena()?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn payload(xml: &str) -> TestResult<Parsed<Element, GlobalChunkAllocator>> {
    parse_payload(xml, ArenaConfig::default()).await
}

async fn parse_payload(
    xml: &str,
    config: ArenaConfig,
) -> TestResult<Parsed<Element, GlobalChunkAllocator>> {
    Ok(parse_element(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(1_048_576).ok_or("zero maximum")?,
            arena: config,
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
        panic!("vCard must not inspect presence or sessions")
    }
}

struct Call {
    identities: Arena<GlobalChunkAllocator>,
    sender: Jid,
    target: Jid,
    payload: Parsed<Element, GlobalChunkAllocator>,
    payload_element: Element,
    discovery: Discovery,
}
impl Call {
    async fn new(sender: &str, target: &str, xml: &str) -> TestResult<Self> {
        Self::with_payload(sender, target, payload(xml).await?)
    }
    fn with_payload(
        sender: &str,
        target: &str,
        payload: Parsed<Element, GlobalChunkAllocator>,
    ) -> TestResult<Self> {
        let mut identities = arena()?;
        let sender = Jid::parse_in(sender, &mut identities)?;
        let target = Jid::parse_in(target, &mut identities)?;
        Ok(Self {
            identities,
            sender,
            target,
            payload_element: payload.value(),
            payload,
            discovery: Discovery::default(),
        })
    }
    fn request<'a>(
        &'a self,
        requester: Option<Requester>,
        lang: Option<&'a str>,
        space: Option<XmlSpace>,
    ) -> TestResult<IqRequest<'a, GlobalChunkAllocator>> {
        Ok(IqRequest {
            sender: self.sender.resolve(&self.identities)?,
            target: self.target.resolve(&self.identities)?,
            discovery: &self.discovery,
            sessions: &NoLookups,
            requester,
            lang,
            space,
            payload: self.payload_element.resolve(self.payload.arena())?,
        })
    }
}

struct TestVCard {
    storage: RedbStorage,
    extension: VCard,
    _directory: tempfile::TempDir,
}
impl TestVCard {
    async fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("vcard.redb"))?;
        let mut transaction = storage.begin_write().await?;
        for owner in [
            "alice@example.com",
            "bob@example.com",
            "alice@other.example",
        ] {
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
            extension: VCard::default(),
            _directory: directory,
        })
    }
    async fn set(
        &self,
        sender: &str,
        target: &str,
        xml: &str,
        commit: bool,
    ) -> TestResult<Result<(), IqError>> {
        let call = Call::new(sender, target, xml).await?;
        self.set_call(&call, commit).await
    }
    async fn set_call(&self, call: &Call, commit: bool) -> TestResult<Result<(), IqError>> {
        let handler: &TestHandler = &self.extension;
        let mut transaction = self.storage.begin_write().await?;
        let mut response = arena()?;
        let result = handler
            .set(
                call.request(None, None, None)?,
                &mut transaction,
                &NoLookups,
                &mut response,
            )
            .await;
        if let Ok(reply) = &result {
            assert!(reply.payload.is_none());
            assert!(reply.effects.accounts.is_empty());
            assert!(reply.results.is_empty());
        }
        if result.is_ok() && commit {
            transaction.commit().await?;
        }
        Ok(result.map(|_| ()))
    }
    async fn stored(&self, owner: &str) -> TestResult<Option<String>> {
        Ok(self
            .storage
            .begin_read()
            .await?
            .vcard(&key(owner)?)
            .await?
            .map(|card| card.xml.into()))
    }
    async fn get(
        &self,
        sender: &str,
        target: &str,
        selector: &str,
        requester: Option<Requester>,
    ) -> TestResult<Result<String, IqError>> {
        let call = Call::new(sender, target, selector).await?;
        let transaction = self.storage.begin_read().await?;
        let mut response = arena()?;
        let handler: &TestHandler = &self.extension;
        let result = handler
            .get(
                call.request(requester, Some("reader-language"), Some(XmlSpace::Invalid))?,
                &transaction,
                &mut response,
            )
            .await;
        Ok(match result {
            Ok(reply) => {
                assert!(reply.effects.accounts.is_empty());
                assert!(reply.results.is_empty());
                Ok(serialize(reply.payload.ok_or("missing card")?, &response)?)
            }
            Err(error) => Err(error),
        })
    }
}

fn accepted(result: Result<(), IqError>) -> TestResult {
    result.map_err(|error| format!("unexpected error: {error:?}").into())
}
fn condition<T>(result: Result<T, IqError>, expected: StanzaErrorCondition) -> TestResult<IqError> {
    let error = result.err().ok_or("unexpected success")?;
    assert_eq!(error.condition(), expected);
    assert_eq!(error.payload(), IqErrorPayload::Omit);
    Ok(error)
}

#[test]
fn complete_replacement_empty_publication_abort_and_consistent_snapshot() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let old = test.storage.begin_read().await?;
        let first = test
            .stored("alice@example.com")
            .await?
            .ok_or("absent first")?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", SECOND, false)
                .await?,
        )?;
        assert_eq!(
            test.stored("alice@example.com").await?.as_deref(),
            Some(first.as_str())
        );
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", SECOND, true)
                .await?,
        )?;
        let second = test
            .stored("alice@example.com")
            .await?
            .ok_or("absent second")?;
        assert!(second.contains("Second"));
        assert!(!second.contains("NICKNAME"));
        assert_eq!(
            old.vcard(&key("alice@example.com")?)
                .await?
                .ok_or("absent snapshot")?
                .xml
                .as_ref(),
            first
        );
        for empty in [
            EMPTY,
            "<vCard xmlns='vcard-temp' version='arbitrary' xml:lang='' xml:space='preserve'> \n\t </vCard>",
        ] {
            accepted(
                test.set("alice@example.com/desk", "alice@example.com", empty, true)
                    .await?,
            )?;
            let result = test
                .get(
                    "bob@example.com/phone",
                    "alice@example.com",
                    EMPTY,
                    Some(Requester::Other),
                )
                .await?
                .map_err(|error| format!("{error:?}"))?;
            assert!(result.contains("vCard"));
            assert!(!result.contains("Second"));
        }
        Ok(())
    })
}

#[test]
fn public_reads_ignore_every_selector_and_requester_without_mutation() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let before = test.stored("alice@example.com").await?;
        for requester in [
            Some(Requester::Owner),
            Some(Requester::PresenceAuthorized),
            Some(Requester::Other),
            None,
        ] {
            for selector in [
                EMPTY,
                "<vCard xmlns='vcard-temp'><FN>filter</FN></vCard>",
                "<vCard xmlns='vcard-temp' extra='opaque' xml:space='invalid'>not a profile</vCard>",
            ] {
                let result = test
                    .get(
                        "bob@example.com/desk",
                        "alice@example.com",
                        selector,
                        requester,
                    )
                    .await?
                    .map_err(|error| format!("{error:?}"))?;
                assert_eq!(Some(result), before);
                assert_eq!(test.stored("alice@example.com").await?, before);
            }
        }
        Ok(())
    })
}

#[test]
fn absence_and_missing_account_hooks_have_the_required_payload_free_shapes() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        let handler: &TestHandler = &test.extension;
        for selector in [
            EMPTY,
            "<vCard xmlns='vcard-temp' xml:space=''><FN>ignored</FN>also ignored</vCard>",
        ] {
            condition(
                test.get(
                    "alice@example.com/desk",
                    "alice@example.com",
                    selector,
                    Some(Requester::Owner),
                )
                .await?,
                StanzaErrorCondition::ItemNotFound,
            )?;
            let hidden = condition(
                test.get(
                    "bob@example.com/desk",
                    "alice@example.com",
                    selector,
                    Some(Requester::Other),
                )
                .await?,
                StanzaErrorCondition::ServiceUnavailable,
            )?;
            let call = Call::new("bob@example.com/desk", "absent@example.com", selector).await?;
            let mut response = arena()?;
            let missing = condition(
                handler.get_missing_account(call.request(None, None, None)?, &mut response),
                StanzaErrorCondition::ServiceUnavailable,
            )?;
            assert_eq!(hidden, missing);
        }
        for target in ["alice@example.com/resource", "example.com"] {
            condition(
                test.get(
                    "alice@example.com/desk",
                    target,
                    EMPTY,
                    Some(Requester::Owner),
                )
                .await?,
                StanzaErrorCondition::ServiceUnavailable,
            )?;
        }
        condition(
            test.set("absent@example.com/desk", "absent@example.com", EMPTY, true)
                .await?,
            StanzaErrorCondition::ServiceUnavailable,
        )?;
        Ok(())
    })
}

#[test]
fn authenticated_complete_target_and_normalized_keys_control_writes() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        for target in [
            "alice@example.com/desk",
            "alice@example.com/other",
            "bob@example.com",
            "alice@other.example",
            "example.com",
            "remote.example",
        ] {
            condition(
                test.set("alice@example.com/desk", target, FIRST, true)
                    .await?,
                StanzaErrorCondition::Forbidden,
            )?;
        }
        let spoof = "<vCard xmlns='vcard-temp' from='bob@example.com'><JABBERID>bob@example.com</JABBERID><FN>Unchanged DATA e&#x301; É</FN></vCard>";
        accepted(
            test.set("ALICE@EXAMPLE.COM/desk", "alice@example.com", spoof, true)
                .await?,
        )?;
        assert!(
            test.stored("alice@example.com")
                .await?
                .ok_or("missing owner")?
                .contains("bob@example.com")
        );
        assert!(test.stored("bob@example.com").await?.is_none());
        assert!(test.stored("alice@other.example").await?.is_none());
        Ok(())
    })
}

#[test]
fn rejection_and_exact_utf8_quota_preserve_previous_row_and_lower_quota_reads() -> TestResult {
    block_on(async {
        let mut test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let previous = test.stored("alice@example.com").await?;
        for xml in [
            "<vCard xmlns='vcard-temp'>direct profile text</vCard>",
            "<vCard xmlns='vcard-temp' xml:space=''/>",
            "<vCard xmlns='vcard-temp'><FN xml:space='invalid'>x</FN></vCard>",
        ] {
            condition(
                test.set("alice@example.com/desk", "alice@example.com", xml, true)
                    .await?,
                StanzaErrorCondition::BadRequest,
            )?;
            assert_eq!(test.stored("alice@example.com").await?, previous);
        }
        let unicode = "<vCard xmlns='vcard-temp' xmlns:q='urn:qname'><FN q:type='q:name'>É e&#x301; 😀</FN></vCard>";
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", unicode, true)
                .await?,
        )?;
        let stored = test
            .stored("alice@example.com")
            .await?
            .ok_or("missing unicode")?;
        test.extension = VCard::new(BTreeMap::from([(
            "example.com".into(),
            quota(stored.len())?,
        )]));
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", unicode, true)
                .await?,
        )?;
        test.extension = VCard::new(BTreeMap::from([(
            "example.com".into(),
            quota(stored.len() - 1)?,
        )]));
        condition(
            test.set("alice@example.com/desk", "alice@example.com", unicode, true)
                .await?,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert_eq!(
            test.stored("alice@example.com").await?.as_deref(),
            Some(stored.as_str())
        );
        assert_eq!(
            test.get(
                "bob@example.com/desk",
                "alice@example.com",
                EMPTY,
                Some(Requester::Other)
            )
            .await?
            .map_err(|error| format!("{error:?}"))?,
            stored
        );
        Ok(())
    })
}

#[test]
fn corrupt_persisted_profiles_are_sanitized_without_changing_the_row() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        for corrupt in [
            "not XML",
            "<vCard xmlns='vcard-temp'/>",
            "<wrong xmlns='vcard-temp' xml:lang='' xml:space='default'/>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='bad'/>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'>private data</vCard>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'><FN xml:space=''>secret</FN></vCard>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'/><second/>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'/></stream:stream>",
        ] {
            let mut transaction = test.storage.begin_write().await?;
            transaction
                .replace_vcard(&key("alice@example.com")?, corrupt, VCardQuota::default())
                .await?;
            transaction.commit().await?;
            let error = condition(
                test.get(
                    "bob@example.com/desk",
                    "alice@example.com",
                    FIRST,
                    Some(Requester::Other),
                )
                .await?,
                StanzaErrorCondition::InternalServerError,
            )?;
            assert_eq!(
                error.failure(),
                Some(super::Failure {
                    kind: super::FailureKind::Storage(StorageErrorKind::CorruptData),
                    operation: "vcard_decode"
                })
            );
            assert!(!format!("{error:?}").contains("secret"));
            assert_eq!(
                test.stored("alice@example.com").await?.as_deref(),
                Some(corrupt)
            );
        }
        for kind in StorageErrorKind::ALL {
            let error = IqError::without_payload(super::storage_error(
                lonewolf_storage::vcard::VCardError::Storage(StorageError::with_source(
                    kind,
                    std::io::Error::other("private profile bytes"),
                )),
                "vcard_read",
            ));
            assert_eq!(
                error.failure().ok_or("missing failure")?.kind,
                super::FailureKind::Storage(kind)
            );
            assert!(!format!("{error:?}").contains("private"));
            assert_eq!(error.payload(), IqErrorPayload::Omit);
        }
        Ok(())
    })
}

#[test]
fn namespace_amplification_exhausts_the_fixed_decoder_before_storage_mutation() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let previous = test.stored("alice@example.com").await?;
        let uri = format!("urn:{}", "n".repeat(10_000));
        let document = format!(
            "<vCard xmlns='vcard-temp' xmlns:q='{uri}' xml:lang='' xml:space='default'>{}</vCard>",
            "<q:X/>".repeat(1000)
        );
        assert!(document.len() < 20_000);
        let large = ArenaConfig {
            max_reserved_bytes: NonZeroUsize::new(64 * 1024 * 1024).ok_or("zero budget")?,
            ..ArenaConfig::default()
        };
        let parsed = parse_payload(&document, large).await?;
        assert!(
            parsed.arena().stats().reserved_bytes > ArenaConfig::default().max_reserved_bytes.get()
        );
        let call = Call::with_payload("alice@example.com/desk", "alice@example.com", parsed)?;
        let mut response = Arena::try_new(large)?;
        let mut transaction = test.storage.begin_write().await?;
        let handler: &TestHandler = &test.extension;
        let error = condition(
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
        assert!(error.failure().is_none());
        assert_eq!(
            transaction
                .vcard(&key("alice@example.com")?)
                .await?
                .map(|card| String::from(card.xml)),
            previous
        );
        transaction.commit().await?;
        assert_eq!(
            test.get(
                "bob@example.com/desk",
                "alice@example.com",
                EMPTY,
                Some(Requester::Other)
            )
            .await?
            .map_err(|error| format!("{error:?}"))?,
            previous.ok_or("missing previous")?
        );
        Ok(())
    })
}

#[test]
fn detached_root_attribute_growth_is_rejected_before_mutation() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let previous = test.stored("alice@example.com").await?;
        let declarations = (0..120)
            .map(|index| format!(" xmlns:p{index}='urn:{index}'"))
            .collect::<String>();
        let attributes = (0..134)
            .map(|index| format!(" a{index}='value'"))
            .collect::<String>();
        let parsed = payload(&format!(
            "<wrapper{declarations}><vCard xmlns='vcard-temp'{attributes}/></wrapper>"
        ))
        .await?;
        let element = parsed
            .value()
            .resolve(parsed.arena())?
            .child("vCard", NAMESPACE)?
            .ok_or("card")?
            .handle();
        let mut call = Call::with_payload("alice@example.com/desk", "alice@example.com", parsed)?;
        call.payload_element = element;
        condition(
            test.set_call(&call, true).await?,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert_eq!(test.stored("alice@example.com").await?, previous);
        Ok(())
    })
}

#[test]
fn response_arena_exhaustion_is_resource_constraint_and_not_persisted_corruption() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        accepted(
            test.set("alice@example.com/desk", "alice@example.com", FIRST, true)
                .await?,
        )?;
        let call = Call::new("bob@example.com/desk", "alice@example.com", EMPTY).await?;
        let handler: &TestHandler = &test.extension;
        let transaction = test.storage.begin_read().await?;
        let mut response = arena()?;
        let large = "x".repeat(4096);
        while response.try_alloc_str(&large).is_ok() {}
        while response.try_alloc_str("x").is_ok() {}
        let error = condition(
            handler
                .get(
                    call.request(Some(Requester::Other), None, None)?,
                    &transaction,
                    &mut response,
                )
                .await,
            StanzaErrorCondition::ResourceConstraint,
        )?;
        assert!(error.failure().is_none());
        let stored = test
            .stored("alice@example.com")
            .await?
            .ok_or("missing previous")?;
        let mut fresh = arena()?;
        let decoded = super::xml::decode(&stored, &mut fresh)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(serialize(decoded, &fresh)?, stored);
        Ok(())
    })
}

#[test]
fn wrong_qname_direct_set_is_payload_free_internal_error_without_mutation() -> TestResult {
    block_on(async {
        let test = TestVCard::new().await?;
        for invalid in ["<wrong xmlns='vcard-temp'/>", "<vCard xmlns='wrong'/>"] {
            condition(
                test.set("alice@example.com/desk", "alice@example.com", invalid, true)
                    .await?,
                StanzaErrorCondition::InternalServerError,
            )?;
            assert!(test.stored("alice@example.com").await?.is_none());
        }
        Ok(())
    })
}

#[test]
fn client_from_and_profile_identity_never_replace_authenticated_storage_owner() -> TestResult {
    use lonewolf_xmpp::parser::{StreamEvent, XmppParser};
    block_on(async {
        let test = TestVCard::new().await?;
        let input = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'><iq type='set' id='test' from='bob@example.com/spoof'><vCard xmlns='vcard-temp'><JABBERID>bob@example.com</JABBERID><FN>Synthetic owner</FN></vCard></iq></stream:stream>";
        let mut parser = XmppParser::new(
            input.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(262_144).ok_or("limit")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ));
        let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
            return Err("expected parsed IQ".into());
        };
        let view = parsed.value().resolve(parsed.arena())?;
        assert_eq!(
            view.from()?.ok_or("spoofed from")?.as_str(),
            "bob@example.com/spoof"
        );
        let mut identities = arena()?;
        let sender = Jid::parse_in("alice@example.com/desk", &mut identities)?;
        let sender = sender.resolve(&identities)?;
        let payload = view.child("vCard", NAMESPACE)?.ok_or("vCard")?;
        let mut response = arena()?;
        let mut transaction = test.storage.begin_write().await?;
        let handler: &TestHandler = &test.extension;
        let result = handler
            .set(
                IqRequest {
                    sender,
                    target: sender.bare(),
                    discovery: &Discovery::default(),
                    sessions: &NoLookups,
                    requester: None,
                    lang: view.lang()?,
                    space: None,
                    payload,
                },
                &mut transaction,
                &NoLookups,
                &mut response,
            )
            .await;
        assert!(result.is_ok());
        assert!(test.stored("alice@example.com").await?.is_none());
        assert!(
            transaction
                .vcard(&key("alice@example.com")?)
                .await?
                .is_some()
        );
        assert!(transaction.vcard(&key("bob@example.com")?).await?.is_none());
        transaction.commit().await?;
        assert!(
            test.stored("alice@example.com")
                .await?
                .ok_or("authenticated owner")?
                .contains("bob@example.com")
        );
        assert!(test.stored("bob@example.com").await?.is_none());
        Ok(())
    })
}
