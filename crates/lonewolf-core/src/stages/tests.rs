// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::num::NonZeroUsize;
use std::time::Duration;

use compio::runtime::Runtime;
use lonewolf_storage::RedbStorage;
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};
use lonewolf_xmpp::stanza::{MessageType, StanzaErrorCondition};

use super::{DeliveryOutcome, deliver};
use crate::config::Config;
use crate::delivery::WorkGroup;
use crate::hosts::Hosts;
use crate::router::local::LocalRouter;
use crate::router::{RoutedStanza, Router, RouterHandle};
use crate::stages::Stage;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: RedbStorage,
    router: Router<GlobalChunkAllocator>,
    handle: RouterHandle<GlobalChunkAllocator>,
    allocator: GlobalChunkAllocator,
    work: WorkGroup,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
        let config = Config::default();
        let hosts = Hosts::new(&config.hosts, None)?;
        let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator));
        let handle = router.handle();
        Ok(Self {
            _directory: directory,
            storage,
            router,
            handle,
            allocator: GlobalChunkAllocator,
            work: WorkGroup::new(),
        })
    }

    fn stage(&self) -> Stage<'_, GlobalChunkAllocator> {
        Stage {
            router: &self.handle,
            storage: &self.storage,
            allocator: &self.allocator,
            work: &self.work,
        }
    }
}

fn account(value: &str) -> TestResult<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in(value, &mut arena)?;
    Ok(AccountKey::try_from(jid.resolve(&arena)?)?)
}

async fn parsed(xml: &str) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let input = format!(
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client'>{xml}"
    );
    let mut parser = XmppParser::new(
        input.as_bytes(),
        ParserConfig {
            max_stanza_bytes: NonZeroUsize::new(4096).ok_or("invalid stanza limit")?,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    );
    assert!(matches!(
        parser.next_event().await?,
        Some(StreamEvent::StreamStart { .. })
    ));
    match parser.next_event().await? {
        Some(StreamEvent::Stanza(stanza)) => Ok(RoutedStanza::from_parsed(stanza)),
        _ => Err("expected stanza".into()),
    }
}

#[test]
fn deliver_routes_a_chat_message_to_a_bound_resource() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let recipient = account("bob@localhost")?;
        let registration = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let stanza = parsed(
            "<message from='alice@localhost/laptop' to='bob@localhost/phone' type='chat' id='routed'><body>Hello</body></message>",
        )
        .await?;
        let mut expected = String::new();
        stanza.resolve()?.write_xml(&mut expected)?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Chat).await;

        assert!(matches!(outcome, Ok(DeliveryOutcome::Routed)));
        let delivered = registration.recv().await.ok_or("missing routed message")?;
        let mut actual = String::new();
        delivered.stanza.resolve()?.write_xml(&mut actual)?;
        assert_eq!(actual, expected);
        drop(registration);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_rejects_a_bare_groupchat_message() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let stanza =
            parsed("<message from='alice@localhost/laptop' to='bob@localhost' type='groupchat'/>")
                .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Groupchat).await;

        assert!(matches!(
            outcome,
            Ok(DeliveryOutcome::Rejected {
                condition: StanzaErrorCondition::ServiceUnavailable,
                ..
            })
        ));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_discards_an_error_message_to_an_absent_account() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let stanza = parsed(
            "<message from='alice@localhost/laptop' to='absent@localhost/phone' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        )
        .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Error).await;

        assert!(matches!(outcome, Ok(DeliveryOutcome::Discarded)));
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}

#[test]
fn deliver_rejects_a_chat_message_without_an_offline_handler() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let recipient = account("bob@localhost")?;
        let registration = fixture
            .handle
            .register(&recipient, Some("phone"), NonZeroUsize::MIN)
            .await?;
        let stanza =
            parsed("<message from='alice@localhost/laptop' to='bob@localhost' type='chat'/>")
                .await?;

        let outcome = deliver(&fixture.stage(), stanza, MessageType::Chat).await;

        assert!(matches!(
            outcome,
            Ok(DeliveryOutcome::Rejected {
                condition: StanzaErrorCondition::ServiceUnavailable,
                ..
            })
        ));
        assert!(registration.take_queued().is_empty());
        drop(registration);
        fixture.router.shutdown().await?;
        Ok(())
    }))?
}
