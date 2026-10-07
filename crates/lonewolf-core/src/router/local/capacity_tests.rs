// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::Config;
use crate::diagnostics::Diagnostics;
use crate::hosts::Hosts;
use crate::router::Router;
use compio::runtime::Runtime;
use lonewolf_admin::{DiagnosticsProvider, ReadinessState};
use lonewolf_util::arena::GlobalChunkAllocator;
use lonewolf_util::pool::{PoolConfig, PooledChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{ParserConfig, StreamEvent, XmppParser};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn account() -> Result<AccountKey, Box<dyn std::error::Error>> {
    let mut arena = Arena::try_new(Default::default())?;
    Ok(AccountKey::try_from(
        Jid::parse_in("capacity@localhost", &mut arena)?.resolve(&arena)?,
    )?)
}

#[test]
fn actual_mailbox_attempts_have_one_exclusive_admission_outcome() -> TestResult {
    Runtime::new()?.block_on(async {
        let xml = b"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'><message to='capacity@localhost/r'/><message to='capacity@localhost/r'/><message to='capacity@localhost/r'/>";
        let mut parser = XmppParser::new(xml.as_slice(), ParserConfig {max_stanza_bytes:NonZeroUsize::new(4096).ok_or("zero stanza")?,arena:Default::default()}, GlobalChunkAllocator);
        assert!(matches!(parser.next_event().await?, Some(StreamEvent::StreamStart {..})));
        let capacity = Arc::new(Capacity::new());
        let (sender,receiver) = async_channel::bounded(1);
        let sender = ResourceSender {sender,capacity:Some(Arc::clone(&capacity))};
        for (index,counter) in [Counter::MailboxAccepted,Counter::MailboxFull,Counter::MailboxClosed].into_iter().enumerate() {
            if index == 2 {receiver.close();}
            let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {return Err("missing stanza".into());};
            let result = sender.try_send(RoutedStanza::from_parsed(parsed));
            assert_eq!(result.is_ok(),index == 0);
            assert_eq!(capacity.counter(counter),1);
            assert_eq!(Counter::ALL.iter().map(|counter|capacity.counter(*counter)).sum::<u64>(),index as u64+1);
        }
        Ok(())
    })
}

#[test]
fn readiness_uses_router_failure_and_retirements_count_only_removed_generations() -> TestResult {
    Runtime::new()?.block_on(async {
        let capacity = Arc::new(Capacity::new());
        let pool = Arc::new(PooledChunkAllocator::try_new(PoolConfig {
            total_bytes: NonZeroUsize::new(8 * 1024 * 1024).ok_or("zero pool")?,
            shards_per_bucket: NonZeroUsize::MIN,
        })?);
        let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
        let diagnostics = Diagnostics::new(
            Arc::clone(&capacity),
            Arc::clone(&pool),
            writer.error_counter(),
        );
        assert_eq!(diagnostics.readiness().state, ReadinessState::Starting);
        let dispatcher = lonewolf_util::core_dispatcher::CoreDispatcher::new(
            NonZeroUsize::MIN,
            NonZeroUsize::MIN,
        )?;
        let normal = Diagnostics::new(
            Arc::clone(&capacity),
            Arc::clone(&pool),
            writer.error_counter(),
        );
        let local = LocalRouter::start_observed(
            &dispatcher.handle(),
            pool,
            NonZeroUsize::MIN,
            Some(Arc::clone(&capacity)),
        )
        .await?;
        let local_handle = local.handle();
        let mut router = Router::new(Hosts::new(&Config::default().hosts, None)?, local);
        diagnostics.set_router(router.handle());
        assert_eq!(diagnostics.readiness().state, ReadinessState::Starting);
        normal.set_router(router.handle());
        normal.serving();
        normal.stop(false);
        assert_eq!(normal.readiness().state, ReadinessState::Stopping);
        normal.stop(true);
        normal.stop(false);
        assert_eq!(normal.readiness().state, ReadinessState::Failed);
        diagnostics.serving();
        assert_eq!(diagnostics.readiness().state, ReadinessState::Ready);
        let account = account()?;
        let old = local_handle
            .register(&account, Some("r"), NonZeroUsize::MIN)
            .await?;
        old.links.inbound.close();
        let replacement = local_handle
            .register(&account, Some("r"), NonZeroUsize::MIN)
            .await?;
        assert_eq!(capacity.counter(Counter::RetirementsEvicted), 1);
        drop(old);
        assert!(local_handle.resource_match(&account, "r").await?.is_some());
        assert_eq!(capacity.counter(Counter::RetirementsEvicted), 1);
        local_handle.retire_account(&account).await?;
        local_handle.retire_account(&account).await?;
        assert_eq!(capacity.counter(Counter::RetirementsAccountDeleted), 1);
        drop(replacement);
        let registration = local_handle
            .register(&account, Some("r"), NonZeroUsize::MIN)
            .await?;
        local_handle.shards[0].close();
        let failure = router.failure().await;
        assert_eq!(failure.reason, RouterFailureReason::Completed);
        assert_eq!(capacity.counter(Counter::RetirementsRouterStopped), 1);
        assert_eq!(diagnostics.readiness().state, ReadinessState::Failed);
        diagnostics.stop(false);
        router.stop();
        assert_eq!(diagnostics.readiness().state, ReadinessState::Failed);
        assert_eq!(
            diagnostics.snapshot().readiness.state,
            ReadinessState::Failed
        );
        drop(registration);
        assert!(router.shutdown().await.is_err());
        dispatcher
            .shutdown(std::time::Duration::from_secs(5))
            .await?;
        Ok(())
    })
}
