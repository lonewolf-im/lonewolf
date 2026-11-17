// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::pin;

use futures_util::FutureExt as _;
use futures_util::future::{Either, select};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::stanza::{
    IqType, MessageType, RoutedStanza, StanzaErrorCondition, StanzaErrorText, StanzaKind,
    StanzaType,
};

use super::ingress::{self, Context, IngressFailure};
use super::metrics::{ComponentMetrics, DropReason};
use super::registry::NOT_CONNECTED_TEXT;

pub(crate) struct Undelivered {
    pub(crate) bounced: u64,
    pub(crate) dropped: u64,
}

struct Accounting<'a> {
    metrics: &'a ComponentMetrics,
    result: Undelivered,
    remaining: u64,
    shutdown_dropped: u64,
}

impl Accounting<'_> {
    fn attempt(&mut self) {
        self.remaining -= 1;
        self.result.bounced += 1;
    }

    fn not_bounceable(&mut self) {
        self.remaining -= 1;
        self.result.dropped += 1;
    }

    fn stop(&mut self) {
        self.result.dropped += self.remaining;
        self.shutdown_dropped += self.remaining;
        self.remaining = 0;
    }

    fn finish(mut self) -> Undelivered {
        self.stop();
        Undelivered {
            bounced: self.result.bounced,
            dropped: self.result.dropped,
        }
    }
}

impl Drop for Accounting<'_> {
    fn drop(&mut self) {
        self.stop();
        self.metrics.bounced(self.result.bounced);
        self.metrics.dropped(
            DropReason::NotBounceable,
            self.result.dropped - self.shutdown_dropped,
        );
        self.metrics
            .dropped(DropReason::Shutdown, self.shutdown_dropped);
    }
}

fn reply<A: ChunkAllocator + Clone>(
    stanza: &RoutedStanza<A>,
    allocator: A,
) -> Option<(StanzaKind, RoutedStanza<A>)> {
    let source = stanza.resolve().ok()?;
    if !matches!(source.stanza_type(), StanzaType::Message(kind) if kind != MessageType::Error)
        && !matches!(
            source.stanza_type(),
            StanzaType::Iq(IqType::Get | IqType::Set)
        )
    {
        return None;
    }
    let kind = source.kind();
    let mut arena = Arena::try_new_in(Default::default(), allocator).ok()?;
    let source = source.clone_in(&mut arena).ok()?;
    let reply = source
        .error_reply_described_in(
            &mut arena,
            StanzaErrorCondition::RemoteServerTimeout,
            None,
            StanzaErrorText::Static(NOT_CONNECTED_TEXT),
        )
        .ok()?
        .build()
        .ok()?;
    Some((kind, RoutedStanza::from_parts(reply, arena)))
}

pub(crate) async fn undelivered<A: ChunkAllocator + Clone + 'static>(
    context: &Context<A>,
    domain: &str,
    stranded: Vec<RoutedStanza<A>>,
    shutdown: impl Future<Output = ()>,
) -> Undelivered {
    undelivered_with(context, domain, stranded, shutdown, ingress::dispatch).await
}

async fn undelivered_with<A, D>(
    context: &Context<A>,
    domain: &str,
    stranded: Vec<RoutedStanza<A>>,
    shutdown: impl Future<Output = ()>,
    mut dispatch: D,
) -> Undelivered
where
    A: ChunkAllocator + Clone + 'static,
    D: for<'a> AsyncFnMut(&'a Context<A>, &'a str, RoutedStanza<A>) -> Result<(), IngressFailure>,
{
    let mut accounting = Accounting {
        metrics: context.registry.metrics(),
        result: Undelivered {
            bounced: 0,
            dropped: 0,
        },
        remaining: stranded.len() as u64,
        shutdown_dropped: 0,
    };
    let mut shutdown = pin!(shutdown);
    for stanza in stranded {
        if shutdown.as_mut().now_or_never().is_some() {
            break;
        }
        let Some((kind, reply)) = reply(&stanza, context.allocator.clone()) else {
            accounting.not_bounceable();
            continue;
        };
        let completed = {
            let attempt = async {
                accounting.attempt();
                dispatch(context, domain, reply).await
            };
            match select(shutdown.as_mut(), pin!(attempt)).await {
                Either::Left(_) => false,
                Either::Right((result, _)) => {
                    if result.is_err() {
                        tracing::debug!(
                            component_domain = domain,
                            stanza_kind = kind.as_str(),
                            "component bounce dispatch failed"
                        );
                    }
                    true
                }
            }
        };
        if !completed {
            break;
        }
    }
    accounting.finish()
}

#[cfg(test)]
mod tests;
