// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::StanzaNamespace;
use lonewolf_xmpp::stream::StreamErrorCondition;

use super::{InboundPeer, IngressContext};
use crate::router::RoutedStanza;
use crate::s2s::metrics::{S2sMetrics, StreamClose};

pub(crate) fn violation_close(condition: StreamErrorCondition) -> StreamClose {
    match condition {
        StreamErrorCondition::Reset => StreamClose::CertificateExpired,
        StreamErrorCondition::SystemShutdown => StreamClose::Shutdown,
        StreamErrorCondition::Conflict => StreamClose::Conflict,
        StreamErrorCondition::ImproperAddressing => StreamClose::ImproperAddressing,
        StreamErrorCondition::HostUnknown => StreamClose::HostUnknown,
        StreamErrorCondition::InvalidFrom => StreamClose::InvalidFrom,
        StreamErrorCondition::InvalidNamespace => StreamClose::InvalidNamespace,
        StreamErrorCondition::UnsupportedStanzaType => StreamClose::UnsupportedStanzaType,
        StreamErrorCondition::InternalServerError => StreamClose::InternalError,
        _ => StreamClose::ProtocolError,
    }
}

pub(crate) fn reader_violation_close(condition: StreamErrorCondition) -> StreamClose {
    match condition {
        StreamErrorCondition::InvalidNamespace => StreamClose::InvalidNamespace,
        StreamErrorCondition::UnsupportedStanzaType => StreamClose::UnsupportedStanzaType,
        _ => StreamClose::ProtocolError,
    }
}

pub(crate) fn validate(
    namespace: StanzaNamespace,
    from: Option<JidRef<'_>>,
    to: Option<JidRef<'_>>,
    peer: &InboundPeer,
) -> Result<(), StreamErrorCondition> {
    if namespace != StanzaNamespace::Server {
        return Err(StreamErrorCondition::InvalidNamespace);
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err(StreamErrorCondition::ImproperAddressing);
    };
    if to.domainpart() != peer.local.as_ref() {
        return Err(StreamErrorCondition::HostUnknown);
    }
    if from.domainpart() != peer.remote.as_ref() {
        return Err(StreamErrorCondition::InvalidFrom);
    }
    Ok(())
}

pub(crate) fn stanza_kind<A: ChunkAllocator>(event: &StreamEvent<A>) -> &'static str {
    match event {
        StreamEvent::Stanza(parsed) => parsed
            .value()
            .resolve(parsed.arena())
            .map(|view| view.kind().as_str())
            .unwrap_or("stanza"),
        StreamEvent::RejectedStanza(parsed) => parsed.value().kind().as_str(),
        StreamEvent::Element(_) => "element",
        _ => "stream",
    }
}

pub(crate) async fn process<A, F>(
    event: StreamEvent<A>,
    peer: &InboundPeer,
    metrics: &S2sMetrics,
    context: &IngressContext<A>,
    count_bidi: bool,
    deliver: F,
) -> Result<(), StreamErrorCondition>
where
    A: ChunkAllocator + Clone + 'static,
    F: AsyncFnOnce(RoutedStanza<A>) -> Result<(), StreamErrorCondition>,
{
    match event {
        StreamEvent::Stanza(parsed) => {
            {
                let view = parsed
                    .value()
                    .resolve(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                validate(
                    view.namespace(),
                    view.from()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?,
                    view.to()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?,
                    peer,
                )?;
                metrics.stanza_received(view.kind());
                if count_bidi {
                    metrics.bidi_stanza_received(view.kind());
                }
            }
            let (stanza, mut arena) = parsed.into_parts();
            let stanza = stanza
                .rescope_derive_in(StanzaNamespace::Client, &mut arena)
                .map_err(|_| StreamErrorCondition::InternalServerError)?;
            deliver(RoutedStanza::from_parts(stanza, arena)).await
        }
        StreamEvent::RejectedStanza(parsed) => {
            let rejected = parsed.value();
            if rejected.namespace() != StanzaNamespace::Server {
                return Err(StreamErrorCondition::InvalidNamespace);
            }
            if rejected.invalid_from() || rejected.invalid_to() {
                return Err(StreamErrorCondition::ImproperAddressing);
            }
            validate(
                rejected.namespace(),
                rejected
                    .from(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?,
                rejected
                    .to(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?,
                peer,
            )?;
            metrics.stanza_received(rejected.kind());
            if count_bidi {
                metrics.bidi_stanza_received(rejected.kind());
            }
            if rejected.can_reply() {
                let mut output = Arena::try_new_in(Default::default(), context.allocator.clone())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let sender = rejected
                    .from(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .ok_or(StreamErrorCondition::ImproperAddressing)?
                    .clone_in(&mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let target = rejected
                    .to(parsed.arena())
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .ok_or(StreamErrorCondition::ImproperAddressing)?
                    .clone_in(&mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let (rejected, mut arena) = parsed.into_parts();
                let sender = sender
                    .resolve(&output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .clone_in(&mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let target = target
                    .resolve(&output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?
                    .clone_in(&mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = rejected
                    .error_in(sender, target, &mut arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = reply
                    .resolve(&arena)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let reply = reply
                    .rescope_in(StanzaNamespace::Client, &mut output)
                    .map_err(|_| StreamErrorCondition::InternalServerError)?;
                let _ = context
                    .router
                    .route_remote(RoutedStanza::from_parts(reply, output));
            }
            Ok(())
        }
        StreamEvent::Element(parsed) => {
            let element = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| StreamErrorCondition::InternalServerError)?;
            if matches!(element.name(), "message" | "iq" | "presence")
                && element.namespace() != "jabber:server"
            {
                Err(StreamErrorCondition::InvalidNamespace)
            } else {
                Err(StreamErrorCondition::UnsupportedStanzaType)
            }
        }
        _ => Err(StreamErrorCondition::UnsupportedStanzaType),
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::Layout;
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use compio::runtime::Runtime;
    use lonewolf_storage::RedbStorage;
    use lonewolf_util::arena::{AllocationError, Chunk, GlobalChunkAllocator};
    use lonewolf_xmpp::stanza::CLIENT_NAMESPACE;
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::config::Config;
    use crate::delivery::WorkGroup;
    use crate::hosts::Hosts;
    use crate::router::{Router, local::LocalRouter};
    use crate::s2s::stream::{S2sReader, S2sReaderLimits};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0'>";
    const RECEIVED_MESSAGE: &str = "lonewolf_s2s_stanzas_received_total{kind=\"message\"} 1";

    #[derive(Default)]
    struct CountingAllocator(AtomicUsize);

    // The wrapper preserves the delegated chunk ownership and layout contracts.
    unsafe impl ChunkAllocator for CountingAllocator {
        fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
            let chunk = GlobalChunkAllocator.allocate(layout)?;
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(chunk)
        }

        unsafe fn deallocate(&self, chunk: Chunk) {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
    }

    struct Fixture<A: ChunkAllocator = GlobalChunkAllocator> {
        context: IngressContext<A>,
        metrics: Arc<S2sMetrics>,
        limits: S2sReaderLimits,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            Self::with_allocator(GlobalChunkAllocator)
        }
    }

    impl<A: ChunkAllocator + Clone + 'static> Fixture<A> {
        fn with_allocator(allocator: A) -> TestResult<Self> {
            let config = Config::default();
            let hosts = Hosts::new(&config.hosts, None)?;
            let router = Router::new(hosts, LocalRouter::new(allocator.clone()));
            let directory = tempfile::tempdir()?;
            Ok(Self {
                context: IngressContext {
                    router: router.handle(),
                    storage: RedbStorage::open(directory.path().join("state.redb"))?,
                    allocator,
                    work: WorkGroup::new().handle(),
                },
                metrics: S2sMetrics::new(0),
                limits: S2sReaderLimits {
                    max_stanza_bytes: config.limits.s2s.max_stanza_bytes,
                    stanzas: config.limits.s2s.incoming_stanzas_per_connection,
                    xml: config.limits.s2s.incoming_xml_per_connection,
                },
                _directory: directory,
            })
        }

        async fn event(&self, xml: &str) -> TestResult<StreamEvent<A>> {
            let mut reader = S2sReader::new(
                Cursor::new(format!("{HEADER}{xml}").into_bytes()),
                &self.limits,
                self.context.allocator.clone(),
                None,
            );
            assert!(matches!(
                reader
                    .next_event()
                    .await
                    .map_err(|error| format!("{error:?}"))?,
                Some(StreamEvent::StreamStart { .. })
            ));
            reader
                .next_event()
                .await
                .map_err(|error| format!("{error:?}"))?
                .ok_or_else(|| "missing peer event".into())
        }

        fn render(&self) -> Result<String, std::fmt::Error> {
            let mut registry = Registry::default();
            self.metrics
                .register(registry.sub_registry_with_prefix("lonewolf"));
            let mut output = String::new();
            prometheus_client::encoding::text::encode(&mut output, &registry)?;
            Ok(output)
        }
    }

    fn peer() -> InboundPeer {
        InboundPeer {
            local: "local.test".into(),
            remote: "peer.test".into(),
            connection_id: 1,
        }
    }

    const CHAT: &str =
        "<message from='u@peer.test/r' to='v@local.test' type='chat'><body>hello</body></message>";

    #[test]
    fn inbound_stanza_reaches_delivery_without_another_arena() -> TestResult {
        Runtime::new()?.block_on(async {
            let allocator = Arc::new(CountingAllocator::default());
            let fixture = Fixture::with_allocator(allocator.clone())?;
            let event = fixture.event(CHAT).await?;
            let after_parse = allocator.0.load(Ordering::Relaxed);
            assert!(after_parse > 0);
            let mut at_delivery = None;
            let result = process(
                event,
                &peer(),
                &fixture.metrics,
                &fixture.context,
                false,
                async |_| {
                    at_delivery = Some(allocator.0.load(Ordering::Relaxed));
                    Ok(())
                },
            )
            .await;
            assert_eq!(result, Ok(()));
            assert_eq!(at_delivery, Some(after_parse));
            Ok(())
        })
    }

    #[test]
    fn inbound_stanza_is_delivered_as_client_namespace() -> TestResult {
        Runtime::new()?.block_on(async {
            let fixture = Fixture::new()?;
            let event = fixture.event(CHAT).await?;
            let StreamEvent::Stanza(parsed) = &event else {
                return Err("missing parsed stanza".into());
            };
            let mut reference_arena = Arena::try_new_in(Default::default(), GlobalChunkAllocator)?;
            let reference = parsed
                .value()
                .resolve(parsed.arena())?
                .rescope_in(StanzaNamespace::Client, &mut reference_arena)?;
            let mut expected = String::new();
            reference
                .resolve(&reference_arena)?
                .write_xml(&mut expected)?;
            let mut delivered = false;
            let result = process(
                event,
                &peer(),
                &fixture.metrics,
                &fixture.context,
                false,
                async |stanza| {
                    let view = stanza
                        .resolve()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    assert_eq!(view.namespace(), StanzaNamespace::Client);
                    let body = view
                        .child("body", CLIENT_NAMESPACE)
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    assert!(body.is_some());
                    let mut actual = String::new();
                    view.write_xml(&mut actual)
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    assert_eq!(actual, expected);
                    delivered = true;
                    Ok(())
                },
            )
            .await;
            assert_eq!(result, Ok(()));
            assert!(delivered);
            Ok(())
        })
    }

    #[test]
    fn valid_stanza_is_rescoped_and_counted_before_delivery() -> TestResult {
        Runtime::new()?.block_on(async {
            let fixture = Fixture::new()?;
            let event = fixture
                .event("<message from='u@peer.test/r' to='v@local.test'/>")
                .await?;
            assert_eq!(stanza_kind(&event), "message");
            let mut delivered = false;
            let result = process(
                event,
                &peer(),
                &fixture.metrics,
                &fixture.context,
                false,
                async |stanza| {
                    let view = stanza
                        .resolve()
                        .map_err(|_| StreamErrorCondition::InternalServerError)?;
                    assert_eq!(view.namespace(), StanzaNamespace::Client);
                    assert!(
                        fixture
                            .render()
                            .map_err(|_| StreamErrorCondition::InternalServerError)?
                            .lines()
                            .any(|line| line == RECEIVED_MESSAGE)
                    );
                    delivered = true;
                    Ok(())
                },
            )
            .await;
            assert_eq!(result, Ok(()));
            assert!(delivered);
            Ok(())
        })
    }

    #[test]
    fn address_violations_return_their_stream_conditions_without_delivery() -> TestResult {
        Runtime::new()?.block_on(async {
            let fixture = Fixture::new()?;
            for (xml, expected) in [
                (
                    "<message from='u@foreign.test/r' to='v@local.test'/>",
                    StreamErrorCondition::InvalidFrom,
                ),
                (
                    "<message from='u@peer.test/r' to='v@foreign.test'/>",
                    StreamErrorCondition::HostUnknown,
                ),
                (
                    "<message from='u@peer.test/r'/>",
                    StreamErrorCondition::ImproperAddressing,
                ),
                (
                    "<message xmlns='jabber:client' from='u@peer.test/r' to='v@local.test'/>",
                    StreamErrorCondition::InvalidNamespace,
                ),
            ] {
                let event = fixture.event(xml).await?;
                let mut delivered = false;
                let result = process(
                    event,
                    &peer(),
                    &fixture.metrics,
                    &fixture.context,
                    false,
                    async |_| {
                        delivered = true;
                        Ok(())
                    },
                )
                .await;
                assert_eq!(result, Err(expected));
                assert!(!delivered);
                assert!(!fixture.render()?.contains("s2s_stanzas_received_total"));
            }
            Ok(())
        })
    }

    #[test]
    fn non_stanza_elements_are_unsupported() -> TestResult {
        Runtime::new()?.block_on(async {
            let fixture = Fixture::new()?;
            let event = fixture
                .event("<db:result xmlns:db='jabber:server:dialback'/>")
                .await?;
            assert_eq!(stanza_kind(&event), "element");
            let mut delivered = false;
            let result = process(
                event,
                &peer(),
                &fixture.metrics,
                &fixture.context,
                false,
                async |_| {
                    delivered = true;
                    Ok(())
                },
            )
            .await;
            assert_eq!(result, Err(StreamErrorCondition::UnsupportedStanzaType));
            assert!(!delivered);
            Ok(())
        })
    }

    #[test]
    fn delivery_errors_are_returned_unchanged() -> TestResult {
        Runtime::new()?.block_on(async {
            let fixture = Fixture::new()?;
            let event = fixture
                .event("<message from='u@peer.test/r' to='v@local.test'/>")
                .await?;
            let mut delivered = false;
            let result = process(
                event,
                &peer(),
                &fixture.metrics,
                &fixture.context,
                false,
                async |_| {
                    delivered = true;
                    Err(StreamErrorCondition::SystemShutdown)
                },
            )
            .await;
            assert_eq!(result, Err(StreamErrorCondition::SystemShutdown));
            assert!(delivered);
            Ok(())
        })
    }
}
