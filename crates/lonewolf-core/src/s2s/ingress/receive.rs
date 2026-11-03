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
            let mut arena = Arena::try_new_in(Default::default(), context.allocator.clone())
                .map_err(|_| StreamErrorCondition::InternalServerError)?;
            let stanza = view
                .rescope_in(StanzaNamespace::Client, &mut arena)
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
    use std::io::Cursor;
    use std::sync::Arc;

    use compio::runtime::Runtime;
    use lonewolf_storage::RedbStorage;
    use lonewolf_util::arena::GlobalChunkAllocator;
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

    struct Fixture {
        context: IngressContext<GlobalChunkAllocator>,
        metrics: Arc<S2sMetrics>,
        limits: S2sReaderLimits,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> TestResult<Self> {
            let config = Config::default();
            let hosts = Hosts::new(&config.hosts, None)?;
            let router = Router::new(hosts, LocalRouter::new(GlobalChunkAllocator));
            let directory = tempfile::tempdir()?;
            Ok(Self {
                context: IngressContext {
                    router: router.handle(),
                    storage: RedbStorage::open(directory.path().join("state.redb"))?,
                    allocator: GlobalChunkAllocator,
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

        async fn event(&self, xml: &str) -> TestResult<StreamEvent<GlobalChunkAllocator>> {
            let mut reader = S2sReader::new(
                Cursor::new(format!("{HEADER}{xml}").into_bytes()),
                &self.limits,
                GlobalChunkAllocator,
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
