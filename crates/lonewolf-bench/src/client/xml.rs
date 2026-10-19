// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use lonewolf_util::arena::{Arena, ArenaConfig, ArenaRead, GlobalChunkAllocator};
use lonewolf_xmpp::{
    jid::Jid,
    parser::{ParseError, ParserConfig, StreamEvent, XmppParser},
    stanza::{
        CLIENT_NAMESPACE, ElementRef, IqType, MessageType, NodeRef, STREAM_NAMESPACE, StanzaType,
    },
};
use tokio::io::{AsyncRead, BufReader};

use super::{
    BenchResult, BodyValidation, CorrelationId, ReceiveRoute, ReceivedEvent, ReceivedKind, failure,
};

pub(super) const TLS_NS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub(super) const SASL_NS: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
pub(super) const BIND_NS: &str = "urn:ietf:params:xml:ns:xmpp-bind";
pub(super) type Parser<R> = XmppParser<BufReader<R>, GlobalChunkAllocator>;
type Event = StreamEvent<GlobalChunkAllocator>;

pub(super) fn config() -> ParserConfig {
    ParserConfig {
        max_stanza_bytes: const { NonZeroUsize::new(262_144).unwrap() },
        arena: ArenaConfig {
            chunk_size: const { NonZeroUsize::new(4096).unwrap() },
            max_reserved_bytes: const { NonZeroUsize::new(4 * 1024 * 1024).unwrap() },
        },
    }
}

pub(super) fn parser<R: AsyncRead>(reader: R) -> Parser<R> {
    XmppParser::new(BufReader::new(reader), config(), GlobalChunkAllocator)
}

pub(super) fn canonical_jid(value: &str) -> BenchResult<String> {
    let mut arena = Arena::try_new(config().arena).map_err(|_| failure("xml_arena"))?;
    let jid = Jid::parse_in(value, &mut arena).map_err(|_| failure("jid_invalid"))?;
    Ok(jid
        .resolve(&arena)
        .map_err(|_| failure("xml_arena"))?
        .as_str()
        .to_owned())
}

pub(super) fn escape(output: &mut String, value: &str) -> BenchResult<()> {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            '\t' | '\n' | '\r' => {
                use std::fmt::Write;
                write!(output, "&#{};", u32::from(ch)).map_err(|_| failure("xml_encode"))?;
            }
            ch if ch >= '\u{20}' && ch != '\u{fffe}' && ch != '\u{ffff}' => output.push(ch),
            _ => return Err(failure("xml_character")),
        }
    }
    Ok(())
}

pub(super) fn stream_header(domain: &str) -> BenchResult<String> {
    let mut header = String::from(
        "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' to='",
    );
    escape(&mut header, domain)?;
    header.push_str("'>");
    Ok(header)
}

pub(super) async fn next<R: AsyncRead + Unpin>(parser: &mut Parser<R>) -> BenchResult<Event> {
    parser
        .next_event()
        .await
        .map_err(|error| {
            failure(
                if error.is_transport_error() || matches!(error, ParseError::UnexpectedEof) {
                    "xml_read"
                } else {
                    "xml_protocol"
                },
            )
        })?
        .ok_or_else(|| failure("stream_ended"))
}

pub(super) async fn features<R: AsyncRead + Unpin>(
    parser: &mut Parser<R>,
    domain: &str,
    name: &str,
    namespace: &str,
) -> BenchResult<()> {
    match next(parser).await? {
        StreamEvent::StreamStart {
            header,
            content_namespace,
            ..
        } => {
            let root = header
                .value()
                .resolve(header.arena())
                .map_err(|_| failure("xml_arena"))?;
            if content_namespace != CLIENT_NAMESPACE
                || attr(&root, "version")? != Some("1.0")
                || attr(&root, "from")? != Some(domain)
            {
                return Err(failure("stream_identity"));
            }
        }
        _ => return Err(failure("stream_header")),
    }
    match next(parser).await? {
        StreamEvent::Element(parsed) => {
            let root = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            if root.name() != "features" || root.namespace() != STREAM_NAMESPACE {
                return Err(failure("stream_features"));
            }
            let feature = root
                .child(name, namespace)
                .map_err(|_| failure("xml_arena"))?
                .ok_or_else(|| failure("required_feature_missing"))?;
            if name == "mechanisms" {
                let mut found = false;
                for child in feature.children().map_err(|_| failure("xml_arena"))? {
                    if let NodeRef::Element(child) = child.map_err(|_| failure("xml_arena"))?
                        && child.name() == "mechanism"
                        && child.namespace() == SASL_NS
                        && child.text().map_err(|_| failure("xml_arena"))? == Some("SCRAM-SHA-256")
                    {
                        found = true;
                    }
                }
                if !found {
                    return Err(failure("scram_mechanism_missing"));
                }
            }
            Ok(())
        }
        _ => Err(failure("stream_features")),
    }
}

pub(super) async fn sasl<R: AsyncRead + Unpin>(
    parser: &mut Parser<R>,
    name: &str,
) -> BenchResult<zeroize::Zeroizing<String>> {
    match next(parser).await? {
        StreamEvent::Element(parsed) => {
            let root = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            if root.name() != name || root.namespace() != SASL_NS {
                return Err(failure("authentication_failed"));
            }
            let text = root
                .text()
                .map_err(|_| failure("xml_arena"))?
                .ok_or_else(|| failure("scram_encoding"))?;
            if text.len() > 4096usize.div_ceil(3) * 4 {
                return Err(failure("scram_size"));
            }
            Ok(zeroize::Zeroizing::new(text.to_owned()))
        }
        _ => Err(failure("authentication_failed")),
    }
}

pub(super) async fn proceed<R: AsyncRead + Unpin>(parser: &mut Parser<R>) -> BenchResult<()> {
    match next(parser).await? {
        StreamEvent::Element(parsed) => {
            let root = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            if root.name() == "proceed"
                && root.namespace() == TLS_NS
                && root
                    .children()
                    .map_err(|_| failure("xml_arena"))?
                    .next()
                    .is_none()
            {
                Ok(())
            } else {
                Err(failure("starttls_rejected"))
            }
        }
        _ => Err(failure("starttls_rejected")),
    }
}

pub(super) async fn binding<R: AsyncRead + Unpin>(
    parser: &mut Parser<R>,
    expected: &str,
) -> BenchResult<String> {
    match next(parser).await? {
        StreamEvent::Stanza(parsed) => {
            let stanza = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            if stanza.stanza_type() != StanzaType::Iq(IqType::Result)
                || stanza.id().map_err(|_| failure("xml_arena"))? != Some("bind")
            {
                return Err(failure("binding_failed"));
            }
            let mut children = stanza.children().map_err(|_| failure("xml_arena"))?;
            let bind = children
                .next()
                .ok_or_else(|| failure("binding_failed"))?
                .map_err(|_| failure("xml_arena"))?;
            if children.next().is_some() || bind.name() != "bind" || bind.namespace() != BIND_NS {
                return Err(failure("binding_failed"));
            }
            let mut jid = None;
            for child in bind.children().map_err(|_| failure("xml_arena"))? {
                match child.map_err(|_| failure("xml_arena"))? {
                    NodeRef::Element(element)
                        if jid.is_none()
                            && element.name() == "jid"
                            && element.namespace() == BIND_NS =>
                    {
                        jid = Some(element)
                    }
                    NodeRef::Text(text)
                        if text
                            .bytes()
                            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) => {}
                    _ => return Err(failure("binding_failed")),
                }
            }
            let Some(jid) = jid else {
                return Err(failure("binding_failed"));
            };
            let jid = canonical_jid(
                jid.text()
                    .map_err(|_| failure("xml_arena"))?
                    .ok_or_else(|| failure("binding_failed"))?,
            )?;
            if jid != expected {
                return Err(failure("binding_identity"));
            }
            Ok(jid)
        }
        _ => Err(failure("binding_failed")),
    }
}

pub(super) fn received(
    event: Event,
    bound_jid: &str,
    route: Option<&ReceiveRoute>,
) -> BenchResult<ReceivedEvent> {
    let kind = match event {
        StreamEvent::StreamEnd => ReceivedKind::StreamEnd,
        StreamEvent::Stanza(parsed) => {
            let stanza = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            let correlation = stanza
                .id()
                .map_err(|_| failure("xml_arena"))?
                .and_then(CorrelationId::parse);
            if stanza.stanza_type().is_error() {
                let condition = stanza
                    .child("error", CLIENT_NAMESPACE)
                    .map_err(|_| failure("xml_arena"))?
                    .map(|error| error_condition(&error))
                    .transpose()?
                    .unwrap_or("undefined-condition");
                ReceivedKind::StanzaError {
                    correlation,
                    condition,
                }
            } else if stanza.stanza_type() == StanzaType::Message(MessageType::Chat) {
                let from = stanza
                    .from()
                    .map_err(|_| failure("xml_arena"))?
                    .map(|v| v.as_str().to_owned());
                let to = stanza
                    .to()
                    .map_err(|_| failure("xml_arena"))?
                    .map(|v| v.as_str().to_owned());
                let mut bodies = 0;
                let mut bytes = 0;
                let mut valid = false;
                for child in stanza.children().map_err(|_| failure("xml_arena"))? {
                    let child = child.map_err(|_| failure("xml_arena"))?;
                    if child.name() == "body" && child.namespace() == CLIENT_NAMESPACE {
                        bodies += 1;
                        let text = child.text().map_err(|_| failure("xml_arena"))?;
                        bytes = text.map_or(0, str::len);
                        valid = match text {
                            Some(text) => text.bytes().all(|byte| byte == b'x'),
                            None => child
                                .children()
                                .map_err(|_| failure("xml_arena"))?
                                .next()
                                .is_none(),
                        };
                    }
                }
                let body = BodyValidation {
                    bytes,
                    ascii_x: valid && bodies == 1,
                };
                let route_valid = to.as_deref() == Some(bound_jid)
                    && from.as_deref().is_some_and(|value| value.contains('/'))
                    && route.is_none_or(|route| {
                        from.as_deref() == Some(route.from.as_str())
                            && body.bytes == route.body_bytes
                            && body.ascii_x
                    });
                ReceivedKind::Chat {
                    correlation,
                    from,
                    to,
                    body,
                    route_valid,
                }
            } else {
                ReceivedKind::Unexpected
            }
        }
        StreamEvent::Element(parsed) => {
            let root = parsed
                .value()
                .resolve(parsed.arena())
                .map_err(|_| failure("xml_arena"))?;
            if root.name() == "error" && root.namespace() == STREAM_NAMESPACE {
                ReceivedKind::StreamError
            } else {
                ReceivedKind::Unexpected
            }
        }
        _ => ReceivedKind::Unexpected,
    };
    Ok(ReceivedEvent {
        at: tokio::time::Instant::now(),
        kind,
    })
}

fn attr<'a, R: ArenaRead>(element: &ElementRef<'a, R>, name: &str) -> BenchResult<Option<&'a str>> {
    element
        .attribute(name, "")
        .map_err(|_| failure("xml_arena"))
}

fn error_condition<R: ArenaRead>(element: &ElementRef<'_, R>) -> BenchResult<&'static str> {
    for node in element.children().map_err(|_| failure("xml_arena"))? {
        if let NodeRef::Element(child) = node.map_err(|_| failure("xml_arena"))?
            && child.namespace() == "urn:ietf:params:xml:ns:xmpp-stanzas"
        {
            return Ok(match child.name() {
                "service-unavailable" => "service-unavailable",
                "resource-constraint" => "resource-constraint",
                "forbidden" => "forbidden",
                "not-allowed" => "not-allowed",
                "item-not-found" => "item-not-found",
                "jid-malformed" => "jid-malformed",
                _ => "undefined-condition",
            });
        }
    }
    Ok("undefined-condition")
}
