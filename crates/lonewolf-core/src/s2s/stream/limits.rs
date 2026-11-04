// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::io::AsyncWrite;
use lonewolf_util::arena::{ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{AsyncWriteError, Element, ElementRef, NodeRef, StanzaRef};
use lonewolf_xmpp::stream::StreamErrorCondition;

use super::{BIDI_NAMESPACE, S2sError};

pub(crate) const NAMESPACE: &str = "urn:xmpp:stream-limits:0";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StreamLimits {
    pub(crate) max_bytes: Option<u32>,
    pub(crate) idle_seconds: Option<u32>,
}

pub(crate) enum FeaturePhase {
    StartTls,
    Sasl { bidi: bool },
    Authenticated,
}

pub(crate) fn local_limits(max_bytes: usize, idle_seconds: u64) -> Result<StreamLimits, S2sError> {
    Ok(StreamLimits {
        max_bytes: Some(max_bytes.try_into().map_err(|_| S2sError::Internal)?),
        idle_seconds: Some(idle_seconds.try_into().map_err(|_| S2sError::Internal)?),
    })
}

fn append_xml(output: &mut String, limits: StreamLimits) -> Result<(), S2sError> {
    let (Some(bytes), Some(idle)) = (limits.max_bytes, limits.idle_seconds) else {
        return Err(S2sError::Internal);
    };
    write!(output, "<limits xmlns='{NAMESPACE}'><max-bytes>{bytes}</max-bytes><idle-seconds>{idle}</idle-seconds></limits>").map_err(|_| S2sError::Internal)
}

pub(crate) fn write_features_xml(
    output: &mut String,
    phase: FeaturePhase,
    limits: StreamLimits,
) -> Result<(), S2sError> {
    output.clear();
    output.push_str("<stream:features>");
    match phase {
        FeaturePhase::StartTls => output
            .push_str("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"),
        FeaturePhase::Sasl { bidi } => {
            output.push_str("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms>");
            if bidi {
                output.push_str("<bidi xmlns='urn:xmpp:features:bidi'/>");
            }
        }
        FeaturePhase::Authenticated => {}
    }
    append_xml(output, limits)?;
    output.push_str("</stream:features>");
    Ok(())
}

pub(crate) fn write_bidi_xml(output: &mut String, limits: StreamLimits) -> Result<(), S2sError> {
    output.clear();
    output.push_str("<bidi xmlns='urn:xmpp:bidi'>");
    append_xml(output, limits)?;
    output.push_str("</bidi>");
    Ok(())
}

fn whitespace(text: &str) -> bool {
    text.bytes()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
}

fn attributes_empty<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<bool, HandleError> {
    let mut empty = true;
    for attribute in element.attributes()? {
        attribute?;
        empty = false;
    }
    Ok(empty)
}

fn number<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<Option<u32>, HandleError> {
    let mut valid = attributes_empty(element)?;
    let mut value = 0u32;
    let mut digits = false;
    let mut sign = false;
    let mut trailing = false;
    for node in element.children()? {
        match node? {
            NodeRef::Element(_) => valid = false,
            NodeRef::Text(text) => {
                for byte in text.bytes() {
                    match byte {
                        b' ' | b'\t' | b'\r' | b'\n' if digits => trailing = true,
                        b' ' | b'\t' | b'\r' | b'\n' if !sign => {}
                        b'+' if !digits && !sign && !trailing => sign = true,
                        b'0'..=b'9' if !trailing => {
                            digits = true;
                            if let Some(next) = value
                                .checked_mul(10)
                                .and_then(|n| n.checked_add(u32::from(byte - b'0')))
                            {
                                value = next;
                            } else {
                                valid = false;
                            }
                        }
                        _ => valid = false,
                    }
                }
            }
        }
    }
    Ok((valid && digits).then_some(value))
}

fn block<R: ArenaRead>(element: &ElementRef<'_, R>) -> Result<Option<StreamLimits>, HandleError> {
    let mut valid = attributes_empty(element)?;
    let mut limits = StreamLimits::default();
    let mut max_seen = false;
    let mut idle_seen = false;
    for node in element.children()? {
        match node? {
            NodeRef::Text(text) => valid &= whitespace(text),
            NodeRef::Element(child) if child.namespace() == NAMESPACE => {
                let (seen, field) = match child.name() {
                    "max-bytes" => (&mut max_seen, &mut limits.max_bytes),
                    "idle-seconds" => (&mut idle_seen, &mut limits.idle_seconds),
                    _ => continue,
                };
                valid &= !*seen;
                *seen = true;
                *field = number(&child)?;
                valid &= field.is_some();
            }
            NodeRef::Element(_) => {}
        }
    }
    Ok(valid.then_some(limits))
}

pub(crate) fn parse_limits<R: ArenaRead>(
    parent: &ElementRef<'_, R>,
) -> Result<Option<StreamLimits>, HandleError> {
    let mut seen = false;
    let mut limits = None;
    for node in parent.children()? {
        if let NodeRef::Element(child) = node?
            && child.name() == "limits"
            && child.namespace() == NAMESPACE
        {
            if seen {
                return Ok(None);
            }
            seen = true;
            limits = block(&child)?;
        }
    }
    Ok(limits)
}

pub(crate) fn parse_bidi<A: ChunkAllocator>(
    parsed: &Parsed<Element, A>,
) -> Result<Option<StreamLimits>, S2sError> {
    let element = parsed.value().resolve(parsed.arena())?;
    let rejected = S2sError::Stream(StreamErrorCondition::NotAuthorized);
    if element.name() != "bidi"
        || element.namespace() != BIDI_NAMESPACE
        || parsed.has_explicit_attributes()
    {
        return Err(rejected);
    }
    for node in element.children()? {
        match node? {
            NodeRef::Text(text) if whitespace(text) => {}
            NodeRef::Element(child)
                if child.name() == "limits" && child.namespace() == NAMESPACE => {}
            _ => return Err(rejected),
        }
    }
    parse_limits(&element).map_err(Into::into)
}

struct CountingSink {
    remaining: u32,
    exceeded: bool,
}
impl AsyncWrite for CountingSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.len() as u64 > u64::from(self.remaining) {
            self.exceeded = true;
            Poll::Ready(Err(io::ErrorKind::FileTooLarge.into()))
        } else {
            self.remaining -= bytes.len() as u32;
            Poll::Ready(Ok(bytes.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) async fn stanza_fits<R: ArenaRead>(
    stanza: &StanzaRef<'_, R>,
    maximum: u32,
) -> Result<bool, S2sError> {
    let mut sink = CountingSink {
        remaining: maximum,
        exceeded: false,
    };
    match stanza.write_xml_async(&mut sink).await {
        Ok(()) => Ok(true),
        Err(AsyncWriteError::Access(_)) => Err(S2sError::Internal),
        Err(AsyncWriteError::Output(_)) if sink.exceeded => Ok(false),
        Err(AsyncWriteError::Output(_)) => Err(S2sError::Internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::parser::{ParserConfig, parse_element};
    use std::num::NonZeroUsize;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    async fn element(xml: &str) -> TestResult<Parsed<Element, GlobalChunkAllocator>> {
        Ok(parse_element(
            xml.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(16_384).ok_or("limit")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        )
        .await?)
    }
    async fn advice(content: &str) -> TestResult<Option<StreamLimits>> {
        let parsed = element(&format!("<features>{content}</features>")).await?;
        Ok(parse_limits(&parsed.value().resolve(parsed.arena())?)?)
    }

    #[test]
    fn unsigned_int_lexical_space_and_bounds() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            for (text, expected) in [
                ("0", Some(0)),
                ("4294967295", Some(u32::MAX)),
                (" \t+00042\r\n", Some(42)),
                ("+0", Some(0)),
                ("4294967296", None),
                ("", None),
                ("+", None),
                ("-0", None),
                ("1.0", None),
                ("1e2", None),
                ("NaN", None),
                ("１２", None),
                ("1 2", None),
                ("+ 1", None),
                ("1+", None),
            ] {
                let parsed = element(&format!("<max-bytes>{text}</max-bytes>")).await?;
                assert_eq!(
                    number(&parsed.value().resolve(parsed.arena())?)?,
                    expected,
                    "{text:?}"
                );
            }
            Ok(())
        })
    }

    #[test]
    fn optional_advice_replaces_fields_but_malformed_blocks_do_not_update() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            assert_eq!(advice("").await?, None);
            for (content, expected) in [
                ("", StreamLimits::default()),
                ("<max-bytes>0</max-bytes>", StreamLimits { max_bytes: Some(0), idle_seconds: None }),
                ("<idle-seconds>4294967295</idle-seconds>", StreamLimits { max_bytes: None, idle_seconds: Some(u32::MAX) }),
                ("<other>secret</other><max-bytes xmlns='wrong'>bad</max-bytes><idle-seconds>2</idle-seconds>", StreamLimits { max_bytes: None, idle_seconds: Some(2) }),
            ] {
                assert_eq!(advice(&format!("<limits xmlns='{NAMESPACE}'>{content}</limits>")).await?, Some(expected));
            }
            for xml in [
                format!("<limits xmlns='{NAMESPACE}'/><limits xmlns='{NAMESPACE}'/>"),
                format!("<limits xmlns='{NAMESPACE}' extra='1'/>"),
                format!("<limits xmlns='{NAMESPACE}'>text<max-bytes>1</max-bytes></limits>"),
                format!("<limits xmlns='{NAMESPACE}'><max-bytes>1</max-bytes>text</limits>"),
                format!("<limits xmlns='{NAMESPACE}'><max-bytes>1</max-bytes><max-bytes>2</max-bytes></limits>"),
                format!("<limits xmlns='{NAMESPACE}'><idle-seconds>1</idle-seconds><idle-seconds>2</idle-seconds></limits>"),
                format!("<limits xmlns='{NAMESPACE}'><max-bytes extra='1'>1</max-bytes></limits>"),
                format!("<limits xmlns='{NAMESPACE}'><max-bytes>1<x/></max-bytes></limits>"),
                format!("<limits xmlns='{NAMESPACE}'><idle-seconds>-1</idle-seconds></limits>"),
            ] { assert_eq!(advice(&xml).await?, None, "{xml}"); }
            Ok(())
        })
    }

    #[test]
    fn bidi_root_remains_strict_while_optional_advice_can_be_ignored() -> TestResult {
        compio::runtime::Runtime::new()?.block_on(async {
            for child in [
                "".to_owned(),
                format!(" \n<limits xmlns='{NAMESPACE}'/>\t"),
                format!("<limits xmlns='{NAMESPACE}'/><limits xmlns='{NAMESPACE}'/>"),
            ] {
                assert!(
                    parse_bidi(
                        &element(&format!("<bidi xmlns='urn:xmpp:bidi'>{child}</bidi>")).await?
                    )
                    .is_ok()
                );
            }
            for xml in [
                "<bidi xmlns='wrong'/>",
                "<x xmlns='urn:xmpp:bidi'/>",
                "<bidi xmlns='urn:xmpp:bidi' extra='x'/>",
                "<bidi xmlns='urn:xmpp:bidi'>text<limits xmlns='urn:xmpp:stream-limits:0'/></bidi>",
                "<bidi xmlns='urn:xmpp:bidi'><limits xmlns='wrong'/></bidi>",
                "<bidi xmlns='urn:xmpp:bidi'><x/></bidi>",
            ] {
                assert!(
                    matches!(
                        parse_bidi(&element(xml).await?),
                        Err(S2sError::Stream(StreamErrorCondition::NotAuthorized))
                    ),
                    "{xml}"
                );
            }
            Ok(())
        })
    }

    #[test]
    fn builders_reuse_buffer_and_include_exact_values_in_each_phase() -> TestResult {
        let local = local_limits(10_000, u64::from(u32::MAX)).map_err(|e| format!("{e:?}"))?;
        let limits = format!(
            "<limits xmlns='{NAMESPACE}'><max-bytes>10000</max-bytes><idle-seconds>4294967295</idle-seconds></limits>"
        );
        let mut xml = String::with_capacity(1024);
        for (phase, prefix) in [
            (
                FeaturePhase::StartTls,
                "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>",
            ),
            (
                FeaturePhase::Sasl { bidi: false },
                "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms>",
            ),
            (
                FeaturePhase::Sasl { bidi: true },
                "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms><bidi xmlns='urn:xmpp:features:bidi'/>",
            ),
            (FeaturePhase::Authenticated, ""),
        ] {
            write_features_xml(&mut xml, phase, local).map_err(|e| format!("{e:?}"))?;
            assert_eq!(
                xml,
                format!("<stream:features>{prefix}{limits}</stream:features>")
            );
            assert_eq!(xml.capacity(), 1024);
        }
        write_bidi_xml(&mut xml, local).map_err(|e| format!("{e:?}"))?;
        assert_eq!(xml, format!("<bidi xmlns='urn:xmpp:bidi'>{limits}</bidi>"));
        assert_eq!(xml.capacity(), 1024);
        Ok(())
    }
}
