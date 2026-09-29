// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element, STREAM_NAMESPACE, XML_NAMESPACE};
use lonewolf_xmpp::stream::StreamError;
use oxilangtag::LanguageTag;

use super::outcome::CloseOutcome;
use crate::hosts::Hosts;

pub(super) const STREAM_FOOTER: &str = "</stream:stream>";

pub(super) struct ClientHeader {
    pub(super) host: String,
    pub(super) response_to: Option<String>,
    pub(super) client_content_namespace: bool,
}

pub(super) fn validate_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
    hosts: &Hosts,
) -> Result<ClientHeader, CloseOutcome> {
    if !matches!(content_namespace, "" | CLIENT_NAMESPACE | STREAM_NAMESPACE) {
        return Err(CloseOutcome::InvalidNamespace);
    }
    let header = header.value().resolve(header.arena())?;
    let version = header
        .attribute("version", "")?
        .ok_or(CloseOutcome::UnsupportedVersion)?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(CloseOutcome::UnsupportedVersion)?;
    if major.is_empty()
        || minor.is_empty()
        || major.bytes().all(|digit| digit == b'0')
        || !major.bytes().all(|digit| digit.is_ascii_digit())
        || !minor.bytes().all(|digit| digit.is_ascii_digit())
    {
        return Err(CloseOutcome::UnsupportedVersion);
    }
    let to = header.attribute("to", "")?;
    let from = header.attribute("from", "")?;
    if header
        .attribute("lang", XML_NAMESPACE)?
        .is_some_and(|lang| LanguageTag::parse(lang).is_err())
    {
        return Err(CloseOutcome::InvalidLanguage);
    }
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let host = match to {
        Some(to) => {
            let jid = Jid::parse_in(to, &mut arena).map_err(|_| CloseOutcome::InvalidTo)?;
            let jid = jid.resolve(&arena)?;
            if jid.localpart().is_some() || jid.resourcepart().is_some() {
                return Err(CloseOutcome::InvalidTo);
            }
            if !hosts.is_local_host(jid.domainpart()) {
                return Err(CloseOutcome::HostUnknown);
            }
            jid.domainpart().to_owned()
        }
        None => hosts.default_host_name().to_owned(),
    };
    let response_to = from
        .map(|from| {
            let jid = Jid::parse_in(from, &mut arena).map_err(|_| CloseOutcome::InvalidFrom)?;
            Ok::<_, CloseOutcome>(jid.bare().resolve(&arena)?.as_str().to_owned())
        })
        .transpose()?;
    Ok(ClientHeader {
        host,
        response_to,
        client_content_namespace: content_namespace == CLIENT_NAMESPACE,
    })
}

pub(super) fn response_to_from_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
) -> Option<String> {
    let header = header.value().resolve(header.arena()).ok()?;
    let from = header.attribute("from", "").ok()??;
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::parse_in(from, &mut arena).ok()?;
    Some(jid.bare().resolve(&arena).ok()?.as_str().to_owned())
}

pub(super) fn response_header_xml(
    host: &str,
    to: Option<&str>,
    client_content_namespace: bool,
    include_version: bool,
) -> Result<String, CloseOutcome> {
    let mut id = [0_u8; 16];
    graviola::random::fill(&mut id).map_err(|_| CloseOutcome::InternalError)?;
    let mut xml = String::with_capacity(192 + host.len() + to.map_or(0, str::len));
    xml.push_str(
        "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams'",
    );
    if client_content_namespace {
        xml.push_str(" xmlns='jabber:client'");
    }
    xml.push_str(" from='");
    escape_attribute(&mut xml, host);
    xml.push_str("' id='");
    write!(xml, "{:032x}", u128::from_be_bytes(id)).map_err(|_| CloseOutcome::InternalError)?;
    xml.push('\'');
    if include_version {
        xml.push_str(" version='1.0'");
    }
    xml.push_str(" xml:lang='en'");
    if let Some(to) = to {
        xml.push_str(" to='");
        escape_attribute(&mut xml, to);
        xml.push('\'');
    }
    xml.push('>');
    Ok(xml)
}

pub(super) fn stream_error_xml(outcome: CloseOutcome) -> Option<String> {
    let condition = outcome.stream_condition()?;
    let mut xml = String::with_capacity(128);
    StreamError::new(condition).write_xml(&mut xml).ok()?;
    xml.push_str(STREAM_FOOTER);
    Some(xml)
}

pub(super) fn escape_attribute(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            '\t' => output.push_str("&#x9;"),
            _ => output.push(ch),
        }
    }
}
