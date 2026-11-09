// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::Parsed;
use lonewolf_xmpp::stanza::{CLIENT_NAMESPACE, Element, STREAM_NAMESPACE, XML_NAMESPACE};
use oxilangtag::LanguageTag;

use super::outcome::CloseOutcome;
use crate::hosts::Hosts;
use crate::xml_stream::{escape_attribute, version_components};

pub(super) struct ClientHeader {
    pub(super) host: String,
    pub(super) response_to: Option<String>,
    pub(super) client_content_namespace: bool,
}

#[derive(Clone, Copy)]
pub(super) enum ResponseVersion<'a> {
    Omitted,
    Current,
    ZeroMajor { minor: &'a str },
}

pub(super) fn response_version_from_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
) -> Result<ResponseVersion<'_>, CloseOutcome> {
    let header = header.value().resolve(header.arena())?;
    let Some(version) = header.attribute("version", "")? else {
        return Ok(ResponseVersion::Omitted);
    };
    Ok(match version_components(version) {
        Some(("0", minor)) => ResponseVersion::ZeroMajor { minor },
        _ => ResponseVersion::Current,
    })
}

pub(super) fn validate_header<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
    extra_header_namespaces: bool,
    hosts: &Hosts,
) -> Result<ClientHeader, CloseOutcome> {
    validate_header_with_default(
        header,
        content_namespace,
        extra_header_namespaces,
        hosts,
        hosts.default_host_name(),
    )
}

pub(super) fn validate_header_with_default<A: ChunkAllocator>(
    header: &Parsed<Element, A>,
    content_namespace: &str,
    extra_header_namespaces: bool,
    hosts: &Hosts,
    default_host: &str,
) -> Result<ClientHeader, CloseOutcome> {
    if extra_header_namespaces
        || !matches!(content_namespace, "" | CLIENT_NAMESPACE | STREAM_NAMESPACE)
    {
        return Err(CloseOutcome::InvalidNamespace);
    }
    let header = header.value().resolve(header.arena())?;
    let version = header
        .attribute("version", "")?
        .ok_or(CloseOutcome::UnsupportedVersion)?;
    let (major, _) = version_components(version).ok_or(CloseOutcome::UnsupportedVersion)?;
    if major == "0" {
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
        None => default_host.to_owned(),
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
    version: ResponseVersion<'_>,
) -> Result<String, CloseOutcome> {
    let mut id = [0_u8; 16];
    graviola::random::fill(&mut id).map_err(|_| CloseOutcome::InternalError)?;
    let version_bytes = match version {
        ResponseVersion::ZeroMajor { minor } => minor.len(),
        _ => 0,
    };
    let mut xml = String::with_capacity(192 + host.len() + to.map_or(0, str::len) + version_bytes);
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
    match version {
        ResponseVersion::Omitted => {}
        ResponseVersion::Current => xml.push_str(" version='1.0'"),
        ResponseVersion::ZeroMajor { minor } => {
            xml.push_str(" version='0.");
            xml.push_str(minor);
            xml.push('\'');
        }
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
    outcome
        .stream_condition()
        .map(crate::xml_stream::stream_error_xml)
}
