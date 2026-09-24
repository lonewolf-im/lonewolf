// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, attributes::Attribute};
use quick_xml::name::{Namespace, NamespaceResolver, PrefixDeclaration, QName, ResolveResult};

use super::{MAX_ATTRIBUTES_PER_ELEMENT, ParseError};
use crate::stanza::incoming::Frame;
use crate::stanza::{
    CLIENT_NAMESPACE, IqType, MessageType, PresenceType, SERVER_NAMESPACE, StanzaNamespace,
    StanzaType, XML_NAMESPACE, xml,
};

const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

pub(super) fn push(
    resolver: &mut NamespaceResolver,
    start: &BytesStart<'_>,
) -> Result<(), ParseError> {
    validate_qname(start.name())?;
    // Namespace values must be normalized before the resolver stores or compares them.
    resolver
        .push(&BytesStart::new(""))
        .map_err(quick_xml::Error::from)?;
    for (index, attribute) in start.attributes().enumerate() {
        if index == MAX_ATTRIBUTES_PER_ELEMENT {
            return Err(ParseError::TooManyAttributes);
        }
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        validate_qname(attribute.key)?;
        if let Some(prefix) = attribute.key.as_namespace_binding() {
            let value = normalized(&attribute)?;
            xml::validate_text(&value)?;
            if value == XMLNS_NAMESPACE
                || (value == XML_NAMESPACE && prefix != PrefixDeclaration::Named("xml"))
                || (value.is_empty() && matches!(prefix, PrefixDeclaration::Named(_)))
            {
                return Err(ParseError::InvalidNamespace);
            }
            resolver
                .add(prefix, Namespace(&value))
                .map_err(quick_xml::Error::from)?;
        }
    }
    Ok(())
}

pub(super) fn element<'a, 'b>(
    resolver: &'a NamespaceResolver,
    start: &'b BytesStart<'_>,
) -> Result<(&'b str, &'a str), ParseError> {
    let (namespace, name) = resolver.resolve_element(start.name());
    Ok((name.into_inner(), resolved_namespace(namespace)?))
}

pub(super) fn content_namespace(resolver: &NamespaceResolver) -> Result<&str, ParseError> {
    let (namespace, _) = resolver.resolve_element(QName("content"));
    resolved_namespace(namespace)
}

pub(super) fn frame<A: ChunkAllocator>(
    resolver: &NamespaceResolver,
    start: &BytesStart<'_>,
    arena: &mut Arena<A>,
    root: bool,
    stream_lang: &str,
) -> Result<Frame, ParseError> {
    let (name, namespace) = element(resolver, start)?;
    let stanza_namespace = match namespace {
        CLIENT_NAMESPACE => Some(StanzaNamespace::Client),
        SERVER_NAMESPACE => Some(StanzaNamespace::Server),
        _ => None,
    };
    let mut frame = if root
        && matches!(name, "message" | "presence" | "iq")
        && let Some(namespace) = stanza_namespace
    {
        let attribute = start
            .try_get_attribute("type")
            .map_err(quick_xml::Error::from)?;
        let value = attribute.as_ref().map(normalized).transpose()?;
        Frame::stanza(stanza_type(name, value.as_deref())?, namespace)
    } else {
        Frame::element(name, namespace, arena)?
    };
    let mut has_lang = false;
    for attribute in start.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        if attribute.key.as_namespace_binding().is_some() {
            continue;
        }
        let (namespace, name) = resolver.resolve_attribute(attribute.key);
        let namespace = resolved_namespace(namespace)?;
        let name = name.into_inner();
        let value = normalized(&attribute)?;
        has_lang |= name == "lang" && namespace == XML_NAMESPACE;
        frame.attribute(name, namespace, &value, arena)?;
    }
    if root && !has_lang && !stream_lang.is_empty() {
        frame.attribute("lang", XML_NAMESPACE, stream_lang, arena)?;
    }
    Ok(frame)
}

fn normalized<'a>(attribute: &Attribute<'a>) -> Result<std::borrow::Cow<'a, str>, ParseError> {
    if attribute.value.contains('<') {
        return Err(ParseError::InvalidXml);
    }
    attribute
        .normalized_value(XmlVersion::Explicit1_0)
        .map_err(ParseError::from)
}

fn resolved_namespace(namespace: ResolveResult<'_>) -> Result<&str, ParseError> {
    match namespace {
        ResolveResult::Unbound => Ok(""),
        ResolveResult::Bound(namespace) => Ok(namespace.into_inner()),
        ResolveResult::Unknown(_) => Err(ParseError::InvalidNamespace),
    }
}

fn validate_qname(name: QName<'_>) -> Result<(), ParseError> {
    let name = name.into_inner();
    if let Some((prefix, local)) = name.split_once(':') {
        xml::validate_name(prefix, "", false)?;
        xml::validate_name(local, "", false)?;
    } else {
        xml::validate_name(name, "", false)?;
    }
    Ok(())
}

fn stanza_type(name: &str, value: Option<&str>) -> Result<StanzaType, ParseError> {
    match (name, value) {
        ("message", None | Some("normal")) => Ok(StanzaType::Message(MessageType::Normal)),
        ("message", Some("chat")) => Ok(StanzaType::Message(MessageType::Chat)),
        ("message", Some("groupchat")) => Ok(StanzaType::Message(MessageType::Groupchat)),
        ("message", Some("headline")) => Ok(StanzaType::Message(MessageType::Headline)),
        ("message", Some("error")) => Ok(StanzaType::Message(MessageType::Error)),
        ("presence", None) => Ok(StanzaType::Presence(PresenceType::Available)),
        ("presence", Some("unavailable")) => Ok(StanzaType::Presence(PresenceType::Unavailable)),
        ("presence", Some("subscribe")) => Ok(StanzaType::Presence(PresenceType::Subscribe)),
        ("presence", Some("subscribed")) => Ok(StanzaType::Presence(PresenceType::Subscribed)),
        ("presence", Some("unsubscribe")) => Ok(StanzaType::Presence(PresenceType::Unsubscribe)),
        ("presence", Some("unsubscribed")) => Ok(StanzaType::Presence(PresenceType::Unsubscribed)),
        ("presence", Some("probe")) => Ok(StanzaType::Presence(PresenceType::Probe)),
        ("presence", Some("error")) => Ok(StanzaType::Presence(PresenceType::Error)),
        ("iq", Some("get")) => Ok(StanzaType::Iq(IqType::Get)),
        ("iq", Some("set")) => Ok(StanzaType::Iq(IqType::Set)),
        ("iq", Some("result")) => Ok(StanzaType::Iq(IqType::Result)),
        ("iq", Some("error")) => Ok(StanzaType::Iq(IqType::Error)),
        _ => Err(ParseError::InvalidStanzaType),
    }
}
