// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ChunkAllocator};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, attributes::Attribute};
use quick_xml::name::{Namespace, NamespaceResolver, PrefixDeclaration, QName, ResolveResult};

use super::{MAX_ATTRIBUTES_PER_ELEMENT, ParseError};
use crate::stanza::incoming::Frame;
use crate::stanza::namespace::NamespaceContext;
use crate::stanza::{
    BuildError, CLIENT_NAMESPACE, SERVER_NAMESPACE, STREAM_NAMESPACE, StanzaKind, StanzaNamespace,
    XML_NAMESPACE, xml,
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
            if value == XMLNS_NAMESPACE
                || (value == XML_NAMESPACE && prefix != PrefixDeclaration::Named("xml"))
                || (value.is_empty() && matches!(prefix, PrefixDeclaration::Named(_)))
            {
                return Err(ParseError::NotWellFormed);
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

pub(super) fn has_extra_header_namespaces(resolver: &NamespaceResolver) -> bool {
    let mut stream_alias_seen = false;
    for (prefix, namespace) in resolver.bindings() {
        let PrefixDeclaration::Named(prefix) = prefix else {
            continue;
        };
        let namespace = namespace.into_inner();
        if prefix == "xml" && namespace == XML_NAMESPACE {
            continue;
        }
        if namespace != STREAM_NAMESPACE || stream_alias_seen {
            return true;
        }
        stream_alias_seen = true;
    }
    false
}

pub(super) fn frame<A: ChunkAllocator>(
    resolver: &NamespaceResolver,
    start: &BytesStart<'_>,
    arena: &mut Arena<A>,
    root: bool,
    stream_lang: &str,
    parent_namespaces: Option<NamespaceContext>,
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
        if start.name().prefix().is_some() {
            return Err(ParseError::BadNamespacePrefix);
        }
        let kind = match name {
            "message" => StanzaKind::Message,
            "presence" => StanzaKind::Presence,
            _ => StanzaKind::Iq,
        };
        Frame::stanza(kind, namespace)
    } else {
        Frame::element(name, namespace, arena)?
    };
    let mut namespaces = parent_namespaces.unwrap_or_default();
    if parent_namespaces.is_none() {
        namespaces.bind("", content_namespace(resolver)?, arena)?;
    }
    for attribute in start.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        if let Some(prefix) = attribute.key.as_namespace_binding() {
            let prefix = match prefix {
                PrefixDeclaration::Default if parent_namespaces.is_none() => continue,
                PrefixDeclaration::Default => "",
                PrefixDeclaration::Named(prefix) => prefix,
            };
            namespaces.bind(prefix, &normalized(&attribute)?, arena)?;
        }
    }
    frame.set_namespaces(namespaces);
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
        frame
            .attribute(name, namespace, &value, arena)
            .map_err(|error| {
                if matches!(error, BuildError::DuplicateAttribute) {
                    ParseError::NotWellFormed
                } else {
                    error.into()
                }
            })?;
    }
    if root && !has_lang && !stream_lang.is_empty() {
        frame.attribute("lang", XML_NAMESPACE, stream_lang, arena)?;
    }
    Ok(frame)
}

fn normalized<'a>(attribute: &Attribute<'a>) -> Result<std::borrow::Cow<'a, str>, ParseError> {
    if attribute.value.contains('<') {
        return Err(ParseError::NotWellFormed);
    }
    let value = attribute.normalized_value(XmlVersion::Explicit1_0)?;
    xml::validate_text(&value).map_err(|_| ParseError::NotWellFormed)?;
    Ok(value)
}

fn resolved_namespace(namespace: ResolveResult<'_>) -> Result<&str, ParseError> {
    match namespace {
        ResolveResult::Unbound => Ok(""),
        ResolveResult::Bound(namespace) => Ok(namespace.into_inner()),
        ResolveResult::Unknown(_) => Err(ParseError::UnboundNamespacePrefix),
    }
}

fn validate_qname(name: QName<'_>) -> Result<(), ParseError> {
    let name = name.into_inner();
    if let Some((prefix, local)) = name.split_once(':') {
        xml::validate_name(prefix, "", false).map_err(|_| ParseError::NotWellFormed)?;
        xml::validate_name(local, "", false).map_err(|_| ParseError::NotWellFormed)?;
    } else {
        xml::validate_name(name, "", false).map_err(|_| ParseError::NotWellFormed)?;
    }
    Ok(())
}
