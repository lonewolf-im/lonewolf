// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use lonewolf_util::arena::{ArenaRead, ChunkAllocator, HandleError};
use lonewolf_xmpp::stanza::{
    AttributeRef, ElementRef, NodeRef, RoutedStanza, StanzaKind, StanzaNamespace, StanzaType,
};

use super::TestResult;

type Attributes = BTreeMap<(String, String), String>;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Stanza {
    kind: StanzaKind,
    stanza_type: StanzaType,
    namespace: StanzaNamespace,
    from: Option<String>,
    to: Option<String>,
    id: Option<String>,
    lang: Option<String>,
    attributes: Attributes,
    children: Vec<Element>,
}

#[derive(Debug, Eq, PartialEq)]
struct Element {
    namespace: String,
    name: String,
    attributes: Attributes,
    children: Vec<Node>,
}

#[derive(Debug, Eq, PartialEq)]
enum Node {
    Element(Element),
    Text(String),
}

fn attributes<'a>(
    attributes: impl Iterator<Item = Result<AttributeRef<'a>, HandleError>>,
) -> TestResult<Attributes> {
    attributes
        .map(|attribute| {
            let attribute = attribute?;
            Ok((
                (attribute.namespace.into(), attribute.name.into()),
                attribute.value.into(),
            ))
        })
        .collect()
}

fn element<R: ArenaRead>(value: ElementRef<'_, R>) -> TestResult<Element> {
    let children = value
        .children()?
        .map(|node| match node? {
            NodeRef::Element(value) => element(value).map(Node::Element),
            NodeRef::Text(value) => Ok(Node::Text(value.into())),
        })
        .collect::<TestResult<_>>()?;
    Ok(Element {
        namespace: value.namespace().into(),
        name: value.name().into(),
        attributes: attributes(value.attributes()?)?,
        children,
    })
}

pub(super) fn stanza<A: ChunkAllocator>(value: &RoutedStanza<A>) -> TestResult<Stanza> {
    let value = value.resolve()?;
    Ok(Stanza {
        kind: value.kind(),
        stanza_type: value.stanza_type(),
        namespace: value.namespace(),
        from: value.from()?.map(|jid| jid.to_string()),
        to: value.to()?.map(|jid| jid.to_string()),
        id: value.id()?.map(str::to_owned),
        lang: value.lang()?.map(str::to_owned),
        attributes: attributes(value.attributes()?)?,
        children: value
            .children()?
            .map(|value| element(value?))
            .collect::<TestResult<_>>()?,
    })
}
