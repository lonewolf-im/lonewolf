// SPDX-License-Identifier: Apache-2.0

//! Builds incoming trees while rejecting duplicate extension attributes.

use lonewolf_util::arena::{Arena, ChunkAllocator};

use super::element::ElementFrame;
use super::{
    AttributesBuilder, BuildError, Element, Header, SliceBuilder, Stanza, StanzaBuilder,
    StanzaNamespace, StanzaType, XML_NAMESPACE, store_text,
};
use crate::jid::Jid;

pub(crate) enum Frame {
    Element(ElementFrame),
    Stanza(StanzaFrame),
}

pub(crate) enum Completed {
    Element(Element),
    Stanza(Stanza),
}

pub(crate) struct StanzaFrame {
    header: Header,
    attributes: AttributesBuilder,
    children: SliceBuilder<Element>,
}

impl Frame {
    pub(crate) fn element<A: ChunkAllocator>(
        name: &str,
        namespace: &str,
        arena: &mut Arena<A>,
    ) -> Result<Self, BuildError> {
        ElementFrame::new(name, namespace, arena).map(Self::Element)
    }

    pub(crate) fn stanza(stanza_type: StanzaType, namespace: StanzaNamespace) -> Self {
        Self::Stanza(StanzaFrame {
            header: Header {
                stanza_type,
                namespace,
                from: None,
                to: None,
                id: None,
                lang: None,
            },
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }

    pub(crate) fn attribute<A: ChunkAllocator>(
        &mut self,
        name: &str,
        namespace: &str,
        value: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        match self {
            Self::Element(frame) => frame.attribute(name, namespace, value, arena),
            Self::Stanza(frame) => match (name, namespace) {
                ("from", "") => {
                    frame.header.from = Some(Jid::parse_in(value, arena)?);
                    Ok(())
                }
                ("to", "") => {
                    frame.header.to = Some(Jid::parse_in(value, arena)?);
                    Ok(())
                }
                ("id", "") => {
                    if value.is_empty() {
                        return Err(BuildError::EmptyId);
                    }
                    frame.header.id = store_text(Some(value), arena)?;
                    Ok(())
                }
                ("lang", XML_NAMESPACE) => {
                    frame.header.lang = store_text(Some(value), arena)?;
                    Ok(())
                }
                ("type", "") => Ok(()),
                _ => {
                    if frame.attributes.find(name, namespace, arena)?.is_some() {
                        return Err(BuildError::DuplicateAttribute);
                    }
                    frame.attributes.set(name, namespace, value, arena)
                }
            },
        }
    }

    pub(crate) fn text<A: ChunkAllocator>(
        &mut self,
        text: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        match self {
            Self::Element(frame) => frame.text(text, arena),
            Self::Stanza(_)
                if text
                    .bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n')) =>
            {
                Ok(())
            }
            Self::Stanza(_) => Err(BuildError::InvalidText),
        }
    }

    pub(crate) fn child<A: ChunkAllocator>(
        &mut self,
        element: Element,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        match self {
            Self::Element(frame) => frame.child(element, arena),
            Self::Stanza(frame) => frame.children.push(element, arena),
        }
    }

    pub(crate) fn finish<A: ChunkAllocator>(
        self,
        arena: &mut Arena<A>,
    ) -> Result<Completed, BuildError> {
        match self {
            Self::Element(frame) => frame.finish(arena).map(Completed::Element),
            Self::Stanza(frame) => StanzaBuilder {
                arena,
                header: frame.header,
                attributes: frame.attributes,
                children: frame.children,
            }
            .build()
            .map(Completed::Stanza),
        }
    }
}
