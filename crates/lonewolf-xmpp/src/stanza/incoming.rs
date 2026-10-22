// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, Handle, HandleError};

use super::element::ElementFrame;
use super::namespace::NamespaceContext;
use super::{
    AttributesBuilder, BuildError, Element, Header, IqType, MessageType, PresenceType,
    SliceBuilder, Stanza, StanzaBuilder, StanzaErrorCondition, StanzaKind, StanzaNamespace,
    StanzaType, XML_NAMESPACE, error_element_in, store_text, xml,
};
use crate::jid::{Jid, JidError, JidRef};

pub(crate) enum Frame {
    Element(ElementFrame),
    Stanza(StanzaFrame),
}

pub(crate) enum Completed {
    Element(Element),
    Stanza(Stanza),
    RejectedStanza(RejectedStanza),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaRejection {
    BadRequest,
    JidMalformed,
}

#[derive(Clone, Copy)]
pub struct RejectedStanza {
    kind: StanzaKind,
    namespace: StanzaNamespace,
    reason: StanzaRejection,
    can_reply: bool,
    invalid_from: bool,
    invalid_to: bool,
    envelope: Handle<RejectedEnvelope>,
}

#[derive(Clone, Copy)]
struct RejectedEnvelope {
    from: Option<Jid>,
    to: Option<Jid>,
    id: Option<Handle<str>>,
    lang: Option<Handle<str>>,
}

impl RejectedStanza {
    pub fn kind(&self) -> StanzaKind {
        self.kind
    }

    pub fn namespace(&self) -> StanzaNamespace {
        self.namespace
    }

    pub fn reason(&self) -> StanzaRejection {
        self.reason
    }

    pub fn can_reply(&self) -> bool {
        self.can_reply
    }

    pub fn invalid_from(&self) -> bool {
        self.invalid_from
    }

    pub fn invalid_to(&self) -> bool {
        self.invalid_to
    }

    pub fn from<'a>(&self, arena: &'a impl ArenaRead) -> Result<Option<JidRef<'a>>, HandleError> {
        arena
            .get(self.envelope)?
            .from
            .map(|jid| jid.resolve(arena))
            .transpose()
    }

    pub fn to<'a>(&self, arena: &'a impl ArenaRead) -> Result<Option<JidRef<'a>>, HandleError> {
        arena
            .get(self.envelope)?
            .to
            .map(|jid| jid.resolve(arena))
            .transpose()
    }

    pub fn id<'a>(&self, arena: &'a impl ArenaRead) -> Result<Option<&'a str>, HandleError> {
        arena
            .get(self.envelope)?
            .id
            .map(|id| arena.get(id))
            .transpose()
    }

    /// The rejection and both JIDs must belong to `arena`.
    /// Returns [`BuildError::InvalidErrorSource`] for IQ responses and error stanzas.
    pub fn error_in<A: ChunkAllocator>(
        &self,
        authenticated: Jid,
        server: Jid,
        arena: &mut Arena<A>,
    ) -> Result<Stanza, BuildError> {
        let envelope = *arena.get(self.envelope)?;
        authenticated.resolve(arena)?;
        server.resolve(arena)?;
        if !self.can_reply {
            return Err(BuildError::InvalidErrorSource);
        }
        let condition = match self.reason {
            StanzaRejection::BadRequest => StanzaErrorCondition::BadRequest,
            StanzaRejection::JidMalformed => StanzaErrorCondition::JidMalformed,
        };
        let error = error_element_in(
            self.namespace,
            condition,
            None,
            condition.default_text(),
            arena,
        )?;
        let stanza_type = match self.kind {
            StanzaKind::Message => StanzaType::Message(MessageType::Error),
            StanzaKind::Presence => StanzaType::Presence(PresenceType::Error),
            StanzaKind::Iq => StanzaType::Iq(IqType::Error),
        };
        let id = match (envelope.id, self.kind) {
            (None, StanzaKind::Iq) => Some(arena.try_alloc_str("")?),
            (id, _) => id,
        };
        StanzaBuilder {
            arena,
            header: Header {
                stanza_type,
                original_message_type: None,
                namespace: self.namespace,
                from: if self.invalid_to() {
                    Some(server)
                } else {
                    envelope.to
                },
                to: Some(authenticated),
                id,
                lang: envelope.lang,
            },
            namespaces: NamespaceContext::default(),
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        }
        .child(error)?
        .build()
    }
}

pub(crate) struct StanzaFrame {
    kind: StanzaKind,
    namespace: StanzaNamespace,
    raw_type: Option<Handle<str>>,
    from: Option<Handle<str>>,
    to: Option<Handle<str>>,
    id: Option<Handle<str>>,
    lang: Option<Handle<str>>,
    invalid_text: bool,
    namespaces: NamespaceContext,
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

    pub(crate) fn stanza(kind: StanzaKind, namespace: StanzaNamespace) -> Self {
        Self::Stanza(StanzaFrame {
            kind,
            namespace,
            raw_type: None,
            from: None,
            to: None,
            id: None,
            lang: None,
            invalid_text: false,
            namespaces: NamespaceContext::default(),
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }

    pub(crate) fn namespaces(&self) -> NamespaceContext {
        match self {
            Self::Element(frame) => frame.namespaces(),
            Self::Stanza(frame) => frame.namespaces,
        }
    }

    pub(crate) fn set_namespaces(&mut self, namespaces: NamespaceContext) {
        match self {
            Self::Element(frame) => frame.set_namespaces(namespaces),
            Self::Stanza(frame) => frame.namespaces = namespaces,
        }
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
            Self::Stanza(frame) => {
                let slot = match (name, namespace) {
                    ("from", "") => &mut frame.from,
                    ("to", "") => &mut frame.to,
                    ("id", "") => &mut frame.id,
                    ("lang", XML_NAMESPACE) => &mut frame.lang,
                    ("type", "") => &mut frame.raw_type,
                    _ => {
                        if frame.attributes.find(name, namespace, arena)?.is_some() {
                            return Err(BuildError::DuplicateAttribute);
                        }
                        return frame.attributes.set(name, namespace, value, arena);
                    }
                };
                *slot = store_text(Some(value), arena)?;
                Ok(())
            }
        }
    }

    pub(crate) fn text<A: ChunkAllocator>(
        &mut self,
        text: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        match self {
            Self::Element(frame) => frame.text(text, arena),
            Self::Stanza(frame) => {
                xml::validate_text(text)?;
                frame.invalid_text |= !text
                    .bytes()
                    .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'));
                Ok(())
            }
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
        scratch: &mut String,
    ) -> Result<Completed, BuildError> {
        match self {
            Self::Element(frame) => frame.finish(arena).map(Completed::Element),
            Self::Stanza(frame) => frame.finish(arena, scratch),
        }
    }
}

impl StanzaFrame {
    fn finish<A: ChunkAllocator>(
        self,
        arena: &mut Arena<A>,
        scratch: &mut String,
    ) -> Result<Completed, BuildError> {
        let raw_type = self.raw_type.map(|value| arena.get(value)).transpose()?;
        let can_reply = raw_type != Some("error")
            && !(self.kind == StanzaKind::Iq && raw_type == Some("result"));
        let stanza_type = stanza_type(self.kind, raw_type);
        let (from, invalid_from) = address(self.from, arena, scratch)?;
        let (to, invalid_to) = address(self.to, arena, scratch)?;
        let header = Header {
            stanza_type: stanza_type.unwrap_or(match self.kind {
                StanzaKind::Message => StanzaType::Message(MessageType::Normal),
                StanzaKind::Presence => StanzaType::Presence(PresenceType::Available),
                StanzaKind::Iq => StanzaType::Iq(IqType::Get),
            }),
            original_message_type: (self.kind == StanzaKind::Message)
                .then_some(self.raw_type)
                .flatten(),
            namespace: self.namespace,
            from,
            to,
            id: self.id,
            lang: self.lang,
        };
        let builder = StanzaBuilder {
            arena,
            header,
            namespaces: self.namespaces,
            attributes: self.attributes,
            children: self.children,
        };
        let invalid_structure = match builder.validate() {
            Ok(()) => self.invalid_text || stanza_type.is_none(),
            Err(
                BuildError::MissingIqId
                | BuildError::InvalidIqPayload
                | BuildError::InvalidErrorPayload
                | BuildError::MissingServerAddresses,
            ) => true,
            Err(error) => return Err(error),
        };
        let reason = if invalid_structure {
            StanzaRejection::BadRequest
        } else if invalid_from || invalid_to {
            StanzaRejection::JidMalformed
        } else {
            return builder.build_validated().map(Completed::Stanza);
        };
        Ok(Completed::RejectedStanza(RejectedStanza {
            kind: self.kind,
            namespace: self.namespace,
            reason,
            can_reply,
            invalid_from,
            invalid_to,
            envelope: arena.try_alloc(RejectedEnvelope {
                from,
                to,
                id: self.id,
                lang: self.lang,
            })?,
        }))
    }
}

fn address<A: ChunkAllocator>(
    raw: Option<Handle<str>>,
    arena: &mut Arena<A>,
    scratch: &mut String,
) -> Result<(Option<Jid>, bool), BuildError> {
    let Some(raw) = raw else {
        return Ok((None, false));
    };
    // Reuse parser scratch so preparing arena-owned text needs no second arena.
    scratch.clear();
    scratch.push_str(arena.get(raw)?);
    let result = Jid::parse_in(scratch, arena);
    scratch.clear();
    match result {
        Ok(jid) => Ok((Some(jid), false)),
        Err(JidError::EmptyPart(_) | JidError::PartTooLong(_) | JidError::InvalidPart(_)) => {
            Ok((None, true))
        }
        Err(error) => Err(error.into()),
    }
}

fn stanza_type(kind: StanzaKind, value: Option<&str>) -> Option<StanzaType> {
    Some(match (kind, value) {
        (StanzaKind::Message, Some("chat")) => StanzaType::Message(MessageType::Chat),
        (StanzaKind::Message, Some("groupchat")) => StanzaType::Message(MessageType::Groupchat),
        (StanzaKind::Message, Some("headline")) => StanzaType::Message(MessageType::Headline),
        (StanzaKind::Message, Some("error")) => StanzaType::Message(MessageType::Error),
        (StanzaKind::Message, _) => StanzaType::Message(MessageType::Normal),
        (StanzaKind::Presence, None) => StanzaType::Presence(PresenceType::Available),
        (StanzaKind::Presence, Some("unavailable")) => {
            StanzaType::Presence(PresenceType::Unavailable)
        }
        (StanzaKind::Presence, Some("subscribe")) => StanzaType::Presence(PresenceType::Subscribe),
        (StanzaKind::Presence, Some("subscribed")) => {
            StanzaType::Presence(PresenceType::Subscribed)
        }
        (StanzaKind::Presence, Some("unsubscribe")) => {
            StanzaType::Presence(PresenceType::Unsubscribe)
        }
        (StanzaKind::Presence, Some("unsubscribed")) => {
            StanzaType::Presence(PresenceType::Unsubscribed)
        }
        (StanzaKind::Presence, Some("probe")) => StanzaType::Presence(PresenceType::Probe),
        (StanzaKind::Presence, Some("error")) => StanzaType::Presence(PresenceType::Error),
        (StanzaKind::Iq, Some("get")) => StanzaType::Iq(IqType::Get),
        (StanzaKind::Iq, Some("set")) => StanzaType::Iq(IqType::Set),
        (StanzaKind::Iq, Some("result")) => StanzaType::Iq(IqType::Result),
        (StanzaKind::Iq, Some("error")) => StanzaType::Iq(IqType::Error),
        _ => return None,
    })
}
