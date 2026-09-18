// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_util::arena::{Arena, ArenaError, ArenaRead, ChunkAllocator, Handle, HandleError};

use crate::jid::{Jid, JidError, JidRef};

mod element;
pub(crate) mod incoming;
mod storage;
pub(crate) mod xml;

pub use element::{AttributeRef, Element, ElementBuilder, ElementRef, NodeRef};

use element::{Attribute, AttributesBuilder};
use storage::{SliceBuilder, StoredSlice};

pub const CLIENT_NAMESPACE: &str = "jabber:client";
pub const SERVER_NAMESPACE: &str = "jabber:server";
pub const STREAM_NAMESPACE: &str = "http://etherx.jabber.org/streams";
pub const STANZA_ERROR_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";
pub const XML_NAMESPACE: &str = xml::XML_NAMESPACE;

/// Includes the root element. Bounds recursive copying and writing.
pub const MAX_ELEMENT_DEPTH: usize = 128;
/// Counts each occurrence of a shared subtree, including text nodes and the root.
pub const MAX_ELEMENT_NODES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaNamespace {
    Client,
    Server,
}

impl StanzaNamespace {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => CLIENT_NAMESPACE,
            Self::Server => SERVER_NAMESPACE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaKind {
    Message,
    Presence,
    Iq,
}

impl StanzaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Presence => "presence",
            Self::Iq => "iq",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    Normal,
    Chat,
    Groupchat,
    Headline,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceType {
    Available,
    Unavailable,
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
    Probe,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IqType {
    Get,
    Set,
    Result,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaType {
    Message(MessageType),
    Presence(PresenceType),
    Iq(IqType),
}

impl StanzaType {
    pub fn kind(self) -> StanzaKind {
        match self {
            Self::Message(_) => StanzaKind::Message,
            Self::Presence(_) => StanzaKind::Presence,
            Self::Iq(_) => StanzaKind::Iq,
        }
    }

    /// Default message and available presence types omit the XML attribute.
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Message(MessageType::Normal) | Self::Presence(PresenceType::Available) => None,
            Self::Message(MessageType::Chat) => Some("chat"),
            Self::Message(MessageType::Groupchat) => Some("groupchat"),
            Self::Message(MessageType::Headline) => Some("headline"),
            Self::Message(MessageType::Error)
            | Self::Presence(PresenceType::Error)
            | Self::Iq(IqType::Error) => Some("error"),
            Self::Presence(PresenceType::Unavailable) => Some("unavailable"),
            Self::Presence(PresenceType::Subscribe) => Some("subscribe"),
            Self::Presence(PresenceType::Subscribed) => Some("subscribed"),
            Self::Presence(PresenceType::Unsubscribe) => Some("unsubscribe"),
            Self::Presence(PresenceType::Unsubscribed) => Some("unsubscribed"),
            Self::Presence(PresenceType::Probe) => Some("probe"),
            Self::Iq(IqType::Get) => Some("get"),
            Self::Iq(IqType::Set) => Some("set"),
            Self::Iq(IqType::Result) => Some("result"),
        }
    }

    pub fn is_error(self) -> bool {
        matches!(
            self,
            Self::Message(MessageType::Error)
                | Self::Presence(PresenceType::Error)
                | Self::Iq(IqType::Error)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    Allocation(ArenaError),
    Access(HandleError),
    Jid(JidError),
    InvalidName,
    InvalidNamespace,
    InvalidText,
    DuplicateAttribute,
    ReservedAttribute,
    EmptyId,
    MissingIqId,
    InvalidIqPayload,
    InvalidErrorPayload,
    MissingServerAddresses,
    NotIqRequest,
    TreeLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    Access(HandleError),
    Output(fmt::Error),
}

#[derive(Clone, Copy)]
struct Header {
    stanza_type: StanzaType,
    namespace: StanzaNamespace,
    from: Option<Jid>,
    to: Option<Jid>,
    id: Option<Handle<str>>,
    lang: Option<Handle<str>>,
}

#[derive(Clone, Copy)]
struct StanzaData {
    header: Header,
    attributes: StoredSlice<Attribute>,
    children: StoredSlice<Element>,
}

/// An immutable, non-owning handle. Keep its arena alive to resolve it.
#[derive(Clone, Copy)]
pub struct Stanza {
    data: Handle<StanzaData>,
}

/// Views cannot outlive the arena borrow, including after freezing.
///
/// ```compile_fail
/// use lonewolf_util::arena::{Arena, ArenaConfig};
/// use lonewolf_xmpp::stanza::{PresenceType, Stanza, StanzaNamespace, StanzaType};
/// let view = {
///     let mut arena = Arena::try_new(ArenaConfig::default()).unwrap();
///     let stanza = Stanza::builder_in(StanzaType::Presence(PresenceType::Available), StanzaNamespace::Client, &mut arena).build().unwrap();
///     stanza.resolve(&arena).unwrap()
/// };
/// println!("{:?}", view.kind());
/// ```
pub struct StanzaRef<'a, R: ArenaRead> {
    arena: &'a R,
    data: &'a StanzaData,
}

/// All retained storage uses the caller's arena. Failed builds do not reclaim allocations.
pub struct StanzaBuilder<'a, A: ChunkAllocator> {
    arena: &'a mut Arena<A>,
    header: Header,
    attributes: AttributesBuilder,
    children: SliceBuilder<Element>,
}

impl Stanza {
    pub fn builder_in<A: ChunkAllocator>(
        stanza_type: StanzaType,
        namespace: StanzaNamespace,
        arena: &mut Arena<A>,
    ) -> StanzaBuilder<'_, A> {
        StanzaBuilder {
            arena,
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
        }
    }

    pub fn resolve<'a, R: ArenaRead>(&self, arena: &'a R) -> Result<StanzaRef<'a, R>, HandleError> {
        Ok(StanzaRef {
            arena,
            data: arena.get(self.data)?,
        })
    }

    /// Shares unchanged storage. Edits do not alter the source stanza.
    pub fn derive_in<'a, A: ChunkAllocator>(
        &self,
        arena: &'a mut Arena<A>,
    ) -> Result<StanzaBuilder<'a, A>, HandleError> {
        let data = *arena.get(self.data)?;
        Ok(StanzaBuilder {
            arena,
            header: data.header,
            attributes: AttributesBuilder::from_slice(data.attributes),
            children: SliceBuilder::from_slice(data.children),
        })
    }

    /// Accepts only IQ get/set requests. Preserves the ID, swaps addresses, and clears content.
    pub fn reply_in<'a, A: ChunkAllocator>(
        &self,
        arena: &'a mut Arena<A>,
    ) -> Result<StanzaBuilder<'a, A>, BuildError> {
        let mut header = arena.get(self.data)?.header;
        if !matches!(
            header.stanza_type,
            StanzaType::Iq(IqType::Get | IqType::Set)
        ) {
            return Err(BuildError::NotIqRequest);
        }
        header.stanza_type = StanzaType::Iq(IqType::Result);
        std::mem::swap(&mut header.from, &mut header.to);
        Ok(StanzaBuilder {
            arena,
            header,
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }
}

impl<'a, R: ArenaRead> StanzaRef<'a, R> {
    pub fn kind(&self) -> StanzaKind {
        self.data.header.stanza_type.kind()
    }

    pub fn stanza_type(&self) -> StanzaType {
        self.data.header.stanza_type
    }

    pub fn namespace(&self) -> StanzaNamespace {
        self.data.header.namespace
    }

    pub fn from(&self) -> Result<Option<JidRef<'a>>, HandleError> {
        self.data
            .header
            .from
            .map(|jid| jid.resolve(self.arena))
            .transpose()
    }

    pub fn to(&self) -> Result<Option<JidRef<'a>>, HandleError> {
        self.data
            .header
            .to
            .map(|jid| jid.resolve(self.arena))
            .transpose()
    }

    pub fn id(&self) -> Result<Option<&'a str>, HandleError> {
        self.data.header.id.map(|id| self.arena.get(id)).transpose()
    }

    pub fn lang(&self) -> Result<Option<&'a str>, HandleError> {
        self.data
            .header
            .lang
            .map(|lang| self.arena.get(lang))
            .transpose()
    }

    /// Yields extension attributes. Common attributes have typed accessors.
    pub fn attributes(
        &self,
    ) -> Result<impl Iterator<Item = Result<AttributeRef<'a>, HandleError>> + 'a, HandleError> {
        element::attributes(self.data.attributes, self.arena)
    }

    pub fn attribute(&self, name: &str, namespace: &str) -> Result<Option<&'a str>, HandleError> {
        for value in self.attributes()? {
            let value = value?;
            if value.name == name && value.namespace == namespace {
                return Ok(Some(value.value));
            }
        }
        Ok(None)
    }

    pub fn children(
        &self,
    ) -> Result<impl Iterator<Item = Result<ElementRef<'a, R>, HandleError>> + 'a, HandleError>
    {
        let arena = self.arena;
        Ok(self
            .data
            .children
            .get(arena)?
            .iter()
            .map(move |child| child.resolve(arena)))
    }

    pub fn child(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<ElementRef<'a, R>>, HandleError> {
        for child in self.children()? {
            let child = child?;
            if child.name() == name && child.namespace() == namespace {
                return Ok(Some(child));
            }
        }
        Ok(None)
    }

    /// Copies all content. The source arena can be dropped after this call.
    pub fn clone_in<A: ChunkAllocator>(&self, arena: &mut Arena<A>) -> Result<Stanza, BuildError> {
        self.to_builder_in(arena)?.build()
    }

    /// Copies all content into the destination before applying edits.
    pub fn to_builder_in<'b, A: ChunkAllocator>(
        &self,
        arena: &'b mut Arena<A>,
    ) -> Result<StanzaBuilder<'b, A>, BuildError> {
        let header = Header {
            stanza_type: self.stanza_type(),
            namespace: self.namespace(),
            from: self.from()?.map(|jid| jid.clone_in(arena)).transpose()?,
            to: self.to()?.map(|jid| jid.clone_in(arena)).transpose()?,
            id: self.id()?.map(|id| arena.try_alloc_str(id)).transpose()?,
            lang: self
                .lang()?
                .map(|lang| arena.try_alloc_str(lang))
                .transpose()?,
        };
        let attributes = AttributesBuilder::copy_from(self.data.attributes, self.arena, arena)?;
        let mut children = SliceBuilder::new();
        for child in self.children()? {
            let child = child?.clone_in(arena)?;
            children.push(child, arena)?;
        }
        Ok(StanzaBuilder {
            arena,
            header,
            attributes,
            children,
        })
    }

    /// Writes explicit namespace declarations. Output failure can leave a partial stanza.
    pub fn write_xml(&self, output: &mut impl fmt::Write) -> Result<(), WriteError> {
        let name = self.kind().as_str();
        write!(output, "<{name}")?;
        xml::attribute(output, "xmlns", self.namespace().as_str())?;
        if let Some(jid) = self.from()? {
            xml::attribute(output, "from", jid.as_str())?;
        }
        if let Some(jid) = self.to()? {
            xml::attribute(output, "to", jid.as_str())?;
        }
        if let Some(id) = self.id()? {
            xml::attribute(output, "id", id)?;
        }
        if let Some(stanza_type) = self.stanza_type().as_str() {
            xml::attribute(output, "type", stanza_type)?;
        }
        if let Some(lang) = self.lang()? {
            xml::attribute(output, "xml:lang", lang)?;
        }
        element::write_attributes(self.data.attributes, self.arena, output)?;
        if self.data.children.get(self.arena)?.is_empty() {
            output.write_str("/>")?;
            return Ok(());
        }
        output.write_char('>')?;
        for child in self.children()? {
            child?.write_in(output, Some(self.namespace().as_str()))?;
        }
        write!(output, "</{name}>")?;
        Ok(())
    }
}

impl<A: ChunkAllocator> StanzaBuilder<'_, A> {
    pub fn stanza_type(mut self, stanza_type: StanzaType) -> Self {
        self.header.stanza_type = stanza_type;
        self
    }

    pub fn from(mut self, jid: Option<Jid>) -> Result<Self, BuildError> {
        if let Some(jid) = jid {
            jid.resolve(self.arena)?;
        }
        self.header.from = jid;
        Ok(self)
    }

    pub fn to(mut self, jid: Option<Jid>) -> Result<Self, BuildError> {
        if let Some(jid) = jid {
            jid.resolve(self.arena)?;
        }
        self.header.to = jid;
        Ok(self)
    }

    pub fn id(mut self, id: Option<&str>) -> Result<Self, BuildError> {
        if id == Some("") {
            return Err(BuildError::EmptyId);
        }
        self.header.id = store_text(id, self.arena)?;
        Ok(self)
    }

    pub fn lang(mut self, lang: Option<&str>) -> Result<Self, BuildError> {
        self.header.lang = store_text(lang, self.arena)?;
        Ok(self)
    }

    /// Sets an extension attribute. Common stanza attributes use their typed setters.
    pub fn attribute(
        mut self,
        name: &str,
        namespace: &str,
        value: &str,
    ) -> Result<Self, BuildError> {
        if reserved_attribute(name, namespace) {
            return Err(BuildError::ReservedAttribute);
        }
        self.attributes.set(name, namespace, value, self.arena)?;
        Ok(self)
    }

    pub fn remove_attribute(mut self, name: &str, namespace: &str) -> Result<Self, BuildError> {
        if reserved_attribute(name, namespace) {
            return Err(BuildError::ReservedAttribute);
        }
        self.attributes.remove(name, namespace, self.arena)?;
        Ok(self)
    }

    pub fn child(mut self, child: Element) -> Result<Self, BuildError> {
        child.resolve(self.arena)?;
        self.children.push(child, self.arena)?;
        Ok(self)
    }

    pub fn remove_children(mut self, name: &str, namespace: &str) -> Result<Self, BuildError> {
        self.children.retain(self.arena, |child, arena| {
            let child = child.resolve(arena)?;
            Ok(child.name() != name || child.namespace() != namespace)
        })?;
        Ok(self)
    }

    pub fn clear_children(mut self) -> Self {
        self.children = SliceBuilder::new();
        self
    }

    /// Checks IQ child counts, error-child placement, and required IDs and server addresses.
    /// Payload schemas and language tags require validation by their protocol handlers.
    pub fn build(self) -> Result<Stanza, BuildError> {
        self.validate()?;
        Ok(Stanza {
            data: self.arena.try_alloc(StanzaData {
                header: self.header,
                attributes: self.attributes.finish(),
                children: self.children.finish(),
            })?,
        })
    }

    fn validate(&self) -> Result<(), BuildError> {
        if self.header.namespace == StanzaNamespace::Server
            && (self.header.from.is_none() || self.header.to.is_none())
        {
            return Err(BuildError::MissingServerAddresses);
        }
        let children = self.children.as_slice(self.arena)?;
        let mut nodes = 1;
        let mut errors = 0;
        for (index, child) in children.iter().enumerate() {
            let child = child.resolve(self.arena)?;
            let (depth, count) = child.size();
            nodes += count;
            if depth >= MAX_ELEMENT_DEPTH || nodes > MAX_ELEMENT_NODES {
                return Err(BuildError::TreeLimitExceeded);
            }
            if child.name() == "error" && child.namespace() == self.header.namespace.as_str() {
                errors += 1;
                if index + 1 != children.len() {
                    return Err(BuildError::InvalidErrorPayload);
                }
            }
        }
        if errors != usize::from(self.header.stanza_type.is_error()) {
            return Err(BuildError::InvalidErrorPayload);
        }
        if let StanzaType::Iq(iq_type) = self.header.stanza_type {
            if self.header.id.is_none() {
                return Err(BuildError::MissingIqId);
            }
            let payloads = children.len() - errors;
            let valid = match iq_type {
                IqType::Get | IqType::Set => payloads == 1,
                IqType::Result | IqType::Error => payloads <= 1,
            };
            if !valid {
                return Err(BuildError::InvalidIqPayload);
            }
        }
        Ok(())
    }
}

fn reserved_attribute(name: &str, namespace: &str) -> bool {
    (namespace.is_empty() && matches!(name, "from" | "to" | "id" | "type" | "xmlns"))
        || (namespace == XML_NAMESPACE && name == "lang")
}

fn store_text<A: ChunkAllocator>(
    text: Option<&str>,
    arena: &mut Arena<A>,
) -> Result<Option<Handle<str>>, BuildError> {
    text.map(|text| {
        xml::validate_text(text)?;
        Ok(arena.try_alloc_str(text)?)
    })
    .transpose()
}

impl fmt::Debug for Stanza {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Stanza").finish_non_exhaustive()
    }
}

impl<R: ArenaRead> fmt::Debug for StanzaRef<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StanzaRef")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl From<ArenaError> for BuildError {
    fn from(error: ArenaError) -> Self {
        Self::Allocation(error)
    }
}
impl From<HandleError> for BuildError {
    fn from(error: HandleError) -> Self {
        Self::Access(error)
    }
}
impl From<JidError> for BuildError {
    fn from(error: JidError) -> Self {
        Self::Jid(error)
    }
}
impl From<HandleError> for WriteError {
    fn from(error: HandleError) -> Self {
        Self::Access(error)
    }
}
impl From<fmt::Error> for WriteError {
    fn from(error: fmt::Error) -> Self {
        Self::Output(error)
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation(error) => write!(formatter, "stanza allocation failed: {error}"),
            Self::Access(error) => write!(formatter, "stanza arena access failed: {error}"),
            Self::Jid(error) => write!(formatter, "stanza address failed: {error}"),
            Self::InvalidName => formatter.write_str("invalid XML local name"),
            Self::InvalidNamespace => formatter.write_str("reserved XML namespace"),
            Self::InvalidText => formatter.write_str("invalid XML character"),
            Self::DuplicateAttribute => formatter.write_str("duplicate XML attribute"),
            Self::ReservedAttribute => {
                formatter.write_str("common stanza attribute requires its typed setter")
            }
            Self::EmptyId => formatter.write_str("stanza ID must not be empty"),
            Self::MissingIqId => formatter.write_str("IQ stanza requires an ID"),
            Self::InvalidIqPayload => formatter.write_str("invalid IQ payload count"),
            Self::InvalidErrorPayload => formatter
                .write_str("error stanza requires one final error child; other types forbid it"),
            Self::MissingServerAddresses => {
                formatter.write_str("server stanza requires both addresses")
            }
            Self::NotIqRequest => {
                formatter.write_str("only IQ requests can produce result replies")
            }
            Self::TreeLimitExceeded => {
                formatter.write_str("XML tree depth or expanded node count exceeds the limit")
            }
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Access(error) => Some(error),
            Self::Jid(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Access(error) => write!(formatter, "XML arena access failed: {error}"),
            Self::Output(error) => write!(formatter, "XML output failed: {error}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Access(error) => Some(error),
            Self::Output(error) => Some(error),
        }
    }
}
