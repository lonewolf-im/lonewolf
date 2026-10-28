// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use futures_util::io::{AsyncWrite, AsyncWriteExt};
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, Handle, HandleError};
use smallvec::SmallVec;

use super::namespace::{NamespaceContext, NamespaceCopies, Prefix};
use super::storage::{SliceBuilder, StoredSlice};
use super::{AsyncWriteError, BuildError, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES, WriteError, xml};

#[derive(Clone, Copy)]
struct Name {
    local: Handle<str>,
    namespace: Handle<str>,
}

impl Name {
    fn new<A: ChunkAllocator>(
        local: &str,
        namespace: &str,
        attribute: bool,
        arena: &mut Arena<A>,
    ) -> Result<Self, BuildError> {
        xml::validate_name(local, namespace, attribute)?;
        Ok(Self {
            local: arena.try_alloc_str(local)?,
            namespace: arena.try_alloc_str(namespace)?,
        })
    }

    fn matches(
        &self,
        local: &str,
        namespace: &str,
        arena: &impl ArenaRead,
    ) -> Result<bool, HandleError> {
        Ok(arena.get(self.local)? == local && arena.get(self.namespace)? == namespace)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Attribute {
    name: Name,
    value: Handle<str>,
}

impl Attribute {
    fn resolve<'a>(&self, arena: &'a impl ArenaRead) -> Result<AttributeRef<'a>, HandleError> {
        Ok(AttributeRef {
            name: arena.get(self.name.local)?,
            namespace: arena.get(self.name.namespace)?,
            value: arena.get(self.value)?,
        })
    }
}

#[derive(Clone, Copy)]
pub struct AttributeRef<'a> {
    /// Excludes the namespace prefix.
    pub name: &'a str,
    /// Contains the resolved URI, or an empty string for no namespace.
    pub namespace: &'a str,
    pub value: &'a str,
}

#[derive(Clone, Copy)]
enum Node {
    Element(Element),
    Text(Handle<str>),
}

pub enum NodeRef<'a, R: ArenaRead> {
    Element(ElementRef<'a, R>),
    Text(&'a str),
}

#[derive(Clone, Copy)]
struct ElementData {
    name: Name,
    namespaces: NamespaceContext,
    attributes: StoredSlice<Attribute>,
    children: StoredSlice<Node>,
    depth: usize,
    nodes: usize,
}

/// Holds immutable content from one arena without retaining that arena.
#[derive(Clone, Copy)]
pub struct Element {
    data: Handle<ElementData>,
}

pub struct ElementRef<'a, R: ArenaRead> {
    handle: Element,
    arena: &'a R,
    data: &'a ElementData,
    name: &'a str,
    namespace: &'a str,
}

struct WriteFrame<'a> {
    element: Element,
    namespace: Option<&'a str>,
    namespaces: NamespaceContext,
    next_child: usize,
}

/// Retains removed or replaced storage until the arena is dropped.
///
/// Failed builds do not reclaim allocations.
pub struct ElementBuilder<'a, A: ChunkAllocator> {
    arena: &'a mut Arena<A>,
    name: Name,
    pub(super) namespaces: NamespaceContext,
    attributes: AttributesBuilder,
    children: SliceBuilder<Node>,
}

pub(crate) struct ElementFrame {
    name: Name,
    pub(super) namespaces: NamespaceContext,
    attributes: AttributesBuilder,
    children: SliceBuilder<Node>,
}

impl ElementFrame {
    pub(super) fn new<A: ChunkAllocator>(
        name: &str,
        namespace: &str,
        arena: &mut Arena<A>,
    ) -> Result<Self, BuildError> {
        Ok(Self {
            name: Name::new(name, namespace, false, arena)?,
            namespaces: NamespaceContext::default(),
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }

    pub(crate) fn namespaces(&self) -> NamespaceContext {
        self.namespaces
    }

    pub(crate) fn set_namespaces(&mut self, namespaces: NamespaceContext) {
        self.namespaces = namespaces;
    }

    pub(super) fn attribute<A: ChunkAllocator>(
        &mut self,
        name: &str,
        namespace: &str,
        value: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        if self.attributes.find(name, namespace, arena)?.is_some() {
            return Err(BuildError::DuplicateAttribute);
        }
        self.attributes.set(name, namespace, value, arena)
    }

    pub(super) fn append_attributes_from<A: ChunkAllocator>(
        &mut self,
        values: StoredSlice<Attribute>,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        self.attributes.append_from(values, source, arena)
    }

    pub(super) fn text<A: ChunkAllocator>(
        &mut self,
        text: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        xml::validate_text(text)?;
        let text = arena.try_alloc_str(text)?;
        self.children.push(Node::Text(text), arena)
    }

    pub(super) fn child<A: ChunkAllocator>(
        &mut self,
        element: Element,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        self.children.push(Node::Element(element), arena)
    }

    pub(super) fn finish<A: ChunkAllocator>(
        self,
        arena: &mut Arena<A>,
    ) -> Result<Element, BuildError> {
        self.into_builder(arena).build()
    }

    pub(super) fn into_builder<'a, A: ChunkAllocator>(
        self,
        arena: &'a mut Arena<A>,
    ) -> ElementBuilder<'a, A> {
        ElementBuilder {
            arena,
            name: self.name,
            namespaces: self.namespaces,
            attributes: self.attributes,
            children: self.children,
        }
    }
}

impl Element {
    /// Accepts a local XML name without a namespace prefix.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::InvalidName`] for an invalid local name,
    /// [`BuildError::InvalidNamespace`] for the reserved `xmlns` URI,
    /// [`BuildError::InvalidText`] for invalid namespace characters, or
    /// [`BuildError::Allocation`] if arena allocation fails.
    pub fn builder_in<'a, A: ChunkAllocator>(
        name: &str,
        namespace: &str,
        arena: &'a mut Arena<A>,
    ) -> Result<ElementBuilder<'a, A>, BuildError> {
        let name = Name::new(name, namespace, false, arena)?;
        Ok(ElementBuilder {
            arena,
            name,
            namespaces: NamespaceContext::default(),
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }

    /// Borrows from the arena that owns this element.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::WrongArena`] for a different arena.
    pub fn resolve<'a, R: ArenaRead>(
        &self,
        arena: &'a R,
    ) -> Result<ElementRef<'a, R>, HandleError> {
        let data = arena.get(self.data)?;
        Ok(ElementRef {
            handle: *self,
            arena,
            data,
            name: arena.get(data.name.local)?,
            namespace: arena.get(data.name.namespace)?,
        })
    }

    /// Shares unchanged storage. Edits do not alter the source element.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::WrongArena`] unless `arena` owns the source.
    pub fn derive_in<'a, A: ChunkAllocator>(
        &self,
        arena: &'a mut Arena<A>,
    ) -> Result<ElementBuilder<'a, A>, HandleError> {
        let data = *arena.get(self.data)?;
        Ok(ElementBuilder {
            arena,
            name: data.name,
            namespaces: data.namespaces,
            attributes: AttributesBuilder::from_slice(data.attributes),
            children: SliceBuilder::from_slice(data.children),
        })
    }
}

impl<'a, R: ArenaRead> ElementRef<'a, R> {
    pub fn handle(&self) -> Element {
        self.handle
    }

    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn namespace(&self) -> &'a str {
        self.namespace
    }

    /// Preserves attribute insertion order.
    pub fn attributes(
        &self,
    ) -> Result<impl Iterator<Item = Result<AttributeRef<'a>, HandleError>> + 'a, HandleError> {
        attributes(self.data.attributes, self.arena)
    }

    /// Matches a local name and namespace URI, without a namespace prefix.
    pub fn attribute(&self, name: &str, namespace: &str) -> Result<Option<&'a str>, HandleError> {
        for attribute in self.attributes()? {
            let attribute = attribute?;
            if attribute.name == name && attribute.namespace == namespace {
                return Ok(Some(attribute.value));
            }
        }
        Ok(None)
    }

    /// Preserves the order of text and element children.
    pub fn children(
        &self,
    ) -> Result<impl Iterator<Item = Result<NodeRef<'a, R>, HandleError>> + 'a, HandleError> {
        let arena = self.arena;
        Ok(self
            .data
            .children
            .get(arena)?
            .iter()
            .map(move |node| match node {
                Node::Element(element) => element.resolve(arena).map(NodeRef::Element),
                Node::Text(text) => arena.get(*text).map(NodeRef::Text),
            }))
    }

    /// Returns only the first child with this local name and namespace URI.
    pub fn child(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<ElementRef<'a, R>>, HandleError> {
        for node in self.children()? {
            if let NodeRef::Element(element) = node?
                && element.name == name
                && element.namespace == namespace
            {
                return Ok(Some(element));
            }
        }
        Ok(None)
    }

    /// Returns text only for an element with one text node and no other nodes.
    pub fn text(&self) -> Result<Option<&'a str>, HandleError> {
        match self.data.children.get(self.arena)? {
            [Node::Text(text)] => self.arena.get(*text).map(Some),
            _ => Ok(None),
        }
    }

    /// Copies all content. The source arena can be dropped after this call.
    pub fn clone_in<A: ChunkAllocator>(&self, arena: &mut Arena<A>) -> Result<Element, BuildError> {
        self.to_builder_in(arena)?.build()
    }

    pub(super) fn rescope_with_namespaces<A: ChunkAllocator>(
        &self,
        from: &str,
        to: &str,
        arena: &mut Arena<A>,
        copies: &mut NamespaceCopies,
        rescoped: &mut NamespaceCopies,
    ) -> Result<Element, BuildError> {
        if self.namespace != from || from == to {
            return self.clone_with_namespaces(arena, copies);
        }
        let mut frame = ElementFrame::new(self.name, to, arena)?;
        frame.namespaces = self
            .data
            .namespaces
            .rescope_in(from, to, self.arena, arena, rescoped)?;
        frame.append_attributes_from(self.data.attributes, self.arena, arena)?;
        for node in self.children()? {
            match node? {
                NodeRef::Element(element) => {
                    let child =
                        element.rescope_with_namespaces(from, to, arena, copies, rescoped)?;
                    frame.child(child, arena)?;
                }
                NodeRef::Text(text) => frame.text(text, arena)?,
            }
        }
        frame.finish(arena)
    }

    /// Copies all content into the destination before applying edits.
    pub fn to_builder_in<'b, A: ChunkAllocator>(
        &self,
        arena: &'b mut Arena<A>,
    ) -> Result<ElementBuilder<'b, A>, BuildError> {
        self.to_builder_with_namespaces(arena, &mut NamespaceCopies::default())
    }

    pub(super) fn clone_with_namespaces<A: ChunkAllocator>(
        &self,
        arena: &mut Arena<A>,
        copies: &mut NamespaceCopies,
    ) -> Result<Element, BuildError> {
        self.to_builder_with_namespaces(arena, copies)?.build()
    }

    fn to_builder_with_namespaces<'b, A: ChunkAllocator>(
        &self,
        arena: &'b mut Arena<A>,
        copies: &mut NamespaceCopies,
    ) -> Result<ElementBuilder<'b, A>, BuildError> {
        let namespaces = self.data.namespaces.clone_in(self.arena, arena, copies)?;
        let name = Name::new(self.name, self.namespace, false, arena)?;
        let attributes = AttributesBuilder::copy_from(self.data.attributes, self.arena, arena)?;
        let mut children = SliceBuilder::new();
        for node in self.children()? {
            let node = match node? {
                NodeRef::Element(element) => {
                    Node::Element(element.clone_with_namespaces(arena, copies)?)
                }
                NodeRef::Text(text) => Node::Text(arena.try_alloc_str(text)?),
            };
            children.push(node, arena)?;
        }
        Ok(ElementBuilder {
            arena,
            name,
            namespaces,
            attributes,
            children,
        })
    }

    /// Writes namespace declarations without requiring an enclosing element.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::Access`] for an unresolved handle or
    /// [`WriteError::Output`] if the destination rejects a write. Either error
    /// can leave partial XML in `output`.
    pub fn write_xml(&self, output: &mut impl fmt::Write) -> Result<(), WriteError> {
        self.write_in(output, None, None)
    }

    /// Writes XML without flushing the destination.
    ///
    /// # Errors
    ///
    /// Access or I/O errors can leave partial XML in `output`.
    pub async fn write_xml_async<W: AsyncWrite + Unpin>(
        &self,
        output: &mut W,
    ) -> Result<(), AsyncWriteError> {
        self.write_in_async(output, None, None).await
    }

    pub(super) fn size(&self) -> (usize, usize) {
        (self.data.depth, self.data.nodes)
    }

    pub(super) fn write_in(
        &self,
        output: &mut impl fmt::Write,
        parent_namespace: Option<&str>,
        parent_context: Option<NamespaceContext>,
    ) -> Result<(), WriteError> {
        let prefix = self
            .data
            .namespaces
            .element_prefix(self.namespace, self.arena)?;
        output.write_char('<')?;
        prefix.write(output)?;
        output.write_str(self.name)?;
        self.data.namespaces.write(
            self.arena,
            output,
            prefix,
            self.namespace,
            parent_namespace,
            parent_context,
        )?;
        write_attributes(
            self.data.attributes,
            self.data.namespaces,
            prefix,
            self.arena,
            output,
        )?;
        let children = self.data.children.get(self.arena)?;
        if children.is_empty() {
            output.write_str("/>")?;
            return Ok(());
        }
        output.write_char('>')?;
        let namespace = self.data.namespaces.child_default(
            prefix,
            self.namespace,
            parent_namespace,
            self.arena,
        )?;
        for child in self.children()? {
            match child? {
                NodeRef::Element(element) => {
                    element.write_in(output, namespace, Some(self.data.namespaces))?
                }
                NodeRef::Text(text) => xml::escape(output, text, false)?,
            }
        }
        output.write_str("</")?;
        prefix.write(output)?;
        output.write_str(self.name)?;
        output.write_char('>')?;
        Ok(())
    }

    pub(super) async fn write_in_async<W: AsyncWrite + Unpin>(
        &self,
        output: &mut W,
        parent_namespace: Option<&'a str>,
        parent_context: Option<NamespaceContext>,
    ) -> Result<(), AsyncWriteError> {
        let mut frames = SmallVec::<[WriteFrame<'a>; 8]>::new();
        let root = self.handle.resolve(self.arena)?;
        let (has_children, namespace) =
            write_start_async(&root, output, parent_namespace, parent_context).await?;
        if has_children {
            frames.push(WriteFrame {
                element: self.handle,
                namespace,
                namespaces: root.data.namespaces,
                next_child: 0,
            });
        }
        while let Some(frame) = frames.last_mut() {
            let element = frame.element.resolve(self.arena)?;
            let children = element.data.children.get(self.arena)?;
            if let Some(child) = children.get(frame.next_child) {
                frame.next_child += 1;
                let namespace = frame.namespace;
                match child {
                    Node::Element(child) => {
                        let view = child.resolve(self.arena)?;
                        let (has_children, child_namespace) =
                            write_start_async(&view, output, namespace, Some(frame.namespaces))
                                .await?;
                        if has_children {
                            frames.push(WriteFrame {
                                element: *child,
                                namespace: child_namespace,
                                namespaces: view.data.namespaces,
                                next_child: 0,
                            });
                        }
                    }
                    Node::Text(text) => {
                        xml::escape_async(output, self.arena.get(*text)?, false).await?;
                    }
                }
            } else {
                write_end_async(&element, output).await?;
                frames.pop();
            }
        }
        Ok(())
    }
}

async fn write_start_async<'a, R: ArenaRead, W: AsyncWrite + Unpin>(
    element: &ElementRef<'a, R>,
    output: &mut W,
    parent_namespace: Option<&'a str>,
    parent_context: Option<NamespaceContext>,
) -> Result<(bool, Option<&'a str>), AsyncWriteError> {
    let prefix = element
        .data
        .namespaces
        .element_prefix(element.namespace, element.arena)?;
    output.write_all(b"<").await?;
    prefix.write_async(output).await?;
    output.write_all(element.name.as_bytes()).await?;
    element
        .data
        .namespaces
        .write_async(
            element.arena,
            output,
            prefix,
            element.namespace,
            parent_namespace,
            parent_context,
        )
        .await?;
    write_attributes_async(
        element.data.attributes,
        element.data.namespaces,
        prefix,
        element.arena,
        output,
    )
    .await?;
    if element.data.children.get(element.arena)?.is_empty() {
        output.write_all(b"/>").await?;
        return Ok((false, None));
    }
    output.write_all(b">").await?;
    let namespace = element.data.namespaces.child_default(
        prefix,
        element.namespace,
        parent_namespace,
        element.arena,
    )?;
    Ok((true, namespace))
}

async fn write_end_async<R: ArenaRead, W: AsyncWrite + Unpin>(
    element: &ElementRef<'_, R>,
    output: &mut W,
) -> Result<(), AsyncWriteError> {
    output.write_all(b"</").await?;
    element
        .data
        .namespaces
        .element_prefix(element.namespace, element.arena)?
        .write_async(output)
        .await?;
    output.write_all(element.name.as_bytes()).await?;
    output.write_all(b">").await?;
    Ok(())
}

impl<A: ChunkAllocator> ElementBuilder<'_, A> {
    /// Replaces a matching attribute without changing its position.
    ///
    /// Matches local names and namespace URIs, without namespace prefixes.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::InvalidName`] for an invalid local name,
    /// [`BuildError::InvalidNamespace`] for a reserved namespace declaration,
    /// [`BuildError::InvalidText`] for invalid XML characters,
    /// [`BuildError::Access`] for an unresolved handle, or
    /// [`BuildError::Allocation`] if arena allocation fails.
    pub fn attribute(
        mut self,
        name: &str,
        namespace: &str,
        value: &str,
    ) -> Result<Self, BuildError> {
        self.attributes.set(name, namespace, value, self.arena)?;
        Ok(self)
    }

    pub fn remove_attribute(mut self, name: &str, namespace: &str) -> Result<Self, BuildError> {
        self.attributes.remove(name, namespace, self.arena)?;
        Ok(self)
    }

    /// Appends a separate text node, ignoring empty strings.
    ///
    /// Consecutive calls do not merge nodes, so [`ElementRef::text`] returns
    /// `None` when more than one nonempty string has been appended.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::InvalidText`] for invalid XML characters,
    /// [`BuildError::Access`] for an unresolved handle, or
    /// [`BuildError::Allocation`] if arena allocation fails.
    pub fn text(mut self, text: &str) -> Result<Self, BuildError> {
        xml::validate_text(text)?;
        if !text.is_empty() {
            let text = self.arena.try_alloc_str(text)?;
            self.children.push(Node::Text(text), self.arena)?;
        }
        Ok(self)
    }

    /// Shares the child's storage; the child must belong to this arena.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::Access`] for a different arena or
    /// [`BuildError::Allocation`] if the child list cannot grow.
    pub fn child(mut self, element: Element) -> Result<Self, BuildError> {
        element.resolve(self.arena)?;
        self.children.push(Node::Element(element), self.arena)?;
        Ok(self)
    }

    /// Removes all matching direct elements while retaining text nodes.
    pub fn remove_children(mut self, name: &str, namespace: &str) -> Result<Self, BuildError> {
        self.children.retain(self.arena, |node, arena| match node {
            Node::Element(element) => arena
                .get(element.data)?
                .name
                .matches(name, namespace, arena)
                .map(|matches| !matches),
            Node::Text(_) => Ok(true),
        })?;
        Ok(self)
    }

    pub fn clear_children(mut self) -> Self {
        self.children = SliceBuilder::new();
        self
    }

    /// Checks tree limits with each shared subtree counted at every occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::TreeLimitExceeded`] above [`MAX_ELEMENT_DEPTH`] or
    /// [`MAX_ELEMENT_NODES`], [`BuildError::Access`] for an unresolved handle,
    /// or [`BuildError::Allocation`] if arena allocation fails.
    pub fn build(self) -> Result<Element, BuildError> {
        let mut depth = 1;
        let mut nodes = 1;
        for child in self.children.as_slice(self.arena)? {
            let (child_depth, child_nodes) = match child {
                Node::Element(element) => element.resolve(self.arena)?.size(),
                Node::Text(_) => (0, 1),
            };
            depth = depth.max(child_depth + 1);
            nodes += child_nodes;
            if depth > MAX_ELEMENT_DEPTH || nodes > MAX_ELEMENT_NODES {
                return Err(BuildError::TreeLimitExceeded);
            }
        }
        Ok(Element {
            data: self.arena.try_alloc(ElementData {
                name: self.name,
                namespaces: self.namespaces,
                attributes: self.attributes.finish(),
                children: self.children.finish(),
                depth,
                nodes,
            })?,
        })
    }
}

pub(super) struct AttributesBuilder {
    values: SliceBuilder<Attribute>,
}

impl AttributesBuilder {
    pub(super) fn new() -> Self {
        Self {
            values: SliceBuilder::new(),
        }
    }

    pub(super) fn from_slice(values: StoredSlice<Attribute>) -> Self {
        Self {
            values: SliceBuilder::from_slice(values),
        }
    }

    pub(super) fn set<A: ChunkAllocator>(
        &mut self,
        name: &str,
        namespace: &str,
        value: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        xml::validate_name(name, namespace, true)?;
        xml::validate_text(value)?;
        let index = self.find(name, namespace, arena)?;
        let stored_name = match index {
            Some(index) => self.values.as_slice(arena)?[index].name,
            None => Name::new(name, namespace, true, arena)?,
        };
        let value = Attribute {
            name: stored_name,
            value: arena.try_alloc_str(value)?,
        };
        match index {
            Some(index) => self.values.set(index, value, arena),
            None => self.values.push(value, arena),
        }
    }

    pub(super) fn remove<A: ChunkAllocator>(
        &mut self,
        name: &str,
        namespace: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        if let Some(index) = self.find(name, namespace, arena)? {
            self.values.remove(index, arena)?;
        }
        Ok(())
    }

    pub(super) fn find(
        &self,
        name: &str,
        namespace: &str,
        arena: &impl ArenaRead,
    ) -> Result<Option<usize>, HandleError> {
        for (index, value) in self.values.as_slice(arena)?.iter().enumerate() {
            if value.name.matches(name, namespace, arena)? {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    pub(super) fn copy_from<A: ChunkAllocator>(
        values: StoredSlice<Attribute>,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
    ) -> Result<Self, BuildError> {
        let mut result = Self::new();
        result.append_from(values, source, arena)?;
        Ok(result)
    }

    /// Incoming attribute names must be unique and absent from this builder.
    pub(super) fn append_from<A: ChunkAllocator>(
        &mut self,
        values: StoredSlice<Attribute>,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        for value in values.get(source)? {
            let value = value.resolve(source)?;
            let value = Attribute {
                name: Name::new(value.name, value.namespace, true, arena)?,
                value: arena.try_alloc_str(value.value)?,
            };
            self.values.push(value, arena)?;
        }
        Ok(())
    }

    pub(super) fn finish(self) -> StoredSlice<Attribute> {
        self.values.finish()
    }
}

pub(super) fn attributes<'a>(
    values: StoredSlice<Attribute>,
    arena: &'a impl ArenaRead,
) -> Result<impl Iterator<Item = Result<AttributeRef<'a>, HandleError>> + 'a, HandleError> {
    Ok(values
        .get(arena)?
        .iter()
        .map(move |attribute| attribute.resolve(arena)))
}

pub(super) fn write_attributes(
    values: StoredSlice<Attribute>,
    namespaces: NamespaceContext,
    element_prefix: Prefix<'_>,
    arena: &impl ArenaRead,
    output: &mut impl fmt::Write,
) -> Result<(), WriteError> {
    let mut generated = match element_prefix {
        Prefix::Generated(index) => index + 1,
        _ => 0,
    };
    for (index, value) in attributes(values, arena)?.enumerate() {
        let value = value?;
        generated = generated.max(index);
        let prefix = namespaces.attribute_prefix(value.namespace, &mut generated, arena)?;
        if let Prefix::Generated(index) = prefix {
            write!(output, " xmlns:ns{index}=\"")?;
            xml::escape(output, value.namespace, true)?;
            output.write_char('"')?;
        }
        output.write_char(' ')?;
        prefix.write(output)?;
        output.write_str(value.name)?;
        output.write_str("=\"")?;
        xml::escape(output, value.value, true)?;
        output.write_char('"')?;
    }
    Ok(())
}

pub(super) async fn write_attributes_async<W: AsyncWrite + Unpin>(
    values: StoredSlice<Attribute>,
    namespaces: NamespaceContext,
    element_prefix: Prefix<'_>,
    arena: &impl ArenaRead,
    output: &mut W,
) -> Result<(), AsyncWriteError> {
    let mut generated = match element_prefix {
        Prefix::Generated(index) => index + 1,
        _ => 0,
    };
    for (index, value) in attributes(values, arena)?.enumerate() {
        let value = value?;
        generated = generated.max(index);
        let prefix = namespaces.attribute_prefix(value.namespace, &mut generated, arena)?;
        if let Prefix::Generated(index) = prefix {
            output.write_all(b" xmlns:ns").await?;
            xml::number_async(output, index).await?;
            output.write_all(b"=\"").await?;
            xml::escape_async(output, value.namespace, true).await?;
            output.write_all(b"\"").await?;
        }
        output.write_all(b" ").await?;
        prefix.write_async(output).await?;
        output.write_all(value.name.as_bytes()).await?;
        output.write_all(b"=\"").await?;
        xml::escape_async(output, value.value, true).await?;
        output.write_all(b"\"").await?;
    }
    Ok(())
}

impl fmt::Debug for Element {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Element").finish_non_exhaustive()
    }
}

impl<R: ArenaRead> fmt::Debug for ElementRef<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ElementRef").finish_non_exhaustive()
    }
}

impl fmt::Debug for AttributeRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttributeRef")
            .finish_non_exhaustive()
    }
}

impl<R: ArenaRead> fmt::Debug for NodeRef<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("NodeRef").finish_non_exhaustive()
    }
}
