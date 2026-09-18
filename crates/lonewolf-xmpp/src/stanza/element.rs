// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, Handle, HandleError};

use super::storage::{SliceBuilder, StoredSlice};
use super::{BuildError, MAX_ELEMENT_DEPTH, MAX_ELEMENT_NODES, STREAM_NAMESPACE, WriteError, xml};

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
    pub name: &'a str,
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
    attributes: StoredSlice<Attribute>,
    children: StoredSlice<Node>,
    depth: usize,
    nodes: usize,
}

/// An immutable, non-owning handle. All content belongs to one caller-owned arena.
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

/// Failed builds can leave unused storage in the arena until it is dropped.
pub struct ElementBuilder<'a, A: ChunkAllocator> {
    arena: &'a mut Arena<A>,
    name: Name,
    attributes: AttributesBuilder,
    children: SliceBuilder<Node>,
}

pub(crate) struct ElementFrame {
    name: Name,
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
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
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
        ElementBuilder {
            arena,
            name: self.name,
            attributes: self.attributes,
            children: self.children,
        }
        .build()
    }
}

impl Element {
    pub fn builder_in<'a, A: ChunkAllocator>(
        name: &str,
        namespace: &str,
        arena: &'a mut Arena<A>,
    ) -> Result<ElementBuilder<'a, A>, BuildError> {
        let name = Name::new(name, namespace, false, arena)?;
        Ok(ElementBuilder {
            arena,
            name,
            attributes: AttributesBuilder::new(),
            children: SliceBuilder::new(),
        })
    }

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
    pub fn derive_in<'a, A: ChunkAllocator>(
        &self,
        arena: &'a mut Arena<A>,
    ) -> Result<ElementBuilder<'a, A>, HandleError> {
        let data = *arena.get(self.data)?;
        Ok(ElementBuilder {
            arena,
            name: data.name,
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

    pub fn attributes(
        &self,
    ) -> Result<impl Iterator<Item = Result<AttributeRef<'a>, HandleError>> + 'a, HandleError> {
        attributes(self.data.attributes, self.arena)
    }

    pub fn attribute(&self, name: &str, namespace: &str) -> Result<Option<&'a str>, HandleError> {
        for attribute in self.attributes()? {
            let attribute = attribute?;
            if attribute.name == name && attribute.namespace == namespace {
                return Ok(Some(attribute.value));
            }
        }
        Ok(None)
    }

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

    /// Returns text only when the element contains one text node and no other nodes.
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

    /// Copies all content into the destination before applying edits.
    pub fn to_builder_in<'b, A: ChunkAllocator>(
        &self,
        arena: &'b mut Arena<A>,
    ) -> Result<ElementBuilder<'b, A>, BuildError> {
        let name = Name::new(self.name, self.namespace, false, arena)?;
        let attributes = AttributesBuilder::copy_from(self.data.attributes, self.arena, arena)?;
        let mut children = SliceBuilder::new();
        for node in self.children()? {
            let node = match node? {
                NodeRef::Element(element) => Node::Element(element.clone_in(arena)?),
                NodeRef::Text(text) => Node::Text(arena.try_alloc_str(text)?),
            };
            children.push(node, arena)?;
        }
        Ok(ElementBuilder {
            arena,
            name,
            attributes,
            children,
        })
    }

    /// Writes explicit namespace declarations. Output failure can leave a partial element.
    pub fn write_xml(&self, output: &mut impl fmt::Write) -> Result<(), WriteError> {
        self.write_in(output, None)
    }

    pub(super) fn size(&self) -> (usize, usize) {
        (self.data.depth, self.data.nodes)
    }

    pub(super) fn write_in(
        &self,
        output: &mut impl fmt::Write,
        parent_namespace: Option<&str>,
    ) -> Result<(), WriteError> {
        let prefix = match self.namespace {
            xml::XML_NAMESPACE => "xml:",
            STREAM_NAMESPACE => "stream:",
            _ => "",
        };
        output.write_char('<')?;
        output.write_str(prefix)?;
        output.write_str(self.name)?;
        if prefix.is_empty() && Some(self.namespace) != parent_namespace {
            xml::attribute(output, "xmlns", self.namespace)?;
        } else if self.namespace == STREAM_NAMESPACE {
            xml::attribute(output, "xmlns:stream", STREAM_NAMESPACE)?;
        }
        write_attributes(self.data.attributes, self.arena, output)?;
        let children = self.data.children.get(self.arena)?;
        if children.is_empty() {
            output.write_str("/>")?;
            return Ok(());
        }
        output.write_char('>')?;
        let namespace = if prefix.is_empty() {
            Some(self.namespace)
        } else {
            parent_namespace
        };
        for child in self.children()? {
            match child? {
                NodeRef::Element(element) => element.write_in(output, namespace)?,
                NodeRef::Text(text) => xml::escape(output, text, false)?,
            }
        }
        output.write_str("</")?;
        output.write_str(prefix)?;
        output.write_str(self.name)?;
        output.write_char('>')?;
        Ok(())
    }
}

impl<A: ChunkAllocator> ElementBuilder<'_, A> {
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

    pub fn text(mut self, text: &str) -> Result<Self, BuildError> {
        xml::validate_text(text)?;
        if !text.is_empty() {
            let text = self.arena.try_alloc_str(text)?;
            self.children.push(Node::Text(text), self.arena)?;
        }
        Ok(self)
    }

    pub fn child(mut self, element: Element) -> Result<Self, BuildError> {
        element.resolve(self.arena)?;
        self.children.push(Node::Element(element), self.arena)?;
        Ok(self)
    }

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
        for value in values.get(source)? {
            let value = value.resolve(source)?;
            let value = Attribute {
                name: Name::new(value.name, value.namespace, true, arena)?,
                value: arena.try_alloc_str(value.value)?,
            };
            result.values.push(value, arena)?;
        }
        Ok(result)
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
    arena: &impl ArenaRead,
    output: &mut impl fmt::Write,
) -> Result<(), WriteError> {
    for (index, value) in attributes(values, arena)?.enumerate() {
        let value = value?;
        match value.namespace {
            "" => xml::attribute(output, value.name, value.value)?,
            xml::XML_NAMESPACE => {
                write!(output, " xml:{}=\"", value.name)?;
                xml::escape(output, value.value, true)?;
                output.write_char('"')?;
            }
            namespace => {
                write!(output, " xmlns:ns{index}=\"")?;
                xml::escape(output, namespace, true)?;
                write!(output, "\" ns{index}:{}=\"", value.name)?;
                xml::escape(output, value.value, true)?;
                output.write_char('"')?;
            }
        }
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
