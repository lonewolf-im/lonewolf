// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;

use futures_util::io::{AsyncWrite, AsyncWriteExt};
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator, Handle, HandleError};
use smallvec::SmallVec;

use super::{AsyncWriteError, BuildError, STREAM_NAMESPACE, WriteError, XML_NAMESPACE, xml};

#[derive(Clone, Copy, Default)]
pub(crate) struct NamespaceContext(Option<Handle<Binding>>);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Rescope<'n> {
    pub(super) from: &'n str,
    pub(super) to: &'n str,
}

#[derive(Clone, Copy)]
pub(super) struct ContextView<'n> {
    pub(super) context: NamespaceContext,
    pub(super) rescope: Option<Rescope<'n>>,
}

#[derive(Clone, Copy)]
struct Binding {
    parent: NamespaceContext,
    prefix: Handle<str>,
    namespace: Handle<str>,
}

#[derive(Default)]
pub(super) struct NamespaceCopies {
    copied: HashMap<*const Binding, Handle<Binding>>,
}

#[derive(Clone, Copy)]
pub(super) enum Prefix<'a> {
    Default,
    Named(&'a str),
    Generated(usize),
}

impl Prefix<'_> {
    pub(super) fn write(self, output: &mut impl fmt::Write) -> fmt::Result {
        match self {
            Self::Default => Ok(()),
            Self::Named(prefix) => write!(output, "{prefix}:"),
            Self::Generated(index) => write!(output, "ns{index}:"),
        }
    }

    pub(super) async fn write_async<W: AsyncWrite + Unpin>(
        self,
        output: &mut W,
    ) -> Result<(), AsyncWriteError> {
        match self {
            Self::Default => return Ok(()),
            Self::Named(prefix) => output.write_all(prefix.as_bytes()).await?,
            Self::Generated(index) => {
                output.write_all(b"ns").await?;
                xml::number_async(output, index).await?;
            }
        }
        output.write_all(b":").await?;
        Ok(())
    }
}

impl NamespaceContext {
    pub(crate) fn bind<A: ChunkAllocator>(
        &mut self,
        prefix: &str,
        namespace: &str,
        arena: &mut Arena<A>,
    ) -> Result<(), BuildError> {
        let prefix = arena.try_alloc_str(prefix)?;
        let namespace = arena.try_alloc_str(namespace)?;
        self.0 = Some(arena.try_alloc(Binding {
            parent: *self,
            prefix,
            namespace,
        })?);
        Ok(())
    }

    fn binding<'a>(
        self,
        prefix: &str,
        arena: &'a impl ArenaRead,
    ) -> Result<Option<&'a Binding>, HandleError> {
        let mut current = self;
        while let Some(handle) = current.0 {
            let binding = arena.get(handle)?;
            if arena.get(binding.prefix)? == prefix {
                return Ok(Some(binding));
            }
            current = binding.parent;
        }
        Ok(None)
    }

    pub(super) fn clone_in<A: ChunkAllocator>(
        self,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
        copies: &mut NamespaceCopies,
    ) -> Result<Self, BuildError> {
        self.copy_in(source, arena, copies, None)
    }

    pub(super) fn rescope_in<A: ChunkAllocator>(
        self,
        from: &str,
        to: &str,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
        copies: &mut NamespaceCopies,
    ) -> Result<Self, BuildError> {
        self.copy_in(source, arena, copies, Some((from, to)))
    }

    fn copy_in<A: ChunkAllocator>(
        self,
        source: &impl ArenaRead,
        arena: &mut Arena<A>,
        copies: &mut NamespaceCopies,
        rescope: Option<(&str, &str)>,
    ) -> Result<Self, BuildError> {
        let mut missing = SmallVec::<[Handle<Binding>; 8]>::new();
        let mut current = self;
        let mut result = Self::default();
        while let Some(handle) = current.0 {
            let original = std::ptr::from_ref(source.get(handle)?);
            if let Some(copied) = copies.copied.get(&original) {
                result = Self(Some(*copied));
                break;
            }
            missing.push(handle);
            current = source.get(handle)?.parent;
        }
        for handle in missing.into_iter().rev() {
            let binding = source.get(handle)?;
            let prefix = source.get(binding.prefix)?;
            let namespace = source.get(binding.namespace)?;
            let namespace = match rescope {
                Some((from, to)) if prefix.is_empty() && namespace == from => to,
                _ => namespace,
            };
            result.bind(prefix, namespace, arena)?;
            if let Some(copied) = result.0 {
                copies.copied.insert(std::ptr::from_ref(binding), copied);
            }
        }
        Ok(result)
    }
}

impl<'n> ContextView<'n> {
    fn substitute<'a>(self, prefix: &str, namespace: &'a str) -> &'a str
    where
        'n: 'a,
    {
        match self.rescope {
            Some(rescope) if prefix.is_empty() && namespace == rescope.from => rescope.to,
            _ => namespace,
        }
    }

    fn bindings<'a>(
        self,
        arena: &'a impl ArenaRead,
    ) -> impl Iterator<Item = Result<(&'a str, &'a str), HandleError>>
    where
        'n: 'a,
    {
        let mut current = self.context;
        std::iter::from_fn(move || {
            while let Some(handle) = current.0 {
                let result = (|| {
                    let binding = arena.get(handle)?;
                    current = binding.parent;
                    let prefix = arena.get(binding.prefix)?;
                    if !self
                        .context
                        .binding(prefix, arena)?
                        .is_some_and(|visible| std::ptr::eq(visible, binding))
                    {
                        return Ok(None);
                    }
                    Ok(Some((
                        prefix,
                        self.substitute(prefix, arena.get(binding.namespace)?),
                    )))
                })();
                match result {
                    Ok(None) => continue,
                    Ok(Some(binding)) => return Some(Ok(binding)),
                    Err(error) => {
                        current = NamespaceContext::default();
                        return Some(Err(error));
                    }
                }
            }
            None
        })
    }

    fn changed_bindings<'a>(
        self,
        parent: Option<Self>,
        arena: &'a impl ArenaRead,
    ) -> impl Iterator<Item = Result<(&'a str, &'a str), HandleError>>
    where
        'n: 'a,
    {
        let unchanged = match (self.context.0, parent.and_then(|view| view.context.0)) {
            (Some(handle), Some(parent_head))
                if parent.is_some_and(|parent| self.rescope == parent.rescope) =>
            {
                arena.get(handle).and_then(|binding| {
                    arena
                        .get(parent_head)
                        .map(|parent| std::ptr::eq(binding, parent))
                })
            }
            _ => Ok(false),
        };
        let mut error = unchanged.err();
        let bindings = if unchanged.unwrap_or(false) {
            Self {
                context: NamespaceContext::default(),
                rescope: self.rescope,
            }
        } else {
            self
        };
        std::iter::from_fn(move || error.take().map(Err)).chain(
            bindings.bindings(arena).filter_map(move |result| {
                let (prefix, namespace) = match result {
                    Ok(binding) => binding,
                    Err(error) => return Some(Err(error)),
                };
                if let Some(parent) = parent {
                    let inherited = parent.resolve(prefix, arena);
                    match inherited {
                        Ok(Some(value)) if value == namespace => return None,
                        Err(error) => return Some(Err(error)),
                        _ => {}
                    }
                }
                Some(Ok((prefix, namespace)))
            }),
        )
    }

    fn resolve<'a>(
        self,
        prefix: &str,
        arena: &'a impl ArenaRead,
    ) -> Result<Option<&'a str>, HandleError>
    where
        'n: 'a,
    {
        self.context
            .binding(prefix, arena)?
            .map(|binding| {
                arena
                    .get(binding.namespace)
                    .map(|namespace| self.substitute(prefix, namespace))
            })
            .transpose()
    }

    fn named_prefix<'a>(
        self,
        namespace: &str,
        arena: &'a impl ArenaRead,
    ) -> Result<Option<&'a str>, HandleError>
    where
        'n: 'a,
    {
        for binding in self.bindings(arena) {
            let (prefix, value) = binding?;
            if !prefix.is_empty() && value == namespace {
                return Ok(Some(prefix));
            }
        }
        Ok(None)
    }

    fn generated(self, mut index: usize, arena: &impl ArenaRead) -> Result<usize, HandleError> {
        loop {
            let mut occupied = false;
            for binding in self.bindings(arena) {
                let (prefix, _) = binding?;
                if prefix.strip_prefix("ns").is_some_and(|suffix| {
                    suffix.parse::<usize>() == Ok(index)
                        && suffix.len() == (index.checked_ilog10().unwrap_or(0) + 1) as usize
                }) {
                    occupied = true;
                    break;
                }
            }
            if !occupied {
                return Ok(index);
            }
            index += 1;
        }
    }

    pub(super) fn element_prefix<'a>(
        self,
        namespace: &str,
        arena: &'a impl ArenaRead,
    ) -> Result<Prefix<'a>, HandleError>
    where
        'n: 'a,
    {
        if namespace == XML_NAMESPACE {
            return Ok(Prefix::Named("xml"));
        }
        if self.context.0.is_none() {
            return Ok(if namespace == STREAM_NAMESPACE {
                Prefix::Named("stream")
            } else {
                Prefix::Default
            });
        }
        let default = self.resolve("", arena)?.unwrap_or("");
        if default == namespace {
            return Ok(Prefix::Default);
        }
        Ok(match self.named_prefix(namespace, arena)? {
            Some(prefix) => Prefix::Named(prefix),
            None => Prefix::Generated(self.generated(0, arena)?),
        })
    }

    pub(super) fn attribute_prefix<'a>(
        self,
        namespace: &str,
        index: &mut usize,
        arena: &'a impl ArenaRead,
    ) -> Result<Prefix<'a>, HandleError>
    where
        'n: 'a,
    {
        if namespace.is_empty() {
            return Ok(Prefix::Default);
        }
        if namespace == XML_NAMESPACE {
            return Ok(Prefix::Named("xml"));
        }
        if let Some(prefix) = self.named_prefix(namespace, arena)? {
            return Ok(Prefix::Named(prefix));
        }
        *index = self.generated(*index, arena)?;
        let prefix = Prefix::Generated(*index);
        *index += 1;
        Ok(prefix)
    }

    pub(super) fn write(
        self,
        arena: &impl ArenaRead,
        output: &mut impl fmt::Write,
        element_prefix: Prefix<'_>,
        namespace: &str,
        parent_namespace: Option<&str>,
        parent_context: Option<Self>,
    ) -> Result<(), WriteError> {
        for binding in self.changed_bindings(parent_context, arena) {
            let (prefix, namespace) = binding?;
            write_binding(output, prefix, namespace)?;
        }
        match element_prefix {
            Prefix::Generated(index) => {
                write!(output, " xmlns:ns{index}=\"")?;
                xml::escape(output, namespace, true)?;
                output.write_char('"')?;
            }
            Prefix::Default if self.context.0.is_none() && Some(namespace) != parent_namespace => {
                xml::attribute(output, "xmlns", namespace)?;
            }
            Prefix::Named("stream") if self.context.0.is_none() => {
                xml::attribute(output, "xmlns:stream", STREAM_NAMESPACE)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) async fn write_async<W: AsyncWrite + Unpin>(
        self,
        arena: &impl ArenaRead,
        output: &mut W,
        element_prefix: Prefix<'_>,
        namespace: &str,
        parent_namespace: Option<&str>,
        parent_context: Option<Self>,
    ) -> Result<(), AsyncWriteError> {
        for binding in self.changed_bindings(parent_context, arena) {
            let (prefix, namespace) = binding?;
            output.write_all(b" xmlns").await?;
            if !prefix.is_empty() {
                output.write_all(b":").await?;
                output.write_all(prefix.as_bytes()).await?;
            }
            output.write_all(b"=\"").await?;
            xml::escape_async(output, namespace, true).await?;
            output.write_all(b"\"").await?;
        }
        match element_prefix {
            Prefix::Generated(index) => {
                output.write_all(b" xmlns:ns").await?;
                xml::number_async(output, index).await?;
                output.write_all(b"=\"").await?;
                xml::escape_async(output, namespace, true).await?;
                output.write_all(b"\"").await?;
            }
            Prefix::Default if self.context.0.is_none() && Some(namespace) != parent_namespace => {
                xml::attribute_async(output, "xmlns", namespace).await?;
            }
            Prefix::Named("stream") if self.context.0.is_none() => {
                xml::attribute_async(output, "xmlns:stream", STREAM_NAMESPACE).await?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn child_default<'a>(
        self,
        prefix: Prefix<'_>,
        namespace: &'a str,
        parent_namespace: Option<&'a str>,
        arena: &'a impl ArenaRead,
    ) -> Result<Option<&'a str>, HandleError>
    where
        'n: 'a,
    {
        if let Some(namespace) = self.resolve("", arena)? {
            return Ok(Some(namespace));
        }
        Ok(if matches!(prefix, Prefix::Default) {
            Some(namespace)
        } else {
            parent_namespace
        })
    }
}

fn write_binding(output: &mut impl fmt::Write, prefix: &str, namespace: &str) -> fmt::Result {
    output.write_str(" xmlns")?;
    if !prefix.is_empty() {
        output.write_char(':')?;
        output.write_str(prefix)?;
    }
    output.write_str("=\"")?;
    xml::escape(output, namespace, true)?;
    output.write_char('"')
}

#[cfg(test)]
mod tests {
    use lonewolf_util::arena::ArenaConfig;

    use super::*;
    use crate::stanza::{CLIENT_NAMESPACE, SERVER_NAMESPACE};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn shared_heads_emit_declarations_when_substitution_changes() -> TestResult {
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let mut context = NamespaceContext::default();
        context.bind("", SERVER_NAMESPACE, &mut arena)?;
        context.bind("s", STREAM_NAMESPACE, &mut arena)?;
        let original = ContextView {
            context,
            rescope: None,
        };
        let substituted = ContextView {
            context,
            rescope: Some(Rescope {
                from: SERVER_NAMESPACE,
                to: CLIENT_NAMESPACE,
            }),
        };
        let other = ContextView {
            context,
            rescope: Some(Rescope {
                from: SERVER_NAMESPACE,
                to: "urn:other",
            }),
        };
        for (child, parent, namespace, expected) in [
            (
                original,
                substituted,
                SERVER_NAMESPACE,
                " xmlns=\"jabber:server\"",
            ),
            (
                substituted,
                original,
                CLIENT_NAMESPACE,
                " xmlns=\"jabber:client\"",
            ),
            (
                substituted,
                other,
                CLIENT_NAMESPACE,
                " xmlns=\"jabber:client\"",
            ),
            (other, substituted, "urn:other", " xmlns=\"urn:other\""),
            (original, original, SERVER_NAMESPACE, ""),
            (substituted, substituted, CLIENT_NAMESPACE, ""),
        ] {
            let mut sync = String::new();
            child.write(
                &arena,
                &mut sync,
                Prefix::Default,
                namespace,
                None,
                Some(parent),
            )?;
            assert_eq!(sync, expected);
            let mut asynchronous = Vec::new();
            futures_executor::block_on(child.write_async(
                &arena,
                &mut asynchronous,
                Prefix::Default,
                namespace,
                None,
                Some(parent),
            ))?;
            assert_eq!(asynchronous, expected.as_bytes());
        }
        let from = SERVER_NAMESPACE.to_owned();
        let to = CLIENT_NAMESPACE.to_owned();
        let equal_substitution = ContextView {
            context,
            rescope: Some(Rescope {
                from: &from,
                to: &to,
            }),
        };
        assert_eq!(
            substituted
                .changed_bindings(Some(equal_substitution), &arena)
                .count(),
            0,
        );
        Ok(())
    }

    #[test]
    fn substitution_reads_inherited_defaults_and_keeps_named_bindings() -> TestResult {
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let mut context = NamespaceContext::default();
        context.bind("", SERVER_NAMESPACE, &mut arena)?;
        context.bind("p", "urn:old", &mut arena)?;
        context.bind("c", SERVER_NAMESPACE, &mut arena)?;
        context.bind("ns0", SERVER_NAMESPACE, &mut arena)?;
        context.bind("s", STREAM_NAMESPACE, &mut arena)?;
        context.bind("p", "urn:new", &mut arena)?;
        let view = ContextView {
            context,
            rescope: Some(Rescope {
                from: SERVER_NAMESPACE,
                to: CLIENT_NAMESPACE,
            }),
        };
        assert_eq!(view.resolve("", &arena)?, Some(CLIENT_NAMESPACE));
        assert_eq!(view.resolve("c", &arena)?, Some(SERVER_NAMESPACE));
        assert_eq!(
            view.bindings(&arena).collect::<Result<Vec<_>, _>>()?,
            [
                ("p", "urn:new"),
                ("s", STREAM_NAMESPACE),
                ("ns0", SERVER_NAMESPACE),
                ("c", SERVER_NAMESPACE),
                ("", CLIENT_NAMESPACE),
            ],
        );
        assert!(matches!(
            view.element_prefix(CLIENT_NAMESPACE, &arena)?,
            Prefix::Default
        ));
        assert!(matches!(
            view.element_prefix(SERVER_NAMESPACE, &arena)?,
            Prefix::Named("ns0")
        ));
        let mut index = 0;
        assert!(matches!(
            view.attribute_prefix(SERVER_NAMESPACE, &mut index, &arena)?,
            Prefix::Named("ns0")
        ));
        assert_eq!(index, 0);
        assert!(matches!(
            view.attribute_prefix("urn:unbound", &mut index, &arena)?,
            Prefix::Generated(1)
        ));
        assert_eq!(index, 2);
        assert_eq!(
            view.child_default(Prefix::Named("ns0"), SERVER_NAMESPACE, None, &arena)?,
            Some(CLIENT_NAMESPACE),
        );
        let mut output = String::new();
        view.write(
            &arena,
            &mut output,
            Prefix::Default,
            CLIENT_NAMESPACE,
            None,
            None,
        )?;
        assert_eq!(
            output,
            " xmlns:p=\"urn:new\" xmlns:s=\"http://etherx.jabber.org/streams\" xmlns:ns0=\"jabber:server\" xmlns:c=\"jabber:server\" xmlns=\"jabber:client\""
        );
        for namespace in ["urn:foreign", ""] {
            let mut shadowed = context;
            shadowed.bind("", namespace, &mut arena)?;
            let shadowed = ContextView {
                context: shadowed,
                rescope: view.rescope,
            };
            assert_eq!(shadowed.resolve("", &arena)?, Some(namespace));
            assert_eq!(
                shadowed.bindings(&arena).next().transpose()?,
                Some(("", namespace))
            );
        }
        Ok(())
    }
}
