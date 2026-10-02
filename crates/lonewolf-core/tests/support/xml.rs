// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::io::{BufReader, Cursor, Read, Write};

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

use super::TestResult;

pub const STREAM_NAMESPACE: &str = "http://etherx.jabber.org/streams";

#[derive(Debug, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub namespace: String,
    attributes: BTreeMap<String, String>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    fn from_start<R>(reader: &NsReader<R>, start: &BytesStart<'_>) -> TestResult<Self> {
        let (namespace, name) = reader.resolver().resolve_element(start.name());
        let namespace = match namespace {
            ResolveResult::Bound(namespace) => namespace.as_ref().into(),
            ResolveResult::Unbound => String::new(),
            ResolveResult::Unknown(_) => return Err("unbound XML namespace prefix".into()),
        };
        let mut attributes = BTreeMap::new();
        for attribute in start.attributes() {
            let attribute = attribute?;
            attributes.insert(
                attribute.key.as_ref().into(),
                attribute
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)?
                    .into_owned(),
            );
        }
        Ok(Self {
            name: name.as_ref().into(),
            namespace,
            attributes,
            children: Vec::new(),
            text: String::new(),
        })
    }

    pub fn assert_xml(&self, expected: &str) -> TestResult {
        let mut stream = XmlStream::new(Cursor::new(expected.as_bytes()));
        let expected = stream.receive()?;
        self.assert_same_content(&expected);
        Ok(())
    }

    fn assert_same_content(&self, expected: &Self) {
        self.assert_name(&expected.namespace, &expected.name);
        assert!(
            self.content_attributes().eq(expected.content_attributes()),
            "attributes differ: actual {self:?}, expected {expected:?}"
        );
        if self.children.is_empty()
            || !self.text.trim().is_empty()
            || !expected.text.trim().is_empty()
        {
            assert_eq!(self.text, expected.text, "{self:?}");
        }
        assert_eq!(self.children.len(), expected.children.len(), "{self:?}");
        for (actual, expected) in self.children.iter().zip(&expected.children) {
            actual.assert_same_content(expected);
        }
    }

    fn content_attributes(&self) -> impl Iterator<Item = (&String, &String)> {
        self.attributes
            .iter()
            .filter(|(name, _)| *name != "xmlns" && !name.starts_with("xmlns:"))
    }

    pub fn assert_name(&self, namespace: &str, name: &str) {
        assert_eq!(self.namespace, namespace, "{self:?}");
        assert_eq!(self.name, name, "{self:?}");
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    pub fn child(&self, namespace: &str, name: &str) -> TestResult<&Self> {
        self.children
            .iter()
            .find(|child| child.namespace == namespace && child.name == name)
            .ok_or_else(|| format!("missing {{{namespace}}}{name} in {self:?}").into())
    }
}

pub struct XmlStream<R> {
    reader: NsReader<BufReader<R>>,
    buffer: Vec<u8>,
}

impl<R: Read> XmlStream<R> {
    pub fn new(transport: R) -> Self {
        Self::from_buffered(BufReader::new(transport))
    }

    fn from_buffered(transport: BufReader<R>) -> Self {
        let mut reader = NsReader::from_reader(transport);
        reader.config_mut().expand_empty_elements = true;
        Self {
            reader,
            buffer: Vec::new(),
        }
    }

    pub fn into_inner(self) -> BufReader<R> {
        self.reader.into_inner()
    }

    pub fn restart(self) -> Self {
        Self::from_buffered(self.into_inner())
    }

    pub fn transport(&mut self) -> &mut R {
        self.reader.get_mut().get_mut()
    }

    pub fn has_buffered_input(&self) -> bool {
        !self.reader.get_ref().buffer().is_empty()
    }

    pub fn send(&mut self, xml: &str) -> TestResult
    where
        R: Write,
    {
        self.send_bytes(xml.as_bytes())
    }

    pub fn send_bytes(&mut self, xml: &[u8]) -> TestResult
    where
        R: Write,
    {
        let transport = self.transport();
        transport.write_all(xml)?;
        transport.flush()?;
        Ok(())
    }

    pub fn open(&mut self) -> TestResult<Element>
    where
        R: Write,
    {
        self.open_with(super::OPEN)?;
        self.features()
    }

    pub fn open_with(&mut self, opening: &str) -> TestResult<Element>
    where
        R: Write,
    {
        self.send(opening)?;
        loop {
            self.buffer.clear();
            match self.reader.read_event_into(&mut self.buffer)? {
                Event::Start(start) => {
                    let header = Element::from_start(&self.reader, &start)?;
                    assert_eq!(header.name, "stream");
                    assert_eq!(header.namespace, STREAM_NAMESPACE);
                    return Ok(header);
                }
                Event::Decl(_) => {}
                event => return Err(format!("expected stream opening, received {event:?}").into()),
            }
        }
    }

    pub fn features(&mut self) -> TestResult<Element> {
        let features = self.receive()?;
        assert_eq!(features.name, "features");
        assert_eq!(features.namespace, STREAM_NAMESPACE);
        Ok(features)
    }

    pub fn receive(&mut self) -> TestResult<Element> {
        let start_offset = self.reader.buffer_position();
        let mut stack: Vec<Element> = Vec::new();
        loop {
            if self.reader.buffer_position() - start_offset > 1024 * 1024 || stack.len() > 32 {
                return Err("XML response exceeded test limits".into());
            }
            self.buffer.clear();
            match self.reader.read_event_into(&mut self.buffer)? {
                Event::Start(start) => stack.push(Element::from_start(&self.reader, &start)?),
                Event::End(_) => {
                    let element = stack.pop().ok_or("stream ended before response")?;
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(element),
                        None => return Ok(element),
                    }
                }
                Event::Text(text) => {
                    let text = text.xml_content(quick_xml::XmlVersion::Implicit1_0);
                    if let Some(element) = stack.last_mut() {
                        element.text.push_str(&text);
                    } else if !text.trim().is_empty() {
                        return Err("unexpected text between stanzas".into());
                    }
                }
                Event::GeneralRef(reference) => {
                    let text = format!("&{};", reference.as_ref());
                    let text = quick_xml::escape::unescape(&text)?;
                    stack
                        .last_mut()
                        .ok_or("entity outside stanza")?
                        .text
                        .push_str(&text);
                }
                Event::CData(text) => {
                    stack
                        .last_mut()
                        .ok_or("CDATA outside stanza")?
                        .text
                        .push_str(text.as_ref());
                }
                event => return Err(format!("unexpected XML event: {event:?}").into()),
            }
        }
    }

    pub fn expect_xml(&mut self, expected: &str) -> TestResult {
        self.receive()?.assert_xml(expected)
    }

    pub fn expect_stream_error(&mut self, condition: &str) -> TestResult {
        let error = self.receive()?;
        error.assert_name(STREAM_NAMESPACE, "error");
        assert_eq!(error.children.len(), 1, "{error:?}");
        error.child(super::STREAM_ERRORS, condition)?;
        self.expect_end()
    }

    pub fn close(&mut self) -> TestResult
    where
        R: Write,
    {
        self.send("</stream:stream>")?;
        self.expect_end()
    }

    pub fn expect_end(&mut self) -> TestResult {
        self.buffer.clear();
        match self.reader.read_event_into(&mut self.buffer)? {
            Event::End(end) => {
                let (namespace, name) = self.reader.resolver().resolve_element(end.name());
                assert_eq!(name.as_ref(), "stream");
                assert!(
                    matches!(namespace, ResolveResult::Bound(ns) if ns.as_ref() == STREAM_NAMESPACE)
                );
            }
            event => return Err(format!("expected stream footer, received {event:?}").into()),
        }
        self.expect_eof()
    }

    pub fn expect_eof(&mut self) -> TestResult {
        let mut byte = [0];
        match self.reader.get_mut().read(&mut byte) {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                Ok(())
            }
            result => Err(format!("expected transport closure, received {result:?}").into()),
        }
    }
}
