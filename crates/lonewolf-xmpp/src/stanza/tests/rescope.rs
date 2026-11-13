// SPDX-License-Identifier: Apache-2.0

use super::*;

fn parse_stream_stanza(
    namespace: StanzaNamespace,
    xml: &str,
) -> Result<(Stanza, Arena), Box<dyn std::error::Error>> {
    parse_stream_with_header(namespace, "", xml)
}

pub(super) struct Case {
    pub(super) name: &'static str,
    pub(super) stanza: Stanza,
    pub(super) arena: Arena,
}

pub(super) type Walk = Vec<(usize, &'static str, String, String, String)>;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) xml: String,
    pub(super) structure: Walk,
    pub(super) offline: String,
    pub(super) forwarded: Result<String, BuildError>,
}

pub(super) fn corpus() -> Result<Vec<Case>, Box<dyn std::error::Error>> {
    let mut cases = Vec::new();
    for namespace in [StanzaNamespace::Client, StanzaNamespace::Server] {
        let content = namespace.as_str();
        let other = if namespace == StanzaNamespace::Client {
            SERVER_NAMESPACE
        } else {
            CLIENT_NAMESPACE
        };
        for (name, kind, attributes, children) in [
            ("chat_body_thread_extension", "message", "type='chat' id='chat-1'", "<body>Hello</body><thread>thread-1</thread><request xmlns='urn:xmpp:receipts'/>".to_owned()),
            ("forwarded_inner_message", "message", "type='chat'", "<forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body/></message></forwarded>".to_owned()),
            ("foreign_prefixed_parent_with_inherited_default", "message", "type='chat'", "<f:x xmlns:f='urn:f'><body>inherits</body></f:x>".to_owned()),
            ("unknown_message_type", "message", "type='x-custom'", "<body>custom</body>".to_owned()),
            ("namespaced_attributes", "message", "xmlns:a='urn:a' a:flag='1'", "<x xmlns='urn:x' a:flag='2'/>".to_owned()),
            ("default_redeclarations", "message", "", format!("<body xmlns='{content}'>explicit</body><x xmlns=''><body>empty</body></x>")),
            ("escaping", "message", "id='&amp;&lt;&gt;&apos;&quot;' plain='&amp;&lt;&gt;&apos;&quot;'", "<body flag='&amp;&lt;&gt;&apos;&quot;'>&amp;&lt;&gt;&apos;&quot;<em>middle</em>tail</body><x xmlns='urn:x' flag='&amp;&lt;&gt;&apos;&quot;'>&amp;&lt;&gt;&apos;&quot;</x>".to_owned()),
            ("foreign_error_namespace", "message", "type='chat'", format!("<error xmlns='{other}'/>")),
        ] {
            let xml = format!("<{kind} from='a@example.org/r' to='b@example.net' {attributes}>{children}</{kind}>");
            let (stanza, arena) = parse_stream_stanza(namespace, &xml)?;
            cases.push(Case { name, stanza, arena });
        }
        for kind in ["message", "presence", "iq"] {
            let xml = format!(
                "<{kind} from='a@example.org/r' to='b@example.net' id='error-1' type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>x</text></error></{kind}>"
            );
            let (stanza, arena) = parse_stream_stanza(namespace, &xml)?;
            cases.push(Case {
                name: "error_payloads",
                stanza,
                arena,
            });
        }
        let (stanza, arena) = parse_stream_stanza(
            namespace,
            "<presence from='a@example.org/r' to='b@example.net'/>",
        )?;
        cases.push(Case {
            name: "self_closing",
            stanza,
            arena,
        });
        for (name, header, xml) in [
            (
                "lang_and_space",
                "xml:lang='es' xml:space='preserve'",
                "<message from='a@example.org/r' to='b@example.net' type='chat'><body xml:lang='en'> text </body></message>",
            ),
            (
                "stream_header_bindings",
                "xmlns:db='jabber:server:dialback' xmlns:s='http://etherx.jabber.org/streams'",
                "<message from='a@example.org/r' to='b@example.net'><x xmlns='urn:qname' kind='s:stream'>db:value</x></message>",
            ),
        ] {
            let (stanza, arena) = parse_stream_with_header(namespace, header, xml)?;
            cases.push(Case {
                name,
                stanza,
                arena,
            });
        }
        for construction in [
            "prefixed_content_under_foreign_default",
            "namespaced_attributes",
            "empty_contexts",
            "maximum_depth",
        ] {
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let from = Jid::parse_in("a@example.org/r", &mut arena)?;
            let to = Jid::parse_in("b@example.net", &mut arena)?;
            let mut children = Vec::new();
            let mut context = super::super::NamespaceContext::default();
            if construction == "prefixed_content_under_foreign_default" {
                context.bind("", "urn:foreign", &mut arena)?;
                context.bind("c", content, &mut arena)?;
                let mut frame = super::super::ElementFrame::new("body", content, &mut arena)?;
                frame.set_namespaces(context);
                frame.text("body", &mut arena)?;
                children.push(frame.finish(&mut arena)?);
                let nested = Element::builder_in("body", content, &mut arena)?
                    .text("foreign subtree")?
                    .build()?;
                children.push(
                    Element::builder_in("extension", "urn:foreign", &mut arena)?
                        .child(nested)?
                        .build()?,
                );
            } else if construction == "namespaced_attributes" {
                children.push(
                    Element::builder_in("body", content, &mut arena)?
                        .attribute("flag", "urn:unbound", "child")?
                        .attribute("content", content, "unchanged")?
                        .build()?,
                );
            } else if construction == "maximum_depth" {
                let mut child = Element::builder_in("body", content, &mut arena)?
                    .text("deep")?
                    .build()?;
                for _ in 1..MAX_ELEMENT_DEPTH - 1 {
                    child = Element::builder_in("nested", content, &mut arena)?
                        .child(child)?
                        .build()?;
                }
                children.push(child);
            }
            let mut builder = Stanza::builder_in(
                StanzaType::Message(MessageType::Chat),
                namespace,
                &mut arena,
            )
            .from(Some(from))?
            .to(Some(to))?;
            builder.namespaces = context;
            if construction == "namespaced_attributes" {
                builder = builder.attribute("flag", "urn:unbound", "root")?;
            }
            for child in children {
                builder = builder.child(child)?;
            }
            let stanza = builder.build()?;
            cases.push(Case {
                name: construction,
                stanza,
                arena,
            });
        }
    }
    for (name, from, to) in [
        ("empty_contexts", None, None),
        ("missing_addresses", Some("a@example.org/r"), None),
        ("missing_addresses", None, Some("b@example.net")),
        ("missing_addresses", None, None),
    ] {
        let mut arena = Arena::try_new(ArenaConfig::default())?;
        let from = from
            .map(|value| Jid::parse_in(value, &mut arena))
            .transpose()?;
        let to = to
            .map(|value| Jid::parse_in(value, &mut arena))
            .transpose()?;
        let stanza = Stanza::builder_in(
            StanzaType::Message(MessageType::Chat),
            StanzaNamespace::Client,
            &mut arena,
        )
        .from(from)?
        .to(to)?
        .build()?;
        cases.push(Case {
            name,
            stanza,
            arena,
        });
    }
    Ok(cases)
}

fn parse_stream_with_header(
    namespace: StanzaNamespace,
    header: &str,
    xml: &str,
) -> Result<(Stanza, Arena), Box<dyn std::error::Error>> {
    futures_executor::block_on(async {
        let input = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='{}' {header}>{xml}",
            namespace.as_str()
        );
        let mut parser = XmppParser::new(
            input.as_bytes(),
            ParserConfig {
                max_stanza_bytes: NonZeroUsize::new(input.len()).ok_or("zero limit")?,
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        );
        assert!(matches!(
            parser.next_event().await?,
            Some(StreamEvent::StreamStart { .. })
        ));
        let Some(StreamEvent::Stanza(parsed)) = parser.next_event().await? else {
            return Err("expected stanza".into());
        };
        Ok(parsed.into_parts())
    })
}

fn walk_element<R: ArenaRead>(
    element: crate::stanza::ElementRef<'_, R>,
    depth: usize,
    rescope: Option<(&str, &str)>,
    result: &mut Walk,
) -> Result<(), HandleError> {
    let rescope = rescope.filter(|(from, _)| element.namespace() == *from);
    let namespace = rescope.map_or(element.namespace(), |(_, to)| to);
    result.push((
        depth,
        "element",
        element.name().into(),
        namespace.into(),
        String::new(),
    ));
    for attribute in element.attributes()? {
        let attribute = attribute?;
        result.push((
            depth,
            "attribute",
            attribute.name.into(),
            attribute.namespace.into(),
            attribute.value.into(),
        ));
    }
    for node in element.children()? {
        match node? {
            NodeRef::Element(child) => walk_element(child, depth + 1, rescope, result)?,
            NodeRef::Text(text) => {
                result.push((depth + 1, "text", String::new(), String::new(), text.into()))
            }
        }
    }
    result.push((
        depth,
        "end",
        element.name().into(),
        namespace.into(),
        String::new(),
    ));
    Ok(())
}

fn walk_as<R: ArenaRead>(
    stanza: &crate::stanza::StanzaRef<'_, R>,
    namespace: StanzaNamespace,
) -> Result<Walk, HandleError> {
    let mut result = vec![(
        0,
        "stanza",
        stanza.kind().as_str().into(),
        namespace.as_str().into(),
        String::new(),
    )];
    for (name, value) in [
        ("from", stanza.from()?.map(|jid| jid.as_str())),
        ("to", stanza.to()?.map(|jid| jid.as_str())),
        ("id", stanza.id()?),
        ("type", stanza.serialized_type()?),
        ("lang", stanza.lang()?),
    ] {
        if let Some(value) = value {
            result.push((
                0,
                "header",
                name.into(),
                if name == "lang" {
                    XML_NAMESPACE.into()
                } else {
                    String::new()
                },
                value.into(),
            ));
        }
    }
    for attribute in stanza.attributes()? {
        let attribute = attribute?;
        result.push((
            0,
            "attribute",
            attribute.name.into(),
            attribute.namespace.into(),
            attribute.value.into(),
        ));
    }
    for child in stanza.children()? {
        walk_element(
            child?,
            1,
            Some((stanza.namespace().as_str(), namespace.as_str())),
            &mut result,
        )?;
    }
    Ok(result)
}

pub(super) fn structural_walk<R: ArenaRead>(
    stanza: &crate::stanza::StanzaRef<'_, R>,
) -> Result<Walk, HandleError> {
    walk_as(stanza, stanza.namespace())
}

pub(super) fn snapshot(
    stanza: Stanza,
    arena: &impl ArenaRead,
) -> Result<Snapshot, Box<dyn std::error::Error>> {
    let view = stanza.resolve(arena)?;
    let xml = stanza_xml(stanza, arena)?;
    let mut writer = FragmentedWriter::default();
    futures_executor::block_on(view.write_xml_async(&mut writer))?;
    assert_eq!(writer.bytes, xml.as_bytes());
    assert_eq!(writer.flushes, 0);
    let structure = structural_walk(&view)?;
    let mut offline_arena = Arena::try_new(ArenaConfig::default())?;
    let offline_stanza = view.to_builder_in(&mut offline_arena)?.build()?;
    let offline = stanza_xml(offline_stanza, &offline_arena)?;
    assert_eq!(offline, xml);
    assert_eq!(
        structural_walk(&offline_stanza.resolve(&offline_arena)?)?,
        structure
    );
    let mut carbons_arena = Arena::try_new(ArenaConfig::default())?;
    let forwarded = view.to_element_in(&mut carbons_arena).and_then(|element| {
        Element::builder_in("forwarded", "urn:xmpp:forward:0", &mut carbons_arena)?
            .child(element)?
            .build()
    });
    let forwarded = match forwarded {
        Ok(element) => {
            let xml = element_xml(element, &carbons_arena)?;
            let mut writer = FragmentedWriter::default();
            futures_executor::block_on(
                element
                    .resolve(&carbons_arena)?
                    .write_xml_async(&mut writer),
            )?;
            assert_eq!(writer.bytes, xml.as_bytes());
            let parsed = futures_executor::block_on(crate::parser::parse_element(
                xml.as_bytes(),
                ParserConfig {
                    max_stanza_bytes: NonZeroUsize::new(xml.len()).ok_or("zero limit")?,
                    arena: ArenaConfig::default(),
                },
                GlobalChunkAllocator,
            ))?;
            let mut reparsed = Vec::new();
            walk_element(
                parsed.value().resolve(parsed.arena())?,
                0,
                None,
                &mut reparsed,
            )?;
            let mut expected = vec![(
                0,
                "element",
                "forwarded".into(),
                "urn:xmpp:forward:0".into(),
                String::new(),
            )];
            for (depth, kind, name, namespace, value) in &structure {
                expected.push((
                    depth + 1,
                    match *kind {
                        "stanza" => "element",
                        "header" => "attribute",
                        other => other,
                    },
                    name.clone(),
                    namespace.clone(),
                    value.clone(),
                ));
            }
            expected.push((
                1,
                "end",
                view.kind().as_str().into(),
                view.namespace().as_str().into(),
                String::new(),
            ));
            expected.push((
                0,
                "end",
                "forwarded".into(),
                "urn:xmpp:forward:0".into(),
                String::new(),
            ));
            assert_eq!(reparsed, expected);
            Ok(xml)
        }
        Err(error) => Err(error),
    };
    Ok(Snapshot {
        xml,
        structure,
        offline,
        forwarded,
    })
}

pub(super) fn oracle(
    case: &Case,
    namespace: StanzaNamespace,
) -> Result<Result<Snapshot, BuildError>, Box<dyn std::error::Error>> {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    match case
        .stanza
        .resolve(&case.arena)?
        .rescope_in(namespace, &mut arena)
    {
        Ok(stanza) => snapshot(stanza, &arena).map(Ok),
        Err(error) => Ok(Err(error)),
    }
}

#[test]
fn foreign_error_namespace() -> TestResult {
    for case in corpus()?
        .into_iter()
        .filter(|case| case.name == "foreign_error_namespace")
    {
        let source = case.stanza.resolve(&case.arena)?.namespace();
        for target in [StanzaNamespace::Client, StanzaNamespace::Server] {
            match oracle(&case, target)? {
                Ok(_) => assert_eq!(source, target),
                Err(error) => {
                    assert_ne!(source, target);
                    assert_eq!(error, BuildError::InvalidErrorPayload);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn corpus_matches_structure_and_copy_paths() -> TestResult {
    let cases = corpus()?;
    assert_eq!(cases.len(), 40);
    for case in &cases {
        let source = case.stanza.resolve(&case.arena)?;
        for target in [StanzaNamespace::Client, StanzaNamespace::Server] {
            let expected_error = if target == StanzaNamespace::Server
                && (source.from()?.is_none() || source.to()?.is_none())
            {
                Some(BuildError::MissingServerAddresses)
            } else if case.name == "foreign_error_namespace" && source.namespace() != target {
                Some(BuildError::InvalidErrorPayload)
            } else {
                None
            };
            match oracle(case, target)? {
                Err(error) => assert_eq!(
                    Some(error),
                    expected_error,
                    "{} {:?} -> {target:?}",
                    case.name,
                    source.namespace()
                ),
                Ok(output) => {
                    assert_eq!(expected_error, None, "{}", case.name);
                    assert_eq!(
                        output.structure,
                        walk_as(&source, target)?,
                        "{} {:?} -> {target:?}",
                        case.name,
                        source.namespace()
                    );
                    if source.namespace() == target {
                        assert_eq!(
                            output.xml,
                            stanza_xml(case.stanza, &case.arena)?,
                            "{}",
                            case.name
                        );
                    }
                    if case.name == "maximum_depth" {
                        assert_eq!(output.forwarded, Err(BuildError::TreeLimitExceeded));
                    } else {
                        assert!(output.forwarded.is_ok(), "{}", case.name);
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn literal_xml_anchors() -> TestResult {
    for case in corpus()? {
        let source = case.stanza.resolve(&case.arena)?.namespace();
        for target in [StanzaNamespace::Client, StanzaNamespace::Server] {
            let (header, children) = match (case.name, source, target) {
                ("chat_body_thread_extension", _, _) => (
                    " id=\"chat-1\" type=\"chat\"",
                    "<body>Hello</body><thread>thread-1</thread><request xmlns=\"urn:xmpp:receipts\"/>",
                ),
                ("forwarded_inner_message", _, _) => (
                    " type=\"chat\"",
                    "<forwarded xmlns=\"urn:xmpp:forward:0\"><message xmlns=\"jabber:client\"><body/></message></forwarded>",
                ),
                (
                    "foreign_prefixed_parent_with_inherited_default",
                    StanzaNamespace::Client,
                    StanzaNamespace::Server,
                ) => (
                    " type=\"chat\"",
                    "<f:x xmlns:f=\"urn:f\" xmlns=\"jabber:client\"><body>inherits</body></f:x>",
                ),
                (
                    "foreign_prefixed_parent_with_inherited_default",
                    StanzaNamespace::Server,
                    StanzaNamespace::Client,
                ) => (
                    " type=\"chat\"",
                    "<f:x xmlns:f=\"urn:f\" xmlns=\"jabber:server\"><body>inherits</body></f:x>",
                ),
                ("foreign_prefixed_parent_with_inherited_default", _, _) => (
                    " type=\"chat\"",
                    "<f:x xmlns:f=\"urn:f\"><body>inherits</body></f:x>",
                ),
                _ => continue,
            };
            let output = oracle(&case, target)??;
            let root = match target {
                StanzaNamespace::Client => {
                    "<message xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" from=\"a@example.org/r\" to=\"b@example.net\""
                }
                StanzaNamespace::Server => {
                    "<message xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:server\" from=\"a@example.org/r\" to=\"b@example.net\""
                }
            };
            assert_eq!(
                output.xml,
                format!("{root}{header}>{children}</message>"),
                "{} {source:?} -> {target:?}",
                case.name
            );
            assert_eq!(
                output.forwarded?,
                format!(
                    "<forwarded xmlns=\"urn:xmpp:forward:0\">{root}{header}>{children}</message></forwarded>"
                )
            );
        }
    }
    Ok(())
}

#[test]
fn write_as_matches_rescope_for_the_corpus() -> TestResult {
    for case in corpus()? {
        let view = case.stanza.resolve(&case.arena)?;
        for target in [StanzaNamespace::Client, StanzaNamespace::Server] {
            let expected = oracle(&case, target)?;
            let validation = view.validate_rescope(target);
            match expected {
                Err(error) => assert_eq!(
                    validation,
                    Err(error),
                    "{} {:?} -> {target:?}",
                    case.name,
                    view.namespace(),
                ),
                Ok(expected) => {
                    validation?;
                    let mut xml = String::new();
                    view.write_xml_as(target, &mut xml)?;
                    assert_eq!(xml, expected.xml, "{} -> {target:?}", case.name);
                    let mut writer = FragmentedWriter::default();
                    futures_executor::block_on(view.write_xml_async_as(target, &mut writer))?;
                    assert_eq!(
                        writer.bytes,
                        expected.xml.as_bytes(),
                        "{} -> {target:?}",
                        case.name
                    );
                    assert_eq!(writer.flushes, 0);
                }
            }
        }
    }
    Ok(())
}

fn assert_stream_header_bindings(xml: &str) -> TestResult {
    use quick_xml::events::Event;
    use quick_xml::name::{QName, ResolveResult};

    let mut reader = quick_xml::NsReader::from_str(xml);
    let mut roots = 0;
    let mut payloads = 0;
    let mut texts = 0;
    loop {
        match reader.read_event()? {
            Event::Start(start) | Event::Empty(start) => {
                let (namespace, local) = reader.resolver().resolve_element(start.name());
                match local.as_ref() {
                    "message" => roots += 1,
                    "x" => {
                        assert!(
                            matches!(namespace, ResolveResult::Bound(namespace) if namespace.as_ref() == "urn:qname")
                        );
                        let kind = start.try_get_attribute("kind")?.ok_or("missing kind")?;
                        assert_eq!(kind.value.as_ref(), "s:stream");
                        assert!(matches!(
                            reader.resolver().resolve_attribute(kind.key).0,
                            ResolveResult::Unbound
                        ));
                        payloads += 1;
                    }
                    _ => return Err("unexpected element".into()),
                }
                for (name, expected) in [
                    ("stream:value", STREAM_NAMESPACE),
                    ("s:value", STREAM_NAMESPACE),
                    ("db:value", "jabber:server:dialback"),
                ] {
                    assert!(
                        matches!(
                            reader.resolver().resolve_prefix(QName(name).prefix(), true),
                            ResolveResult::Bound(namespace) if namespace.as_ref() == expected
                        ),
                        "{xml}"
                    );
                }
            }
            Event::Text(text) => {
                assert_eq!(text.as_ref(), "db:value");
                texts += 1;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!((roots, payloads, texts), (1, 1, 1));
    Ok(())
}

#[test]
fn write_as_round_trips_through_the_parser() -> TestResult {
    let mut missing_addresses = 0;
    let mut invalid_errors = 0;
    let mut server_serializations = 0;
    let mut parser_rejections = 0;
    let mut restored = 0;
    for case in corpus()? {
        let source = case.stanza.resolve(&case.arena)?;
        if source.namespace() != StanzaNamespace::Client {
            continue;
        }
        let expected_server = match oracle(&case, StanzaNamespace::Server)? {
            Ok(expected) => expected,
            Err(error) => {
                assert_eq!(source.validate_rescope(StanzaNamespace::Server), Err(error));
                match error {
                    BuildError::MissingServerAddresses => missing_addresses += 1,
                    BuildError::InvalidErrorPayload => invalid_errors += 1,
                    _ => {
                        return Err(format!(
                            "{}: unexpected validation error {error:?}",
                            case.name
                        )
                        .into());
                    }
                }
                continue;
            }
        };
        source.validate_rescope(StanzaNamespace::Server)?;
        let mut xml = String::new();
        source.write_xml_as(StanzaNamespace::Server, &mut xml)?;
        assert_eq!(xml, expected_server.xml, "{}", case.name);
        server_serializations += 1;
        let candidate = parse_stream_stanza(StanzaNamespace::Server, &xml);
        let reference = parse_stream_stanza(StanzaNamespace::Server, &expected_server.xml);
        if case.name == "prefixed_content_under_foreign_default" {
            for parsed in [candidate, reference] {
                let error = parsed.err().ok_or("expected prefixed-root rejection")?;
                assert!(
                    matches!(
                        error.downcast_ref::<crate::parser::ParseError>(),
                        Some(crate::parser::ParseError::BadNamespacePrefix)
                    ),
                    "{error}"
                );
            }
            parser_rejections += 1;
            continue;
        }
        let (candidate, candidate_arena) =
            candidate.map_err(|error| format!("{} candidate: {error}", case.name))?;
        let (reference, reference_arena) =
            reference.map_err(|error| format!("{} reference: {error}", case.name))?;
        let original_structure = structural_walk(&source)?;
        let mut client_outputs = Vec::new();
        for (parsed, arena) in [(candidate, candidate_arena), (reference, reference_arena)] {
            assert_eq!(
                structural_walk(&parsed.resolve(&arena)?)?,
                expected_server.structure,
                "{}",
                case.name
            );
            let mut client_arena = Arena::try_new(ArenaConfig::default())?;
            let client = parsed
                .resolve(&arena)?
                .rescope_in(StanzaNamespace::Client, &mut client_arena)?;
            assert_eq!(
                structural_walk(&client.resolve(&client_arena)?)?,
                original_structure,
                "{}",
                case.name
            );
            client_outputs.push(stanza_xml(client, &client_arena)?);
        }
        assert_eq!(client_outputs[0], client_outputs[1], "{}", case.name);
        if case.name == "stream_header_bindings" {
            for output in [
                &xml,
                &expected_server.xml,
                &client_outputs[0],
                &client_outputs[1],
            ] {
                assert_stream_header_bindings(output)?;
            }
        }
        restored += 1;
    }
    assert_eq!(
        (
            missing_addresses,
            invalid_errors,
            server_serializations,
            parser_rejections,
            restored
        ),
        (4, 1, 17, 1, 16)
    );
    Ok(())
}

#[test]
fn write_as_needs_no_arena() -> TestResult {
    let fail = Arc::new(AtomicBool::new(false));
    let mut arena = Arena::try_new_in(
        ArenaConfig::default(),
        FailingAllocator { fail: fail.clone() },
    )?;
    let from = Jid::parse_in("a@example.org/r", &mut arena)?;
    let to = Jid::parse_in("b@example.net", &mut arena)?;
    let text = "x".repeat(ArenaConfig::default().chunk_size.get() * 2);
    let body = Element::builder_in("body", CLIENT_NAMESPACE, &mut arena)?
        .text(&text)?
        .build()?;
    let stanza = Stanza::builder_in(
        StanzaType::Message(MessageType::Chat),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(Some(from))?
    .to(Some(to))?
    .child(body)?
    .build()?;
    let mut oracle_arena = Arena::try_new_in(
        ArenaConfig::default(),
        FailingAllocator { fail: fail.clone() },
    )?;
    let view = stanza.resolve(&arena)?;
    let copied = view.rescope_in(StanzaNamespace::Server, &mut oracle_arena)?;
    let expected = stanza_xml(copied, &oracle_arena)?;
    let mut refused_arena = Arena::try_new_in(
        ArenaConfig::default(),
        FailingAllocator { fail: fail.clone() },
    )?;
    assert!(text.len() > refused_arena.stats().reserved_bytes);
    fail.store(true, Ordering::Relaxed);
    assert_eq!(
        view.rescope_in(StanzaNamespace::Server, &mut refused_arena)
            .err(),
        Some(BuildError::Allocation(ArenaError::Allocation(
            AllocationError::Exhausted
        ))),
    );
    view.validate_rescope(StanzaNamespace::Server)?;
    let mut xml = String::new();
    view.write_xml_as(StanzaNamespace::Server, &mut xml)?;
    assert_eq!(xml, expected);
    let mut writer = FragmentedWriter::default();
    futures_executor::block_on(view.write_xml_async_as(StanzaNamespace::Server, &mut writer))?;
    assert_eq!(writer.bytes, expected.as_bytes());
    assert_eq!(writer.flushes, 0);
    Ok(())
}
