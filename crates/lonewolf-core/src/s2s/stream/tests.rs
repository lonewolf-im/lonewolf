// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::pin::pin;
use std::task::{Context, Poll};
use std::time::Duration;

use compio::net::TcpListener;
use compio::runtime::Runtime;
use compio::time::timeout;
use futures_util::poll;
use lonewolf_util::arena::{AllocationError, GlobalChunkAllocator};
use lonewolf_xmpp::parser::parse_element;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type TestReader = S2sReader<GlobalChunkAllocator, io::Cursor<Vec<u8>>>;
const HEADER: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' to='local.test' from='peer.test'>";

fn success<T>(result: Result<T, S2sError>) -> TestResult<T> {
    result.map_err(|error| format!("{error:?}").into())
}

fn limits() -> S2sReaderLimits {
    S2sReaderLimits {
        max_stanza_bytes: NonZeroUsize::new(16_384).unwrap_or(NonZeroUsize::MIN),
        stanzas: EventRate {
            per_second: NonZeroUsize::new(100).unwrap_or(NonZeroUsize::MIN),
            burst: NonZeroUsize::new(100).unwrap_or(NonZeroUsize::MIN),
        },
        xml: ByteRate::default(),
    }
}

fn reader(xml: &str, limits: &S2sReaderLimits) -> TestReader {
    S2sReader::new(
        io::Cursor::new(xml.as_bytes().to_owned()),
        limits,
        GlobalChunkAllocator,
    )
}

async fn header(xml: &str) -> TestResult<(Parsed<Element, GlobalChunkAllocator>, String)> {
    let mut reader = reader(xml, &limits());
    let Some(StreamEvent::StreamStart {
        header,
        content_namespace,
        ..
    }) = success(reader.next_event().await)?
    else {
        return Err("expected stream header".into());
    };
    Ok((header, content_namespace))
}

async fn element(xml: &str) -> TestResult<Parsed<Element, GlobalChunkAllocator>> {
    Ok(parse_element(
        xml.as_bytes(),
        ParserConfig {
            max_stanza_bytes: limits().max_stanza_bytes,
            arena: ArenaConfig::default(),
        },
        GlobalChunkAllocator,
    )
    .await?)
}

#[test]
fn initial_headers_normalize_domains_and_accept_extra_namespaces() -> TestResult {
    Runtime::new()?.block_on(async {
        for (xml, to, from) in [
            (HEADER.to_owned(), "local.test", Some("peer.test")),
            (HEADER.replace("from='peer.test'", ""), "local.test", None),
            (
                HEADER.replace(
                    "version='1.0'",
                    "version='0001.009' xml:lang='en-US' xmlns:db='jabber:server:dialback'",
                ),
                "local.test",
                Some("peer.test"),
            ),
            (
                HEADER
                    .replace("local.test", "LOCAL.TEST")
                    .replace("peer.test", "PEER.TEST"),
                "local.test",
                Some("peer.test"),
            ),
            (
                HEADER.replace(" xmlns='jabber:server'", ""),
                "local.test",
                Some("peer.test"),
            ),
        ] {
            let (header, namespace) = header(&xml).await?;
            let result = validate_initial_header(&header, &namespace)
                .map_err(|error| format!("{error:?}"))?;
            assert_eq!(result.to.as_ref(), to);
            assert_eq!(result.from.as_deref(), from);
        }
        Ok(())
    })
}

#[test]
fn initial_headers_reject_namespace_version_language_and_nondomain_jids() -> TestResult {
    Runtime::new()?.block_on(async {
        for (xml, condition) in [
            (
                HEADER.replace("jabber:server", "jabber:client"),
                StreamErrorCondition::InvalidNamespace,
            ),
            (
                HEADER.replace("jabber:server", "urn:unknown"),
                StreamErrorCondition::InvalidNamespace,
            ),
            (
                HEADER.replace(" version='1.0'", ""),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='0.9'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='2.0'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1.'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='.0'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1.a'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1.0.1'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='+1.0'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1.0' xml:lang='en_US'"),
                StreamErrorCondition::InvalidXml,
            ),
            (
                HEADER.replace(" to='local.test'", ""),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("local.test", ""),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("local.test", "user@local.test"),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("local.test", "local.test/resource"),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("peer.test", ""),
                StreamErrorCondition::InvalidFrom,
            ),
            (
                HEADER.replace("peer.test", "user@peer.test"),
                StreamErrorCondition::InvalidFrom,
            ),
            (
                HEADER.replace("peer.test", "peer.test/resource"),
                StreamErrorCondition::InvalidFrom,
            ),
        ] {
            let (header, namespace) = header(&xml).await?;
            assert_eq!(
                validate_initial_header(&header, &namespace),
                Err(condition),
                "{xml}"
            );
        }
        Ok(())
    })
}

#[test]
fn response_headers_allow_missing_from_and_validate_normalized_identity() -> TestResult {
    Runtime::new()?.block_on(async {
        for xml in [
            HEADER.to_owned(),
            HEADER.replace("peer.test", "PEER.TEST"),
            HEADER.replace(" from='peer.test'", ""),
        ] {
            let (header, namespace) = header(&xml).await?;
            assert_eq!(
                validate_response_header(&header, &namespace, "PEER.TEST"),
                Ok(())
            );
        }
        for (xml, condition) in [
            (
                HEADER.replace("peer.test", "other.test"),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("peer.test", "user@peer.test"),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("peer.test", "peer.test/resource"),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("peer.test", ""),
                StreamErrorCondition::HostUnknown,
            ),
            (
                HEADER.replace("jabber:server", "jabber:client"),
                StreamErrorCondition::InvalidNamespace,
            ),
            (
                HEADER.replace(" version='1.0'", ""),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='2.0'"),
                StreamErrorCondition::UnsupportedVersion,
            ),
            (
                HEADER.replace("version='1.0'", "version='1.0' xml:lang='?'"),
                StreamErrorCondition::InvalidXml,
            ),
        ] {
            let (header, namespace) = header(&xml).await?;
            assert_eq!(
                validate_response_header(&header, &namespace, "peer.test"),
                Err(condition)
            );
        }
        Ok(())
    })
}

#[test]
fn header_builders_escape_attributes_and_generate_fresh_lowercase_hex_ids() -> TestResult {
    Runtime::new()?.block_on(async {
        assert_eq!(initial_header_xml("local.test", "peer.test"), "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' from='local.test' to='peer.test' version='1.0' xml:lang='en'>");
        let value = "a&<'\"\n\r\t>";
        let escaped = "a&amp;&lt;&apos;&quot;&#xA;&#xD;&#x9;>";
        assert_eq!(
            initial_header_xml(value, value),
            format!("{HEADER_PREFIX}{escaped}' to='{escaped}' version='1.0' xml:lang='en'>")
        );
        let mut ids = Vec::new();
        for to in [Some(value), None, Some("peer.test")] {
            let xml = success(response_header_xml(value, to))?;
            let (parsed, namespace) = header(&xml).await?;
            assert_eq!(namespace, SERVER_NAMESPACE);
            let view = parsed.value().resolve(parsed.arena())?;
            let id = view.attribute("id", "")?.ok_or("missing id")?;
            assert_eq!(id.len(), 32);
            assert!(
                id.bytes()
                    .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
            );
            assert!(!ids.iter().any(|previous| previous == id));
            ids.push(id.to_owned());
            assert_eq!(view.attribute("from", "")?, Some(value));
            assert_eq!(view.attribute("to", "")?, to);
            let to_xml = to
                .map(|to| {
                    let mut escaped = String::new();
                    escape_attribute(&mut escaped, to);
                    format!(" to='{escaped}'")
                })
                .unwrap_or_default();
            assert_eq!(
                xml,
                format!("{HEADER_PREFIX}{escaped}' id='{id}'{to_xml} version='1.0' xml:lang='en'>")
            );
        }
        Ok(())
    })
}

#[test]
fn constants_and_negotiation_builders_emit_exact_xml() {
    assert_eq!(
        STARTTLS_REQUIRED_FEATURES,
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
    );
    assert_eq!(
        EXTERNAL_FEATURES,
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>"
    );
    assert_eq!(EMPTY_FEATURES, "<stream:features/>");
    assert_eq!(
        STARTTLS,
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    assert_eq!(
        PROCEED,
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    assert_eq!(
        TLS_FAILURE,
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    assert_eq!(
        SASL_SUCCESS,
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
    );
    assert_eq!(
        EMPTY_CHALLENGE,
        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
    );
    assert_eq!(
        auth_external_xml("peer.test"),
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>cGVlci50ZXN0</auth>"
    );
    assert_eq!(
        auth_external_xml(""),
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>"
    );
    for (failure, name) in [
        (SaslFailure::Aborted, "aborted"),
        (SaslFailure::InvalidAuthzid, "invalid-authzid"),
        (SaslFailure::InvalidMechanism, "invalid-mechanism"),
        (SaslFailure::MalformedRequest, "malformed-request"),
        (SaslFailure::NotAuthorized, "not-authorized"),
    ] {
        assert_eq!(
            sasl_failure_xml(failure),
            format!("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><{name}/></failure>")
        );
    }
    assert_eq!(
        stream_error_xml(StreamErrorCondition::HostUnknown),
        "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>"
    );
}

#[test]
fn feature_parsing_selects_namespaces_and_exact_mechanism_text() -> TestResult {
    Runtime::new()?.block_on(async {
        for (body, expected) in [
            ("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>", Features { starttls: true, external: false }),
            ("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms>", Features { starttls: false, external: true }),
            ("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism><mechanism>EXTERNAL</mechanism></mechanisms>", Features { starttls: false, external: true }),
            ("<dialback xmlns='urn:xmpp:features:dialback'/>", Features::default()),
            ("<starttls xmlns='urn:wrong'/><mechanisms xmlns='urn:wrong'><mechanism>EXTERNAL</mechanism></mechanisms>", Features::default()),
            ("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism> EXTERNAL</mechanism><mechanism>external</mechanism><mechanism xmlns='urn:wrong'>EXTERNAL</mechanism></mechanisms>", Features::default()),
            ("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms>", Features { starttls: true, external: true }),
        ] {
            let parsed = element(&format!("<stream:features xmlns:stream='http://etherx.jabber.org/streams'>{body}</stream:features>")).await?;
            assert_eq!(parse_features(&parsed), expected);
        }
        Ok(())
    })
}

#[test]
fn external_auth_distinguishes_absent_empty_encoded_and_malformed_responses() -> TestResult {
    Runtime::new()?.block_on(async {
        for (body, mechanism, expected) in [
            ("", "EXTERNAL", Ok(Auth::NoInitialResponse)),
            ("=", "EXTERNAL", Ok(Auth::Response(Vec::new()))),
            (
                "cGVlci50ZXN0",
                "EXTERNAL",
                Ok(Auth::Response(b"peer.test".to_vec())),
            ),
            (
                "w6k=",
                "EXTERNAL",
                Ok(Auth::Response("é".as_bytes().to_vec())),
            ),
            ("?", "EXTERNAL", Err(SaslFailure::MalformedRequest)),
            ("/w==", "EXTERNAL", Err(SaslFailure::MalformedRequest)),
            (
                "cGVlci50ZXN0",
                "external",
                Err(SaslFailure::InvalidMechanism),
            ),
            ("=", "SCRAM-SHA-256", Err(SaslFailure::InvalidMechanism)),
        ] {
            let parsed = element(&format!(
                "<auth xmlns='{SASL_NAMESPACE}' mechanism='{mechanism}'>{body}</auth>"
            ))
            .await?;
            assert_eq!(parse_auth(&parsed), expected);
        }
        assert_eq!(
            parse_auth(&element(&format!("<auth xmlns='{SASL_NAMESPACE}'/>")).await?),
            Err(SaslFailure::InvalidMechanism)
        );
        assert_eq!(
            parse_auth(
                &element(&format!(
                    "<auth xmlns='{SASL_NAMESPACE}' mechanism='EXTERNAL'/>"
                ))
                .await?
            ),
            Ok(Auth::NoInitialResponse)
        );
        Ok(())
    })
}

#[test]
fn reader_leaves_all_bytes_after_starttls_and_proceed_in_memory_pipe() -> TestResult {
    Runtime::new()?.block_on(async {
        for negotiation in [STARTTLS, PROCEED] {
            let (input, mut output) = tokio::io::duplex(4_096);
            let tail = b"\x16\x03\x03\0\x06\xff\0TLS!";
            output
                .write_all(format!("{HEADER}{negotiation}").as_bytes())
                .await?;
            output.write_all(tail).await?;
            let mut reader = S2sReader::new(
                BufReader::with_capacity(1, input),
                &limits(),
                GlobalChunkAllocator,
            );
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::StreamStart { .. })
            ));
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::Element(_))
            ));
            let mut raw = success(reader.take_input().await)?.into_inner();
            let mut remaining = [0; 11];
            raw.read_exact(&mut remaining).await?;
            assert_eq!(&remaining, tail);
        }
        Ok(())
    })
}

#[test]
fn plain_tcp_reader_preserves_tls_record_bytes_in_raw_transport() -> TestResult {
    Runtime::new()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (input, _) = listener.accept().await?;
        let tail = b"\x16\x03\x03\0\x04TLS!";
        let mut xml = format!("{HEADER}{STARTTLS}").into_bytes();
        xml.extend_from_slice(tail);
        let compio::buf::BufResult(result, _) =
            compio::io::AsyncWriteExt::write_all(&mut &client, xml).await;
        result?;
        let mut reader = S2sReader::plain(input.clone(), &limits(), GlobalChunkAllocator);
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::Element(_))
        ));
        drop(success(reader.take_input().await)?);
        let compio::buf::BufResult(result, remaining) =
            compio::io::AsyncReadExt::read_exact(&mut &input, vec![0; tail.len()]).await;
        result?;
        assert_eq!(remaining.as_slice(), tail);
        Ok(())
    })
}

#[test]
fn reader_surfaces_peer_conditions_and_undefined_errors() -> TestResult {
    Runtime::new()?.block_on(async {
        for (body, condition) in [
            ("<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>", StreamErrorCondition::HostUnknown),
            ("", StreamErrorCondition::UndefinedCondition),
            ("<unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>", StreamErrorCondition::UndefinedCondition),
            ("<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>private</text>", StreamErrorCondition::UndefinedCondition),
            ("<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>", StreamErrorCondition::UndefinedCondition),
        ] {
            let mut reader = reader(&format!("{HEADER}<stream:error>{body}</stream:error>"), &limits());
            assert!(matches!(success(reader.next_event().await)?, Some(StreamEvent::StreamStart { .. })));
            assert!(matches!(reader.next_event().await, Err(S2sError::PeerError(actual)) if actual == condition));
        }
        Ok(())
    })
}

#[test]
fn stanza_budget_charges_valid_and_rejected_stanzas_and_survives_cancellation() -> TestResult {
    Runtime::new()?.block_on(async {
        for stanza in [
            "<message from='peer.test' to='local.test'/>",
            "<iq type='unknown'/>",
        ] {
            let mut limits = limits();
            limits.stanzas = EventRate {
                per_second: NonZeroUsize::MIN,
                burst: NonZeroUsize::MIN,
            };
            let mut reader = reader(
                &format!(
                    "{HEADER}<message from='peer.test' to='local.test'/>{stanza}</stream:stream>"
                ),
                &limits,
            );
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::StreamStart { .. })
            ));
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::Stanza(_))
            ));
            {
                let mut next = pin!(reader.next_event());
                assert!(poll!(next.as_mut()).is_pending());
            }
            let event = success(timeout(Duration::from_secs(5), reader.next_event()).await?)?;
            assert!(matches!(
                (stanza, event),
                (
                    "<message from='peer.test' to='local.test'/>",
                    Some(StreamEvent::Stanza(_))
                ) | ("<iq type='unknown'/>", Some(StreamEvent::RejectedStanza(_)))
            ));
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::StreamEnd)
            ));
            assert!(success(reader.next_event().await)?.is_none());
        }
        Ok(())
    })
}

#[test]
fn negotiation_elements_and_whitespace_do_not_charge_stanza_budget() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut limits = limits();
        limits.stanzas.burst = NonZeroUsize::MIN;
        let mut reader = reader(
            &format!("{HEADER} \r\n{STARTTLS}{PROCEED}{SASL_SUCCESS}<message from='peer.test' to='local.test'/></stream:stream>"),
            &limits,
        );
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        for _ in 0..3 {
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::Element(_))
            ));
        }
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::Stanza(_))
        ));
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamEnd)
        ));
        Ok(())
    })
}

#[test]
fn restart_retains_stanza_allowance_and_unread_bytes() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut limits = limits();
        limits.stanzas = EventRate {
            per_second: NonZeroUsize::MIN,
            burst: NonZeroUsize::MIN,
        };
        let mut reader = reader(&format!("{HEADER}<message from='peer.test' to='local.test'/>{HEADER}<message from='peer.test' to='local.test'/>"), &limits);
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::Stanza(_))
        ));
        success(reader.restart())?;
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        {
            let mut next = pin!(reader.next_event());
            assert!(poll!(next.as_mut()).is_pending());
        }
        assert!(matches!(
            success(timeout(Duration::from_secs(5), reader.next_event()).await?)?,
            Some(StreamEvent::Stanza(_))
        ));
        Ok(())
    })
}

#[test]
fn byte_budget_delays_xml_before_event_delivery() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut limits = limits();
        limits.xml = ByteRate {
            bytes_per_second: NonZeroUsize::new(100).ok_or("rate")?,
            burst_bytes: NonZeroUsize::new(HEADER.len()).ok_or("burst")?,
        };
        let mut reader = reader(
            &format!("{HEADER}<message from='peer.test' to='local.test'/>"),
            &limits,
        );
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        {
            let mut next = pin!(reader.next_event());
            assert!(poll!(next.as_mut()).is_pending());
        }
        assert!(matches!(
            success(timeout(Duration::from_secs(5), reader.next_event()).await?)?,
            Some(StreamEvent::Stanza(_))
        ));
        Ok(())
    })
}

#[test]
fn take_input_abandons_pending_parse_and_token_wait_without_losing_trailing_bytes() -> TestResult {
    Runtime::new()?.block_on(async {
        let mut limits = limits();
        limits.stanzas = EventRate {
            per_second: NonZeroUsize::MIN,
            burst: NonZeroUsize::MIN,
        };
        let mut reader = reader(&format!("{HEADER}<message from='peer.test' to='local.test'/><message from='peer.test' to='local.test'/>trailing"), &limits);
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::Stanza(_))
        ));
        {
            let mut next = pin!(reader.next_event());
            assert!(poll!(next.as_mut()).is_pending());
        }
        let mut input = success(reader.take_input().await)?;
        let mut remaining = Vec::new();
        input.read_to_end(&mut remaining).await?;
        assert_eq!(remaining, b"trailing");
        let (input, mut output) = tokio::io::duplex(4_096);
        output.write_all(HEADER.as_bytes()).await?;
        let mut reader = S2sReader::new(BufReader::new(input), &limits, GlobalChunkAllocator);
        assert!(matches!(
            success(reader.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        {
            let mut next = pin!(reader.next_event());
            assert!(poll!(next.as_mut()).is_pending());
        }
        let mut input = success(reader.take_input().await)?;
        output.write_all(b"remaining").await?;
        let mut remaining = [0; 9];
        input.read_exact(&mut remaining).await?;
        assert_eq!(&remaining, b"remaining");
        Ok(())
    })
}

#[test]
fn reader_maps_oversize_malformed_and_truncated_input() -> TestResult {
    Runtime::new()?.block_on(async {
        for (xml, size, expected) in [
            (
                format!("{HEADER}<message><body>too large</body></message>"),
                16,
                S2sError::Stream(StreamErrorCondition::PolicyViolation),
            ),
            (
                format!("{HEADER}<message></presence>"),
                1024,
                S2sError::Stream(StreamErrorCondition::NotWellFormed),
            ),
            (
                format!("{HEADER}<message>"),
                1024,
                S2sError::Stream(StreamErrorCondition::BadFormat),
            ),
        ] {
            let mut limits = limits();
            limits.max_stanza_bytes = NonZeroUsize::new(size).ok_or("size")?;
            let mut reader = reader(&xml, &limits);
            assert!(matches!(
                success(reader.next_event().await)?,
                Some(StreamEvent::StreamStart { .. })
            ));
            assert!(matches!(reader.next_event().await, Err(actual) if actual == expected));
        }
        Ok(())
    })
}

#[test]
fn parse_and_io_errors_match_c2s_conditions_and_preserve_timeout() {
    for (error, expected) in [
        (
            ParseError::NotWellFormed,
            S2sError::Stream(StreamErrorCondition::NotWellFormed),
        ),
        (
            ParseError::UnboundNamespacePrefix,
            S2sError::Stream(StreamErrorCondition::NotWellFormed),
        ),
        (
            ParseError::RestrictedXml,
            S2sError::Stream(StreamErrorCondition::RestrictedXml),
        ),
        (
            ParseError::UnsupportedEncoding,
            S2sError::Stream(StreamErrorCondition::UnsupportedEncoding),
        ),
        (
            ParseError::InvalidNamespace,
            S2sError::Stream(StreamErrorCondition::InvalidNamespace),
        ),
        (
            ParseError::BadNamespacePrefix,
            S2sError::Stream(StreamErrorCondition::BadNamespacePrefix),
        ),
        (
            ParseError::InvalidXml,
            S2sError::Stream(StreamErrorCondition::InvalidXml),
        ),
        (
            ParseError::UnexpectedEvent,
            S2sError::Stream(StreamErrorCondition::BadFormat),
        ),
        (
            ParseError::UnexpectedEof,
            S2sError::Stream(StreamErrorCondition::BadFormat),
        ),
        (
            ParseError::ParserFailed,
            S2sError::Stream(StreamErrorCondition::BadFormat),
        ),
        (
            ParseError::TooManyAttributes,
            S2sError::Stream(StreamErrorCondition::PolicyViolation),
        ),
        (
            ParseError::Build(BuildError::InvalidText),
            S2sError::Stream(StreamErrorCondition::BadFormat),
        ),
        (
            ParseError::Build(BuildError::TreeLimitExceeded),
            S2sError::Stream(StreamErrorCondition::PolicyViolation),
        ),
        (
            ParseError::Build(BuildError::Allocation(ArenaError::ArenaLimitExceeded)),
            S2sError::Stream(StreamErrorCondition::PolicyViolation),
        ),
        (
            ParseError::Build(BuildError::Allocation(ArenaError::Allocation(
                AllocationError::Exhausted,
            ))),
            S2sError::Internal,
        ),
        (
            ParseError::from(quick_xml::Error::from(io::Error::from(
                io::ErrorKind::TimedOut,
            ))),
            S2sError::Timeout,
        ),
        (
            ParseError::from(quick_xml::Error::from(io::Error::from(
                io::ErrorKind::BrokenPipe,
            ))),
            S2sError::Io,
        ),
    ] {
        assert_eq!(S2sError::from(error), expected);
    }
    assert_eq!(
        S2sError::from(io::Error::from(io::ErrorKind::TimedOut)),
        S2sError::Timeout
    );
    assert_eq!(
        S2sError::from(io::Error::from(io::ErrorKind::ConnectionReset)),
        S2sError::Io
    );
}

#[derive(Clone, Default)]
struct Output(Rc<std::cell::RefCell<Vec<u8>>>);

impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn writer_buffers_stanzas_and_flushes_send_keepalive_and_one_footer() -> TestResult {
    Runtime::new()?.block_on(async {
        let output = Output::default();
        let mut writer = S2sWriter::new(output.clone());
        success(writer.send(EMPTY_FEATURES).await)?;
        assert_eq!(output.0.borrow().as_slice(), EMPTY_FEATURES.as_bytes());
        let mut input = reader(
            &format!("{HEADER}<message from='peer.test' to='local.test'><body>hello</body></message>"),
            &limits(),
        );
        assert!(matches!(
            success(input.next_event().await)?,
            Some(StreamEvent::StreamStart { .. })
        ));
        let Some(StreamEvent::Stanza(parsed)) = success(input.next_event().await)? else {
            return Err("stanza".into());
        };
        let stanza = parsed.value().resolve(parsed.arena())?;
        success(writer.write_stanza(&stanza).await)?;
        assert_eq!(output.0.borrow().as_slice(), EMPTY_FEATURES.as_bytes());
        success(writer.flush().await)?;
        assert_eq!(
            output.0.borrow().as_slice(),
            br#"<stream:features/><message xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:server" from="peer.test" to="local.test"><body>hello</body></message>"#
        );
        let written = output.0.borrow().len();
        success(writer.whitespace_keepalive().await)?;
        assert_eq!(&output.0.borrow()[written..], b" ");
        for condition in [None, Some(StreamErrorCondition::HostUnknown)] {
            let output = Output::default();
            let mut writer = S2sWriter::new(output.clone());
            success(writer.close(condition).await)?;
            let expected = condition
                .map(stream_error_xml)
                .unwrap_or_else(|| STREAM_FOOTER.to_owned());
            assert_eq!(output.0.borrow().as_slice(), expected.as_bytes());
        }
        Ok(())
    })
}
