// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use lonewolf_util::arena::{ArenaConfig, GlobalChunkAllocator};
use lonewolf_xmpp::parser::{ParserConfig, parse_element};
use prometheus_client::registry::Registry;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

async fn event(xml: &str) -> TestResult<StreamEvent<GlobalChunkAllocator>> {
    Ok(StreamEvent::Element(
        parse_element(
            xml.as_bytes(),
            ParserConfig {
                max_stanza_bytes: std::num::NonZeroUsize::new(16_384)
                    .unwrap_or(std::num::NonZeroUsize::MIN),
                arena: ArenaConfig::default(),
            },
            GlobalChunkAllocator,
        )
        .await?,
    ))
}

fn render(metrics: &Arc<S2sMetrics>) -> TestResult<String> {
    let mut registry = Registry::default();
    metrics.register(registry.sub_registry_with_prefix("lonewolf"));
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, &registry)?;
    Ok(output)
}

fn sample(output: &str, outcome: &str, count: usize) {
    let prefix = format!(
        "lonewolf_s2s_authentications_total{{direction=\"outbound\",outcome=\"{outcome}\"}} "
    );
    let value = output.lines().find_map(|line| line.strip_prefix(&prefix));
    if count == 0 {
        assert!(value.is_none(), "unexpected {prefix}: {output}");
    } else {
        assert_eq!(value, Some(count.to_string().as_str()), "{output}");
    }
}

#[test]
fn establishment_errors_have_bounded_reasons_conditions_and_outcomes() {
    use EstablishError::*;
    use NegotiationFailure::*;
    for (error, reason, auth) in [
        (NoService, "no_service", None),
        (NotFound, "not_found", None),
        (DnsUnavailable, "dns_unavailable", None),
        (Unreachable, "unreachable", Some("unreachable")),
        (
            Tls("certificate_untrusted"),
            "certificate_untrusted",
            Some("certificate_untrusted"),
        ),
        (
            Tls("certificate_name"),
            "certificate_name",
            Some("certificate_name"),
        ),
        (
            Tls("certificate_purpose"),
            "certificate_purpose",
            Some("certificate_purpose"),
        ),
        (
            Tls("certificate_expired"),
            "certificate_expired",
            Some("certificate_expired"),
        ),
        (Tls("handshake"), "handshake", Some("tls_failure")),
        (Negotiation(NoTls), "no_tls", Some("no_tls")),
        (Negotiation(TlsRefused), "tls_refused", Some("tls_refused")),
        (
            Negotiation(ExternalNotOffered),
            "external_not_offered",
            Some("external_not_offered"),
        ),
        (
            Negotiation(SaslFailure("not-authorized")),
            "sasl_failure",
            Some("sasl_failure"),
        ),
        (Negotiation(Protocol), "protocol", Some("protocol")),
        (Timeout, "timeout", Some("timeout")),
    ] {
        assert_eq!(error.reason(), reason);
        assert_eq!(error.authentication().map(AuthOutcome::as_str), auth);
        assert_eq!(
            error.condition(),
            if auth.is_none() {
                StanzaErrorCondition::RemoteServerNotFound
            } else {
                StanzaErrorCondition::RemoteServerTimeout
            }
        );
        assert!(
            reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        assert_eq!(
            error.stage(),
            match error {
                NoService | NotFound | DnsUnavailable => "dns",
                Unreachable => "connect",
                Tls(_) => "tls",
                _ => "negotiation",
            }
        );
    }
}

#[test]
fn dns_mapping_preserves_endpoints_and_distinguishes_invalid_domains() {
    for (via, name) in [
        (ResolvedVia::Srv, "srv"),
        (ResolvedVia::Fallback, "fallback"),
        (ResolvedVia::Static, "static"),
        (ResolvedVia::Literal, "literal"),
    ] {
        let endpoints = vec![std::net::SocketAddr::from(([127, 0, 0, 1], 5269))];
        let (outcome, result) = dns_result(Ok(Resolved {
            endpoints: endpoints.clone(),
            via,
        }));
        assert_eq!(outcome.as_str(), name);
        assert_eq!(result.map(|resolved| resolved.endpoints), Ok(endpoints));
    }
    for (error, name, expected) in [
        (
            ResolveError::NoService,
            "no_service",
            EstablishError::NoService,
        ),
        (
            ResolveError::NotFound,
            "not_found",
            EstablishError::NotFound,
        ),
        (
            ResolveError::Unavailable,
            "unavailable",
            EstablishError::DnsUnavailable,
        ),
        (
            ResolveError::InvalidDomain,
            "invalid_domain",
            EstablishError::NotFound,
        ),
    ] {
        let (outcome, result) = dns_result(Err(error));
        assert_eq!(outcome.as_str(), name);
        assert_eq!(result.map(|resolved| resolved.endpoints), Err(expected));
    }
}

#[test]
fn tls_classification_uses_typed_errors_and_io_sources() -> TestResult {
    let time = UnixTime::now();
    for (error, expected) in [
        (CertificateError::UnknownIssuer, "certificate_untrusted"),
        (CertificateError::BadSignature, "certificate_untrusted"),
        (CertificateError::NotValidForName, "certificate_name"),
        (
            CertificateError::NotValidForNameContext {
                expected: ServerName::try_from("remote.test")?,
                presented: vec!["other.test".to_owned()],
            },
            "certificate_name",
        ),
        (CertificateError::InvalidPurpose, "certificate_purpose"),
        (
            CertificateError::InvalidPurposeContext {
                required: rustls::ExtendedKeyPurpose::ServerAuth,
                presented: vec![rustls::ExtendedKeyPurpose::ClientAuth],
            },
            "certificate_purpose",
        ),
        (CertificateError::Expired, "certificate_expired"),
        (
            CertificateError::ExpiredContext {
                time,
                not_after: time,
            },
            "certificate_expired",
        ),
        (CertificateError::NotValidYet, "certificate_expired"),
        (
            CertificateError::NotValidYetContext {
                time,
                not_before: time,
            },
            "certificate_expired",
        ),
        (CertificateError::BadEncoding, "handshake"),
        (CertificateError::Revoked, "handshake"),
    ] {
        let error = rustls::Error::InvalidCertificate(error);
        assert_eq!(tls_reason(&error), expected);
        assert_eq!(
            tls_failure(io::Error::new(io::ErrorKind::InvalidData, error)).error,
            EstablishError::Tls(expected)
        );
    }
    assert_eq!(
        tls_reason(&rustls::Error::NoCertificatesPresented),
        "handshake"
    );
    assert_eq!(
        tls_failure(io::Error::from(io::ErrorKind::ConnectionReset)).error,
        EstablishError::Tls("handshake")
    );
    Ok(())
}

#[test]
fn peer_validity_must_extend_past_negotiation_completion() {
    let completion = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let expired = Failure::from(EstablishError::Tls("certificate_expired"));
    for valid_until in [completion - Duration::from_nanos(1), completion] {
        assert_eq!(unexpired_validity(valid_until, completion), Err(expired));
    }
    let valid_until = completion + Duration::from_nanos(1);
    assert_eq!(unexpired_validity(valid_until, completion), Ok(valid_until));
}

#[test]
fn configured_anchor_expiry_rejects_an_otherwise_valid_peer_at_completion() -> TestResult {
    use base64::Engine as _;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    };

    let epoch = 2_000_000_000;
    let now = time::OffsetDateTime::from_unix_timestamp(epoch)?;
    let mut root = CertificateParams::new(Vec::<String>::new())?;
    root.serial_number = Some(1u64.into());
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root.not_before = now - time::Duration::days(1);
    root.not_after = now + time::Duration::seconds(10);
    let mut leaf = CertificateParams::new(vec!["remote.test".into()])?;
    leaf.serial_number = Some(2u64.into());
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.not_before = now - time::Duration::days(1);
    leaf.not_after = now + time::Duration::days(1);
    let [leaf, root] = crate::hosts::test_support::signed_chain(root, leaf)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("anchors.pem");
    std::fs::write(
        &path,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(root.as_ref()),
        ),
    )?;
    let trust = PeerTrust::load(
        &crate::config::S2sTlsConfig {
            trust_anchors_path: Some(path),
        },
        Arc::new(rustls_graviola::default_provider()),
    )?;
    let expiry = SystemTime::UNIX_EPOCH + Duration::from_secs(epoch as u64 + 10);
    let initial = trust.verify_chain(
        std::slice::from_ref(&leaf),
        UnixTime::since_unix_epoch(Duration::from_secs(epoch as u64)),
    )?;
    assert_eq!(initial.valid_until, expiry);
    for (seconds, expired) in [(9, false), (10, true), (11, true)] {
        let elapsed = Duration::from_secs(epoch as u64 + seconds);
        let validity = trust.verify_chain(
            std::slice::from_ref(&leaf),
            UnixTime::since_unix_epoch(elapsed),
        )?;
        assert_eq!(validity.valid_until, expiry);
        let result = unexpired_validity(validity.valid_until, SystemTime::UNIX_EPOCH + elapsed);
        assert_eq!(
            result,
            if expired {
                Err(EstablishError::Tls("certificate_expired").into())
            } else {
                Ok(expiry)
            }
        );
    }
    Ok(())
}

#[test]
fn sasl_failure_names_remain_static_and_bounded() {
    for name in [
        "aborted",
        "account-disabled",
        "credentials-expired",
        "encryption-required",
        "incorrect-encoding",
        "invalid-authzid",
        "invalid-mechanism",
        "malformed-request",
        "mechanism-too-weak",
        "not-authorized",
        "temporary-auth-failure",
    ] {
        assert_eq!(sasl_condition(name), name);
    }
    for name in [
        "",
        "unknown",
        "NOT-AUTHORIZED",
        "not-authorizéd",
        "abcdefghijklmnopqrstuvwxyzabcdefg",
    ] {
        assert_eq!(sasl_condition(name), "other");
    }
}

#[test]
fn required_features_use_exact_element_names_and_namespaces() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        let xml = stream::STARTTLS_REQUIRED_FEATURES.replace(
            "<stream:features>",
            "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>",
        );
        let offered = features(event(&xml).await?).map_err(|error| format!("{error:?}"))?;
        assert_eq!(require_starttls(&offered), Ok(()));
        assert_eq!(
            require_external(&offered).map_err(|failure| failure.error),
            Err(EstablishError::Negotiation(NegotiationFailure::ExternalNotOffered)),
        );
        let xml = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
        let offered = features(event(xml).await?).map_err(|error| format!("{error:?}"))?;
        assert_eq!(require_external(&offered), Ok(()));
        let no_tls = require_starttls(&offered)
            .err()
            .ok_or("expected missing STARTTLS")?;
        assert_eq!(
            no_tls.error,
            EstablishError::Negotiation(NegotiationFailure::NoTls),
        );
        assert_eq!(no_tls.condition, Some(StreamErrorCondition::PolicyViolation));
        for xml in [
            "<features/>",
            "<features xmlns='urn:wrong'><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></features>",
            "<stream:other xmlns:stream='http://etherx.jabber.org/streams'/>",
        ] {
            assert_eq!(features(event(xml).await?), Err(protocol()));
        }
        let xml = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><starttls xmlns='urn:wrong'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>external</mechanism></mechanisms></stream:features>";
        let wrong = features(event(xml).await?).map_err(|error| format!("{error:?}"))?;
        assert!(!wrong.starttls && !wrong.external);
        assert_eq!(
            features(StreamEvent::<GlobalChunkAllocator>::StreamEnd),
            Err(protocol()),
        );
        Ok(())
    })
}

#[test]
fn tls_and_sasl_replies_reject_malformed_elements_and_repeated_challenges() -> TestResult {
    compio::runtime::Runtime::new()?.block_on(async {
        assert_eq!(proceed(event(stream::PROCEED).await?), Ok(()));
        assert_eq!(
            proceed(event(stream::TLS_FAILURE).await?).map_err(|failure| failure.error),
            Err(EstablishError::Negotiation(NegotiationFailure::TlsRefused)),
        );
        for xml in [
            "<proceed/>",
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'>x</proceed>",
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls' extra='x'/>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        ] {
            assert_eq!(proceed(event(xml).await?), Err(protocol()));
        }
        assert_eq!(
            sasl_reply(event(stream::SASL_SUCCESS).await?, false),
            Ok(SaslReply::Success),
        );
        assert_eq!(
            sasl_reply(event(stream::SASL_SUCCESS).await?, true),
            Ok(SaslReply::Success),
        );
        assert_eq!(
            sasl_reply(event(stream::EMPTY_CHALLENGE).await?, false),
            Ok(SaslReply::Challenge),
        );
        assert_eq!(
            sasl_reply(event(stream::EMPTY_CHALLENGE).await?, true),
            Err(protocol()),
        );
        for xml in [
            "<success/>",
            "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>=</challenge>",
            "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><child/></challenge>",
            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>x</success>",
        ] {
            assert_eq!(sasl_reply(event(xml).await?, false), Err(protocol()));
        }
        for (xml, name) in [
            ("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/><aborted/></failure>", "not-authorized"),
            ("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><unknown/></failure>", "other"),
            ("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted xmlns='urn:wrong'/></failure>", "other"),
            ("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>", "other"),
        ] {
            assert_eq!(
                sasl_reply(event(xml).await?, false).map_err(|failure| failure.error),
                Err(EstablishError::Negotiation(NegotiationFailure::SaslFailure(name))),
            );
        }
        let StreamEvent::Element(response) = event(EMPTY_RESPONSE).await? else {
            return Err("expected response".into());
        };
        let response = response.value().resolve(response.arena())?;
        assert_eq!(response.name(), "response");
        assert_eq!(response.namespace(), SASL_NAMESPACE);
        assert_eq!(response.text()?, Some("="));
        Ok(())
    })
}

#[test]
fn last_connected_failure_survives_later_connection_failures() {
    let name = Failure::from(EstablishError::Tls("certificate_name"));
    let timeout = Failure::from(EstablishError::Timeout);
    for (failures, expected) in [
        (vec![], EstablishError::Unreachable.into()),
        (vec![None, None], EstablishError::Unreachable.into()),
        (vec![None, Some(name), None], name),
        (vec![Some(name), Some(timeout), None], timeout),
        (vec![Some(timeout), None, Some(protocol())], protocol()),
    ] {
        let mut attempts = Attempts::default();
        for failure in failures {
            attempts.failed(failure);
        }
        assert_eq!(attempts.failure(), expected);
    }
}

#[test]
fn accounting_excludes_cleanup_and_emits_only_the_completed_outcome() -> TestResult {
    let now = Instant::now();
    let metrics = S2sMetrics::new(0);
    let mut accounting = Accounting::new(Arc::clone(&metrics), now);
    accounting.pause(now + Duration::from_secs(2));
    assert_eq!(
        accounting.sample(now + Duration::from_secs(8)).1,
        Duration::from_secs(2)
    );
    accounting.resume(now + Duration::from_secs(8));
    accounting.select(AuthOutcome::Success, now + Duration::from_secs(11));
    assert_eq!(
        accounting.sample(now + Duration::from_secs(99)).1,
        Duration::from_secs(5)
    );
    accounting.record(now + Duration::from_secs(99));
    accounting.record(now + Duration::from_secs(100));
    drop(accounting);
    let output = render(&metrics)?;
    sample(&output, "success", 1);
    sample(&output, "protocol", 0);
    assert!(
        output.lines().any(|line| line
            == "lonewolf_s2s_negotiation_duration_seconds_sum{direction=\"outbound\"} 5.0"),
        "{output}"
    );
    Ok(())
}

#[test]
fn cancellation_preserves_selected_failures_and_counts_unfinished_work_as_protocol() -> TestResult {
    let now = Instant::now();
    let metrics = S2sMetrics::new(0);
    let mut cancelled = Accounting::new(Arc::clone(&metrics), now);
    assert_eq!(
        cancelled.sample(now + Duration::from_secs(3)).0.as_str(),
        "protocol"
    );
    assert_eq!(
        cancelled.sample(now + Duration::from_secs(3)).1,
        Duration::from_secs(3)
    );
    cancelled.pause(now + Duration::from_secs(3));
    drop(cancelled);
    let mut final_cleanup = Accounting::new(Arc::clone(&metrics), now);
    final_cleanup.select(AuthOutcome::Timeout, now + Duration::from_secs(4));
    final_cleanup.select(AuthOutcome::Protocol, now + Duration::from_secs(8));
    let (outcome, elapsed) = final_cleanup.sample(now + Duration::from_secs(99));
    assert_eq!(outcome.as_str(), "timeout");
    assert_eq!(elapsed, Duration::from_secs(4));
    drop(final_cleanup);
    let output = render(&metrics)?;
    sample(&output, "protocol", 1);
    sample(&output, "timeout", 1);
    sample(&output, "success", 0);
    Ok(())
}

#[test]
fn setup_failures_and_deadlines_keep_negotiation_and_cleanup_separate() {
    assert_eq!(require_setup(None::<()>), Err(protocol().error));
    assert_eq!(require_setup(Some(7)), Ok(7));
    let now = Instant::now();
    assert_eq!(
        deadline(now, S2sLimits::default().connect_timeout_secs),
        now + Duration::from_secs(10)
    );
    let negotiation = deadline(now, S2sLimits::default().negotiation_timeout_secs);
    assert_eq!(negotiation, now + Duration::from_secs(30));
    let cleanup = negotiation + CLOSE_BUDGET;
    assert_eq!(cleanup, now + Duration::from_secs(36));
    assert_eq!(
        footer_deadline(cleanup, negotiation),
        now + Duration::from_secs(35)
    );
    assert_eq!(
        footer_deadline(cleanup, negotiation + Duration::from_secs(3)),
        cleanup
    );
    assert_eq!(
        Failure::from(S2sError::Stream(StreamErrorCondition::HostUnknown)).condition,
        Some(StreamErrorCondition::HostUnknown)
    );
    assert_eq!(
        Failure::from(S2sError::Timeout).error,
        EstablishError::Timeout
    );
}

#[test]
fn domain_context_is_bounded_and_hides_address_literals() {
    assert_eq!(safe_domain("remote.test"), "remote.test");
    assert_eq!(safe_domain("remote\n.test"), "remote\u{fffd}.test");
    assert_eq!(safe_domain(&"x".repeat(300)).len(), 253);
    for literal in ["127.0.0.1", "::1", "[::1]"] {
        assert_eq!(safe_domain(literal), "<literal>");
    }
}
