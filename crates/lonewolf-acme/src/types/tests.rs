// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn pending_replacement_intent_is_required_explicit_and_canonical() -> TestResult {
    for replaces in [None, Some("AQID.AQ".to_owned())] {
        let mut pending = host().order.ok_or("missing order")?;
        pending.replaces = replaces.clone();
        let mut value = serde_json::to_value(&pending)?;
        assert!(value.get("replaces").is_some());
        assert_eq!(value["replaces"], serde_json::to_value(&replaces)?);
        let restored: PendingOrder = decode(&encode(&pending)?)?;
        assert_eq!(restored.replaces, replaces);
        value
            .as_object_mut()
            .ok_or("missing object")?
            .remove("replaces");
        assert!(matches!(
            decode::<PendingOrder>(&serde_json::to_vec(&value)?),
            Err(StateError::CorruptData)
        ));
    }
    for identifier in [
        "", "AQID", ".AQ", "AQID.", "AQID.AQ=", "AQID.gA", "AQID.AAE", "YR.AQ", "AQID.AB",
    ] {
        let mut value = serde_json::to_value(host().order.ok_or("missing order")?)?;
        value["replaces"] = serde_json::Value::String(identifier.into());
        assert!(
            serde_json::from_value::<PendingOrder>(value).is_err(),
            "{identifier}"
        );
    }
    let mut value = serde_json::to_value(host().order.ok_or("missing order")?)?;
    value["replaces"] = serde_json::Value::String("A".repeat(MAX_RECORD + 1));
    assert!(serde_json::from_value::<PendingOrder>(value).is_err());
    Ok(())
}

fn account() -> StoredAccount {
    StoredAccount {
        key_pkcs8: Zeroizing::new(vec![1, 2, 3]),
        credentials_json: Some(Zeroizing::new(br#"{"credential":"secret"}"#.to_vec())),
        retry: RetryState {
            failures: 3,
            not_before_unix: 42,
        },
    }
}

fn host() -> StoredHost {
    StoredHost {
        host: ManagedHost {
            xmpp_domain: "example.com".into(),
            dns_name: "example.com".into(),
        },
        certificate: Some(StoredCertificate {
            replaces: None,
            material: CertificateMaterial {
                chain: vec![vec![1, 2, 3]],
                private_key_pkcs8: Zeroizing::new(vec![4, 5, 6]),
            },
            not_before_unix: 10,
            not_after_unix: 20,
            renew_at_unix: 0,
            ari_check_at_unix: 100,
            fallback_at_unix: 0,
            ari_window: None,
            ari_failures: 0,
        }),
        order: Some(PendingOrder {
            replaces: None,
            url: Some("https://ca.example/order/1".into()),
            key_pkcs8: Zeroizing::new(vec![7, 8, 9]),
            csr_der: vec![10, 11, 12],
            started_unix: 30,
            expires_unix: Some(25),
        }),
        retry: RetryState {
            failures: 2,
            not_before_unix: 100,
        },
    }
}

#[test]
fn secret_records_round_trip_without_buffer_growth() -> TestResult {
    let original = account();
    let encoded = encode(&original)?;
    assert_eq!(encoded.capacity(), MAX_RECORD);
    let restored: StoredAccount = decode(&encoded)?;
    restored.validate()?;
    assert_eq!(restored.key_pkcs8.as_slice(), original.key_pkcs8.as_slice());
    assert_eq!(restored.key_pkcs8.capacity(), MAX_KEY);
    assert_eq!(
        restored.credentials_json.as_deref(),
        original.credentials_json.as_deref()
    );
    assert_eq!(
        restored
            .credentials_json
            .as_ref()
            .map(|value| value.capacity()),
        Some(MAX_CREDENTIALS)
    );
    assert_eq!(restored.retry, original.retry);
    Ok(())
}

#[test]
fn expired_orders_and_independent_schedules_are_valid() -> TestResult {
    let original = host();
    original.validate()?;
    let restored: StoredHost = decode(&encode(&original)?)?;
    restored.validate()?;
    assert_eq!(
        restored
            .certificate
            .as_ref()
            .map(|certificate| certificate.renew_at_unix),
        Some(0)
    );
    assert_eq!(
        restored
            .certificate
            .as_ref()
            .map(|certificate| certificate.ari_check_at_unix),
        Some(100)
    );
    assert_eq!(
        restored.order.as_ref().and_then(|order| order.expires_unix),
        Some(25)
    );
    Ok(())
}

#[test]
fn credentials_require_one_complete_json_value() -> TestResult {
    for value in [b"".as_slice(), b"{", b"{} {}", b"null trailing"] {
        let mut input = account();
        input.credentials_json = Some(Zeroizing::new(value.to_vec()));
        assert_eq!(input.validate(), Err(StateError::InvalidData));
    }
    for value in [b"null".as_slice(), b"{} \n", b"[1,true,\"value\"]"] {
        let mut input = account();
        input.credentials_json = Some(Zeroizing::new(value.to_vec()));
        input.validate()?;
    }
    Ok(())
}

#[test]
fn write_validation_bounds_all_material() {
    let mut input = account();
    input.key_pkcs8 = Zeroizing::new(vec![1; MAX_KEY + 1]);
    assert_eq!(input.validate(), Err(StateError::InvalidData));
    input.key_pkcs8.clear();
    assert_eq!(input.validate(), Err(StateError::InvalidData));
    let mut input = account();
    input.credentials_json = Some(Zeroizing::new(vec![b' '; MAX_CREDENTIALS + 1]));
    assert_eq!(input.validate(), Err(StateError::InvalidData));

    for chain in [
        Vec::new(),
        vec![Vec::new()],
        vec![vec![1]; 17],
        vec![vec![1; MAX_CHAIN + 1]],
    ] {
        let mut input = host();
        if let Some(certificate) = &mut input.certificate {
            certificate.material.chain = chain;
        }
        assert_eq!(input.validate(), Err(StateError::InvalidData));
    }
    let mut input = host();
    if let Some(order) = &mut input.order {
        order.csr_der.clear();
    }
    assert_eq!(input.validate(), Err(StateError::InvalidData));
}

#[test]
fn malformed_partial_secrets_and_oversized_decodes_fail_closed() -> TestResult {
    for bytes in [
        br#"{"key_pkcs8":[1,2,"secret"]}"#.as_slice(),
        br#"{"key_pkcs8":[1,2"#,
        br#"{"key_pkcs8":[1],"credentials_json":[1,"secret"]}"#,
        br#"{"key_pkcs8":[1],"credentials_json":null,"retry":{"failures":0,"not_before_unix":0},"secret":"hidden"}"#,
    ] {
        assert!(matches!(decode::<StoredAccount>(bytes), Err(StateError::CorruptData)));
    }
    let mut input = account();
    input.key_pkcs8 = Zeroizing::new(vec![1; MAX_KEY + 1]);
    assert!(matches!(
        decode::<StoredAccount>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    input = account();
    input.credentials_json = Some(Zeroizing::new(vec![1; MAX_CREDENTIALS + 1]));
    assert!(matches!(
        decode::<StoredAccount>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    assert!(matches!(
        decode::<StoredAccount>(&vec![0; MAX_RECORD + 1]),
        Err(StateError::CorruptData)
    ));
    let input = vec![255_u8; MAX_RECORD];
    assert!(matches!(encode(&input), Err(StateError::InvalidData)));
    let mut input = host();
    if let Some(certificate) = &mut input.certificate {
        certificate.material.chain = vec![vec![1]; 17];
    }
    assert!(matches!(
        decode::<StoredHost>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    Ok(())
}

#[test]
fn timestamps_and_certificate_intervals_are_checked() {
    assert_eq!(timestamp(u64::MAX), Err(StateError::InvalidData));
    assert_eq!(timestamp(i64::MAX as u64 + 1), Err(StateError::InvalidData));
    let mut input = account();
    input.retry.not_before_unix = u64::MAX;
    assert_eq!(input.validate(), Err(StateError::InvalidData));
    let mut input = host();
    if let Some(certificate) = &mut input.certificate {
        certificate.not_after_unix = certificate.not_before_unix;
    }
    assert_eq!(input.validate(), Err(StateError::InvalidData));
    let mut input = host();
    if let Some(order) = &mut input.order {
        order.expires_unix = Some(u64::MAX);
    }
    assert_eq!(input.validate(), Err(StateError::InvalidData));
}

#[test]
fn urls_preserve_exact_spelling_and_reject_invalid_authorities() -> TestResult {
    for url in [
        "https://ca.example/directory",
        "https://CA.example:443/directory?x=%2f",
        "https://[::1]:443/directory",
    ] {
        validate_url(url)?;
    }
    for url in [
        "http://ca.example/",
        "https://user@ca.example/",
        "https://ca.example/#fragment",
        "https://ca.example:0/",
        "https://ca.example:99999/",
        "https://ca.example:/",
        "https://[bad]/",
        "https://ca.example/ bad",
    ] {
        assert_eq!(validate_url(url), Err(StateError::InvalidData));
    }
    assert_eq!(
        validate_url(&format!("https://ca.example/{}", "a".repeat(MAX_URL))),
        Err(StateError::InvalidData)
    );
    Ok(())
}

#[test]
fn hosts_require_normalized_xmpp_and_matching_canonical_dns() -> TestResult {
    for (xmpp, dns) in [
        ("example.com", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ] {
        let mut input = host();
        input.host.xmpp_domain = xmpp.into();
        input.host.dns_name = dns.into();
        input.validate()?;
    }
    for (xmpp, dns) in [
        ("Example.com", "example.com"),
        ("example.com", "other.example"),
        ("user@example.com", "example.com"),
        ("example.com/resource", "example.com"),
        ("localhost", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        ("example.localhost", "example.localhost"),
        ("example.com", "Example.com"),
        ("example.com.", "example.com."),
    ] {
        let mut input = host();
        input.host.xmpp_domain = xmpp.into();
        input.host.dns_name = dns.into();
        assert_eq!(
            input.validate(),
            Err(StateError::InvalidData),
            "{xmpp}, {dns}"
        );
    }
    Ok(())
}

#[test]
fn errors_contain_only_static_context_and_have_no_secret_source() {
    for error in [
        StateError::InvalidData,
        StateError::CorruptData,
        StateError::UnsupportedData,
        StateError::Unavailable,
        StateError::UnsafePath,
        StateError::StateUncertain,
        StateError::Closed,
        StateError::DeadlineElapsed,
        StateError::Other,
    ] {
        assert!(!error.to_string().contains("secret"));
        assert!(error.source().is_none());
    }
}

#[test]
fn maximum_chain_and_secret_sizes_fit_the_encoded_record_bound() -> TestResult {
    let mut input = host();
    if let Some(certificate) = &mut input.certificate {
        certificate.material.chain = vec![vec![255; MAX_CHAIN / 16]; 16];
        certificate.material.private_key_pkcs8 = Zeroizing::new(vec![255; MAX_KEY]);
    }
    input.validate()?;
    let encoded = encode(&input)?;
    assert!(encoded.len() <= MAX_RECORD);
    let restored: StoredHost = decode(&encoded)?;
    restored.validate()?;
    assert_eq!(
        restored.certificate.as_ref().map(|certificate| certificate
            .material
            .chain
            .iter()
            .map(Vec::len)
            .sum::<usize>()),
        Some(MAX_CHAIN)
    );

    let mut input = account();
    input.key_pkcs8 = Zeroizing::new(vec![255; MAX_KEY]);
    let mut credentials = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIALS));
    credentials.push(b'"');
    credentials.resize(MAX_CREDENTIALS - 1, b'x');
    credentials.push(b'"');
    input.credentials_json = Some(credentials);
    input.validate()?;
    let restored: StoredAccount = decode(&encode(&input)?)?;
    restored.validate()?;
    Ok(())
}

#[test]
fn bounded_fields_reject_oversized_decodes() -> TestResult {
    let mut input = host();
    input.host.xmpp_domain = "x".repeat(1024);
    assert!(matches!(
        decode::<StoredHost>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    let mut input = host();
    input.host.dns_name = "x".repeat(254);
    assert!(matches!(
        decode::<StoredHost>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    let mut input = host();
    if let Some(order) = &mut input.order {
        order.url = Some(format!("https://ca.example/{}", "x".repeat(MAX_URL)));
    }
    assert!(matches!(
        decode::<StoredHost>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    let mut input = host();
    if let Some(certificate) = &mut input.certificate {
        certificate.material.chain = vec![vec![255; MAX_CHAIN + 1]];
    }
    assert!(matches!(
        decode::<StoredHost>(&encode(&input)?),
        Err(StateError::CorruptData)
    ));
    Ok(())
}

#[test]
fn ari_schedule_rejects_invalid_window_and_timestamp_relationships() -> TestResult {
    let original = host();
    for window in [
        AriWindow {
            start_unix: 12,
            end_unix: 12,
            selected_unix: 12,
        },
        AriWindow {
            start_unix: 12,
            end_unix: 21,
            selected_unix: 14,
        },
        AriWindow {
            start_unix: 12,
            end_unix: 18,
            selected_unix: 18,
        },
        AriWindow {
            start_unix: 12,
            end_unix: 18,
            selected_unix: 11,
        },
        AriWindow {
            start_unix: 0,
            end_unix: u64::MAX,
            selected_unix: 0,
        },
    ] {
        let mut record = original.clone();
        let cert = record.certificate.as_mut().ok_or("certificate")?;
        cert.renew_at_unix = window.selected_unix;
        cert.ari_window = Some(window);
        assert_eq!(record.validate(), Err(StateError::InvalidData));
    }
    let mut record = original.clone();
    let cert = record.certificate.as_mut().ok_or("certificate")?;
    cert.ari_window = Some(AriWindow {
        start_unix: 12,
        end_unix: 18,
        selected_unix: 14,
    });
    assert_eq!(record.validate(), Err(StateError::InvalidData));
    for field in ["fallback_at_unix", "ari_check_at_unix"] {
        let mut value = serde_json::to_value(&original)?;
        value["certificate"][field] = serde_json::json!(u64::MAX);
        let restored: StoredHost = decode(&serde_json::to_vec(&value)?)?;
        assert_eq!(restored.validate(), Err(StateError::InvalidData));
    }
    let mut value = serde_json::to_value(&original)?;
    value["certificate"]["ari_window"] =
        serde_json::json!({"start_unix":12,"end_unix":18,"selected_unix":14,"extra":0});
    assert!(decode::<StoredHost>(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn installed_replacement_relationship_requires_explicit_canonical_bounded_identifier() -> TestResult
{
    for replaces in [None, Some("AQID.AQ".to_owned())] {
        let mut record = host();
        record.certificate.as_mut().ok_or("certificate")?.replaces = replaces.clone();
        let restored: StoredHost = decode(&encode(&record)?)?;
        restored.validate()?;
        assert_eq!(
            restored.certificate.ok_or("certificate")?.replaces,
            replaces
        );
    }
    let mut value = serde_json::to_value(host())?;
    value["certificate"]
        .as_object_mut()
        .ok_or("certificate")?
        .remove("replaces");
    assert!(decode::<StoredHost>(&serde_json::to_vec(&value)?).is_err());
    for invalid in [
        String::new(),
        "AQID.AQ=".into(),
        "AQID.AAE".into(),
        "A".repeat(MAX_RECORD + 1),
    ] {
        value["certificate"]["replaces"] = serde_json::json!(invalid);
        assert!(decode::<StoredHost>(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}
