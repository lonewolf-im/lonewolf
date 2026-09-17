// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use bumpalo::Bump;
use lonewolf_xmpp::jid::{Jid, JidError, JidPart, MAX_JID_LEN, MAX_PART_LEN};

#[test]
fn parses_components_before_normalization() -> Result<(), JidError> {
    let arena = Bump::new();
    for (input, local, domain, resource) in [
        ("example.com", None, "example.com", None),
        ("alice@example.com", Some("alice"), "example.com", None),
        (
            "alice@example.com/Desktop",
            Some("alice"),
            "example.com",
            Some("Desktop"),
        ),
        ("example.com/a@b/c", None, "example.com", Some("a@b/c")),
        (
            "a.example.com/b@example.net",
            None,
            "a.example.com",
            Some("b@example.net"),
        ),
        ("example.com//", None, "example.com", Some("/")),
        (
            r"foo\20bar@example.com",
            Some(r"foo\20bar"),
            "example.com",
            None,
        ),
    ] {
        let jid = Jid::parse_in(input, &arena)?;
        assert_eq!(jid.localpart(), local, "{input}");
        assert_eq!(jid.domainpart(), domain, "{input}");
        assert_eq!(jid.resourcepart(), resource, "{input}");
        assert_eq!(jid.is_bare(), resource.is_none());
        assert_eq!(jid.is_full(), resource.is_some());
        assert_eq!(jid.as_str(), input);
    }
    Ok(())
}

#[test]
fn normalizes_localparts_and_preserves_resource_case() -> Result<(), JidError> {
    let arena = Bump::new();
    for (input, expected) in [
        ("ALICE@EXAMPLE.COM/Desktop", "alice@example.com/Desktop"),
        ("ＦＯＯ@example.com/ＦＯＯ", "foo@example.com/ＦＯＯ"),
        ("E\u{301}@example.com/e\u{301}", "é@example.com/é"),
        ("Σ@example.com/Σ", "σ@example.com/Σ"),
        ("İ@example.com", "i\u{307}@example.com"),
        ("fußball@example.com", "fußball@example.com"),
        ("example.com/foo\u{a0}bar", "example.com/foo bar"),
        ("example.com/\u{3000}", "example.com/ "),
        ("king@example.com/♚", "king@example.com/♚"),
    ] {
        let jid = Jid::parse_in(input, &arena)?;
        assert_eq!(jid.as_str(), expected, "{input}");
        assert_eq!(Jid::parse_in(jid.as_str(), &arena)?, jid);
    }
    assert_ne!(
        Jid::parse_in("fuß@example.com", &arena)?,
        Jid::parse_in("fuss@example.com", &arena)?
    );
    assert_ne!(
        Jid::parse_in("example.com/A", &arena)?,
        Jid::parse_in("example.com/a", &arena)?
    );
    Ok(())
}

#[test]
fn normalizes_domains_and_ip_literals() -> Result<(), JidError> {
    let arena = Bump::new();
    for (input, expected) in [
        ("EXAMPLE.COM.", "example.com"),
        ("example.com。", "example.com"),
        ("ＥＸＡＭＰＬＥ．ＣＯＭ", "example.com"),
        ("example｡com", "example.com"),
        ("xn--bcher-kva.example", "bücher.example"),
        ("BÜCHER.example", "bücher.example"),
        ("faß.de", "faß.de"),
        ("localhost", "localhost"),
        ("192.0.2.1", "192.0.2.1"),
        ("[2001:0DB8:0000:0000:0000:0000:0000:0001]", "[2001:db8::1]"),
        ("[::FFFF:C000:201]", "[::ffff:192.0.2.1]"),
        ("[FE80::1%25Eth0]", "[fe80::1%25Eth0]"),
        ("[fe80::1%25eth%32]", "[fe80::1%25eth%32]"),
    ] {
        let jid = Jid::parse_in(input, &arena)?;
        assert_eq!(jid.as_str(), expected, "{input}");
        assert_eq!(Jid::parse_in(jid.as_str(), &arena)?, jid);
    }
    Ok(())
}

#[test]
fn rejects_empty_parts_and_invalid_localparts() {
    let arena = Bump::new();
    for (input, expected) in [
        ("", JidError::EmptyPart(JidPart::Domainpart)),
        (".", JidError::EmptyPart(JidPart::Domainpart)),
        ("@example.com", JidError::EmptyPart(JidPart::Localpart)),
        ("alice@", JidError::EmptyPart(JidPart::Domainpart)),
        ("example.com/", JidError::EmptyPart(JidPart::Resourcepart)),
        ("a b@example.com", JidError::InvalidPart(JidPart::Localpart)),
        (
            "a\u{a0}b@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            "a\u{ad}b@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            "a\u{200b}b@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            "a\u{378}b@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            "a\u{e000}b@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        ("☃@example.com", JidError::InvalidPart(JidPart::Localpart)),
        ("Ⅳ@example.com", JidError::InvalidPart(JidPart::Localpart)),
        (
            "ａ＠ｂ@example.com",
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            "a@b@example.com",
            JidError::InvalidPart(JidPart::Domainpart),
        ),
    ] {
        assert_eq!(Jid::parse_in(input, &arena), Err(expected), "{input:?}");
    }
    for local in [
        "a\"b", "a&b", "a'b", "a/b", "a:b", "a<b", "a>b", "a@b", "a\0b", "a\nb",
    ] {
        assert_eq!(
            Jid::from_parts_in(Some(local), "example.com", None, &arena),
            Err(JidError::InvalidPart(JidPart::Localpart)),
            "{local:?}"
        );
    }
}

#[test]
fn rejects_invalid_resourceparts() {
    let arena = Bump::new();
    for resource in [
        "a\0b",
        "a\nb",
        "a\tb",
        "a\u{7f}b",
        "\u{378}",
        "\u{e000}",
        "\u{ffff}",
        "\u{200b}",
        "\u{202e}",
        "a\u{200d}b",
    ] {
        assert_eq!(
            Jid::from_parts_in(None, "example.com", Some(resource), &arena),
            Err(JidError::InvalidPart(JidPart::Resourcepart)),
            "{resource:?}"
        );
    }
}

#[test]
fn rejects_invalid_domains() {
    let arena = Bump::new();
    for domain in [
        "a..b",
        "example.com..",
        "-example.com",
        "example-.com",
        "ab--cd.com",
        "_xmpp.example.com",
        "a b",
        "a\0b",
        "a\nb",
        "example.com:5222",
        "user@example.com",
        "example.com/resource",
        "xn--",
        "xn--a.example",
        "xn--abc-",
        "xn--a-ecp.ru",
        "xn--0.pt",
        "\u{301}a.example",
        "☃.example",
        "xn--n3h.example",
        "🦀.example",
        "a\u{20d0}.example",
        "a\u{1d242}.example",
        "a\u{0345}.example",
        "a\u{ad}b.example",
        "a\u{200b}b.example",
        "ⓐ.example",
        "a\u{200c}b.example",
        "a\u{200d}b.example",
        "a·b.example",
        "・.example",
        "aא.example",
        "2001:db8::1",
        "[]",
        "[127.0.0.1]",
        "[::1",
        "[::1]extra",
        "[::1%eth0]",
        "[::1%25]",
        "[::1%25eth%]",
        "[::1%25eth%xx]",
        "[::1%25eth 0]",
    ] {
        assert_eq!(
            Jid::from_parts_in(None, domain, None, &arena),
            Err(JidError::InvalidPart(JidPart::Domainpart)),
            "{domain:?}"
        );
    }
}

#[test]
fn applies_context_and_bidirectional_rules() -> Result<(), JidError> {
    let arena = Bump::new();
    for local in ["l·l", "אב", "אב1", "אב١", "क्\u{200d}ष", "ب\u{200c}ب"] {
        assert!(
            Jid::from_parts_in(Some(local), "example.com", None, &arena).is_ok(),
            "{local}"
        );
    }
    for local in [
        "a·b",
        "abcאב",
        "אבa",
        "אב1١",
        "1אב",
        "a\u{200c}b",
        "a\u{200d}b",
    ] {
        assert_eq!(
            Jid::from_parts_in(Some(local), "example.com", None, &arena),
            Err(JidError::InvalidPart(JidPart::Localpart)),
            "{local}"
        );
    }
    for domain in [
        "l·l.example",
        "͵α.example",
        "א׳.example",
        "カ・ナ.example",
        "אב.example",
        "क्\u{200d}ष.example",
        "ب\u{200c}ب.example",
    ] {
        let jid = Jid::parse_in(domain, &arena)?;
        assert_eq!(jid.domainpart(), domain);
    }
    for domain in [
        "͵a.example",
        "a׳.example",
        "אב1١.example",
        "אב١۱.example",
        "a・b.example",
        "1.אב",
    ] {
        assert_eq!(
            Jid::parse_in(domain, &arena),
            Err(JidError::InvalidPart(JidPart::Domainpart)),
            "{domain}"
        );
    }
    assert_eq!(
        Jid::parse_in("example.com/aאב", &arena)?.resourcepart(),
        Some("aאב")
    );
    Ok(())
}

#[test]
fn enforces_byte_limits_after_normalization() -> Result<(), JidError> {
    let arena = Bump::new();
    let local = "a".repeat(MAX_PART_LEN);
    let resource = "r".repeat(MAX_PART_LEN);
    let jid = Jid::from_parts_in(Some(&local), "example.com", Some(&resource), &arena)?;
    assert_eq!(jid.localpart(), Some(local.as_str()));
    assert_eq!(jid.resourcepart(), Some(resource.as_str()));
    for (local, resource, part) in [
        (Some("a".repeat(MAX_PART_LEN + 1)), None, JidPart::Localpart),
        (Some("é".repeat(512)), None, JidPart::Localpart),
        (
            None,
            Some("r".repeat(MAX_PART_LEN + 1)),
            JidPart::Resourcepart,
        ),
        (None, Some("é".repeat(512)), JidPart::Resourcepart),
        (Some("İ".repeat(342)), None, JidPart::Localpart),
    ] {
        assert_eq!(
            Jid::from_parts_in(local.as_deref(), "example.com", resource.as_deref(), &arena),
            Err(JidError::PartTooLong(part))
        );
    }
    let decomposed = "e\u{301}".repeat(511);
    assert!(decomposed.len() > MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(Some(&decomposed), "example.com", Some(&decomposed), &arena)?
            .localpart()
            .map(str::len),
        Some(1022)
    );
    let wide = "Ａ".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(Some(&wide), "example.com", None, &arena)?.localpart(),
        Some(local.as_str())
    );
    let spaces = "\u{3000}".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(None, "example.com", Some(&spaces), &arena)?
            .resourcepart()
            .map(str::len),
        Some(MAX_PART_LEN)
    );
    Ok(())
}

#[test]
fn enforces_dns_wire_lengths() -> Result<(), JidError> {
    let arena = Bump::new();
    let label = "a".repeat(63);
    let domain = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    assert_eq!(domain.len(), 253);
    assert_eq!(Jid::parse_in(&domain, &arena)?.domainpart(), domain);
    for domain in ["a".repeat(64), format!("{domain}a"), "é".repeat(58)] {
        assert_eq!(
            Jid::parse_in(&domain, &arena),
            Err(JidError::InvalidPart(JidPart::Domainpart))
        );
    }
    assert!(Jid::parse_in(&"é".repeat(57), &arena).is_ok());
    Ok(())
}

#[test]
fn rejects_oversized_inputs_before_unicode_preparation() {
    let arena = Bump::new();
    let input = "l·l".repeat(65536);
    for (local, domain, resource, part) in [
        (
            Some(input.as_str()),
            "example.com",
            None,
            JidPart::Localpart,
        ),
        (None, input.as_str(), None, JidPart::Domainpart),
        (
            None,
            "example.com",
            Some(input.as_str()),
            JidPart::Resourcepart,
        ),
    ] {
        assert_eq!(
            Jid::from_parts_in(local, domain, resource, &arena),
            Err(JidError::PartTooLong(part))
        );
    }
}

#[test]
fn trusted_constructor_checks_structure_without_preparing_text() -> Result<(), JidError> {
    let arena = Bump::new();
    let jid = Jid::from_trusted_parts_in(Some("ALICE"), "EXAMPLE.COM", Some("E\u{301}"), &arena)?;
    assert_eq!(jid.as_str(), "ALICE@EXAMPLE.COM/E\u{301}");
    for (local, domain, resource, expected) in [
        (
            Some(""),
            "example.com",
            None,
            JidError::EmptyPart(JidPart::Localpart),
        ),
        (None, "", None, JidError::EmptyPart(JidPart::Domainpart)),
        (
            None,
            "example.com",
            Some(""),
            JidError::EmptyPart(JidPart::Resourcepart),
        ),
        (
            Some("a@b"),
            "example.com",
            None,
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            Some("a/b"),
            "example.com",
            None,
            JidError::InvalidPart(JidPart::Localpart),
        ),
        (
            None,
            "a@b",
            None,
            JidError::InvalidPart(JidPart::Domainpart),
        ),
        (
            None,
            "a/b",
            None,
            JidError::InvalidPart(JidPart::Domainpart),
        ),
    ] {
        assert_eq!(
            Jid::from_trusted_parts_in(local, domain, resource, &arena),
            Err(expected)
        );
    }
    let long = "x".repeat(MAX_PART_LEN + 1);
    for (local, domain, resource, part) in [
        (Some(long.as_str()), "example.com", None, JidPart::Localpart),
        (None, long.as_str(), None, JidPart::Domainpart),
        (
            None,
            "example.com",
            Some(long.as_str()),
            JidPart::Resourcepart,
        ),
    ] {
        assert_eq!(
            Jid::from_trusted_parts_in(local, domain, resource, &arena),
            Err(JidError::PartTooLong(part))
        );
    }
    let part = "x".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_trusted_parts_in(Some(&part), &part, Some(&part), &arena)?
            .as_str()
            .len(),
        MAX_JID_LEN
    );
    Ok(())
}

#[test]
fn storage_is_independent_of_input_and_source_arena() -> Result<(), JidError> {
    let target = Bump::new();
    let copied;
    let replaced;
    {
        let source = Bump::new();
        let jid;
        {
            let input = String::from("ALICE@EXAMPLE.COM/old");
            jid = Jid::parse_in(&input, &source)?;
        }
        assert_eq!(jid.as_str(), "alice@example.com/old");
        copied = jid.clone_in(&target)?;
        replaced = jid.with_resource_in("e\u{301}@other/resource", &target)?;
        assert_ne!(copied.as_str().as_ptr(), jid.as_str().as_ptr());
    }
    assert_eq!(copied.as_str(), "alice@example.com/old");
    assert_eq!(replaced.as_str(), "alice@example.com/é@other/resource");
    Ok(())
}

#[test]
fn clones_and_bare_views_reuse_storage() -> Result<(), JidError> {
    let arena = Bump::new();
    let jid = Jid::parse_in("alice@example.com/resource", &arena)?;
    let remaining = arena.chunk_capacity();
    let copied = jid.clone();
    let bare = jid.bare();
    assert_eq!(copied, jid);
    assert_eq!(copied.as_str().as_ptr(), jid.as_str().as_ptr());
    assert_eq!(bare.as_str().as_ptr(), jid.as_str().as_ptr());
    assert_eq!(bare.as_str(), "alice@example.com");
    assert_eq!(bare.localpart(), Some("alice"));
    assert_eq!(bare.domainpart(), "example.com");
    assert_eq!(bare.resourcepart(), None);
    assert_eq!(bare.bare(), bare);
    assert_eq!(arena.chunk_capacity(), remaining);
    Ok(())
}

#[test]
fn equality_and_hash_use_normalized_text() -> Result<(), JidError> {
    let first = Bump::new();
    let second = Bump::new();
    let a = Jid::parse_in("É@XN--BCHER-KVA.EXAMPLE/r", &first)?;
    let b = Jid::parse_in("e\u{301}@bücher.example/r", &second)?;
    let mut hash_a = DefaultHasher::new();
    let mut hash_b = DefaultHasher::new();
    a.hash(&mut hash_a);
    b.hash(&mut hash_b);
    assert_eq!(a, b);
    assert_eq!(hash_a.finish(), hash_b.finish());
    assert_ne!(a, a.bare());
    Ok(())
}

#[test]
fn formats_text_only_when_explicitly_requested() -> Result<(), JidError> {
    let arena = Bump::new();
    let jid = Jid::parse_in("secret@example.com/Private", &arena)?;
    assert_eq!(format!("{jid}"), "secret@example.com/Private");
    assert_eq!(format!("{jid:?}"), "Jid { .. }");
    assert!(!format!("{jid:#?}").contains("secret"));
    assert!(!format!("{jid:#?}").contains("example.com"));
    assert!(!format!("{jid:#?}").contains("Private"));
    assert_eq!(
        JidError::EmptyPart(JidPart::Localpart).to_string(),
        "localpart must not be empty"
    );
    assert_eq!(
        JidError::PartTooLong(JidPart::Resourcepart).to_string(),
        "resourcepart exceeds the byte limit"
    );
    assert_eq!(
        JidError::InvalidPart(JidPart::Domainpart).to_string(),
        "domainpart is invalid"
    );
    Ok(())
}

#[test]
fn propagates_arena_allocation_failures() -> Result<(), JidError> {
    let full = Bump::new();
    full.set_allocation_limit(Some(0));
    assert_eq!(
        Jid::parse_in("example.com", &full),
        Err(JidError::AllocationFailed)
    );
    assert_eq!(
        Jid::parse_in("É@bücher.example/é", &full),
        Err(JidError::AllocationFailed)
    );
    assert_eq!(
        Jid::from_trusted_parts_in(None, "example.com", None, &full),
        Err(JidError::AllocationFailed)
    );
    let source = Bump::new();
    let jid = Jid::parse_in("example.com", &source)?;
    assert_eq!(jid.clone_in(&full), Err(JidError::AllocationFailed));
    assert_eq!(
        jid.with_resource_in("new", &full),
        Err(JidError::AllocationFailed)
    );
    assert_eq!(
        jid.with_resource_in("", &full),
        Err(JidError::EmptyPart(JidPart::Resourcepart))
    );
    Ok(())
}

#[test]
fn arena_can_be_reused_after_jids_are_dropped() -> Result<(), JidError> {
    let mut arena = Bump::new();
    {
        let jid = Jid::parse_in("alice@example.com/first", &arena)?;
        assert_eq!(jid.resourcepart(), Some("first"));
    }
    arena.reset();
    let jid = Jid::parse_in("bob@example.com/second", &arena)?;
    assert_eq!(jid.localpart(), Some("bob"));
    assert_eq!(jid.resourcepart(), Some("second"));
    Ok(())
}

#[test]
fn accepted_mutations_round_trip_without_changing_components() -> Result<(), JidError> {
    let arena = Bump::new();
    for base in [
        "alice@example.com/resource",
        "é@bücher.example/é",
        "אב@example.com/r",
        "example.com/a@b/c",
    ] {
        for offset in base
            .char_indices()
            .map(|(offset, _)| offset)
            .chain(std::iter::once(base.len()))
        {
            for inserted in [
                '@', '/', '.', '\0', ' ', 'Ａ', 'é', '\u{301}', '\u{200d}', '\u{fffd}',
            ] {
                let mut input = base.to_owned();
                input.insert(offset, inserted);
                if let Ok(jid) = Jid::parse_in(&input, &arena) {
                    let reparsed = Jid::parse_in(jid.as_str(), &arena)?;
                    let from_parts = Jid::from_parts_in(
                        jid.localpart(),
                        jid.domainpart(),
                        jid.resourcepart(),
                        &arena,
                    )?;
                    assert_eq!(reparsed, jid, "{input:?}");
                    assert_eq!(from_parts, jid, "{input:?}");
                    assert_eq!(reparsed.localpart(), jid.localpart());
                    assert_eq!(reparsed.domainpart(), jid.domainpart());
                    assert_eq!(reparsed.resourcepart(), jid.resourcepart());
                    assert!(jid.as_str().len() <= MAX_JID_LEN);
                }
            }
        }
    }
    Ok(())
}
