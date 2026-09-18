// SPDX-License-Identifier: Apache-2.0

use std::alloc::Layout;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use lonewolf_util::arena::{
    AllocationError, Arena, ArenaConfig, ArenaError, Chunk, ChunkAllocator, GlobalChunkAllocator,
    HandleError,
};
use lonewolf_xmpp::jid::{Jid, JidError, JidPart, JidRef, MAX_JID_LEN, MAX_PART_LEN};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn parses_components_before_normalization() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
        let jid = Jid::parse_in(input, &mut arena)?;
        let jid = jid.resolve(&arena)?;
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
fn normalizes_localparts_and_preserves_resource_case() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
        let jid = Jid::parse_in(input, &mut arena)?;
        let reparsed = Jid::parse_in(expected, &mut arena)?;
        let jid = jid.resolve(&arena)?;
        assert_eq!(jid.as_str(), expected, "{input}");
        assert_eq!(reparsed.resolve(&arena)?, jid);
    }
    for (left, right) in [
        ("fuß@example.com", "fuss@example.com"),
        ("example.com/A", "example.com/a"),
    ] {
        let left = Jid::parse_in(left, &mut arena)?;
        let right = Jid::parse_in(right, &mut arena)?;
        assert_ne!(left.resolve(&arena)?, right.resolve(&arena)?);
    }
    Ok(())
}

#[test]
fn normalizes_domains_and_ip_literals() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
        let jid = Jid::parse_in(input, &mut arena)?;
        let reparsed = Jid::parse_in(expected, &mut arena)?;
        let jid = jid.resolve(&arena)?;
        assert_eq!(jid.as_str(), expected, "{input}");
        assert_eq!(reparsed.resolve(&arena)?, jid);
    }
    Ok(())
}

#[test]
fn rejects_empty_parts_and_invalid_localparts() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
        assert_eq!(
            Jid::parse_in(input, &mut arena).map(|_| ()),
            Err(expected),
            "{input:?}"
        );
    }
    for local in [
        "a\"b", "a&b", "a'b", "a/b", "a:b", "a<b", "a>b", "a@b", "a\0b", "a\nb",
    ] {
        assert_eq!(
            Jid::from_parts_in(Some(local), "example.com", None, &mut arena).map(|_| ()),
            Err(JidError::InvalidPart(JidPart::Localpart)),
            "{local:?}"
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_resourceparts() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
            Jid::from_parts_in(None, "example.com", Some(resource), &mut arena).map(|_| ()),
            Err(JidError::InvalidPart(JidPart::Resourcepart)),
            "{resource:?}"
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_domains() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
            Jid::from_parts_in(None, domain, None, &mut arena).map(|_| ()),
            Err(JidError::InvalidPart(JidPart::Domainpart)),
            "{domain:?}"
        );
    }
    Ok(())
}

#[test]
fn applies_context_and_bidirectional_rules() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    for local in ["l·l", "אב", "אב1", "אב١", "क्\u{200d}ष", "ب\u{200c}ب"] {
        assert!(
            Jid::from_parts_in(Some(local), "example.com", None, &mut arena).is_ok(),
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
            Jid::from_parts_in(Some(local), "example.com", None, &mut arena).map(|_| ()),
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
        let jid = Jid::parse_in(domain, &mut arena)?;
        let jid = jid.resolve(&arena)?;
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
            Jid::parse_in(domain, &mut arena).map(|_| ()),
            Err(JidError::InvalidPart(JidPart::Domainpart)),
            "{domain}"
        );
    }
    assert_eq!(
        Jid::parse_in("example.com/aאב", &mut arena)?
            .resolve(&arena)?
            .resourcepart(),
        Some("aאב")
    );
    Ok(())
}

#[test]
fn enforces_byte_limits_after_normalization() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let local = "a".repeat(MAX_PART_LEN);
    let resource = "r".repeat(MAX_PART_LEN);
    let jid = Jid::from_parts_in(Some(&local), "example.com", Some(&resource), &mut arena)?;
    let jid = jid.resolve(&arena)?;
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
            Jid::from_parts_in(
                local.as_deref(),
                "example.com",
                resource.as_deref(),
                &mut arena
            )
            .map(|_| ()),
            Err(JidError::PartTooLong(part))
        );
    }
    let decomposed = "e\u{301}".repeat(511);
    assert!(decomposed.len() > MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(
            Some(&decomposed),
            "example.com",
            Some(&decomposed),
            &mut arena
        )?
        .resolve(&arena)?
        .localpart()
        .map(str::len),
        Some(1022)
    );
    let wide = "Ａ".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(Some(&wide), "example.com", None, &mut arena)?
            .resolve(&arena)?
            .localpart(),
        Some(local.as_str())
    );
    let spaces = "\u{3000}".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_parts_in(None, "example.com", Some(&spaces), &mut arena)?
            .resolve(&arena)?
            .resourcepart()
            .map(str::len),
        Some(MAX_PART_LEN)
    );
    Ok(())
}

#[test]
fn enforces_dns_wire_lengths() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let label = "a".repeat(63);
    let domain = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    assert_eq!(domain.len(), 253);
    assert_eq!(
        Jid::parse_in(&domain, &mut arena)?
            .resolve(&arena)?
            .domainpart(),
        domain
    );
    for domain in ["a".repeat(64), format!("{domain}a"), "é".repeat(58)] {
        assert_eq!(
            Jid::parse_in(&domain, &mut arena).map(|_| ()),
            Err(JidError::InvalidPart(JidPart::Domainpart))
        );
    }
    assert!(Jid::parse_in(&"é".repeat(57), &mut arena).is_ok());
    Ok(())
}

#[test]
fn rejects_oversized_inputs_before_unicode_preparation() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
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
            Jid::from_parts_in(local, domain, resource, &mut arena).map(|_| ()),
            Err(JidError::PartTooLong(part))
        );
    }
    Ok(())
}

#[test]
fn trusted_constructor_checks_structure_without_preparing_text() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid =
        Jid::from_trusted_parts_in(Some("ALICE"), "EXAMPLE.COM", Some("E\u{301}"), &mut arena)?;
    let jid = jid.resolve(&arena)?;
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
            Jid::from_trusted_parts_in(local, domain, resource, &mut arena).map(|_| ()),
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
            Jid::from_trusted_parts_in(local, domain, resource, &mut arena).map(|_| ()),
            Err(JidError::PartTooLong(part))
        );
    }
    let part = "x".repeat(MAX_PART_LEN);
    assert_eq!(
        Jid::from_trusted_parts_in(Some(&part), &part, Some(&part), &mut arena)?
            .resolve(&arena)?
            .as_str()
            .len(),
        MAX_JID_LEN
    );
    Ok(())
}
#[test]
fn storage_is_independent_of_input_and_source_arena() -> TestResult {
    let mut target = Arena::try_new(ArenaConfig::default())?;
    let copied;
    let replaced;
    {
        let mut source = Arena::try_new(ArenaConfig::default())?;
        let jid;
        {
            let input = String::from("ALICE@EXAMPLE.COM/old");
            jid = Jid::parse_in(&input, &mut source)?;
        }
        let jid = jid.resolve(&source)?;
        assert_eq!(jid.as_str(), "alice@example.com/old");
        copied = jid.clone_in(&mut target)?;
        replaced = jid.with_resource_in("e\u{301}@other/resource", &mut target)?;
        assert_ne!(
            copied.resolve(&target)?.as_str().as_ptr(),
            jid.as_str().as_ptr()
        );
    }
    assert_eq!(copied.resolve(&target)?.as_str(), "alice@example.com/old");
    assert_eq!(
        replaced.resolve(&target)?.as_str(),
        "alice@example.com/é@other/resource"
    );
    Ok(())
}

#[test]
fn copies_and_bare_views_reuse_arena_storage() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("alice@example.com/resource", &mut arena)?;
    let before = arena.stats();
    let copied = jid;
    let bare = jid.bare();
    assert!(jid.is_full());
    assert!(!jid.is_bare());
    assert!(bare.is_bare());
    assert!(!bare.is_full());
    assert_eq!(copied.resolve(&arena)?, jid.resolve(&arena)?);
    assert_eq!(
        copied.resolve(&arena)?.as_str().as_ptr(),
        jid.resolve(&arena)?.as_str().as_ptr()
    );
    assert_eq!(
        bare.resolve(&arena)?.as_str().as_ptr(),
        jid.resolve(&arena)?.as_str().as_ptr()
    );
    assert_eq!(bare.bare().resolve(&arena)?, bare.resolve(&arena)?);
    assert_eq!(before.used_bytes, "alice@example.com/resource".len());
    assert_eq!(arena.stats(), before);

    let shared = arena.freeze();
    let bare = bare.resolve(&shared)?;
    assert_eq!(bare.as_str(), "alice@example.com");
    assert_eq!(bare.localpart(), Some("alice"));
    assert_eq!(bare.domainpart(), "example.com");
    assert_eq!(bare.resourcepart(), None);
    assert_eq!(bare.bare(), bare);
    assert_eq!(jid.resolve(&shared)?.bare(), bare);
    Ok(())
}

#[test]
fn equality_and_hash_use_normalized_text() -> TestResult {
    let mut first = Arena::try_new(ArenaConfig::default())?;
    let mut second = Arena::try_new(ArenaConfig::default())?;
    let a = Jid::parse_in("É@XN--BCHER-KVA.EXAMPLE/r", &mut first)?;
    let b = Jid::parse_in("e\u{301}@bücher.example/r", &mut second)?;
    let a = a.resolve(&first)?;
    let b = b.resolve(&second)?;
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
fn formats_text_only_when_explicitly_requested() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("secret@example.com/Private", &mut arena)?;
    let view = jid.resolve(&arena)?;
    assert_eq!(format!("{view}"), "secret@example.com/Private");
    assert_eq!(format!("{jid:?}"), "Jid { .. }");
    assert_eq!(format!("{view:?}"), "JidRef { .. }");
    for output in [format!("{jid:#?}"), format!("{view:#?}")] {
        assert!(!output.contains("secret"));
        assert!(!output.contains("example.com"));
        assert!(!output.contains("Private"));
    }
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
fn propagates_arena_capacity_failures() -> TestResult {
    let mut full = Arena::try_new(ArenaConfig {
        max_reserved_bytes: NonZeroUsize::new(4096).ok_or("limit")?,
        ..ArenaConfig::default()
    })?;
    while full.try_alloc(0_u8).is_ok() {}
    let before = full.stats();
    let error = JidError::AllocationFailed(ArenaError::ArenaLimitExceeded);
    assert_eq!(Jid::parse_in("example.com", &mut full).err(), Some(error));
    assert_eq!(
        Jid::parse_in("É@bücher.example/é", &mut full).err(),
        Some(error)
    );
    assert_eq!(
        Jid::from_trusted_parts_in(None, "example.com", None, &mut full).err(),
        Some(error)
    );
    let mut source = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("example.com", &mut source)?;
    let view = jid.resolve(&source)?;
    assert_eq!(view.clone_in(&mut full).err(), Some(error));
    assert_eq!(view.with_resource_in("new", &mut full).err(), Some(error));
    assert_eq!(
        view.with_resource_in("", &mut full).err(),
        Some(JidError::EmptyPart(JidPart::Resourcepart))
    );
    assert_eq!(full.stats(), before);
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}

#[test]
fn resource_replacement_in_the_same_arena_preserves_the_original() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("alice@example.com/old", &mut arena)?;
    let replaced = jid.with_resource_in("e\u{301}@other/resource", &mut arena)?;
    assert_eq!(jid.resolve(&arena)?.as_str(), "alice@example.com/old");
    assert_eq!(
        replaced.resolve(&arena)?.as_str(),
        "alice@example.com/é@other/resource"
    );
    let bare = replaced.bare();
    let replaced_again = bare.with_resource_in("last", &mut arena)?;
    assert_eq!(
        replaced_again.resolve(&arena)?.as_str(),
        "alice@example.com/last"
    );
    let before = arena.stats();
    assert_eq!(
        jid.with_resource_in("", &mut arena).err(),
        Some(JidError::EmptyPart(JidPart::Resourcepart))
    );
    assert_eq!(arena.stats(), before);
    Ok(())
}

#[test]
fn wrong_arena_and_expired_jids_are_rejected() -> TestResult {
    let mut source = Arena::try_new(ArenaConfig::default())?;
    let jid = Jid::parse_in("alice@example.com/resource", &mut source)?;
    let mut other = Arena::try_new(ArenaConfig::default())?;
    assert_eq!(jid.resolve(&other), Err(HandleError::WrongArena));
    assert_eq!(
        jid.with_resource_in("new", &mut other).err(),
        Some(JidError::AccessFailed(HandleError::WrongArena))
    );
    drop(source);
    let shared = other.freeze();
    assert_eq!(jid.resolve(&shared), Err(HandleError::WrongArena));
    assert_eq!(jid.bare().resolve(&shared), Err(HandleError::WrongArena));
    Ok(())
}

#[derive(Default)]
struct PoolAllocator {
    cached: Mutex<Option<Chunk>>,
    live_chunks: AtomicUsize,
    returned_chunks: AtomicUsize,
    fail: AtomicBool,
}

// Cached chunks have no remaining users and retain their full allocation layouts.
unsafe impl ChunkAllocator for PoolAllocator {
    fn allocate(&self, layout: Layout) -> Result<Chunk, AllocationError> {
        if layout.size() == 0 {
            return Err(AllocationError::UnsupportedLayout);
        }
        if self.fail.load(Ordering::Relaxed) {
            return Err(AllocationError::Exhausted);
        }
        let cached = self
            .cached
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let chunk = match cached {
            Some(chunk)
                if chunk.capacity() >= layout.size()
                    && chunk.layout().align() >= layout.align() =>
            {
                chunk
            }
            cached => {
                if let Some(chunk) = cached {
                    unsafe { GlobalChunkAllocator.deallocate(chunk) };
                }
                let layout = Layout::from_size_align(4096.max(layout.size()), layout.align())
                    .map_err(|_| AllocationError::UnsupportedLayout)?;
                GlobalChunkAllocator.allocate(layout)?
            }
        };
        self.live_chunks.fetch_add(1, Ordering::Relaxed);
        Ok(chunk)
    }

    unsafe fn deallocate(&self, chunk: Chunk) {
        self.live_chunks.fetch_sub(1, Ordering::Relaxed);
        self.returned_chunks.fetch_add(1, Ordering::Relaxed);
        let previous = self
            .cached
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .replace(chunk);
        if let Some(chunk) = previous {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
    }
}

impl Drop for PoolAllocator {
    fn drop(&mut self) {
        assert_eq!(self.live_chunks.load(Ordering::Relaxed), 0);
        if let Some(chunk) = self
            .cached
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            unsafe { GlobalChunkAllocator.deallocate(chunk) };
        }
    }
}

#[test]
fn arena_reuse_does_not_revive_old_jids() -> TestResult {
    let allocator = Arc::new(PoolAllocator::default());
    let mut first = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
    let old = Jid::parse_in("alice@example.com/first", &mut first)?;
    let address = old.resolve(&first)?.as_str().as_ptr();
    drop(first.freeze());
    let mut second = Arena::try_new_in(ArenaConfig::default(), allocator)?;
    let current = Jid::parse_in("bob@example.com/second", &mut second)?;
    assert_eq!(current.resolve(&second)?.as_str().as_ptr(), address);
    assert_eq!(old.resolve(&second), Err(HandleError::WrongArena));
    assert_eq!(current.resolve(&second)?.localpart(), Some("bob"));
    assert_eq!(current.resolve(&second)?.resourcepart(), Some("second"));
    Ok(())
}

#[test]
fn arena_backend_failure_preserves_jid_storage() -> TestResult {
    let allocator = Arc::new(PoolAllocator::default());
    let mut arena = Arena::try_new_in(ArenaConfig::default(), allocator.clone())?;
    let jid = Jid::parse_in("example.com", &mut arena)?;
    arena.try_alloc_slice_fill(3500, 0_u8)?;
    allocator.fail.store(true, Ordering::Relaxed);
    let before = arena.stats();
    let resource = "r".repeat(MAX_PART_LEN);
    let error = JidError::AllocationFailed(ArenaError::Allocation(AllocationError::Exhausted));
    assert_eq!(
        jid.with_resource_in(&resource, &mut arena).err(),
        Some(error)
    );
    assert_eq!(arena.stats(), before);
    assert_eq!(jid.resolve(&arena)?.as_str(), "example.com");
    allocator.fail.store(false, Ordering::Relaxed);
    let replaced = jid.with_resource_in(&resource, &mut arena)?;
    assert_eq!(
        replaced.resolve(&arena)?.resourcepart(),
        Some(resource.as_str())
    );
    Ok(())
}

#[test]
fn shared_arena_keeps_jids_alive_for_multiple_recipients() -> TestResult {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    fn assert_copy<T: Copy>() {}
    assert_send_sync_static::<Jid>();
    assert_copy::<Jid>();
    assert_copy::<JidRef<'_>>();

    let allocator = Arc::new(PoolAllocator::default());
    let backend: Arc<dyn ChunkAllocator> = allocator.clone();
    let mut arena = Arena::try_new_in(ArenaConfig::default(), backend)?;
    let from = Jid::parse_in("ALICE@EXAMPLE.COM/Desktop", &mut arena)?;
    let to = Jid::parse_in("BOB@EXAMPLE.COM", &mut arena)?;
    let stanza = arena.try_alloc([from, to])?;
    let arena = arena.freeze();
    let barrier = Barrier::new(2);
    thread::scope(|scope| {
        for _ in 0..2 {
            let recipient = arena.clone();
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                let Ok(jids) = recipient.get(stanza) else {
                    panic!("stanza must resolve")
                };
                assert_eq!(
                    jids[0].resolve(&recipient).map(|jid| jid.as_str()),
                    Ok("alice@example.com/Desktop")
                );
                assert_eq!(
                    jids[1].resolve(&recipient).map(|jid| jid.as_str()),
                    Ok("bob@example.com")
                );
            });
        }
        drop(arena);
    });
    assert_eq!(allocator.live_chunks.load(Ordering::Relaxed), 0);
    assert_eq!(allocator.returned_chunks.load(Ordering::Relaxed), 1);
    Ok(())
}

#[test]
fn accepted_mutations_round_trip_without_changing_components() -> TestResult {
    let mut arena = Arena::try_new(ArenaConfig::default())?;
    let mut target = Arena::try_new(ArenaConfig::default())?;
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
                if let Ok(jid) = Jid::parse_in(&input, &mut arena) {
                    let jid = jid.resolve(&arena)?;
                    let reparsed = Jid::parse_in(jid.as_str(), &mut target)?;
                    let from_parts = Jid::from_parts_in(
                        jid.localpart(),
                        jid.domainpart(),
                        jid.resourcepart(),
                        &mut target,
                    )?;
                    let reparsed = reparsed.resolve(&target)?;
                    let from_parts = from_parts.resolve(&target)?;
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
