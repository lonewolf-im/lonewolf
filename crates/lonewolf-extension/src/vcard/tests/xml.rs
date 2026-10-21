// SPDX-License-Identifier: Apache-2.0

use super::super::xml::{decode, encode};
use super::*;

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

async fn encoded(
    xml: &str,
    lang: Option<&str>,
    space: Option<XmlSpace>,
    limit: usize,
) -> TestResult<Result<String, crate::delivery::HandlerError>> {
    let parsed = payload(xml).await?;
    let mut scratch = arena()?;
    Ok(encode(
        &parsed.value().resolve(parsed.arena())?,
        lang,
        space,
        quota(limit)?,
        &mut scratch,
    )
    .await)
}

#[test]
fn root_language_space_inheritance_overrides_resets_and_nested_validity() -> TestResult {
    block_on(async {
        for inherited_lang in [None, Some(""), Some("en")] {
            for inherited_space in [
                None,
                Some(XmlSpace::Default),
                Some(XmlSpace::Preserve),
                Some(XmlSpace::Invalid),
            ] {
                for root_lang in [None, Some(""), Some("fr")] {
                    for root_space in [
                        None,
                        Some("default"),
                        Some("preserve"),
                        Some(""),
                        Some("bad"),
                    ] {
                        let lang = root_lang
                            .map(|lang| format!(" xml:lang='{lang}'"))
                            .unwrap_or_default();
                        let space = root_space
                            .map(|space| format!(" xml:space='{space}'"))
                            .unwrap_or_default();
                        let xml = format!(
                            "<vCard xmlns='vcard-temp'{lang}{space}><FN xml:lang='' xml:space='default'> A \n B </FN><NICKNAME xml:lang='de' xml:space='preserve'> C </NICKNAME></vCard>"
                        );
                        let result =
                            encoded(&xml, inherited_lang, inherited_space, 262_144).await?;
                        let invalid = matches!(root_space, Some("" | "bad"))
                            || (root_space.is_none() && inherited_space == Some(XmlSpace::Invalid));
                        if invalid {
                            assert_eq!(
                                result.err().ok_or("invalid accepted")?.condition(),
                                StanzaErrorCondition::BadRequest
                            );
                        } else {
                            let document = result.map_err(|error| format!("{error:?}"))?;
                            let parsed = payload(&document).await?;
                            let root = parsed.value().resolve(parsed.arena())?;
                            assert_eq!(
                                root.attribute("lang", XML_NS)?,
                                Some(root_lang.unwrap_or(inherited_lang.unwrap_or("")))
                            );
                            assert_eq!(
                                root.attribute("space", XML_NS)?,
                                Some(root_space.unwrap_or(
                                    if inherited_space == Some(XmlSpace::Preserve) {
                                        "preserve"
                                    } else {
                                        "default"
                                    }
                                ))
                            );
                            let child = root.child("FN", NAMESPACE)?.ok_or("missing FN")?;
                            assert_eq!(child.attribute("lang", XML_NS)?, Some(""));
                            assert_eq!(child.attribute("space", XML_NS)?, Some("default"));
                            assert_eq!(child.text()?, Some(" A \n B "));
                            let mut response = arena()?;
                            let element = decode(&document, &mut response)
                                .await
                                .map_err(|error| format!("{error:?}"))?;
                            assert_eq!(serialize(element, &response)?, document);
                        }
                    }
                }
            }
        }
        for bad in [
            "<vCard xmlns='vcard-temp'><AGENT><vCard xml:space='bad'/></AGENT></vCard>",
            "<vCard xmlns='vcard-temp'>\u{a0}</vCard>",
        ] {
            assert_eq!(
                encoded(bad, None, None, 262_144)
                    .await?
                    .err()
                    .ok_or("invalid accepted")?
                    .condition(),
                StanzaErrorCondition::BadRequest
            );
        }
        Ok(())
    })
}

#[test]
fn normative_repeated_nested_opaque_fields_and_ordered_mixed_content_round_trip() -> TestResult {
    block_on(async {
        let source = "<vCard xmlns='vcard-temp' version='3.0' xml:base='https://invalid.example/base/'><FN>Case É e&#x301;</FN><N><FAMILY>Example</FAMILY><GIVEN>Test</GIVEN></N><ADR><STREET>First</STREET><CTRY>ES</CTRY></ADR><ADR><STREET>Second</STREET><CTRY>GB</CTRY></ADR><TEL><HOME/><NUMBER>123</NUMBER></TEL><TEL><WORK/><NUMBER/></TEL><EMAIL><USERID>Case@invalid.example</USERID></EMAIL><AGENT><vCard><FN>Nested</FN></vCard></AGENT><URL>../unchanged?a=1&amp;b=2</URL><PHOTO><TYPE>image/unknown</TYPE><BINVAL> /++opaque== \n </BINVAL><EXTVAL>https://invalid.example/not-fetched</EXTVAL></PHOTO><x:opaque xmlns:x='urn:foreign' x:attr='Value'>before<x:inner/>between<x:inner/>after</x:opaque></vCard>";
        let document = encoded(source, Some("en"), Some(XmlSpace::Preserve), 262_144)
            .await?
            .map_err(|error| format!("{error:?}"))?;
        let parsed = payload(&document).await?;
        let root = parsed.value().resolve(parsed.arena())?;
        assert_eq!(root.attribute("version", "")?, Some("3.0"));
        assert_eq!(
            root.attribute("base", XML_NS)?,
            Some("https://invalid.example/base/")
        );
        let names = root
            .children()?
            .map(|node| match node {
                Ok(lonewolf_xmpp::stanza::NodeRef::Element(element)) => Ok(element.name()),
                _ => Err("unexpected root text"),
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            names,
            [
                "FN", "N", "ADR", "ADR", "TEL", "TEL", "EMAIL", "AGENT", "URL", "PHOTO", "opaque"
            ]
        );
        assert_eq!(
            root.child("FN", NAMESPACE)?.ok_or("FN")?.text()?,
            Some("Case É e\u{301}")
        );
        let opaque = root.child("opaque", "urn:foreign")?.ok_or("opaque")?;
        let mut nodes = opaque.children()?;
        assert!(matches!(
            nodes.next().transpose()?,
            Some(lonewolf_xmpp::stanza::NodeRef::Text("before"))
        ));
        assert!(matches!(
            nodes.next().transpose()?,
            Some(lonewolf_xmpp::stanza::NodeRef::Element(_))
        ));
        assert!(matches!(
            nodes.next().transpose()?,
            Some(lonewolf_xmpp::stanza::NodeRef::Text("between"))
        ));
        assert!(matches!(
            nodes.next().transpose()?,
            Some(lonewolf_xmpp::stanza::NodeRef::Element(_))
        ));
        assert!(matches!(
            nodes.next().transpose()?,
            Some(lonewolf_xmpp::stanza::NodeRef::Text("after"))
        ));
        assert!(nodes.next().is_none());
        let mut response = arena()?;
        let result = decode(&document, &mut response)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(serialize(result, &response)?, document);
        assert!(document.contains("../unchanged?a=1&amp;b=2"));
        assert!(document.contains("/++opaque== \n"));
        Ok(())
    })
}

#[test]
fn inherited_namespaces_qname_values_rebindings_and_default_resets_survive_detachment() -> TestResult
{
    block_on(async {
        let parsed = payload("<envelope xmlns='urn:envelope' xmlns:v='vcard-temp' xmlns:q='urn:qname-only' xmlns:a='urn:attribute' xml:base='https://ancestor.invalid/'><v:vCard a:type='q:Root'><v:FN>q:Text</v:FN><foreign xmlns='urn:foreign' xmlns:q='urn:rebound' a:type='q:Child'><reset xmlns=''>q:Plain</reset></foreign></v:vCard></envelope>").await?;
        let root = parsed.value().resolve(parsed.arena())?;
        let card = root.child("vCard", NAMESPACE)?.ok_or("missing vCard")?;
        let mut scratch = arena()?;
        let document = encode(
            &card,
            Some("en"),
            Some(XmlSpace::Preserve),
            VCardQuota::default(),
            &mut scratch,
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
        assert!(document.contains("xmlns:q=\"urn:qname-only\""));
        assert!(document.contains("xmlns:q=\"urn:rebound\""));
        assert!(document.contains("xmlns=\"\""));
        assert!(!document.contains("xml:base"));
        assert!(!document.contains("envelope>"));
        let restored = payload(&document).await?;
        let card = restored.value().resolve(restored.arena())?;
        assert_eq!(card.attribute("type", "urn:attribute")?, Some("q:Root"));
        assert_eq!(
            card.child("FN", NAMESPACE)?.ok_or("FN")?.text()?,
            Some("q:Text")
        );
        let foreign = card.child("foreign", "urn:foreign")?.ok_or("foreign")?;
        assert_eq!(foreign.attribute("type", "urn:attribute")?, Some("q:Child"));
        assert_eq!(
            foreign.child("reset", "")?.ok_or("reset")?.text()?,
            Some("q:Plain")
        );
        let mut response = arena()?;
        let result = decode(&document, &mut response)
            .await
            .map_err(|error| format!("{error:?}"))?;
        let replay = serialize(result, &response)?;
        assert!(replay.contains("xmlns:q=\"urn:qname-only\""));
        assert!(replay.contains("xmlns:q=\"urn:rebound\""));
        let reparsed = payload(&replay).await?;
        let card = reparsed.value().resolve(reparsed.arena())?;
        assert_eq!(card.attribute("type", "urn:attribute")?, Some("q:Root"));
        let foreign = card.child("foreign", "urn:foreign")?.ok_or("foreign")?;
        assert_eq!(
            foreign.child("reset", "")?.ok_or("reset")?.text()?,
            Some("q:Plain")
        );
        Ok(())
    })
}

#[test]
fn xml_whitespace_character_references_and_semantic_reparse_stability() -> TestResult {
    block_on(async {
        let source = "<vCard xmlns='vcard-temp'><FN literal=' A\r\nB\rC\tD\nE ' references='&#xD;&#xA;&#x9;'>A\r\nB\rC\tD\nE&#xD;&#xA;&#x9;</FN></vCard>";
        let document = encoded(source, None, None, 262_144)
            .await?
            .map_err(|error| format!("{error:?}"))?;
        let parsed = payload(&document).await?;
        let root = parsed.value().resolve(parsed.arena())?;
        let field = root.child("FN", NAMESPACE)?.ok_or("FN")?;
        assert_eq!(field.attribute("literal", "")?, Some(" A B C D E "));
        assert_eq!(field.attribute("references", "")?, Some("\r\n\t"));
        assert_eq!(field.text()?, Some("A\nB\nC\tD\nE\r\n\t"));
        assert!(document.contains("&#xD;"));
        let stable = encoded(
            &document,
            Some("unrelated-reader"),
            Some(XmlSpace::Preserve),
            262_144,
        )
        .await?
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(document, stable);
        Ok(())
    })
}

#[test]
fn original_size_count_rejects_before_any_context_clone_and_added_context_counts() -> TestResult {
    block_on(async {
        let parsed = payload(FIRST).await?;
        let root = parsed.value().resolve(parsed.arena())?;
        let mut scratch = arena()?;
        let before = scratch.stats();
        let error = encode(
            &root,
            Some("en"),
            Some(XmlSpace::Preserve),
            quota(1)?,
            &mut scratch,
        )
        .await
        .err()
        .ok_or("oversize accepted")?;
        assert_eq!(error.condition(), StanzaErrorCondition::ResourceConstraint);
        assert_eq!(scratch.stats(), before);
        let source_bytes = serialize(parsed.value(), parsed.arena())?.len();
        let error = encode(
            &root,
            Some("en"),
            Some(XmlSpace::Preserve),
            quota(source_bytes)?,
            &mut scratch,
        )
        .await
        .err()
        .ok_or("metadata not counted")?;
        assert_eq!(error.condition(), StanzaErrorCondition::ResourceConstraint);
        let exact = encoded(FIRST, Some("en"), Some(XmlSpace::Preserve), 262_144)
            .await?
            .map_err(|error| format!("{error:?}"))?;
        assert!(exact.len() > source_bytes);
        assert_eq!(
            encoded(FIRST, Some("en"), Some(XmlSpace::Preserve), exact.len())
                .await?
                .map_err(|error| format!("{error:?}"))?,
            exact
        );
        assert_eq!(
            encoded(FIRST, Some("en"), Some(XmlSpace::Preserve), exact.len() - 1)
                .await?
                .err()
                .ok_or("extra byte accepted")?
                .condition(),
            StanzaErrorCondition::ResourceConstraint
        );
        Ok(())
    })
}

#[test]
fn detached_namespace_bytes_count_toward_the_exact_quota() -> TestResult {
    block_on(async {
        let parsed = payload("<wrapper xmlns:q='urn:only-qname-value'><vCard xmlns='vcard-temp'><FN>q:Name</FN></vCard></wrapper>").await?;
        let parent = parsed.value().resolve(parsed.arena())?;
        let root = parent.child("vCard", NAMESPACE)?.ok_or("card")?;
        let mut scratch = arena()?;
        let exact = encode(&root, None, None, VCardQuota::default(), &mut scratch)
            .await
            .map_err(|error| format!("{error:?}"))?;
        assert!(exact.contains("xmlns:q=\"urn:only-qname-value\""));
        for (limit, succeeds) in [(exact.len(), true), (exact.len() - 1, false)] {
            let mut scratch = arena()?;
            let result = encode(&root, None, None, quota(limit)?, &mut scratch).await;
            if succeeds {
                assert_eq!(result.map_err(|error| format!("{error:?}"))?, exact);
            } else {
                assert_eq!(
                    result.err().ok_or("oversize accepted")?.condition(),
                    StanzaErrorCondition::ResourceConstraint
                );
            }
        }
        Ok(())
    })
}

#[test]
fn decoder_rejects_missing_metadata_wrong_roots_and_excessive_structure_as_corruption() -> TestResult
{
    block_on(async {
        let depth = lonewolf_xmpp::stanza::MAX_ELEMENT_DEPTH;
        let excessive = format!(
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'>{}{}</vCard>",
            "<FN>".repeat(depth),
            "</FN>".repeat(depth)
        );
        let attributes = (0..lonewolf_xmpp::parser::MAX_ATTRIBUTES_PER_ELEMENT)
            .map(|index| format!(" a{index}='x'"))
            .collect::<String>();
        let excessive_attributes =
            format!("<vCard xmlns='vcard-temp' xml:lang='' xml:space='default'{attributes}/>");
        for invalid in [
            "<vCard xmlns='vcard-temp' xml:space='default'/>",
            "<vCard xmlns='vcard-temp' xml:lang=''/>",
            "<vCard xmlns='vcard-temp' xml:lang='' xml:space=''/>",
            "<vCard xmlns='wrong' xml:lang='' xml:space='default'/>",
            excessive.as_str(),
            excessive_attributes.as_str(),
        ] {
            let mut response = arena()?;
            let error = decode(invalid, &mut response)
                .await
                .err()
                .ok_or("corrupt accepted")?;
            assert_eq!(error.condition(), StanzaErrorCondition::InternalServerError);
            assert_eq!(
                error.failure().ok_or("failure missing")?.kind,
                crate::delivery::FailureKind::Storage(StorageErrorKind::CorruptData)
            );
        }
        Ok(())
    })
}

#[test]
fn arbitrary_uploaded_versions_and_names_remain_opaque_compatibility_data() -> TestResult {
    block_on(async {
        for version in ["", "2.0", "3.0", "arbitrary", "a&amp;b"] {
            let source = format!(
                "<vCard xmlns='vcard-temp' version='{version}'><fn>Case Unchanged</fn><VERSION>opaque historical field</VERSION></vCard>"
            );
            let document = encoded(&source, None, None, 262_144)
                .await?
                .map_err(|error| format!("{error:?}"))?;
            let parsed = payload(&document).await?;
            let root = parsed.value().resolve(parsed.arena())?;
            assert_eq!(
                root.attribute("version", "")?,
                Some(if version == "a&amp;b" { "a&b" } else { version })
            );
            assert_eq!(
                root.child("fn", NAMESPACE)?
                    .ok_or("opaque lowercase field")?
                    .text()?,
                Some("Case Unchanged")
            );
            assert_eq!(
                root.child("VERSION", NAMESPACE)?
                    .ok_or("opaque version field")?
                    .text()?,
                Some("opaque historical field")
            );
        }
        Ok(())
    })
}
