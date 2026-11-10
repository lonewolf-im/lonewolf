// SPDX-License-Identifier: Apache-2.0

use lonewolf_util::arena::{ChunkAllocator, HandleError};
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::{NodeRef, STREAM_NAMESPACE};
use lonewolf_xmpp::stream::{STREAM_ERROR_NAMESPACE, StreamError, StreamErrorCondition};

pub(crate) mod limiter;
pub(crate) mod parse;
pub(crate) mod reader;

pub(crate) const STREAM_FOOTER: &str = "</stream:stream>";

pub(crate) fn version_components(version: &str) -> Option<(&str, &str)> {
    let (major, minor) = version.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|digit| digit.is_ascii_digit())
        || !minor.bytes().all(|digit| digit.is_ascii_digit())
    {
        return None;
    }
    Some((normalized_component(major), normalized_component(minor)))
}

fn normalized_component(component: &str) -> &str {
    let normalized = component.trim_start_matches('0');
    if normalized.is_empty() {
        "0"
    } else {
        normalized
    }
}

pub(crate) fn escape_attribute(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            '\t' => output.push_str("&#x9;"),
            _ => output.push(ch),
        }
    }
}

pub(crate) fn stream_error_xml(condition: StreamErrorCondition) -> String {
    let mut xml = String::with_capacity(128);
    let _ = StreamError::new(condition).write_xml(&mut xml);
    xml.push_str(STREAM_FOOTER);
    xml
}

pub(crate) fn peer_stream_error<A: ChunkAllocator>(
    event: &StreamEvent<A>,
) -> Result<Option<StreamErrorCondition>, HandleError> {
    let StreamEvent::Element(parsed) = event else {
        return Ok(None);
    };
    let element = parsed.value().resolve(parsed.arena())?;
    if element.namespace() != STREAM_NAMESPACE || element.name() != "error" {
        return Ok(None);
    }
    let mut condition = None;
    for child in element.children()? {
        if let NodeRef::Element(child) = child?
            && child.namespace() == STREAM_ERROR_NAMESPACE
            && child.name() != "text"
        {
            if condition.is_some() {
                return Ok(Some(StreamErrorCondition::UndefinedCondition));
            }
            condition = Some(
                StreamErrorCondition::from_name(child.name())
                    .unwrap_or(StreamErrorCondition::UndefinedCondition),
            );
        }
    }
    Ok(Some(
        condition.unwrap_or(StreamErrorCondition::UndefinedCondition),
    ))
}

#[cfg(test)]
mod tests;
