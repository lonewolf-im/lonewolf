// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::stanza::{
    BuildError, Element, MessageType, RoutedStanza, Stanza, StanzaNamespace, StanzaType,
};

use super::{FORWARD_NAMESPACE, NAMESPACE};
use crate::archive::ArchiveId;
use crate::delivery::{DeliveryError, HostLookup};
use crate::observer::MessageRole;

const STANZA_ID_NAMESPACE: &str = "urn:xmpp:sid:0";

pub struct Original<'a, A: ChunkAllocator> {
    pub stanza: &'a RoutedStanza<A>,
    pub role: MessageRole,
    /// The owner's archive ID for a sent copy.
    pub archived: Option<ArchiveId>,
}

/// Builds one copy per full JID in `targets`, with one shared forwarded payload.
/// Returns no copies when the result would exceed the stanza tree limits.
pub fn build<A: ChunkAllocator>(
    owner: &AccountKey,
    original: Original<'_, A>,
    hosts: &dyn HostLookup,
    targets: &[&str],
    mut arena: Arena<A>,
) -> Result<Vec<RoutedStanza<A>>, DeliveryError> {
    let view = original.stanza.resolve()?;
    let StanzaType::Message(kind) = view.stanza_type() else {
        return Err(DeliveryError);
    };
    if view.namespace() != StanzaNamespace::Client {
        return Err(DeliveryError);
    }
    let stanzas = (|| -> Result<Vec<Stanza>, BuildError> {
        let inner = match original.role {
            MessageRole::Received => view.to_element_in(&mut arena)?,
            MessageRole::Sent => {
                let archive_id = if let Some(id) = original.archived {
                    let mut buffer = [0; 20];
                    let capacity = buffer.len();
                    let mut output = buffer.as_mut_slice();
                    write!(&mut output, "{id}").map_err(|_| BuildError::InvalidText)?;
                    let written = capacity - output.len();
                    let id = std::str::from_utf8(&buffer[..written])
                        .map_err(|_| BuildError::InvalidText)?;
                    Some(
                        Element::builder_in("stanza-id", STANZA_ID_NAMESPACE, &mut arena)?
                            .attribute("id", "", id)?
                            .attribute("by", "", owner.as_str())?
                            .build()?,
                    )
                } else {
                    None
                };
                let recipient = view
                    .to()?
                    .filter(|to| hosts.is_local_host(to.domainpart()))
                    .map(|to| to.bare().as_str());
                let mut builder = view.to_element_builder_in_filtered(&mut arena, |child| {
                    if child.name() != "stanza-id" || child.namespace() != STANZA_ID_NAMESPACE {
                        return Ok(true);
                    }
                    let by = child.attribute("by", "")?;
                    Ok(by != Some(owner.as_str()) && (recipient.is_none() || by != recipient))
                })?;
                if let Some(id) = archive_id {
                    builder = builder.child(id)?;
                }
                builder.build()?
            }
        };
        let forwarded = Element::builder_in("forwarded", FORWARD_NAMESPACE, &mut arena)?
            .child(inner)?
            .build()?;
        let container = Element::builder_in(
            match original.role {
                MessageRole::Sent => "sent",
                MessageRole::Received => "received",
            },
            NAMESPACE,
            &mut arena,
        )?
        .child(forwarded)?
        .build()?;
        let owner_bare =
            Jid::from_trusted_parts_in(Some(owner.username()), owner.domain(), None, &mut arena)?;
        let wrapper_type = match kind {
            MessageType::Chat => MessageType::Chat,
            MessageType::Headline => MessageType::Headline,
            _ => MessageType::Normal,
        };
        let mut stanzas = Vec::with_capacity(targets.len());
        for target in targets {
            let target = Jid::parse_in(target, &mut arena)?;
            stanzas.push(
                Stanza::builder_in(
                    StanzaType::Message(wrapper_type),
                    StanzaNamespace::Client,
                    &mut arena,
                )
                .from(Some(owner_bare))?
                .to(Some(target))?
                .child(container)?
                .build()?,
            );
        }
        Ok(stanzas)
    })();
    match stanzas {
        Ok(stanzas) => Ok(RoutedStanza::from_parts_shared(stanzas, arena)),
        Err(BuildError::TreeLimitExceeded) => {
            tracing::debug!(outcome = "tree_limit_exceeded", "carbons copies skipped");
            Ok(Vec::new())
        }
        Err(_) => Err(DeliveryError),
    }
}
