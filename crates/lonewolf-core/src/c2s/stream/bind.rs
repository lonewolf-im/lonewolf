// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;

use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, IqType, NodeRef, STANZA_ERROR_NAMESPACE, StanzaNamespace, StanzaRef,
    StanzaType,
};

use super::establish::Established;
use super::header::escape_attribute;
use super::outcome::CloseOutcome;
use super::session::{Session, Writer, namespace_error};
use crate::hosts::Hosts;
use crate::router::{Registration, RouterError, RouterHandle};

const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const BIND_FEATURES: &str =
    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";
const MAX_BIND_FAILURES: usize = 6;

/// An authenticated stream whose resource is registered with the router.
pub(super) struct Bound<A: ChunkAllocator> {
    pub(super) session: Session<A>,
    pub(super) registration: Registration<A>,
    pub(super) router: RouterHandle<A>,
    pub(super) allocator: A,
    pub(super) resource_requested: bool,
}

enum BindRequestError {
    Malformed,
    Internal,
}

pub(super) async fn bind_resource<A: ChunkAllocator + Clone>(
    established: Established<A>,
    hosts: &Hosts,
    account: &AccountKey,
    router: &RouterHandle<A>,
    max_resources_per_account: NonZeroUsize,
    allocator: A,
) -> Result<Bound<A>, CloseOutcome> {
    let mut session = established.session.restart().await?;
    let header = session.read_header(hosts).await?;
    if header.host != session.host()
        || header
            .response_to
            .as_deref()
            .is_some_and(|from| from != account.as_str())
    {
        return Err(session
            .writer
            .reject_header(
                header.response_to.as_deref(),
                header.client_content_namespace,
                CloseOutcome::InvalidFrom,
            )
            .await);
    }
    session.writer.send_header(&header).await?;
    session.writer.send(BIND_FEATURES).await?;
    let mut invalid_attempts = 0;
    loop {
        let parsed = match session.next_event().await? {
            Some(StreamEvent::Stanza(parsed)) => parsed,
            Some(StreamEvent::StreamEnd) | None => return Err(session.writer.close().await),
            Some(event) => {
                let outcome = namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedInput);
                return Err(session.writer.fail(outcome).await);
            }
        };
        let Ok(stanza) = parsed.value().resolve(parsed.arena()) else {
            return Err(session.writer.fail(CloseOutcome::InternalError).await);
        };
        if stanza.namespace() != StanzaNamespace::Client {
            return Err(session.writer.fail(CloseOutcome::InvalidNamespace).await);
        }
        if stanza.stanza_type() != StanzaType::Iq(IqType::Set) {
            return Err(session.writer.fail(CloseOutcome::UnsupportedInput).await);
        }
        let id = match stanza.id() {
            Ok(Some(id)) => id,
            Ok(None) => return Err(session.writer.fail(CloseOutcome::ParserError).await),
            Err(_) => return Err(session.writer.fail(CloseOutcome::InternalError).await),
        };
        let Ok(from) = stanza.from() else {
            return Err(session.writer.fail(CloseOutcome::InternalError).await);
        };
        if from.is_some_and(|from| from.as_str() != account.as_str()) {
            return Err(session.writer.fail(CloseOutcome::InvalidFrom).await);
        }
        let Ok(to) = stanza.to() else {
            return Err(session.writer.fail(CloseOutcome::InternalError).await);
        };
        if to.is_some_and(|to| to.as_str() != session.host()) {
            return Err(session.writer.fail(CloseOutcome::UnsupportedInput).await);
        }
        let requested = match requested_resource(&stanza) {
            Ok(requested) => requested,
            Err(BindRequestError::Malformed) => {
                send_bind_error(&mut session.writer, id, "modify", "bad-request").await?;
                invalid_attempts += 1;
                if invalid_attempts == MAX_BIND_FAILURES {
                    return Err(session
                        .writer
                        .fail(CloseOutcome::BindingAttemptsExceeded)
                        .await);
                }
                continue;
            }
            Err(BindRequestError::Internal) => {
                return Err(session.writer.fail(CloseOutcome::InternalError).await);
            }
        };
        let registration = match router
            .register(account, requested, max_resources_per_account)
            .await
        {
            Ok(registration) => registration,
            Err(RouterError::InvalidResource) => {
                send_bind_error(&mut session.writer, id, "modify", "bad-request").await?;
                invalid_attempts += 1;
                if invalid_attempts == MAX_BIND_FAILURES {
                    return Err(session
                        .writer
                        .fail(CloseOutcome::BindingAttemptsExceeded)
                        .await);
                }
                continue;
            }
            Err(RouterError::ResourceLimit) => {
                send_bind_error(&mut session.writer, id, "wait", "resource-constraint").await?;
                continue;
            }
            Err(_) => return Err(session.writer.fail(CloseOutcome::InternalError).await),
        };
        send_bind_result(&mut session.writer, id, &registration).await?;
        return Ok(Bound {
            session,
            registration,
            router: router.clone(),
            allocator,
            resource_requested: requested.is_some(),
        });
    }
}

fn requested_resource<'a, R: ArenaRead>(
    stanza: &StanzaRef<'a, R>,
) -> Result<Option<&'a str>, BindRequestError> {
    let mut children = stanza.children().map_err(|_| BindRequestError::Internal)?;
    let bind = children
        .next()
        .ok_or(BindRequestError::Malformed)?
        .map_err(|_| BindRequestError::Internal)?;
    if children
        .next()
        .transpose()
        .map_err(|_| BindRequestError::Internal)?
        .is_some()
        || bind.name() != "bind"
        || bind.namespace() != BIND_NAMESPACE
    {
        return Err(BindRequestError::Malformed);
    }
    if bind
        .attributes()
        .map_err(|_| BindRequestError::Internal)?
        .next()
        .transpose()
        .map_err(|_| BindRequestError::Internal)?
        .is_some()
    {
        return Err(BindRequestError::Malformed);
    }
    let mut resource = None;
    for child in bind.children().map_err(|_| BindRequestError::Internal)? {
        match child.map_err(|_| BindRequestError::Internal)? {
            NodeRef::Text(text) if text.trim().is_empty() => {}
            NodeRef::Element(element)
                if element.name() == "resource"
                    && element.namespace() == BIND_NAMESPACE
                    && resource.is_none() =>
            {
                if element
                    .attributes()
                    .map_err(|_| BindRequestError::Internal)?
                    .next()
                    .transpose()
                    .map_err(|_| BindRequestError::Internal)?
                    .is_some()
                {
                    return Err(BindRequestError::Malformed);
                }
                let text = element
                    .text()
                    .map_err(|_| BindRequestError::Internal)?
                    .filter(|text| !text.is_empty())
                    .ok_or(BindRequestError::Malformed)?;
                resource = Some(text);
            }
            _ => return Err(BindRequestError::Malformed),
        }
    }
    Ok(resource)
}

async fn send_bind_result<A: ChunkAllocator>(
    writer: &mut Writer,
    id: &str,
    registration: &Registration<A>,
) -> Result<(), CloseOutcome> {
    let jid = registration.full_jid();
    let mut xml = String::with_capacity(119 + CLIENT_NAMESPACE.len() + id.len() + jid.len());
    xml.push_str("<iq xmlns='");
    xml.push_str(CLIENT_NAMESPACE);
    xml.push_str("' type='result' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'><bind xmlns='");
    xml.push_str(BIND_NAMESPACE);
    xml.push_str("'><jid>");
    escape_text(&mut xml, &jid);
    xml.push_str("</jid></bind></iq>");
    writer.send(&xml).await
}

async fn send_bind_error(
    writer: &mut Writer,
    id: &str,
    error_type: &str,
    condition: &str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(129 + CLIENT_NAMESPACE.len() + id.len());
    xml.push_str("<iq xmlns='");
    xml.push_str(CLIENT_NAMESPACE);
    xml.push_str("' type='error' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'><error type='");
    xml.push_str(error_type);
    xml.push_str("'><");
    xml.push_str(condition);
    xml.push_str(" xmlns='");
    xml.push_str(STANZA_ERROR_NAMESPACE);
    xml.push_str("'/></error></iq>");
    writer.send(&xml).await
}

fn escape_text(output: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(ch),
        }
    }
}
