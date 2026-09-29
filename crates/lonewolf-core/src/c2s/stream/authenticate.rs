// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Write as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lonewolf_auth::scram::SCRAM_POLICY_ITERATIONS;
use lonewolf_auth::server::{BindingType, ClientFirst, Mechanism, ServerError};
use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::{Element, NodeRef, XML_NAMESPACE};

use super::establish::Established;
use super::outcome::CloseOutcome;
use super::session::{Session, Writer, namespace_error};
use crate::c2s::AuthService;
use crate::config::AuthMechanisms;
use crate::hosts::Hosts;

pub(super) const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const MAX_AUTH_ATTEMPTS: usize = 3;

pub(super) fn sasl_features(mechanisms: AuthMechanisms) -> String {
    let mut features = String::with_capacity(440);
    features.push_str("<stream:features>");
    if mechanisms.has_plus() {
        features.push_str("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding>");
    }
    features.push_str("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
    for mechanism in [
        Mechanism::Sha256Plus,
        Mechanism::Sha256,
        Mechanism::Sha1Plus,
        Mechanism::Sha1,
    ] {
        if mechanisms.allows(mechanism) {
            features.push_str("<mechanism>");
            features.push_str(mechanism.name());
            features.push_str("</mechanism>");
        }
    }
    features.push_str("</mechanisms></stream:features>");
    features
}

pub(super) async fn authenticate<A: ChunkAllocator + Clone>(
    established: &mut Established<A>,
    hosts: &Hosts,
    auth: &AuthService,
    mechanisms: AuthMechanisms,
) -> Result<(AccountKey, Mechanism), CloseOutcome> {
    let Some(endpoint) = hosts.tls_server_end_point(established.session.host()) else {
        return Err(CloseOutcome::InternalError);
    };
    let session = &mut established.session;
    let host = session.host().to_owned();
    let mut replacement_auth = None;
    for _ in 0..MAX_AUTH_ATTEMPTS {
        let (mechanism, initial) = if let Some(auth) = replacement_auth.take() {
            auth
        } else {
            let Some(event) = session.next_event().await? else {
                return Err(CloseOutcome::Eof);
            };
            if let Some(outcome) = namespace_error(&event) {
                return Err(session.writer.fail(outcome).await);
            }
            match event {
                StreamEvent::Element(element) => match parse_sasl_message(&element) {
                    Ok(SaslMessage::Auth { mechanism, payload }) => (mechanism, payload),
                    Ok(SaslMessage::Abort) => {
                        send_sasl_failure(&mut session.writer, "aborted").await?;
                        continue;
                    }
                    Err(condition) => {
                        send_sasl_failure(&mut session.writer, condition).await?;
                        continue;
                    }
                    _ => {
                        return Err(session.writer.fail(CloseOutcome::UnsupportedInput).await);
                    }
                },
                StreamEvent::StreamEnd => return Err(session.writer.close().await),
                _ => {
                    return Err(session.writer.fail(CloseOutcome::UnsupportedInput).await);
                }
            }
        };
        let Some(mechanism) = mechanism.filter(|mechanism| mechanisms.allows(*mechanism)) else {
            send_sasl_failure(&mut session.writer, "invalid-mechanism").await?;
            continue;
        };
        let initial = if initial.is_empty() {
            session
                .writer
                .send("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
                .await?;
            match next_challenge_response(session).await? {
                ChallengeResponse::Data(response) => response,
                ChallengeResponse::Auth { mechanism, payload } => {
                    replacement_auth = Some((mechanism, payload));
                    continue;
                }
                ChallengeResponse::Retry => continue,
            }
        } else {
            initial
        };
        let first = match ClientFirst::parse(mechanism, &initial, mechanisms.has_plus()) {
            Ok(first) => first,
            Err(error) => {
                send_sasl_failure(&mut session.writer, scram_failure(error)).await?;
                continue;
            }
        };
        let binding_kind = first.binding();
        let account = account_key(first.username(), &host);
        let authzid_matches = first
            .authzid()
            .is_none_or(|authzid| account_key_from_jid(authzid).as_ref() == account.as_ref());
        let verifier = match account.as_ref() {
            Some(key) => match auth.accounts.get_scram(key, mechanism.hash()).await {
                Ok(verifier) => verifier,
                Err(_) => {
                    send_sasl_failure(&mut session.writer, "temporary-auth-failure").await?;
                    continue;
                }
            },
            None => None,
        };
        let verifier = verifier.filter(|verifier| verifier.iterations() == SCRAM_POLICY_ITERATIONS);
        let known = verifier.is_some() && authzid_matches;
        let verifier = match verifier {
            Some(verifier) => verifier,
            None => match auth.decoy.verifier(
                mechanism.hash(),
                &decoy_identity(account.as_ref(), first.username(), &host),
            ) {
                Ok(verifier) => verifier,
                Err(_) => return Err(session.writer.fail(CloseOutcome::InternalError).await),
            },
        };
        let mut server_nonce = [0_u8; 24];
        if graviola::random::fill(&mut server_nonce).is_err() {
            return Err(session.writer.fail(CloseOutcome::InternalError).await);
        }
        let nonce = STANDARD.encode(server_nonce);
        let (server, challenge) = match first.start(verifier, &nonce) {
            Ok(value) => value,
            Err(_) => return Err(session.writer.fail(CloseOutcome::InternalError).await),
        };
        send_sasl_data(&mut session.writer, "challenge", &challenge).await?;
        let response = match next_challenge_response(session).await? {
            ChallengeResponse::Data(response) => response,
            ChallengeResponse::Auth { mechanism, payload } => {
                replacement_auth = Some((mechanism, payload));
                continue;
            }
            ChallengeResponse::Retry => continue,
        };
        let binding_data: &[u8] = match binding_kind {
            Some(BindingType::TlsExporter) => &established.binding.exporter,
            Some(BindingType::TlsServerEndPoint) => endpoint,
            None => &[],
        };
        let final_message = server.finish(&response, binding_data);
        let authenticated = match final_message {
            Ok(message) if known => Some(message),
            Ok(_) | Err(ServerError::InvalidProof | ServerError::ChannelBindingMismatch) => None,
            Err(error) => {
                send_sasl_failure(&mut session.writer, scram_failure(error)).await?;
                continue;
            }
        };
        if let Some(final_message) = authenticated {
            let Some(account_key) = account.as_ref() else {
                return Err(CloseOutcome::InternalError);
            };
            let current = match auth.accounts.get_scram(account_key, mechanism.hash()).await {
                Ok(current) => current,
                Err(_) => {
                    send_sasl_failure(&mut session.writer, "temporary-auth-failure").await?;
                    continue;
                }
            };
            if current
                .as_ref()
                .is_some_and(|current| server.credential_is_current(current))
            {
                if established
                    .client_from
                    .as_deref()
                    .is_some_and(|from| from != account_key.as_str())
                {
                    return Err(session.writer.fail(CloseOutcome::InvalidFrom).await);
                }
                send_sasl_data(&mut session.writer, "success", &final_message).await?;
                return account
                    .map(|account| (account, mechanism))
                    .ok_or(CloseOutcome::InternalError);
            }
        }
        send_sasl_failure(&mut session.writer, "not-authorized").await?;
    }
    Err(session
        .writer
        .fail(CloseOutcome::AuthenticationAttemptsExceeded)
        .await)
}

pub(super) fn account_key(username: &str, host: &str) -> Option<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::from_parts_in(Some(username), host, None, &mut arena).ok()?;
    AccountKey::try_from(jid.resolve(&arena).ok()?).ok()
}

pub(super) fn decoy_identity<'a>(
    account: Option<&'a AccountKey>,
    username: &str,
    host: &str,
) -> Cow<'a, str> {
    match account {
        Some(account) => Cow::Borrowed(account.as_str()),
        None => Cow::Owned(format!("\0{host}\0{username}")),
    }
}

fn account_key_from_jid(jid: &str) -> Option<AccountKey> {
    let mut arena = Arena::try_new(ArenaConfig::default()).ok()?;
    let jid = Jid::parse_in(jid, &mut arena).ok()?;
    AccountKey::try_from(jid.resolve(&arena).ok()?).ok()
}

fn scram_failure(error: ServerError) -> &'static str {
    match error {
        ServerError::Malformed => "malformed-request",
        ServerError::UnsupportedBinding => "malformed-request",
        ServerError::ChannelBindingMismatch | ServerError::InvalidProof => "not-authorized",
        ServerError::HashMismatch | ServerError::RandomUnavailable => "temporary-auth-failure",
    }
}

enum SaslMessage {
    Auth {
        mechanism: Option<Mechanism>,
        payload: Vec<u8>,
    },
    Response(Vec<u8>),
    Abort,
}

fn parse_sasl_message<A: ChunkAllocator>(
    element: &Parsed<Element, A>,
) -> Result<SaslMessage, &'static str> {
    let view = element
        .value()
        .resolve(element.arena())
        .map_err(|_| "malformed-request")?;
    if view.namespace() != SASL_NAMESPACE {
        return Err("malformed-request");
    }
    let mut mechanism = None;
    let mut attribute_count = 0;
    for attribute in view.attributes().map_err(|_| "malformed-request")? {
        let attribute = attribute.map_err(|_| "malformed-request")?;
        if attribute.name == "lang" && attribute.namespace == XML_NAMESPACE {
            continue;
        }
        attribute_count += 1;
        if attribute.name == "mechanism" && attribute.namespace.is_empty() {
            mechanism = Some(attribute.value);
        }
    }
    let mut content = None;
    for child in view.children().map_err(|_| "malformed-request")? {
        let child = child.map_err(|_| "malformed-request")?;
        match child {
            NodeRef::Text(text) if content.is_none() => content = Some(text),
            _ => return Err("malformed-request"),
        }
    }
    match view.name() {
        "auth" if attribute_count == 1 => {
            let mechanism = mechanism.ok_or("malformed-request")?;
            Ok(SaslMessage::Auth {
                mechanism: Mechanism::from_name(mechanism),
                payload: decode_sasl_text(content)?,
            })
        }
        "response" if attribute_count == 0 => Ok(SaslMessage::Response(decode_sasl_text(content)?)),
        "abort" if attribute_count == 0 && content.is_none() => Ok(SaslMessage::Abort),
        _ => Err("malformed-request"),
    }
}

fn decode_sasl_text(text: Option<&str>) -> Result<Vec<u8>, &'static str> {
    let text = text.unwrap_or_default();
    if text == "=" || text.is_empty() {
        return Ok(Vec::new());
    }
    if text.len() > 8_192 {
        return Err("malformed-request");
    }
    STANDARD.decode(text).map_err(|_| "incorrect-encoding")
}

enum ChallengeResponse {
    Data(Vec<u8>),
    Auth {
        mechanism: Option<Mechanism>,
        payload: Vec<u8>,
    },
    Retry,
}

/// Reads the client's answer to a challenge; a malformed answer is rejected and retried.
async fn next_challenge_response<A: ChunkAllocator + Clone>(
    session: &mut Session<A>,
) -> Result<ChallengeResponse, CloseOutcome> {
    let Some(event) = session.next_event().await? else {
        return Err(CloseOutcome::Eof);
    };
    if let Some(outcome) = namespace_error(&event) {
        return Err(session.writer.fail(outcome).await);
    }
    let failure = match event {
        StreamEvent::Element(element) => match parse_sasl_message(&element) {
            Ok(SaslMessage::Response(response)) => return Ok(ChallengeResponse::Data(response)),
            Ok(SaslMessage::Auth { mechanism, payload }) => {
                return Ok(ChallengeResponse::Auth { mechanism, payload });
            }
            Ok(SaslMessage::Abort) => "aborted",
            Err(condition) => condition,
        },
        StreamEvent::StreamEnd => return Err(session.writer.close().await),
        _ => "malformed-request",
    };
    send_sasl_failure(&mut session.writer, failure).await?;
    Ok(ChallengeResponse::Retry)
}

async fn send_sasl_failure(
    writer: &mut Writer,
    condition: &'static str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(SASL_NAMESPACE.len() + condition.len() + 48);
    write!(
        xml,
        "<failure xmlns='{SASL_NAMESPACE}'><{condition}/></failure>"
    )
    .map_err(|_| CloseOutcome::InternalError)?;
    writer.send(&xml).await
}

async fn send_sasl_data(
    writer: &mut Writer,
    kind: &'static str,
    message: &str,
) -> Result<(), CloseOutcome> {
    let mut xml = String::with_capacity(message.len() * 4 / 3 + 96);
    write!(xml, "<{kind} xmlns='{SASL_NAMESPACE}'>").map_err(|_| CloseOutcome::InternalError)?;
    STANDARD.encode_string(message, &mut xml);
    write!(xml, "</{kind}>").map_err(|_| CloseOutcome::InternalError)?;
    writer.send(&xml).await
}
