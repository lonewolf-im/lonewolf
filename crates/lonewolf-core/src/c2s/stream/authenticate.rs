// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Write as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lonewolf_auth::scram::SCRAM_POLICY_ITERATIONS;
use lonewolf_auth::server::{BindingType, ClientFirst, Mechanism, ScramServer, ServerError};
use lonewolf_storage::account::{AccountKey, AccountRepository};
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::{Element, NodeRef, XML_NAMESPACE};

use super::establish::Established;
use super::outcome::CloseOutcome;
use super::session::{Session, namespace_error};
use crate::c2s::AuthService;
use crate::config::AuthMechanisms;
use crate::hosts::Hosts;

pub(super) const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const EMPTY_CHALLENGE: &str = "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
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

/// Runs SASL SCRAM until the client authenticates or exhausts its attempts.
/// A rejected request, an aborted exchange and a replaced request each cost one attempt.
pub(super) async fn authenticate<A: ChunkAllocator + Clone>(
    established: &mut Established<A>,
    hosts: &Hosts,
    auth: &AuthService,
    mechanisms: AuthMechanisms,
) -> Result<(AccountKey, Mechanism), CloseOutcome> {
    let Established {
        session,
        client_from,
        binding,
        auth_started_at: _,
    } = established;
    let host = session.host().to_owned();
    let Some(endpoint) = hosts.tls_server_end_point(&host) else {
        return Err(CloseOutcome::InternalError);
    };
    let mut authentication = Authentication {
        session,
        host: &host,
        client_from: client_from.as_deref(),
        exporter: &binding.exporter,
        endpoint,
        auth,
        mechanisms,
    };
    let mut replacement = None;
    for _ in 0..MAX_AUTH_ATTEMPTS {
        let request = match replacement.take() {
            Some(request) => request,
            None => match authentication.read_request().await? {
                Some(request) => request,
                None => continue,
            },
        };
        match authentication.attempt(request).await? {
            Attempt::Authenticated(account, mechanism) => return Ok((account, mechanism)),
            Attempt::Rejected => {}
            Attempt::Replaced(request) => replacement = Some(request),
        }
    }
    Err(authentication
        .session
        .writer
        .fail(CloseOutcome::AuthenticationAttemptsExceeded)
        .await)
}

struct Authentication<'a, A: ChunkAllocator> {
    session: &'a mut Session<A>,
    host: &'a str,
    client_from: Option<&'a str>,
    exporter: &'a [u8; 32],
    endpoint: &'a [u8],
    auth: &'a AuthService,
    mechanisms: AuthMechanisms,
}

struct AuthRequest {
    mechanism: Option<Mechanism>,
    initial: Vec<u8>,
}

enum Attempt {
    Authenticated(AccountKey, Mechanism),
    /// A SASL failure was sent and the client may try again.
    Rejected,
    /// The client opened a new exchange instead of answering the challenge.
    Replaced(AuthRequest),
}

enum Response {
    Data(Vec<u8>),
    Request(AuthRequest),
    Rejected,
}

/// The account a first message names, and whether its stored credential may authenticate it.
struct Identity {
    account: Option<AccountKey>,
    known: bool,
}

impl<A: ChunkAllocator + Clone> Authentication<'_, A> {
    /// Reads the next `<auth/>`; a malformed or aborted request is rejected and yields `None`.
    async fn read_request(&mut self) -> Result<Option<AuthRequest>, CloseOutcome> {
        let failure = match self.next_element().await? {
            StreamEvent::Element(element) => match parse_sasl_message(&element) {
                Ok(SaslMessage::Auth(request)) => return Ok(Some(request)),
                Ok(SaslMessage::Abort) => "aborted",
                Ok(SaslMessage::Response(_)) => {
                    return Err(self
                        .session
                        .writer
                        .fail(CloseOutcome::UnsupportedInput)
                        .await);
                }
                Err(condition) => condition,
            },
            _ => {
                return Err(self
                    .session
                    .writer
                    .fail(CloseOutcome::UnsupportedInput)
                    .await);
            }
        };
        self.reject(failure).await?;
        Ok(None)
    }

    async fn attempt(&mut self, request: AuthRequest) -> Result<Attempt, CloseOutcome> {
        let Some(mechanism) = request
            .mechanism
            .filter(|mechanism| self.mechanisms.allows(*mechanism))
        else {
            self.reject("invalid-mechanism").await?;
            return Ok(Attempt::Rejected);
        };
        let initial = if request.initial.is_empty() {
            self.session.writer.send(EMPTY_CHALLENGE).await?;
            match self.read_response().await? {
                Response::Data(initial) => initial,
                Response::Request(request) => return Ok(Attempt::Replaced(request)),
                Response::Rejected => return Ok(Attempt::Rejected),
            }
        } else {
            request.initial
        };
        let first = match ClientFirst::parse(mechanism, &initial, self.mechanisms.has_plus()) {
            Ok(first) => first,
            Err(error) => {
                self.reject(scram_failure(error)).await?;
                return Ok(Attempt::Rejected);
            }
        };
        let Some((identity, server, challenge)) = self.challenge(mechanism, first).await? else {
            return Ok(Attempt::Rejected);
        };
        self.send_sasl("challenge", &challenge).await?;
        let response = match self.read_response().await? {
            Response::Data(response) => response,
            Response::Request(request) => return Ok(Attempt::Replaced(request)),
            Response::Rejected => return Ok(Attempt::Rejected),
        };
        self.verify(mechanism, identity, &server, &response).await
    }

    /// Issues the server challenge for the account's verifier.
    /// Unknown accounts, stale credentials and authorization identity mismatches get a
    /// decoy verifier so the exchange takes the same path and fails only at the proof.
    async fn challenge(
        &mut self,
        mechanism: Mechanism,
        first: ClientFirst,
    ) -> Result<Option<(Identity, ScramServer, String)>, CloseOutcome> {
        let account = account_key(first.username(), self.host);
        let authzid_matches = first
            .authzid()
            .is_none_or(|authzid| account_key_from_jid(authzid).as_ref() == account.as_ref());
        let verifier = match account.as_ref() {
            Some(key) => match self.auth.accounts.get_scram(key, mechanism.hash()).await {
                Ok(verifier) => verifier,
                Err(_) => {
                    self.reject("temporary-auth-failure").await?;
                    return Ok(None);
                }
            },
            None => None,
        };
        let verifier = verifier.filter(|verifier| verifier.iterations() == SCRAM_POLICY_ITERATIONS);
        let known = verifier.is_some() && authzid_matches;
        let verifier = match verifier {
            Some(verifier) => verifier,
            None => match self.auth.decoy.verifier(
                mechanism.hash(),
                &decoy_identity(account.as_ref(), first.username(), self.host),
            ) {
                Ok(verifier) => verifier,
                Err(_) => {
                    return Err(self.session.writer.fail(CloseOutcome::InternalError).await);
                }
            },
        };
        let mut server_nonce = [0_u8; 24];
        if graviola::random::fill(&mut server_nonce).is_err() {
            return Err(self.session.writer.fail(CloseOutcome::InternalError).await);
        }
        let nonce = STANDARD.encode(server_nonce);
        match first.start(verifier, &nonce) {
            Ok((server, challenge)) => Ok(Some((Identity { account, known }, server, challenge))),
            Err(_) => Err(self.session.writer.fail(CloseOutcome::InternalError).await),
        }
    }

    /// Checks the client proof and, for a known account, that its credential is still current.
    async fn verify(
        &mut self,
        mechanism: Mechanism,
        identity: Identity,
        server: &ScramServer,
        response: &[u8],
    ) -> Result<Attempt, CloseOutcome> {
        let binding_data: &[u8] = match server.binding() {
            Some(BindingType::TlsExporter) => self.exporter,
            Some(BindingType::TlsServerEndPoint) => self.endpoint,
            None => &[],
        };
        let final_message = match server.finish(response, binding_data) {
            Ok(message) if identity.known => Some(message),
            Ok(_) | Err(ServerError::InvalidProof | ServerError::ChannelBindingMismatch) => None,
            Err(error) => {
                self.reject(scram_failure(error)).await?;
                return Ok(Attempt::Rejected);
            }
        };
        if let Some(final_message) = final_message {
            let Some(account) = identity.account else {
                return Err(CloseOutcome::InternalError);
            };
            let current = match self
                .auth
                .accounts
                .get_scram(&account, mechanism.hash())
                .await
            {
                Ok(current) => current,
                Err(_) => {
                    self.reject("temporary-auth-failure").await?;
                    return Ok(Attempt::Rejected);
                }
            };
            if current
                .as_ref()
                .is_some_and(|current| server.credential_is_current(current))
            {
                if self
                    .client_from
                    .is_some_and(|from| from != account.as_str())
                {
                    return Err(self.session.writer.fail(CloseOutcome::InvalidFrom).await);
                }
                self.send_sasl("success", &final_message).await?;
                return Ok(Attempt::Authenticated(account, mechanism));
            }
        }
        self.reject("not-authorized").await?;
        Ok(Attempt::Rejected)
    }

    /// Reads the client's answer to a challenge; a malformed answer is rejected.
    async fn read_response(&mut self) -> Result<Response, CloseOutcome> {
        let failure = match self.next_element().await? {
            StreamEvent::Element(element) => match parse_sasl_message(&element) {
                Ok(SaslMessage::Response(response)) => return Ok(Response::Data(response)),
                Ok(SaslMessage::Auth(request)) => return Ok(Response::Request(request)),
                Ok(SaslMessage::Abort) => "aborted",
                Err(condition) => condition,
            },
            _ => "malformed-request",
        };
        self.reject(failure).await?;
        Ok(Response::Rejected)
    }

    /// Reads the next event, ending the stream on the client's footer.
    async fn next_element(&mut self) -> Result<StreamEvent<A>, CloseOutcome> {
        let Some(event) = self.session.next_event().await? else {
            return Err(CloseOutcome::Eof);
        };
        if let Some(outcome) = namespace_error(&event) {
            return Err(self.session.writer.fail(outcome).await);
        }
        if matches!(event, StreamEvent::StreamEnd) {
            return Err(self.session.writer.close().await);
        }
        Ok(event)
    }

    async fn reject(&mut self, condition: &'static str) -> Result<(), CloseOutcome> {
        let mut xml = String::with_capacity(SASL_NAMESPACE.len() + condition.len() + 48);
        write!(
            xml,
            "<failure xmlns='{SASL_NAMESPACE}'><{condition}/></failure>"
        )
        .map_err(|_| CloseOutcome::InternalError)?;
        self.session.writer.send(&xml).await
    }

    async fn send_sasl(&mut self, kind: &'static str, message: &str) -> Result<(), CloseOutcome> {
        let mut xml = String::with_capacity(message.len() * 4 / 3 + 96);
        write!(xml, "<{kind} xmlns='{SASL_NAMESPACE}'>")
            .map_err(|_| CloseOutcome::InternalError)?;
        STANDARD.encode_string(message, &mut xml);
        write!(xml, "</{kind}>").map_err(|_| CloseOutcome::InternalError)?;
        self.session.writer.send(&xml).await
    }
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
    Auth(AuthRequest),
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
            Ok(SaslMessage::Auth(AuthRequest {
                mechanism: Mechanism::from_name(mechanism),
                initial: decode_sasl_text(content)?,
            }))
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
