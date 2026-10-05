// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Write as _;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use lonewolf_auth::scram::SCRAM_POLICY_ITERATIONS;
use lonewolf_auth::server::{BindingType, ClientFirst, Mechanism, ScramServer, ServerError};
use lonewolf_storage::account::AccountKey;
use lonewolf_util::arena::{Arena, ArenaConfig, ChunkAllocator};
use lonewolf_xmpp::jid::Jid;
use lonewolf_xmpp::parser::{Parsed, StreamEvent};
use lonewolf_xmpp::stanza::{Element, NodeRef, XML_NAMESPACE};

use super::certificate::CertificateMonitor;
use super::establish::Established;
use super::outcome::CloseOutcome;
use super::session::{Session, namespace_error};
use crate::c2s::AuthService;
use crate::config::AuthMechanisms;
use crate::hosts::Hosts;
use crate::hosts::client_identity::{ClientValidity, VerifiedClient};

pub(super) const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const EMPTY_CHALLENGE: &str = "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>";
const MAX_AUTH_ATTEMPTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SaslMechanism {
    External,
    Scram(Mechanism),
}

impl SaslMechanism {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::External => "EXTERNAL",
            Self::Scram(mechanism) => mechanism.name(),
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        if name == "EXTERNAL" {
            Some(Self::External)
        } else {
            Mechanism::from_name(name).map(Self::Scram)
        }
    }
}

pub(super) fn sasl_features(mechanisms: AuthMechanisms, external_available: bool) -> String {
    let mut features = String::with_capacity(480);
    features.push_str("<stream:features>");
    if mechanisms.has_plus() {
        features.push_str("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'><channel-binding type='tls-server-end-point'/><channel-binding type='tls-exporter'/></sasl-channel-binding>");
    }
    features.push_str("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
    if mechanisms.allows_external() && external_available {
        features.push_str("<mechanism>EXTERNAL</mechanism>");
    }
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

/// A rejected request, an aborted exchange and a replaced request each cost one attempt.
pub(super) async fn authenticate<A: ChunkAllocator + Clone>(
    established: &mut Established<A>,
    hosts: &Hosts,
    auth: &AuthService,
    mechanisms: AuthMechanisms,
) -> Result<(AccountKey, SaslMechanism), CloseOutcome> {
    let Established {
        session,
        client_from,
        binding,
        auth_started_at: _,
        client,
        monitor,
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
        exporter_use: ExporterUse::Unused,
        endpoint,
        auth,
        mechanisms,
        client: client.as_ref(),
        client_validity: None,
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
        let attempt = authentication.attempt(request).await?;
        let exporter_finished = matches!(authentication.exporter_use, ExporterUse::InUse);
        if exporter_finished {
            authentication.exporter_use = ExporterUse::Finished;
        }
        match attempt {
            Attempt::Authenticated(account, mechanism) => {
                let validity = authentication.client_validity;
                if let Some(validity) = validity {
                    let client = client.take().ok_or(CloseOutcome::InternalError)?;
                    *monitor = Some(CertificateMonitor::new(client, validity));
                } else {
                    client.take();
                }
                return Ok((account, mechanism));
            }
            _ if exporter_finished => return Err(CloseOutcome::LocalClose),
            Attempt::Rejected => {}
            Attempt::Replaced(request) => replacement = Some(request),
        }
    }
    Err(CloseOutcome::AuthenticationAttemptsExceeded)
}

struct Authentication<'a, A: ChunkAllocator> {
    session: &'a mut Session<A>,
    host: &'a str,
    client_from: Option<&'a str>,
    exporter: &'a [u8; 32],
    exporter_use: ExporterUse,
    endpoint: &'a [u8],
    auth: &'a AuthService,
    mechanisms: AuthMechanisms,
    client: Option<&'a VerifiedClient>,
    client_validity: Option<ClientValidity>,
}

enum ExporterUse {
    Unused,
    InUse,
    Finished,
}

struct AuthRequest {
    mechanism: Option<SaslMechanism>,
    initial: Option<Vec<u8>>,
}

enum Attempt {
    Authenticated(AccountKey, SaslMechanism),
    Rejected,
    Replaced(AuthRequest),
}

enum Response {
    Data(Vec<u8>),
    Request(AuthRequest),
    Rejected,
}

enum Authorization {
    Allowed,
    Invalid,
}

struct Identity {
    account: Option<AccountKey>,
    credential_known: bool,
    authorization: Authorization,
}

impl<A: ChunkAllocator + Clone> Authentication<'_, A> {
    async fn read_request(&mut self) -> Result<Option<AuthRequest>, CloseOutcome> {
        let failure = match self.next_element().await? {
            StreamEvent::Element(element) => match parse_sasl_message(&element) {
                Ok(SaslMessage::Auth(request)) => return Ok(Some(request)),
                Ok(SaslMessage::Abort) => "aborted",
                Ok(SaslMessage::Response(_)) => {
                    return Err(CloseOutcome::UnsupportedInput);
                }
                Err(condition) => condition,
            },
            _ => {
                return Err(CloseOutcome::UnsupportedInput);
            }
        };
        self.reject(failure).await?;
        Ok(None)
    }

    async fn attempt(&mut self, request: AuthRequest) -> Result<Attempt, CloseOutcome> {
        let Some(mechanism) = request.mechanism.filter(|mechanism| match mechanism {
            SaslMechanism::External => {
                self.mechanisms.allows_external()
                    && self
                        .client
                        .is_some_and(|client| !client.identities().accounts.is_empty())
            }
            SaslMechanism::Scram(mechanism) => self.mechanisms.allows(*mechanism),
        }) else {
            self.reject("invalid-mechanism").await?;
            return Ok(Attempt::Rejected);
        };
        let initial = if request.initial.is_none() {
            self.session.writer.send(EMPTY_CHALLENGE).await?;
            match self.read_response().await? {
                Response::Data(initial) => initial,
                Response::Request(request) => return Ok(Attempt::Replaced(request)),
                Response::Rejected => return Ok(Attempt::Rejected),
            }
        } else {
            request.initial.unwrap_or_default()
        };
        let mechanism = match mechanism {
            SaslMechanism::External => return self.external(&initial).await,
            SaslMechanism::Scram(mechanism) => mechanism,
        };
        let first = match ClientFirst::parse(mechanism, &initial, self.mechanisms.has_plus()) {
            Ok(first) => first,
            Err(error) => {
                self.reject(scram_failure(error)).await?;
                return Ok(Attempt::Rejected);
            }
        };
        if first.binding() == Some(BindingType::TlsExporter) {
            match self.exporter_use {
                ExporterUse::Unused => self.exporter_use = ExporterUse::InUse,
                ExporterUse::InUse | ExporterUse::Finished => {
                    return Err(CloseOutcome::LocalClose);
                }
            }
        }
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

    async fn external(&mut self, initial: &[u8]) -> Result<Attempt, CloseOutcome> {
        let identity = match std::str::from_utf8(initial) {
            Ok(identity) => identity,
            Err(_) => {
                self.reject("malformed-request").await?;
                return Ok(Attempt::Rejected);
            }
        };
        let requested = if identity.is_empty() {
            None
        } else {
            match account_key_from_jid(identity) {
                Some(account) => Some(account),
                None => {
                    self.reject("invalid-authzid").await?;
                    return Ok(Attempt::Rejected);
                }
            }
        };
        let Some(client) = self.client else {
            return Err(CloseOutcome::InternalError);
        };
        let account = match client
            .identities()
            .authorize(requested.as_ref(), self.client_from)
        {
            Ok(account) => account.clone(),
            Err(_) => {
                self.reject("invalid-authzid").await?;
                return Ok(Attempt::Rejected);
            }
        };
        match self.auth.account_exists(&account).await {
            Ok(true) => {}
            Ok(false) => {
                self.reject("not-authorized").await?;
                return Ok(Attempt::Rejected);
            }
            Err(_) => {
                self.reject("temporary-auth-failure").await?;
                return Ok(Attempt::Rejected);
            }
        }
        if self
            .client_from
            .is_some_and(|from| from != account.as_str())
        {
            return Err(CloseOutcome::InvalidFrom);
        }
        let validity = super::certificate::revalidate(client, *client.validity()).await?;
        match self.auth.account_exists(&account).await {
            Ok(true) => {}
            Ok(false) => {
                self.reject("not-authorized").await?;
                return Ok(Attempt::Rejected);
            }
            Err(_) => {
                self.reject("temporary-auth-failure").await?;
                return Ok(Attempt::Rejected);
            }
        }
        super::certificate::before_expiry(
            validity.valid_until,
            self.session
                .writer
                .send("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"),
        )
        .await?;
        self.client_validity = Some(validity);
        Ok(Attempt::Authenticated(account, SaslMechanism::External))
    }

    /// Unknown accounts and unsupported stored credentials use a decoy until proof verification.
    async fn challenge(
        &mut self,
        mechanism: Mechanism,
        first: ClientFirst,
    ) -> Result<Option<(Identity, ScramServer, String)>, CloseOutcome> {
        let account = account_key(first.username(), self.host);
        let authorization = if first
            .authzid()
            .is_none_or(|authzid| account_key_from_jid(authzid).as_ref() == account.as_ref())
        {
            Authorization::Allowed
        } else {
            Authorization::Invalid
        };
        let verifier = match account.as_ref() {
            Some(key) => match self.auth.scram(key, mechanism.hash()).await {
                Ok(verifier) => verifier,
                Err(_) => {
                    self.reject("temporary-auth-failure").await?;
                    return Ok(None);
                }
            },
            None => None,
        };
        let verifier = verifier.filter(|verifier| verifier.iterations() == SCRAM_POLICY_ITERATIONS);
        let credential_known = verifier.is_some();
        let verifier = match verifier {
            Some(verifier) => verifier,
            None => match self.auth.decoy().verifier(
                mechanism.hash(),
                &decoy_identity(account.as_ref(), first.username(), self.host),
            ) {
                Ok(verifier) => verifier,
                Err(_) => {
                    return Err(CloseOutcome::InternalError);
                }
            },
        };
        let mut server_nonce = [0_u8; 24];
        if graviola::random::fill(&mut server_nonce).is_err() {
            return Err(CloseOutcome::InternalError);
        }
        let nonce = STANDARD.encode(server_nonce);
        match first.start(verifier, &nonce) {
            Ok((server, challenge)) => Ok(Some((
                Identity {
                    account,
                    credential_known,
                    authorization,
                },
                server,
                challenge,
            ))),
            Err(_) => Err(CloseOutcome::InternalError),
        }
    }

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
            Ok(message) if identity.credential_known => Some(message),
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
            let current = match self.auth.scram(&account, mechanism.hash()).await {
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
                // Authorization failures must not reveal an account before its credential is verified.
                if matches!(identity.authorization, Authorization::Invalid) {
                    self.reject("invalid-authzid").await?;
                    return Ok(Attempt::Rejected);
                }
                if self
                    .client_from
                    .is_some_and(|from| from != account.as_str())
                {
                    return Err(CloseOutcome::InvalidFrom);
                }
                self.send_sasl("success", &final_message).await?;
                return Ok(Attempt::Authenticated(
                    account,
                    SaslMechanism::Scram(mechanism),
                ));
            }
        }
        self.reject("not-authorized").await?;
        Ok(Attempt::Rejected)
    }

    async fn read_response(&mut self) -> Result<Response, CloseOutcome> {
        let failure = match self.next_element().await? {
            StreamEvent::Element(element) => match parse_sasl_message(&element) {
                Ok(SaslMessage::Response(response)) => return Ok(Response::Data(response)),
                Ok(SaslMessage::Auth(request)) => return Ok(Response::Request(request)),
                Ok(SaslMessage::Abort) => "aborted",
                Err(condition) => condition,
            },
            StreamEvent::Stanza(_) | StreamEvent::RejectedStanza(_) => {
                return Err(CloseOutcome::UnsupportedInput);
            }
            _ => "malformed-request",
        };
        self.reject(failure).await?;
        Ok(Response::Rejected)
    }

    async fn next_element(&mut self) -> Result<StreamEvent<A>, CloseOutcome> {
        let Some(event) = self.session.next_event().await? else {
            return Err(CloseOutcome::Eof);
        };
        if let Some(outcome) = namespace_error(&event) {
            return Err(outcome);
        }
        if matches!(event, StreamEvent::StreamEnd) {
            return Err(CloseOutcome::StreamEnd);
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
                mechanism: SaslMechanism::from_name(mechanism),
                initial: if content.is_none_or(str::is_empty) {
                    None
                } else {
                    Some(decode_sasl_text(content)?)
                },
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
