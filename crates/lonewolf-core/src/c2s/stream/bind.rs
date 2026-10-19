// SPDX-License-Identifier: Apache-2.0

use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::future::{Either, select};
use futures_util::io::AsyncWrite;
use lonewolf_storage::account::{AccountKey, AccountReads};
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::{ArenaRead, ChunkAllocator};
use lonewolf_xmpp::parser::StreamEvent;
use lonewolf_xmpp::stanza::{
    CLIENT_NAMESPACE, IqType, NodeRef, STANZA_ERROR_NAMESPACE, StanzaKind, StanzaNamespace,
    StanzaRef, StanzaType,
};

use super::certificate::CertificateMonitor;
use super::establish::{Established, STARTTLS_FAILURE, is_starttls_element};
use super::header::{ResponseVersion, escape_attribute};
use super::outcome::CloseOutcome;
use super::session::{Session, Writer, namespace_error};
use crate::c2s::metrics::C2sWorkerMetrics;
use crate::hosts::Hosts;
use crate::router::{Registration, RouterError, RouterHandle};

const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const BIND_FEATURE: &str = "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>";
const BIND_FEATURES: &str =
    "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BindRejection {
    BadRequest,
    ServiceUnavailable,
    ResourceConstraint,
}

impl BindRejection {
    pub(crate) const ALL: [Self; 3] = [
        Self::BadRequest,
        Self::ServiceUnavailable,
        Self::ResourceConstraint,
    ];

    pub(crate) fn error_type(self) -> &'static str {
        match self {
            Self::BadRequest => "modify",
            Self::ServiceUnavailable => "cancel",
            Self::ResourceConstraint => "wait",
        }
    }

    pub(crate) fn condition(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::ServiceUnavailable => "service-unavailable",
            Self::ResourceConstraint => "resource-constraint",
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::ServiceUnavailable => "service_unavailable",
            Self::ResourceConstraint => "resource_constraint",
        }
    }
}

pub(super) struct Bound<A: ChunkAllocator> {
    pub(super) session: Session<A>,
    pub(super) monitor: Option<CertificateMonitor>,
    pub(super) registration: Registration<A>,
    pub(super) router: RouterHandle<A>,
    pub(super) storage: RedbStorage,
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
    storage: RedbStorage,
    settings: &super::StreamSettings<A>,
    allocator: A,
) -> Result<Bound<A>, CloseOutcome> {
    drop(established.client);
    let monitor = established.monitor;
    let mut session = established.session;
    let restart = session.restart();
    let context = session.close.clone();
    let result = super::run_phase(
        context.phase_deadline,
        CloseOutcome::BindingTimeout,
        context.interrupt(async {
            if restart.is_err() {
                return Err(session
                    .writer
                    .reject_header(
                        None,
                        false,
                        ResponseVersion::Current,
                        CloseOutcome::ParserError,
                    )
                    .await);
            }
            let operation = bind_session(
                &mut session,
                hosts,
                account,
                router,
                settings.max_resources_per_account,
                1 + settings.resource_binding_retries.get(),
                &storage,
                monitor.as_ref(),
                &settings.metrics,
            );
            match &monitor {
                Some(monitor) => monitor.interrupt(operation).await,
                None => operation.await,
            }
        }),
    )
    .await;
    let (registration, resource_requested) = match result {
        Ok(bound) => bound,
        Err(outcome) => return Err(session.finish(outcome).await),
    };
    Ok(Bound {
        session,
        monitor,
        registration,
        router: router.clone(),
        storage,
        allocator,
        resource_requested,
    })
}

#[expect(clippy::too_many_arguments)]
async fn bind_session<A: ChunkAllocator + Clone>(
    session: &mut Session<A>,
    hosts: &Hosts,
    account: &AccountKey,
    router: &RouterHandle<A>,
    max_resources_per_account: NonZeroUsize,
    max_failures: usize,
    storage: &RedbStorage,
    certificate: Option<&CertificateMonitor>,
    metrics: &C2sWorkerMetrics,
) -> Result<(Registration<A>, bool), CloseOutcome> {
    let header = session.read_header(hosts).await?;
    if header.host != session.host() {
        return Err(session
            .writer
            .reject_header(
                header.response_to.as_deref(),
                header.client_content_namespace,
                ResponseVersion::Current,
                CloseOutcome::HostUnknown,
            )
            .await);
    }
    if header
        .response_to
        .as_deref()
        .is_some_and(|from| from != account.as_str())
    {
        return Err(session
            .writer
            .reject_header(
                header.response_to.as_deref(),
                header.client_content_namespace,
                ResponseVersion::Current,
                CloseOutcome::InvalidFrom,
            )
            .await);
    }
    session.writer.send_header(&header).await?;
    let extension_features = router.stream_features(session.host());
    if extension_features.is_empty() {
        session.writer.send(BIND_FEATURES).await?;
    } else {
        let features =
            format!("<stream:features>{BIND_FEATURE}{extension_features}</stream:features>");
        session.writer.send(&features).await?;
    }
    let mut invalid_attempts = 0;
    loop {
        if let Some(monitor) = certificate {
            monitor.check()?;
        }
        let parsed = match session.next_event().await? {
            Some(StreamEvent::Element(element)) if is_starttls_element(&element) => {
                session.writer.send(STARTTLS_FAILURE).await?;
                return Err(CloseOutcome::StartTlsRejected);
            }
            Some(StreamEvent::Stanza(parsed)) => parsed,
            Some(StreamEvent::RejectedStanza(parsed)) => {
                let rejected = parsed.value();
                if rejected.namespace() != StanzaNamespace::Client {
                    return Err(CloseOutcome::InvalidNamespace);
                }
                if rejected.kind() != StanzaKind::Iq {
                    return Err(CloseOutcome::UnsupportedInput);
                }
                let from = rejected
                    .from(parsed.arena())
                    .map_err(|_| CloseOutcome::InternalError)?;
                if rejected.invalid_from()
                    || from.is_some_and(|from| from.as_str() != account.as_str())
                {
                    return Err(CloseOutcome::InvalidFrom);
                }
                let to = rejected
                    .to(parsed.arena())
                    .map_err(|_| CloseOutcome::InternalError)?;
                if rejected.invalid_to()
                    || to.is_some_and(|to| {
                        to.as_str() != session.host() && to.as_str() != account.as_str()
                    })
                {
                    return Err(CloseOutcome::UnsupportedInput);
                }
                if !rejected.can_reply() {
                    continue;
                }
                let id = rejected
                    .id(parsed.arena())
                    .map_err(|_| CloseOutcome::InternalError)?
                    .unwrap_or("");
                reject_bind(
                    &mut session.writer,
                    id,
                    BindRejection::BadRequest,
                    &mut invalid_attempts,
                    max_failures,
                    metrics,
                )
                .await?;
                continue;
            }
            Some(StreamEvent::StreamEnd) | None => return Err(CloseOutcome::StreamEnd),
            Some(event) => {
                let outcome = namespace_error(&event).unwrap_or(CloseOutcome::UnsupportedInput);
                return Err(outcome);
            }
        };
        let Ok(stanza) = parsed.value().resolve(parsed.arena()) else {
            return Err(CloseOutcome::InternalError);
        };
        if stanza.namespace() != StanzaNamespace::Client {
            return Err(CloseOutcome::InvalidNamespace);
        }
        let StanzaType::Iq(iq_type) = stanza.stanza_type() else {
            return Err(CloseOutcome::UnsupportedInput);
        };
        let Ok(from) = stanza.from() else {
            return Err(CloseOutcome::InternalError);
        };
        if from.is_some_and(|from| from.as_str() != account.as_str()) {
            return Err(CloseOutcome::InvalidFrom);
        }
        let Ok(to) = stanza.to() else {
            return Err(CloseOutcome::InternalError);
        };
        if to.is_some_and(|to| to.as_str() != session.host() && to.as_str() != account.as_str()) {
            return Err(CloseOutcome::UnsupportedInput);
        }
        if matches!(iq_type, IqType::Result | IqType::Error) {
            continue;
        }
        let id = match stanza.id() {
            Ok(Some(id)) => id,
            Ok(None) => return Err(CloseOutcome::ParserError),
            Err(_) => return Err(CloseOutcome::InternalError),
        };
        let payload = stanza
            .children()
            .map_err(|_| CloseOutcome::InternalError)?
            .next()
            .transpose()
            .map_err(|_| CloseOutcome::InternalError)?;
        if iq_type != IqType::Set
            || !payload.is_some_and(|payload| {
                payload.name() == "bind" && payload.namespace() == BIND_NAMESPACE
            })
        {
            reject_bind(
                &mut session.writer,
                id,
                BindRejection::ServiceUnavailable,
                &mut invalid_attempts,
                max_failures,
                metrics,
            )
            .await?;
            continue;
        }
        let mut requested = match requested_resource(&stanza) {
            Ok(requested) => requested,
            Err(BindRequestError::Malformed) => {
                reject_bind(
                    &mut session.writer,
                    id,
                    BindRejection::BadRequest,
                    &mut invalid_attempts,
                    max_failures,
                    metrics,
                )
                .await?;
                continue;
            }
            Err(BindRequestError::Internal) => {
                return Err(CloseOutcome::InternalError);
            }
        };
        let result = match router
            .register(account, requested, max_resources_per_account)
            .await
        {
            Err(RouterError::InvalidResource) if requested.is_some() => {
                requested = None;
                router
                    .register(account, None, max_resources_per_account)
                    .await
            }
            result => result,
        };
        let registration = match result {
            Ok(registration) => registration,
            Err(RouterError::ResourceLimit) => {
                reject_bind(
                    &mut session.writer,
                    id,
                    BindRejection::ResourceConstraint,
                    &mut invalid_attempts,
                    max_failures,
                    metrics,
                )
                .await?;
                continue;
            }
            Err(_) => return Err(CloseOutcome::InternalError),
        };
        let registration =
            complete_binding(&mut session.writer, storage, certificate, registration, id).await?;
        metrics.binding_succeeded();
        return Ok((registration, requested.is_some()));
    }
}

async fn complete_binding<A: ChunkAllocator, W: AsyncWrite + Unpin>(
    writer: &mut Writer<W>,
    storage: &RedbStorage,
    certificate: Option<&CertificateMonitor>,
    registration: Registration<A>,
    id: &str,
) -> Result<Registration<A>, CloseOutcome> {
    if let Some(monitor) = certificate {
        monitor.check()?;
    }
    // Register before this read so a later deletion can retire the session.
    if storage
        .begin_read()
        .await
        .map_err(|_| CloseOutcome::InternalError)?
        .account(registration.account())
        .await
        .map_err(|_| CloseOutcome::InternalError)?
        .is_none()
    {
        return Err(CloseOutcome::AccountDeleted);
    }
    match select(
        pin!(registration.wait_retired()),
        pin!(send_bind_result(writer, id, &registration)),
    )
    .await
    {
        Either::Left((Ok(retired), _)) => return Err(retired.cause.into()),
        Either::Left(_) => return Err(CloseOutcome::InternalError),
        Either::Right((result, _)) => result?,
    }
    Ok(registration)
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
                let text = element.text().map_err(|_| BindRequestError::Internal)?;
                if text.is_none()
                    && element
                        .children()
                        .map_err(|_| BindRequestError::Internal)?
                        .next()
                        .transpose()
                        .map_err(|_| BindRequestError::Internal)?
                        .is_some()
                {
                    return Err(BindRequestError::Malformed);
                }
                resource = Some(text.unwrap_or(""));
            }
            _ => return Err(BindRequestError::Malformed),
        }
    }
    Ok(resource.filter(|text| !text.is_empty()))
}

async fn send_bind_result<A: ChunkAllocator, W: AsyncWrite + Unpin>(
    writer: &mut Writer<W>,
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
    writer.send_stanza_xml(&xml, StanzaKind::Iq).await
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
    writer.send_stanza_xml(&xml, StanzaKind::Iq).await
}

async fn reject_bind(
    writer: &mut Writer,
    id: &str,
    rejection: BindRejection,
    attempts: &mut usize,
    max_failures: usize,
    metrics: &C2sWorkerMetrics,
) -> Result<(), CloseOutcome> {
    send_bind_error(writer, id, rejection.error_type(), rejection.condition()).await?;
    metrics.binding_rejected(rejection);
    *attempts += 1;
    if *attempts == max_failures {
        return Err(CloseOutcome::BindingAttemptsExceeded);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use compio::runtime::Runtime;
    use futures_channel::oneshot;
    use futures_util::future::join;
    use lonewolf_auth::scram::{
        SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
    };
    use lonewolf_storage::WriteTransaction;
    use lonewolf_storage::account::{AccountWrites, NewAccount};
    use lonewolf_util::arena::{Arena, ArenaConfig, GlobalChunkAllocator};
    use lonewolf_xmpp::jid::Jid;

    use super::*;
    use crate::c2s::metrics::C2sMetrics;
    use crate::config::Config;
    use crate::router::Router;
    use crate::router::local::LocalRouter;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct PendingOutput(Option<oneshot::Sender<()>>);

    impl AsyncWrite for PendingOutput {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(entered) = self.0.take() {
                let _ = entered.send(());
            }
            Poll::Pending
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            panic!("binding must not close the transport")
        }
    }

    #[test]
    fn deleted_account_rejects_provisional_registration_and_releases_resource_slot() -> TestResult {
        Runtime::new()?.block_on(async {
            let directory = tempfile::tempdir()?;
            let storage = RedbStorage::open(directory.path().join("accounts.redb"))?;
            let config = Config::default();
            let router = Router::new(
                Hosts::new(&config.hosts, None)?,
                LocalRouter::new(GlobalChunkAllocator),
            );
            let router = router.handle();
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let account = AccountKey::try_from(
                Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?,
            )?;
            let registration = router
                .register(&account, Some("desk"), NonZeroUsize::MIN)
                .await?;
            let mut writer = Writer::new(
                futures_util::io::Cursor::new(Vec::new()),
                "localhost".into(),
                C2sWorkerMetrics::detached(),
            );
            assert!(matches!(
                complete_binding(&mut writer, &storage, None, registration, "bind").await,
                Err(CloseOutcome::AccountDeleted)
            ));
            assert!(router.resource_match(&account, "desk").await?.is_none());
            let replacement = router
                .register(&account, Some("desk"), NonZeroUsize::MIN)
                .await?;
            assert_eq!(replacement.full_jid(), "alice@localhost/desk");
            Ok(())
        })
    }

    #[test]
    fn account_deletion_cancels_pending_bind_result_and_releases_resource_slot() -> TestResult {
        Runtime::new()?.block_on(async {
            let directory = tempfile::tempdir()?;
            let storage = RedbStorage::open(directory.path().join("accounts.redb"))?;
            let config = Config::default();
            let router = Router::new(
                Hosts::new(&config.hosts, None)?,
                LocalRouter::new(GlobalChunkAllocator),
            );
            let router = router.handle();
            let mut arena = Arena::try_new(ArenaConfig::default())?;
            let account = AccountKey::try_from(
                Jid::parse_in("alice@localhost", &mut arena)?.resolve(&arena)?,
            )?;
            let mut transaction = storage.begin_write().await?;
            transaction
                .create_account(NewAccount {
                    key: account.clone(),
                    credentials: ScramCredentials::new(ScramVerifier::Sha1(
                        ScramSha1Verifier::new([1; 16], SCRAM_POLICY_ITERATIONS, [2; 20], [3; 20]),
                    )),
                })
                .await?;
            transaction.commit().await?;
            let registration = router
                .register(&account, Some("desk"), NonZeroUsize::MIN)
                .await?;
            let unrelated =
                AccountKey::try_from(Jid::parse_in("bob@localhost", &mut arena)?.resolve(&arena)?)?;
            let bob = router
                .register(&unrelated, Some("desk"), NonZeroUsize::MIN)
                .await?;
            let metrics = C2sMetrics::detached();
            let (entered, pending) = oneshot::channel();
            let mut writer = Writer::new(
                PendingOutput(Some(entered)),
                "localhost".into(),
                metrics.worker(0, 0),
            );
            let deletion = async {
                pending.await?;
                let mut transaction = storage.begin_write().await?;
                transaction.delete_account(&account).await?;
                transaction.commit().await?;
                router.retire_account(&account).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (bound, deleted) = compio::time::timeout(
                std::time::Duration::from_secs(5),
                join(
                    complete_binding(&mut writer, &storage, None, registration, "bind"),
                    deletion,
                ),
            )
            .await?;
            deleted?;
            assert!(matches!(bound, Err(CloseOutcome::AccountDeleted)));
            assert!(router.resource_match(&account, "desk").await?.is_none());
            assert!(bob.liveness().is_alive());
            assert!(
                metrics
                    .render()?
                    .contains("lonewolf_c2s_stanzas_sent_total{listener=\"0\",kind=\"iq\"} 0\n")
            );
            let replacement = router
                .register(&account, Some("desk"), NonZeroUsize::MIN)
                .await?;
            assert_eq!(replacement.full_jid(), "alice@localhost/desk");
            Ok(())
        })
    }
}
