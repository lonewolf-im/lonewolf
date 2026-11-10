// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use lonewolf_extension::Effects;
use lonewolf_extension::delivery::{Failure, FailureKind};
use lonewolf_extension::discovery::Discovery;
use lonewolf_extension::iq::{
    IqError, IqErrorPayload, IqHandler, IqReply, IqRequest, IqRequestType, IqScope, Requester,
    SessionIqHandler, XmlSpace,
};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::{RedbRead, RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ArenaRead, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};
use lonewolf_xmpp::stanza::{Element, Stanza, StanzaErrorCondition, StanzaRef, XML_NAMESPACE};

use super::Origin;
use crate::delivery::{
    EffectsDiagnostics, EffectsError, EffectsIdentity, Pending, RouterDelivery, after_turn,
    commit_and_deliver, report_failure, report_server_failure, storage_failure,
};
use crate::router::{Destination, MailboxEntry, RoutedStanza};
use crate::stages::iq::{
    IqTarget, ReplyError, error_reply_omitting_payload, iq_requester, iq_target,
    require_iq_account, result_reply,
};
use crate::stages::{Stage, StageFailure};

pub(crate) enum IqInput<A: ChunkAllocator> {
    Owned {
        request: Stanza,
        arena: Arena<A>,
        sender: Jid,
    },
    Routed(RoutedStanza<A>),
}

impl<A: ChunkAllocator + Clone> IqInput<A> {
    pub(crate) fn into_owned(
        self,
        allocator: &A,
    ) -> Result<(Stanza, Arena<A>, Option<Jid>), StageFailure> {
        match self {
            Self::Owned {
                request,
                arena,
                sender,
            } => Ok((request, arena, Some(sender))),
            Self::Routed(routed) => {
                let mut arena = Arena::try_new_in(Default::default(), allocator.clone())?;
                let request = routed.resolve()?.clone_in(&mut arena)?;
                Ok((request, arena, None))
            }
        }
    }
}

pub(crate) struct IqAnswer<A: ChunkAllocator> {
    pub(crate) request: Stanza,
    pub(crate) arena: Arena<A>,
    /// None uses the sender validated by the routed ingress.
    pub(crate) sender: Option<Jid>,
    pub(crate) response: Arena<A>,
    pub(crate) reply: Result<Option<Element>, IqError>,
    pub(crate) results: Vec<Stanza>,
}

pub(crate) struct IqCompletion<A: ChunkAllocator> {
    /// Write these entries before the answer to preserve mailbox order.
    pub(crate) queued: Vec<MailboxEntry<A>>,
    pub(crate) answer: IqAnswer<A>,
}

pub(crate) enum IqPending<A: ChunkAllocator> {
    Get(Pending<Result<IqCompletion<A>, StageFailure>>),
    Set {
        pending: Pending<Result<Vec<MailboxEntry<A>>, EffectsError>>,
        answer: IqAnswer<A>,
    },
}

impl<A: ChunkAllocator> IqPending<A> {
    pub(crate) async fn turned(&mut self) {
        match self {
            Self::Get(pending) => pending.turned().await,
            Self::Set { pending, .. } => pending.turned().await,
        }
    }
    pub(crate) async fn finished(self) -> Option<Result<IqCompletion<A>, StageFailure>> {
        match self {
            Self::Get(pending) => pending.finished().await,
            Self::Set { pending, answer } => pending.finished().await.map(|result| {
                result
                    .map(|queued| IqCompletion { queued, answer })
                    .map_err(|_| StageFailure)
            }),
        }
    }
}

pub(crate) enum IqDisposition<A: ChunkAllocator> {
    Unavailable {
        input: IqInput<A>,
        condition: StanzaErrorCondition,
        /// Retains the response budget until the origin queues the error.
        response: Option<Arena<A>>,
    },
    Answer(IqAnswer<A>),
    Ordered(IqPending<A>),
    SessionIq {
        handler: Arc<dyn SessionIqHandler<A>>,
        request: Stanza,
        arena: Arena<A>,
        sender: Jid,
        response: Arena<A>,
    },
}

enum Handler<A: ChunkAllocator> {
    Session(Arc<dyn SessionIqHandler<A>>),
    Regular(Option<Arc<dyn IqHandler<A, RedbStorage>>>),
}

fn lookup<A: ChunkAllocator + Clone, R: ArenaRead>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    view: &StanzaRef<'_, R>,
    sender: JidRef<'_>,
    destination: Destination,
    kind: IqRequestType,
) -> Result<Handler<A>, StageFailure> {
    let target = view.to()?.unwrap_or_else(|| sender.bare());
    let payload = view.children()?.next().transpose()?.ok_or(StageFailure)?;
    let scope = match destination {
        Destination::Account => IqScope::Account,
        Destination::Server => IqScope::Server,
        _ => return Err(StageFailure),
    };
    let registry = stage.router.iq_handlers(target.domainpart());
    if origin.session().is_some()
        && kind == IqRequestType::Set
        && scope == IqScope::Account
        && let Some(handler) =
            registry.and_then(|registry| registry.find_session(payload.namespace(), payload.name()))
    {
        return Ok(Handler::Session(Arc::clone(handler)));
    }
    Ok(Handler::Regular(
        registry
            .and_then(|registry| registry.find(scope, kind, payload.namespace(), payload.name()))
            .map(Arc::clone),
    ))
}

fn effective_sender<'a, A: ChunkAllocator>(
    request: &Stanza,
    arena: &'a Arena<A>,
    sender: Option<Jid>,
) -> Result<JidRef<'a>, StageFailure> {
    Ok(match sender {
        Some(sender) => sender.resolve(arena)?,
        None => request.resolve(arena)?.from()?.ok_or(StageFailure)?,
    })
}

/// Requires an admitted request addressed to an account or server.
pub(crate) async fn handle_request<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    input: IqInput<A>,
    destination: Destination,
    kind: IqRequestType,
    target_account: Option<AccountKey>,
) -> Result<IqDisposition<A>, StageFailure> {
    let response = if matches!(&input, IqInput::Owned { .. }) {
        Some(Arena::try_new_in(
            Default::default(),
            stage.allocator.clone(),
        )?)
    } else {
        None
    };
    let handler = match &input {
        IqInput::Owned {
            request,
            arena,
            sender,
        } => lookup(
            stage,
            origin,
            &request.resolve(arena)?,
            sender.resolve(arena)?,
            destination,
            kind,
        )?,
        IqInput::Routed(routed) => {
            let view = routed.resolve()?;
            lookup(
                stage,
                origin,
                &view,
                view.from()?.ok_or(StageFailure)?,
                destination,
                kind,
            )?
        }
    };
    if let Handler::Session(handler) = handler {
        let (request, arena, sender) = input.into_owned(stage.allocator)?;
        return Ok(IqDisposition::SessionIq {
            handler,
            request,
            arena,
            sender: sender.ok_or(StageFailure)?,
            response: response.ok_or(StageFailure)?,
        });
    }
    let target_account = if destination == Destination::Account && target_account.is_none() {
        Some(match &input {
            IqInput::Owned {
                request,
                arena,
                sender,
            } => {
                let sender = sender.resolve(arena)?;
                AccountKey::try_from(
                    request
                        .resolve(arena)?
                        .to()?
                        .unwrap_or_else(|| sender.bare())
                        .bare(),
                )?
            }
            IqInput::Routed(routed) => {
                AccountKey::try_from(routed.resolve()?.to()?.ok_or(StageFailure)?.bare())?
            }
        })
    } else {
        target_account
    };
    let Handler::Regular(Some(handler)) = handler else {
        return Ok(IqDisposition::Unavailable {
            input,
            condition: StanzaErrorCondition::ServiceUnavailable,
            response,
        });
    };
    let (request, arena, sender) = input.into_owned(stage.allocator)?;
    let response = match response {
        Some(response) => response,
        None => Arena::try_new_in(Default::default(), stage.allocator.clone())?,
    };
    let answer = IqAnswer {
        request,
        arena,
        sender,
        response,
        reply: Ok(None),
        results: Vec::new(),
    };
    match kind {
        IqRequestType::Get => prepare_get(stage, origin, answer, handler, target_account).await,
        IqRequestType::Set => prepare_set(stage, origin, answer, handler, target_account).await,
    }
}

pub(crate) enum Diagnostics {
    Session(AccountKey),
    External(Box<str>),
}

impl Diagnostics {
    fn report(&self, failure: Failure, target: Option<&AccountKey>) {
        match self {
            Self::Session(account) => report_failure(failure, account),
            Self::External(domain) => match target {
                Some(account) => report_failure(failure, account),
                None => report_server_failure(failure, domain),
            },
        }
    }
}

fn diagnostic_account<'a, A: ChunkAllocator + Clone>(
    origin: &'a Origin<'_, A>,
    target: Option<&'a AccountKey>,
) -> Option<&'a AccountKey> {
    origin.sender().or(target)
}

pub(crate) async fn prepare_get<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    answer: IqAnswer<A>,
    handler: Arc<dyn IqHandler<A, RedbStorage>>,
    target_account: Option<AccountKey>,
) -> Result<IqDisposition<A>, StageFailure> {
    let sender = effective_sender(&answer.request, &answer.arena, answer.sender)?;
    let target = answer
        .request
        .resolve(&answer.arena)?
        .to()?
        .unwrap_or_else(|| sender.bare());
    let discovery = Arc::clone(
        stage
            .router
            .discovery(target.domainpart())
            .ok_or(StageFailure)?,
    );
    let delivery = RouterDelivery::new(stage.router, stage.allocator, origin.session());
    let (transaction, ticket) = Arc::clone(stage.router.order())
        .fix(
            target_account.iter().cloned().collect(),
            stage.storage.begin_read(),
        )
        .await
        .map_err(|error| {
            origin.report(
                storage_failure(error, "iq_get_begin_read"),
                diagnostic_account(origin, target_account.as_ref()),
            );
            StageFailure
        })?;
    let diagnostics = match origin {
        Origin::Session(session) => Diagnostics::Session(session.account().clone()),
        Origin::Remote { local, .. } => Diagnostics::External(Box::from(*local)),
        Origin::Service { domain } => Diagnostics::External(Box::from(*domain)),
    };
    let IqAnswer {
        request,
        arena,
        sender,
        response,
        ..
    } = answer;
    let work = GetWork {
        diagnostics,
        target_account,
        transaction,
        handler,
        discovery,
        arena,
        request,
        sender,
        response,
        delivery,
    };
    let pending = after_turn(
        stage.work.start(),
        ticket,
        origin.session().map(|session| session.mailbox()),
        move |queued, ticket| async move {
            let result = work.run(queued).await;
            drop(ticket);
            result
        },
    );
    Ok(IqDisposition::Ordered(IqPending::Get(pending)))
}

pub(crate) async fn prepare_set<A: ChunkAllocator + Clone + 'static>(
    stage: &Stage<'_, A>,
    origin: &Origin<'_, A>,
    mut answer: IqAnswer<A>,
    handler: Arc<dyn IqHandler<A, RedbStorage>>,
    target_account: Option<AccountKey>,
) -> Result<IqDisposition<A>, StageFailure> {
    let sender = effective_sender(&answer.request, &answer.arena, answer.sender)?;
    let target = answer
        .request
        .resolve(&answer.arena)?
        .to()?
        .unwrap_or_else(|| sender.bare());
    let discovery = Arc::clone(
        stage
            .router
            .discovery(target.domainpart())
            .ok_or(StageFailure)?,
    );
    let delivery = RouterDelivery::new(stage.router, stage.allocator, origin.session());
    let mut transaction = stage.storage.begin_write().await.map_err(|error| {
        origin.report(
            storage_failure(error, "iq_set_begin_write"),
            diagnostic_account(origin, target_account.as_ref()),
        );
        StageFailure
    })?;
    let reply = match require_iq_account(&transaction, target_account.as_ref()).await {
        Err(error) => Err(error.into()),
        Ok(()) => {
            handler
                .set(
                    request_context(
                        &answer.request,
                        &answer.arena,
                        answer.sender,
                        &discovery,
                        &delivery,
                        None,
                    )?,
                    &mut transaction,
                    &delivery,
                    &mut answer.response,
                )
                .await
        }
    };
    match reply {
        Ok(IqReply {
            payload,
            effects,
            results,
        }) => {
            answer.reply = Ok(payload);
            answer.results = results;
            let identity = match origin {
                Origin::Session(session) => EffectsIdentity::Account(session.account().clone()),
                Origin::Remote { local, .. } => target_account.map_or_else(
                    || EffectsIdentity::Server(Box::from(*local)),
                    EffectsIdentity::Account,
                ),
                Origin::Service { domain } => target_account.map_or_else(
                    || EffectsIdentity::Server(Box::from(*domain)),
                    EffectsIdentity::Account,
                ),
            };
            let pending = commit_and_deliver(
                stage.work.start(),
                Arc::clone(stage.router.order()),
                transaction,
                effects,
                delivery,
                origin.session().map(|session| session.mailbox()),
                EffectsDiagnostics {
                    identity,
                    commit_operation: "iq_set_commit",
                    delivery_operation: "iq_set_effects",
                },
            );
            Ok(IqDisposition::Ordered(IqPending::Set { pending, answer }))
        }
        Err(error) => {
            drop(transaction);
            if let Some(failure) = error.handler_error().failure() {
                origin.report(failure, diagnostic_account(origin, target_account.as_ref()));
            }
            answer.reply = Err(error);
            Ok(IqDisposition::Answer(answer))
        }
    }
}

fn request_context<'a, A: ChunkAllocator + Clone>(
    request: &Stanza,
    arena: &'a Arena<A>,
    sender: Option<Jid>,
    discovery: &'a Discovery,
    delivery: &'a RouterDelivery<A>,
    requester: Option<Requester>,
) -> Result<IqRequest<'a, A>, StageFailure> {
    let sender = effective_sender(request, arena, sender)?;
    let view = request.resolve(arena)?;
    Ok(IqRequest {
        sender,
        target: view.to()?.unwrap_or_else(|| sender.bare()),
        discovery,
        sessions: delivery,
        requester,
        lang: view.lang()?,
        space: view
            .attribute("space", XML_NAMESPACE)?
            .map(XmlSpace::from_attribute),
        payload: view.children()?.next().transpose()?.ok_or(StageFailure)?,
    })
}

pub(crate) struct GetWork<A: ChunkAllocator> {
    pub(crate) diagnostics: Diagnostics,
    pub(crate) target_account: Option<AccountKey>,
    pub(crate) transaction: RedbRead,
    pub(crate) handler: Arc<dyn IqHandler<A, RedbStorage>>,
    pub(crate) discovery: Arc<Discovery>,
    pub(crate) arena: Arena<A>,
    pub(crate) request: Stanza,
    pub(crate) sender: Option<Jid>,
    pub(crate) response: Arena<A>,
    pub(crate) delivery: RouterDelivery<A>,
}

impl<A: ChunkAllocator + Clone> GetWork<A> {
    pub(crate) async fn run(
        mut self,
        queued: Vec<MailboxEntry<A>>,
    ) -> Result<IqCompletion<A>, StageFailure> {
        let reply = match iq_target(&self.transaction, self.target_account.as_ref()).await {
            Err(error) => Err(error.into()),
            Ok(target) => {
                let sender = effective_sender(&self.request, &self.arena, self.sender)?;
                let requester = match target {
                    IqTarget::Server => Ok(None),
                    IqTarget::Present => iq_requester(
                        self.delivery.router(),
                        self.target_account.as_ref().ok_or(StageFailure)?,
                        sender,
                        &self.transaction,
                    )
                    .await
                    .map(Some),
                    IqTarget::Missing => Ok(Some(
                        if sender.bare().as_str()
                            == self.target_account.as_ref().ok_or(StageFailure)?.as_str()
                        {
                            Requester::Owner
                        } else {
                            Requester::Other
                        },
                    )),
                };
                match requester {
                    Err(error) => Err(error.into()),
                    Ok(requester) => {
                        let request = request_context(
                            &self.request,
                            &self.arena,
                            self.sender,
                            &self.discovery,
                            &self.delivery,
                            requester,
                        )?;
                        match target {
                            IqTarget::Missing => self
                                .handler
                                .get_missing_account(request, &mut self.response)
                                .map(|payload| IqReply::new(payload, Effects::none())),
                            _ => {
                                self.handler
                                    .get(request, &self.transaction, &mut self.response)
                                    .await
                            }
                        }
                    }
                }
            }
        };
        drop(self.transaction);
        let (reply, results) = match reply {
            Ok(IqReply {
                payload,
                effects,
                results,
            }) => {
                (effects.deliver)(&self.delivery).await.map_err(|_| {
                    self.diagnostics.report(
                        Failure {
                            kind: FailureKind::Delivery,
                            operation: "iq_get_effects",
                        },
                        self.target_account.as_ref(),
                    );
                    StageFailure
                })?;
                (Ok(payload), results)
            }
            Err(error) => {
                if let Some(failure) = error.handler_error().failure() {
                    self.diagnostics
                        .report(failure, self.target_account.as_ref());
                }
                (Err(error), Vec::new())
            }
        };
        Ok(IqCompletion {
            queued,
            answer: IqAnswer {
                request: self.request,
                arena: self.arena,
                sender: self.sender,
                response: self.response,
                reply,
                results,
            },
        })
    }
}

pub(crate) enum AnswerStanzas<A: ChunkAllocator> {
    One { stanza: Stanza, arena: Arena<A> },
    Shared(Vec<RoutedStanza<A>>),
}

pub(crate) fn render_answer<A: ChunkAllocator + Clone>(
    origin: &Origin<'_, A>,
    allocator: &A,
    answer: IqAnswer<A>,
) -> Result<AnswerStanzas<A>, ReplyError> {
    let IqAnswer {
        request,
        mut arena,
        sender,
        mut response,
        reply,
        mut results,
    } = answer;
    match reply {
        Err(error) => match error.payload() {
            IqErrorPayload::Include => {
                let builder = request.error_reply_described_in(
                    &mut arena,
                    error.condition(),
                    None,
                    error.handler_error().text(),
                )?;
                let stanza = match sender {
                    Some(sender) => builder.to(Some(sender))?.build()?,
                    None => builder.build()?,
                };
                Ok(AnswerStanzas::One { stanza, arena })
            }
            IqErrorPayload::Omit => {
                let mut response = Arena::try_new_in(Default::default(), allocator.clone())?;
                let view = request.resolve(&arena)?;
                let sender = match sender {
                    Some(sender) => sender.resolve(&arena)?,
                    None => view.from()?.ok_or(ReplyError)?,
                };
                let stanza = error_reply_omitting_payload(
                    &view,
                    sender,
                    error.condition(),
                    error.handler_error().text(),
                    &mut response,
                )?;
                Ok(AnswerStanzas::One {
                    stanza,
                    arena: response,
                })
            }
        },
        Ok(payload) => {
            let view = request.resolve(&arena)?;
            let sender_ref = match sender {
                Some(sender) => sender.resolve(&arena)?,
                None => view.from()?.ok_or(ReplyError)?,
            };
            for result in &results {
                let target = if !matches!(origin, Origin::Remote { .. }) {
                    result.resolve(&response)?.to()?.map(|to| to.as_str())
                } else {
                    result
                        .resolve(&response)
                        .ok()
                        .and_then(|view| view.to().ok().flatten())
                        .map(|to| to.as_str())
                };
                if target != Some(sender_ref.as_str()) {
                    match origin {
                        Origin::Session(session) => {
                            tracing::error!(account_jid = ?session.account().as_str(), operation = "iq_results", outcome = "misaddressed", "internal operation failed")
                        }
                        Origin::Remote { local, .. } | Origin::Service { domain: local } => {
                            if let Some(target) = view.to()?.filter(|to| to.localpart().is_some()) {
                                tracing::error!(account_jid = ?target.bare().as_str(), operation = "iq_results", outcome = "misaddressed", "internal operation failed");
                            } else {
                                tracing::error!(
                                    local_domain = *local,
                                    operation = "iq_results",
                                    outcome = "misaddressed",
                                    "internal operation failed"
                                );
                            }
                        }
                    }
                    let builder = request.error_reply_with_in(
                        &mut arena,
                        StanzaErrorCondition::InternalServerError,
                        None,
                    )?;
                    let stanza = match sender {
                        Some(sender) => builder.to(Some(sender))?.build()?,
                        None => builder.build()?,
                    };
                    return Ok(AnswerStanzas::One { stanza, arena });
                }
            }
            let stanza = result_reply(&view, sender_ref, payload, &mut response)?;
            if results.is_empty() {
                Ok(AnswerStanzas::One {
                    stanza,
                    arena: response,
                })
            } else {
                results.push(stanza);
                Ok(AnswerStanzas::Shared(RoutedStanza::from_parts_shared(
                    results, response,
                )))
            }
        }
    }
}
