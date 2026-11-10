// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::stages::ingress::presence::authorize_probe;
use futures_channel::oneshot;
use futures_util::{
    future::{Either, select},
    poll,
};
use lonewolf_auth::scram::{
    SCRAM_POLICY_ITERATIONS, ScramCredentials, ScramSha1Verifier, ScramVerifier,
};
use lonewolf_extension::presence::{PresenceFuture, PresenceHandler, PresenceRequestType};
use lonewolf_storage::WriteTransaction;
use lonewolf_storage::account::{AccountWrites, NewAccount};
use lonewolf_storage::vcard::{VCardQuota, VCardReads, VCardWrites};
use lonewolf_xmpp::jid::JidRef;
use lonewolf_xmpp::stanza::{PresenceType, StanzaErrorCondition};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

type Gate = (oneshot::Sender<()>, oneshot::Receiver<()>);

#[derive(Debug)]
enum Call {
    Visibility {
        owner: String,
        observer: String,
        snapshot: usize,
        card: Option<Box<str>>,
    },
    Policy {
        owner: String,
        peer: String,
        direction: Direction,
        snapshot: usize,
        card: Option<Box<str>>,
    },
}

struct ProbeRecorder {
    calls: PlMutex<Vec<Call>>,
    verdict: PlMutex<Verdict>,
    visibility_failure: AtomicBool,
    subscribed: AtomicBool,
    policy_gate: PlMutex<Option<Gate>>,
    policy_done: PlMutex<Option<(Direction, oneshot::Sender<()>)>>,
}

impl Default for ProbeRecorder {
    fn default() -> Self {
        Self {
            calls: PlMutex::default(),
            verdict: PlMutex::new(Verdict::Allow),
            visibility_failure: AtomicBool::new(false),
            subscribed: AtomicBool::new(true),
            policy_gate: PlMutex::default(),
            policy_done: PlMutex::default(),
        }
    }
}

impl Extension<GlobalChunkAllocator, RedbStorage> for ProbeRecorder {
    fn name(&self) -> &'static str {
        "probe-recorder"
    }
    fn register(
        self: Arc<Self>,
        _: &str,
        slots: &mut Slots<'_, GlobalChunkAllocator, RedbStorage>,
    ) -> Result<(), RegistrationError> {
        slots.policy(self.clone());
        slots.presence(PresenceRequestType::Probe, self)
    }
}

impl PolicyHandler<RedbStorage> for ProbeRecorder {
    fn check<'a>(
        &'a self,
        request: PolicyRequest<'a>,
        transaction: &'a RedbRead,
    ) -> PolicyFuture<'a> {
        Box::pin(async move {
            assert_eq!(request.kind, StanzaType::Presence(PresenceType::Probe));
            let card = transaction
                .vcard(request.account)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .map(|card| card.xml);
            self.calls.lock().push(Call::Policy {
                owner: request.account.as_str().into(),
                peer: request.peer.as_str().into(),
                direction: request.direction,
                snapshot: std::ptr::from_ref(transaction) as usize,
                card,
            });
            let gate = self.policy_gate.lock().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                release
                    .await
                    .map_err(|_| StanzaErrorCondition::InternalServerError)?;
            }
            if let Some((_, done)) = self
                .policy_done
                .lock()
                .take_if(|(direction, _)| *direction == request.direction)
            {
                let _ = done.send(());
            }
            Ok(*self.verdict.lock())
        })
    }
}

impl PresenceHandler<GlobalChunkAllocator, RedbStorage> for ProbeRecorder {
    fn visibility<'a>(
        &'a self,
        owner: &'a AccountKey,
        observer: JidRef<'a>,
        transaction: &'a RedbRead,
    ) -> PresenceFuture<'a, bool> {
        Box::pin(async move {
            let card = transaction
                .vcard(owner)
                .await
                .map_err(|_| StanzaErrorCondition::InternalServerError)?
                .map(|card| card.xml);
            self.calls.lock().push(Call::Visibility {
                owner: owner.as_str().into(),
                observer: observer.as_str().into(),
                snapshot: std::ptr::from_ref(transaction) as usize,
                card,
            });
            if self.visibility_failure.load(Ordering::SeqCst) {
                return Err(StanzaErrorCondition::InternalServerError.into());
            }
            Ok(self.subscribed.load(Ordering::SeqCst))
        })
    }
}

fn fixture(recorder: Arc<ProbeRecorder>) -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let storage = RedbStorage::open(directory.path().join("lonewolf.dat"))?;
    let mut extensions = Extensions::default();
    extensions.register(recorder)?;
    let router = Router::new(
        Hosts::new(&Config::default().hosts, None)?,
        LocalRouter::new(GlobalChunkAllocator),
    )
    .with_extensions(BTreeMap::from([(
        "localhost".into(),
        extensions.enable_host("localhost", ["probe-recorder"])?,
    )]));
    Ok(Fixture {
        _directory: directory,
        storage,
        handle: router.handle(),
        router,
        work: WorkGroup::new().handle(),
        recorder: Arc::default(),
    })
}

async fn create_account(fixture: &Fixture, name: &str) -> TestResult {
    let mut transaction = fixture.storage.begin_write().await?;
    transaction
        .create_account(NewAccount {
            key: account(name)?,
            credentials: ScramCredentials::new(ScramVerifier::Sha1(ScramSha1Verifier::new(
                [1; 16],
                SCRAM_POLICY_ITERATIONS,
                [2; 20],
                [3; 20],
            ))),
        })
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn probe(from: Option<&str>, to: Option<&str>) -> TestResult<RoutedStanza<GlobalChunkAllocator>> {
    let mut arena = Arena::try_new(Default::default())?;
    let from = from
        .map(|from| Jid::parse_in(from, &mut arena))
        .transpose()?;
    let to = to.map(|to| Jid::parse_in(to, &mut arena)).transpose()?;
    let stanza = Stanza::builder_in(
        StanzaType::Presence(PresenceType::Probe),
        StanzaNamespace::Client,
        &mut arena,
    )
    .from(from)?
    .to(to)?
    .build()?;
    Ok(RoutedStanza::from_parts(stanza, arena))
}

#[test]
fn local_and_remote_probes_share_one_authorization() -> TestResult {
    Runtime::new()?.block_on(async {
        let recorder = Arc::new(ProbeRecorder::default());
        let fixture = fixture(recorder.clone())?;
        create_account(&fixture, "bob@localhost").await?;
        for (source, target, from, to, exists_gate, visibility, directions) in [
            (
                Some("alice@localhost"),
                Some("bob@localhost"),
                "alice@localhost/desk",
                "bob@localhost/phone",
                false,
                true,
                vec![Direction::Outbound, Direction::Inbound],
            ),
            (
                Some("alice@localhost"),
                None,
                "alice@localhost/desk",
                "bob@remote.test/phone",
                false,
                false,
                vec![Direction::Outbound],
            ),
            (
                None,
                Some("bob@localhost"),
                "alice@remote.test/desk",
                "bob@localhost/phone",
                true,
                true,
                vec![Direction::Inbound],
            ),
            (
                Some("bob@localhost"),
                Some("bob@localhost"),
                "bob@localhost/desk",
                "bob@localhost/phone",
                false,
                true,
                vec![],
            ),
            (
                None,
                Some("missing@localhost"),
                "alice@remote.test/desk",
                "missing@localhost",
                true,
                false,
                vec![Direction::Inbound],
            ),
            (
                Some("alice@localhost"),
                Some("missing@localhost"),
                "alice@localhost/desk",
                "missing@localhost",
                false,
                true,
                vec![Direction::Outbound, Direction::Inbound],
            ),
        ] {
            for subscribed in [false, true] {
                recorder.subscribed.store(subscribed, Ordering::SeqCst);
                recorder.calls.lock().clear();
                let routed = probe(Some(from), Some(to))?;
                let grant = authorize_probe(
                    fixture.handle.clone(),
                    fixture.storage.clone(),
                    source.map(account).transpose()?,
                    target.map(account).transpose()?,
                    &routed,
                    exists_gate,
                )
                .await
                .map_err(|_| "authorization")?
                .ok_or("missing grant")?;
                assert_eq!(grant.subscribed, visibility && subscribed);
                let calls = recorder.calls.lock();
                assert_eq!(calls.len(), usize::from(visibility) + directions.len());
                if visibility {
                    let Call::Visibility {
                        owner, observer, ..
                    } = &calls[0]
                    else {
                        return Err("visibility did not run first".into());
                    };
                    assert_eq!(owner, target.ok_or("target")?);
                    assert_eq!(observer, from);
                }
                for (call, direction) in calls[usize::from(visibility)..].iter().zip(&directions) {
                    let Call::Policy {
                        owner,
                        peer,
                        direction: actual,
                        ..
                    } = call
                    else {
                        return Err("policy call".into());
                    };
                    assert_eq!(actual, direction);
                    assert_eq!(
                        owner,
                        if *direction == Direction::Outbound {
                            source.ok_or("source")?
                        } else {
                            target.ok_or("target")?
                        }
                    );
                    assert_eq!(
                        peer,
                        if *direction == Direction::Outbound {
                            to
                        } else {
                            from
                        }
                    );
                }
                drop(grant.ticket);
            }
        }
        for verdict in [
            Verdict::Drop,
            Verdict::Reject {
                condition: StanzaErrorCondition::Forbidden,
                application: None,
                text: None,
            },
        ] {
            *recorder.verdict.lock() = verdict;
            for (source, target, from, to, exists_gate) in [
                (
                    Some("alice@localhost"),
                    Some("bob@localhost"),
                    "alice@localhost/desk",
                    "bob@localhost",
                    false,
                ),
                (
                    Some("alice@localhost"),
                    None,
                    "alice@localhost/desk",
                    "bob@remote.test",
                    false,
                ),
                (
                    None,
                    Some("bob@localhost"),
                    "alice@remote.test/desk",
                    "bob@localhost",
                    true,
                ),
            ] {
                let routed = probe(Some(from), Some(to))?;
                assert!(
                    authorize_probe(
                        fixture.handle.clone(),
                        fixture.storage.clone(),
                        source.map(account).transpose()?,
                        target.map(account).transpose()?,
                        &routed,
                        exists_gate
                    )
                    .await
                    .map_err(|_| "rejected authorization")?
                    .is_none()
                );
            }
        }
        recorder.calls.lock().clear();
        recorder.visibility_failure.store(true, Ordering::SeqCst);
        let routed = probe(Some("alice@localhost/desk"), Some("bob@localhost"))?;
        assert!(
            authorize_probe(
                fixture.handle.clone(),
                fixture.storage.clone(),
                Some(account("alice@localhost")?),
                Some(account("bob@localhost")?),
                &routed,
                false
            )
            .await
            .is_err()
        );
        assert!(matches!(
            &recorder.calls.lock()[..],
            [Call::Visibility { .. }]
        ));
        fixture.router.shutdown().await?;
        Ok(())
    })
}

#[test]
fn probe_visibility_and_policy_keep_one_snapshot_while_waiting_for_turn() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(Duration::from_secs(5), async {
        for (source, target, from, to, check_exists, owner) in [
            (
                Some("alice@localhost"),
                Some("bob@localhost"),
                "alice@localhost/desk",
                "bob@localhost",
                false,
                "bob@localhost",
            ),
            (
                Some("alice@localhost"),
                None,
                "alice@localhost/desk",
                "bob@remote.test",
                false,
                "alice@localhost",
            ),
            (
                None,
                Some("bob@localhost"),
                "alice@remote.test/desk",
                "bob@localhost",
                true,
                "bob@localhost",
            ),
        ] {
            let recorder = Arc::new(ProbeRecorder::default());
            let fixture = fixture(recorder.clone())?;
            create_account(&fixture, "alice@localhost").await?;
            create_account(&fixture, "bob@localhost").await?;
            let ((), blocker) = fixture
                .handle
                .order()
                .fix(vec![account(owner)?], async {
                    Ok::<_, crate::stages::StageFailure>(())
                })
                .await
                .map_err(|_| "ticket")?;
            let (entered, reached) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *recorder.policy_gate.lock() = Some((entered, resume));
            let (done, completed) = oneshot::channel();
            *recorder.policy_done.lock() = Some((
                if target.is_some() {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                },
                done,
            ));
            let routed = probe(Some(from), Some(to))?;
            let mut authorization = Box::pin(authorize_probe(
                fixture.handle.clone(),
                fixture.storage.clone(),
                source.map(account).transpose()?,
                target.map(account).transpose()?,
                &routed,
                check_exists,
            ));
            match select(reached, authorization.as_mut()).await {
                Either::Left((entered, _)) => entered?,
                Either::Right(_) => return Err("authorization preceded policy".into()),
            }
            let mut transaction = fixture.storage.begin_write().await?;
            transaction
                .replace_vcard(
                    &account(owner)?,
                    "<vCard xmlns='vcard-temp'/>",
                    VCardQuota::default(),
                )
                .await?;
            transaction.commit().await?;
            release.send(()).map_err(|_| "policy cancelled")?;
            match select(completed, authorization.as_mut()).await {
                Either::Left((done, _)) => done?,
                Either::Right(_) => return Err("authorization preceded final policy".into()),
            }
            assert!(poll!(authorization.as_mut()).is_pending());
            {
                let calls = recorder.calls.lock();
                let mut snapshot = None;
                for call in calls.iter() {
                    let (current, card) = match call {
                        Call::Visibility { snapshot, card, .. }
                        | Call::Policy { snapshot, card, .. } => (*snapshot, card),
                    };
                    assert!(card.is_none());
                    assert_eq!(*snapshot.get_or_insert(current), current);
                }
                assert_eq!(
                    calls.len(),
                    if source.is_some() && target.is_some() {
                        3
                    } else if target.is_some() {
                        2
                    } else {
                        1
                    }
                );
            }
            drop(blocker);
            let grant = authorization
                .await
                .map_err(|_| "authorization")?
                .ok_or("grant")?;
            drop(grant.ticket);
            fixture.router.shutdown().await?;
        }
        Ok(())
    }))?
}

#[test]
fn probe_required_addresses_are_checked_without_policy_handlers() -> TestResult {
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(false)?;
        for (source, target, from, to) in [
            (
                Some("alice@localhost"),
                Some("bob@localhost"),
                None,
                Some("bob@localhost"),
            ),
            (
                Some("alice@localhost"),
                None,
                Some("alice@localhost/desk"),
                None,
            ),
        ] {
            let routed = probe(from, to)?;
            assert!(
                authorize_probe(
                    fixture.handle.clone(),
                    fixture.storage.clone(),
                    source.map(account).transpose()?,
                    target.map(account).transpose()?,
                    &routed,
                    false
                )
                .await
                .is_err()
            );
        }
        fixture.router.shutdown().await?;
        Ok(())
    })
}
