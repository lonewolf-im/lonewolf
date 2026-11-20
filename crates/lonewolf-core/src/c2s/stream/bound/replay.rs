// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::mem;
use std::sync::Arc;

use lonewolf_extension::message::{Backlog, MessageHandler};
use lonewolf_storage::account::AccountKey;
use lonewolf_storage::offline::OfflineSequence;
use lonewolf_storage::{RedbStorage, Storage};
use lonewolf_util::arena::{Arena, ChunkAllocator};
use lonewolf_xmpp::jid::{Jid, JidRef};

use super::{
    CloseOutcome, Outbox, OutboxWriter, Outgoing, Release, ReplayKind, ReplayOutcome, StoredKind,
    StoredRecordError, acknowledge_backlog, acknowledge_messages, close_storage_failure,
};
use crate::delivery::report_handler_failure;
use crate::router::{Destination, RoutedStanza, RouterHandle};
use crate::stages::policy::{self, ReplayDisposition, Selection};

pub(super) struct ReplayPolicy<A: ChunkAllocator> {
    pub(super) router: RouterHandle<A>,
    pub(super) resource: Box<str>,
}

#[derive(Default)]
pub(super) struct ReplayCounts {
    pub(super) written: usize,
    pub(super) skipped: usize,
}

impl<A: ChunkAllocator + Clone, W: OutboxWriter<A>> Outbox<'_, A, W> {
    pub(super) async fn write_offline(
        &mut self,
        backlog: Backlog,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        policy: Option<ReplayPolicy<A>>,
    ) -> Result<ReplayCounts, CloseOutcome> {
        // Bound the pending selective acknowledgement to one replay page.
        if self
            .releases
            .iter()
            .any(|(_, release)| matches!(release, Release::BacklogMessages { .. }))
        {
            self.writer.flush(self.written).await?;
            self.release_through(self.written);
        }
        if let Some(task) = self.selective_acknowledgement.as_mut() {
            task.await.map_err(|_| CloseOutcome::InternalError)?;
            self.selective_acknowledgement = None;
        }
        let recipient = policy
            .as_ref()
            .map(|policy| {
                let mut arena = Arena::try_new_in(Default::default(), self.allocator.clone())?;
                let jid = Jid::from_trusted_parts_in(
                    Some(self.account.username()),
                    self.account.domain(),
                    Some(&policy.resource),
                    &mut arena,
                )?;
                Ok::<_, CloseOutcome>((policy, jid, arena))
            })
            .transpose()?;
        let recipient = recipient
            .as_ref()
            .map(|(policy, jid, arena)| jid.resolve(arena).map(|jid| (&policy.router, jid)))
            .transpose()?;
        let Backlog { through, mut page } = backlog;
        let kind = ReplayKind::OfflineMessage;
        let mut counts = ReplayCounts::default();
        let mut deferred = false;
        let mut acknowledged = Vec::new();
        'pages: loop {
            for (entry, bytes) in page.iter() {
                if !self.liveness.is_alive() {
                    break 'pages;
                }
                let record = self
                    .admit_offline(entry.sequence, bytes, &*handler, recipient)
                    .await;
                if !self.liveness.is_alive() {
                    break 'pages;
                }
                match record {
                    Ok(None) => continue,
                    Ok(Some((stanza, ReplayDisposition::Deliver))) => {
                        self.written = self.written.next();
                        self.writer.write(Outgoing::Routed(stanza)).await?;
                        self.metrics
                            .replay_records(kind, ReplayOutcome::Delivered, 1);
                        counts.written += 1;
                    }
                    Ok(Some((_, ReplayDisposition::Discard))) => {
                        self.metrics.replay_records(kind, ReplayOutcome::Blocked, 1);
                        counts.skipped += 1;
                    }
                    Ok(Some((_, ReplayDisposition::DeferForOtherResource))) => {
                        self.metrics.replay_records(kind, ReplayOutcome::Blocked, 1);
                        counts.skipped += 1;
                        if !deferred {
                            // A cumulative acknowledgement would remove this record.
                            acknowledged.extend(
                                page.iter()
                                    .map(|(earlier, _)| earlier.sequence)
                                    .take_while(|sequence| *sequence < entry.sequence),
                            );
                            deferred = true;
                        }
                        continue;
                    }
                    Err(StoredRecordError::InvalidContent) => {
                        self.metrics.replay_records(kind, ReplayOutcome::Invalid, 1);
                        counts.skipped += 1;
                        tracing::error!(
                            sequence = entry.sequence.get(),
                            "stored offline message rejected"
                        );
                    }
                    Err(StoredRecordError::ReplayFailure) => {
                        return Err(CloseOutcome::InternalError);
                    }
                }
                if deferred {
                    acknowledged.push(entry.sequence);
                }
            }
            let Some(last) = page.resume_after().map(|entry| entry.sequence) else {
                break;
            };
            if page.is_complete() {
                let release = if deferred {
                    (!acknowledged.is_empty()).then_some(Release::BacklogMessages {
                        handler,
                        sequences: acknowledged,
                    })
                } else {
                    Some(Release::Backlog {
                        handler,
                        through: last,
                    })
                };
                if let Some(release) = release {
                    self.releases.push_back((self.written, release));
                }
                break;
            }
            self.writer.flush(self.written).await?;
            self.release_through(self.written);
            // Commit this page before a later transport failure can retire the session.
            if deferred {
                self.acknowledge_replay_sequences(&*handler, mem::take(&mut acknowledged))
                    .await?;
            } else {
                acknowledge_backlog(
                    &self.storage,
                    &self.account,
                    &self.liveness,
                    &*handler,
                    &Cell::new(last),
                )
                .await
                .map_err(|error| {
                    report_handler_failure(&error, &self.account);
                    CloseOutcome::InternalError
                })?;
            }
            let transaction = self.storage.begin_read().await.map_err(|error| {
                close_storage_failure(error, "offline_replay_begin_read", &self.account)
            })?;
            if !self.liveness.is_alive() {
                break;
            }
            page = handler
                .backlog_page(&self.account, &transaction, last, through, page)
                .await
                .map_err(|error| {
                    report_handler_failure(&error, &self.account);
                    CloseOutcome::InternalError
                })?;
            drop(transaction);
            self.metrics.replay_page_read(kind, page.byte_len());
        }
        Ok(counts)
    }

    pub(super) fn release_replay_sequences(
        &mut self,
        handler: Arc<dyn MessageHandler<A, RedbStorage>>,
        sequences: Vec<OfflineSequence>,
    ) {
        let storage = self.storage.clone();
        let account = self.account.clone();
        let liveness = self.liveness.clone();
        self.selective_acknowledgement =
            Some(compio::runtime::spawn(self.work.start().run(async move {
                if let Err(error) = acknowledge_messages(
                    &storage,
                    &account,
                    &liveness,
                    &*handler,
                    &RefCell::new(sequences),
                )
                .await
                {
                    report_handler_failure(&error, &account);
                }
            })));
    }

    async fn acknowledge_replay_sequences(
        &self,
        handler: &dyn MessageHandler<A, RedbStorage>,
        sequences: Vec<OfflineSequence>,
    ) -> Result<(), CloseOutcome> {
        acknowledge_messages(
            &self.storage,
            &self.account,
            &self.liveness,
            handler,
            &RefCell::new(sequences),
        )
        .await
        .map_err(|error| {
            report_handler_failure(&error, &self.account);
            CloseOutcome::InternalError
        })
    }

    async fn admit_offline(
        &self,
        sequence: OfflineSequence,
        bytes: &[u8],
        handler: &dyn MessageHandler<A, RedbStorage>,
        recipient: Option<(&RouterHandle<A>, JidRef<'_>)>,
    ) -> Result<Option<(RoutedStanza<A>, ReplayDisposition)>, StoredRecordError> {
        let record = self.parse_stored(bytes, StoredKind::Message).await;
        let Some((router, to)) = recipient else {
            return record.map(|stanza| Some((stanza, ReplayDisposition::Deliver)));
        };
        let view = match &record {
            Ok(stanza) => Some(stanza.resolve()?),
            Err(StoredRecordError::InvalidContent) => None,
            Err(StoredRecordError::ReplayFailure) => return Err(StoredRecordError::ReplayFailure),
        };
        let from = view.as_ref().map(|view| view.from()).transpose()?.flatten();
        let sender = from
            .filter(|from| {
                from.bare() != to.bare()
                    && matches!(
                        router.destination(*from),
                        Destination::Account | Destination::Resource
                    )
                    && Selection::Explicit.configured(router, from.domainpart())
            })
            .map(|from| AccountKey::try_from(from.bare()))
            .transpose()
            .map_err(|_| StoredRecordError::ReplayFailure)?;
        let owner_policy = Selection::Explicit.configured(router, self.account.domain());
        if !owner_policy && sender.is_none() {
            return record.map(|stanza| Some((stanza, ReplayDisposition::Deliver)));
        }
        let mut accounts = Vec::with_capacity(1 + usize::from(sender.is_some()));
        accounts.push(self.account.clone());
        accounts.extend(sender.iter().cloned());
        let (snapshot, mut ticket) = router
            .order()
            .fix(accounts, self.storage.begin_read())
            .await
            .map_err(|error| {
                close_storage_failure(error, "offline_replay_policy_begin_read", &self.account);
                StoredRecordError::ReplayFailure
            })?;
        ticket.turn().await;
        if !handler
            .replay_contains(&self.account, sequence, &snapshot)
            .await
            .map_err(|error| {
                report_handler_failure(&error, &self.account);
                StoredRecordError::ReplayFailure
            })?
        {
            return Ok(None);
        }
        let view = view.ok_or(StoredRecordError::InvalidContent)?;
        let disposition = if let Some(from) = from {
            policy::check_offline_replay(
                router,
                &snapshot,
                &self.account,
                sender.as_ref(),
                from,
                to,
                view.stanza_type(),
            )
            .await
            .map_err(|_| StoredRecordError::ReplayFailure)?
        } else {
            return Err(StoredRecordError::InvalidContent);
        };
        Ok(Some((record?, disposition)))
    }
}
