// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use lonewolf_extension::message::{StoreOutcome, UndeliverableMessage};
use lonewolf_storage::roster::RosterJid;

use super::*;
use crate::logging::tests::Capture;

#[test]
fn failed_replay_write_and_flush_emit_no_flushed_or_committed_success() -> TestResult {
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        for fail_write in [true, false] {
            let fixture = Fixture::new(&[MESSAGE]).await?;
            let mut outbox = fixture.outbox(
                GlobalChunkAllocator,
                ControlledWriter {
                    fail_write,
                    fail_flush: !fail_write,
                    ..Default::default()
                },
            );
            outbox.push(Output::Offline {
                backlog: fixture.backlog().await?,
                handler: Arc::new(Offline::new(Default::default())),
            });
            assert_eq!(outbox.flush().await, Err(CloseOutcome::TransportError));
            assert_eq!(fixture.count().await?, 1);
            assert_eq!(capture.count("offline replay flushed")?, 0);
            assert_eq!(capture.count("outcome=\"committed\"")?, 0);
            drop(outbox);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn large_replay_logs_one_batch_after_flush_then_acknowledges_after_writer_admission() -> TestResult
{
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        let mut messages: Vec<&[u8]> = vec![MESSAGE; 80];
        messages.push(b"<message");
        let fixture = Fixture::new(&messages).await?;
        let held_writer = fixture.storage.begin_write().await?;
        let (entered, flushing) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let mut outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter {
            flush_entered: Some(entered),
            flush_release: Some(released),
            ..Default::default()
        });
        let subscriptions = (0..2).map(|_| PendingSubscription {
            sender: RosterJid::from(fixture.registration.account()),
            stanza: b"<presence xmlns='jabber:client' from='bob@localhost' to='bob@localhost' type='subscribe' id='PRIVATE-PENDING'/>".as_slice().into(),
        }).collect();
        outbox.push(Output::Requests(subscriptions));
        outbox.push(Output::Offline {
            backlog: fixture.backlog().await?,
            handler: Arc::new(Offline::new(Default::default())),
        });
        let mut flush = Box::pin(outbox.flush());
        assert!(poll!(flush.as_mut()).is_pending());
        flushing.await?;
        assert_eq!(capture.count("offline replay flushed")?, 0);
        assert_eq!(capture.count("pending subscriptions flushed")?, 0);
        release.send(()).map_err(|_| "flush gate closed")?;
        flush.await.map_err(|error| format!("{error:?}"))?;
        assert_eq!(capture.count("offline replay flushed")?, 1);
        assert_eq!(capture.count("pending subscriptions flushed")?, 1);
        assert_eq!(capture.count("outcome=\"committed\"")?, 0);
        let logs = capture.read()?;
        assert!(logs.contains("messages_written=80 messages_skipped=1"));
        assert!(logs.contains("pending_count=2"));
        for private in ["bob@localhost", "PRIVATE-PENDING", "id=stored", "<message", "through="] {
            assert!(!logs.contains(private), "leaked {private}");
        }
        drop(held_writer);
        (&mut outbox.acknowledgement.as_mut().ok_or("missing worker")?.task).await?;
        assert_eq!(capture.count("operation=\"acknowledge_replay\" outcome=\"committed\"")?, 1);
        assert_eq!(fixture.count().await?, 0);
        drop(outbox);
        fixture.finish().await
    })
}

#[test]
fn staging_offline_storage_logs_no_commit_until_the_detached_commit_finishes() -> TestResult {
    let capture = Capture::new()?;
    Runtime::new()?.block_on(async {
        let fixture = Fixture::new(&[]).await?;
        let outbox = fixture.outbox(GlobalChunkAllocator, ControlledWriter::default());
        let stanza = outbox
            .parse_stored(MESSAGE, StoredKind::Message)
            .await
            .map_err(|_| "stored message parse failed")?;
        let handler = Arc::new(Offline::new(Default::default()));
        for commit in [false, true] {
            let mut transaction = fixture.storage.begin_write().await?;
            let mut scratch = Arena::try_new(ArenaConfig::default())?;
            let stored = <Offline as MessageHandler<GlobalChunkAllocator, RedbStorage>>::store(
                &handler,
                UndeliverableMessage {
                    recipient: fixture.registration.account(),
                    stanza: &stanza,
                    received_at: SystemTime::now(),
                },
                &mut transaction,
                &mut scratch,
            )
            .await
            .map_err(|error| format!("{error:?}"))?;
            let StoreOutcome::Stored(sequence) = stored else {
                return Err("message not stored".into());
            };
            assert_eq!(capture.count("outcome=\"stored\"")?, 0);
            if commit {
                let pending = commit_and_store(
                    fixture.router.handle(),
                    fixture.storage.clone(),
                    transaction,
                    handler.clone(),
                    StoredDelivery {
                        recipient: fixture.registration.account().clone(),
                        sequence,
                        stanza: stanza.clone(),
                        bytes: MESSAGE.len(),
                    },
                );
                assert!(matches!(pending.finished().await, Some(Ok(()))));
            } else {
                drop(transaction);
                assert_eq!(fixture.count().await?, 0);
            }
        }
        assert_eq!(capture.count("outcome=\"stored\"")?, 1);
        assert_eq!(
            capture.count("operation=\"reroute\" outcome=\"retained\" reason=\"offline\"")?,
            1
        );
        assert_eq!(capture.count("outcome=\"committed\"")?, 0);
        drop(outbox);
        fixture.finish().await
    })
}
