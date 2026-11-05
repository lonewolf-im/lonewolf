// SPDX-License-Identifier: Apache-2.0

use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::pin::pin;

use futures_util::poll;
use lonewolf_storage::Storage;
use lonewolf_util::arena::GlobalChunkAllocator;
use prometheus_client::registry::Registry;

use super::manager_tests::{manager, message, run, stanza};
use super::*;
use crate::config::Config;
use crate::router::{Router, local::LocalRouter};
use crate::s2s::metrics::StreamClose;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Registration = BidiRegistration<GlobalChunkAllocator>;
const TIMEOUT: Duration = Duration::from_secs(5);

struct RefusedEndpoint {
    address: SocketAddr,
    _accepted: TcpStream,
    _keeper: TcpStream,
}

impl RefusedEndpoint {
    fn reserve() -> io::Result<Self> {
        let deadline = Instant::now() + TIMEOUT;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(false)?;
        socket.set_reuse_port(false)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        socket.listen(1)?;
        let listener: TcpListener = socket.into();
        let address = listener.local_addr()?;
        let keeper = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
        let (accepted, _) = listener.accept()?;
        // The reservation carries no data and must not leave its port in TIME_WAIT.
        socket2::SockRef::from(&accepted).set_linger(Some(Duration::ZERO))?;
        // A bound, non-listening socket can drop connection attempts on macOS.
        drop(listener);
        let endpoint = Self {
            address,
            _accepted: accepted,
            _keeper: keeper,
        };
        loop {
            let connection = TcpStream::connect_timeout(&address, remaining(deadline)?);
            remaining(deadline)?;
            match connection {
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => return Ok(endpoint),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                            | ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
                Ok(mut probe) => loop {
                    probe.set_read_timeout(Some(remaining(deadline)?))?;
                    let received = probe.read(&mut [0]);
                    remaining(deadline)?;
                    match received {
                        Ok(0) => break,
                        Ok(_) => {
                            return Err(io::Error::other(
                                "refusal probe received application data",
                            ));
                        }
                        Err(error) if error.kind() == ErrorKind::Interrupted => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::ConnectionReset
                                    | ErrorKind::ConnectionAborted
                                    | ErrorKind::NotConnected
                            ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                },
            }
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "refused endpoint deadline expired"))
}

struct Fixture {
    remote: RemoteRouter<GlobalChunkAllocator>,
    router: Router<GlobalChunkAllocator>,
    _directory: tempfile::TempDir,
    _refused: Option<RefusedEndpoint>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        Self::with_route(None)
    }

    fn with_route(route: Option<SocketAddr>) -> TestResult<Self> {
        let refused = route.is_none().then(RefusedEndpoint::reserve).transpose()?;
        let address = route
            .or_else(|| refused.as_ref().map(|endpoint| endpoint.address))
            .ok_or("missing route")?;
        let mut config = Config::default();
        config
            .s2s
            .routes
            .insert("remote.test".into(), vec![address]);
        let hosts = Hosts::new(&config.hosts, config.xmpp.default_host.as_deref())?;
        let trust = PeerTrust::load(&config.s2s.tls, hosts.crypto_provider())?;
        let directory = tempfile::tempdir()?;
        let storage = RedbStorage::open(directory.path().join("state.redb"))?;
        let remote = RemoteRouter::new(
            hosts.clone(),
            PeerVerification {
                trust,
                revocation: PeerRevocation::disabled(),
            },
            Arc::new(Resolver::new(&config.s2s)?),
            &config.limits.s2s,
            GlobalChunkAllocator,
            S2sMetrics::new(0),
            Some(BidiIngress { storage }),
        );
        let router =
            Router::new(hosts, LocalRouter::new(GlobalChunkAllocator)).with_remote(remote.clone());
        Ok(Self {
            remote,
            router,
            _directory: directory,
            _refused: refused,
        })
    }

    fn register(&self) -> TestResult<Registration> {
        self.remote
            .register_bidi(&self.router.handle(), "localhost", "remote.test")
            .ok_or_else(|| "missing bidirectional registration".into())
    }

    fn snapshot(&self) -> LinkSnapshot {
        self.remote.inner.snapshot()
    }

    fn render(&self) -> TestResult<String> {
        let mut registry = Registry::default();
        self.remote
            .inner
            .metrics
            .register(registry.sub_registry_with_prefix("lonewolf"));
        let mut output = String::new();
        prometheus_client::encoding::text::encode(&mut output, &registry)?;
        Ok(output)
    }

    async fn route(&self) -> TestResult {
        self.remote
            .route(
                &self.router.handle(),
                "localhost",
                "remote.test",
                message().await?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    }

    async fn finish(self) -> TestResult {
        self.remote.join(Instant::now() + TIMEOUT).await?;
        self.router.shutdown().await?;
        Ok(())
    }
}

fn assert_sample(output: &str, sample: &str) {
    assert!(
        output.lines().any(|line| line == sample),
        "missing {sample} in {output}"
    );
}

#[test]
fn registration_requires_bidirectional_mode_and_a_running_router() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let disabled = manager(S2sLimits::default())?;
        assert!(!disabled.bidirectional());
        assert!(
            disabled
                .register_bidi(&fixture.router.handle(), "localhost", "remote.test")
                .is_none()
        );
        disabled.join(Instant::now() + TIMEOUT).await?;
        assert!(fixture.remote.bidirectional());
        drop(
            fixture
                .remote
                .inner
                .bidi
                .as_ref()
                .ok_or("missing ingress storage")?
                .storage
                .begin_read()
                .await?,
        );
        let registration = fixture.register()?;
        fixture.remote.stop();
        assert!(
            fixture
                .remote
                .register_bidi(&fixture.router.handle(), "localhost", "remote.test")
                .is_none()
        );
        drop(registration);
        fixture.finish().await
    })
}

#[test]
fn new_link_goes_to_the_newest_standby_without_dialing() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let first = fixture.register()?;
        let second = fixture.register()?;
        fixture.route().await?;
        let queue = second.assigned().await.ok_or("missing assigned queue")?;
        assert!(poll!(pin!(first.assigned())).is_pending());
        assert_eq!(queue.receiver.len(), 1);
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 1",
        );
        assert!(
            !fixture
                .render()?
                .contains("lonewolf_s2s_dns_resolutions_total")
        );
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_outbound_links{state=\"connecting\"} 1",
        );
        let stanza = queue.receiver.try_recv()?.into_stanza();
        let view = stanza.resolve()?;
        assert_eq!(view.kind().as_str(), "message");
        assert_eq!(
            view.from()?.ok_or("missing sender")?.localpart(),
            Some("alice")
        );
        assert_eq!(
            view.from()?.ok_or("missing sender")?.resourcepart(),
            Some("desk")
        );
        assert_eq!(
            view.from()?.ok_or("missing sender")?.domainpart(),
            "localhost"
        );
        assert_eq!(
            view.to()?.ok_or("missing target")?.domainpart(),
            "remote.test"
        );
        assert_eq!(view.to()?.ok_or("missing target")?.localpart(), Some("bob"));
        assert_eq!(
            view.to()?.ok_or("missing target")?.resourcepart(),
            Some("phone")
        );
        fixture.remote.stop();
        second.release(Some(queue));
        drop(first);
        fixture.finish().await
    })
}

#[test]
fn registration_clears_a_backoff_entry() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        fixture.remote.inner.state.lock().entries.insert(
            ("localhost".into(), "remote.test".into()),
            Entry::Backoff {
                started_at: Instant::now(),
                delay: TIMEOUT,
                condition: RemoteFailure::Timeout,
                failures: 3,
            },
        );
        let registration = fixture.register()?;
        assert_eq!(fixture.snapshot().backoff, 0);
        fixture.route().await?;
        let queue = registration
            .assigned()
            .await
            .ok_or("missing assigned queue")?;
        fixture.remote.stop();
        registration.release(Some(queue));
        fixture.finish().await
    })
}

#[test]
fn releasing_an_empty_queue_removes_the_entry() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let registration = fixture.register()?;
        fixture.route().await?;
        let queue = registration
            .assigned()
            .await
            .ok_or("missing assigned queue")?;
        drop(queue.receiver.recv().await?);
        registration.release(Some(queue));
        let snapshot = fixture.snapshot();
        assert_eq!(snapshot.connecting + snapshot.ready + snapshot.backoff, 0);
        assert_eq!(snapshot.queued_stanzas, 0);
        fixture.finish().await
    })
}

#[test]
fn released_stanzas_move_to_another_standby_then_to_a_dialed_link() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let first = fixture.register()?;
        let second = fixture.register()?;
        fixture.route().await?;
        let queue = second.assigned().await.ok_or("missing assigned queue")?;
        second.release(Some(queue));
        let queue = first.assigned().await.ok_or("missing reassigned queue")?;
        assert_eq!(queue.receiver.len(), 1);
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 2",
        );
        first.release(Some(queue));
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"dialed_link\"} 1",
        );
        fixture.remote.inner.group.lock().await.drain().await;
        let output = fixture.render()?;
        assert_sample(
            &output,
            "lonewolf_s2s_dns_resolutions_total{outcome=\"static\"} 1",
        );
        assert_sample(
            &output,
            "lonewolf_s2s_authentications_total{direction=\"outbound\",outcome=\"unreachable\"} 1",
        );
        fixture.finish().await
    })
}

#[test]
fn dial_failure_hands_the_queue_to_a_standby_registered_meanwhile() -> TestResult {
    run(async {
        let listener = compio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let fixture = Fixture::with_route(Some(listener.local_addr()?))?;
        fixture.route().await?;
        let (socket, _) = listener.accept().await?;
        let registration = fixture.register()?;
        drop(socket);
        let queue = registration
            .assigned()
            .await
            .ok_or("missing assigned queue")?;
        assert_eq!(queue.receiver.len(), 1);
        assert_eq!(fixture.snapshot().backoff, 0);
        assert!(!fixture.render()?.contains("lonewolf_s2s_bounces_total"));
        fixture.remote.stop();
        registration.release(Some(queue));
        fixture.finish().await
    })
}

#[test]
fn registration_before_failure_disposition_receives_the_queue() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let task = fixture
            .remote
            .admit(
                "localhost",
                "remote.test",
                stanza(
                    "<message from='alice@localhost/desk' to='bob@remote.test/phone' id='before'/>",
                )
                .await?,
            )
            .map_err(|error| format!("{error:?}"))?
            .ok_or("missing launch")?;
        let counters = Arc::clone(&task.queue.counters);
        let registration = fixture.register()?;
        assert!(matches!(
            fixture.remote.inner.failed(
                task.queue,
                0,
                RemoteFailure::Timeout,
                Instant::now(),
                1000,
            ),
            FailureDisposition::HandedOff
        ));
        let queue = registration
            .assigned()
            .await
            .ok_or("missing assigned queue")?;
        assert!(Arc::ptr_eq(&queue.counters, &counters));
        assert_eq!(queue.pair.0.as_ref(), "localhost");
        assert_eq!(queue.pair.1.as_ref(), "remote.test");
        let received = queue.receiver.try_recv()?.into_stanza();
        assert_eq!(received.resolve()?.id()?, Some("before"));
        assert_eq!(fixture.snapshot().backoff, 0);
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 1",
        );
        assert!(!fixture.render()?.contains("lonewolf_s2s_bounces_total"));
        registration.release(Some(queue));
        drop(task.guard);
        fixture.finish().await
    })
}

#[test]
fn registration_after_failure_disposition_clears_backoff_without_reclaiming_old_queue() -> TestResult
{
    run(async {
        let fixture = Fixture::new()?;
        let old = fixture
            .remote
            .admit(
                "localhost",
                "remote.test",
                stanza(
                    "<message from='alice@localhost/desk' to='bob@remote.test/phone' id='old'/>",
                )
                .await?,
            )
            .map_err(|error| format!("{error:?}"))?
            .ok_or("missing old launch")?;
        let now = Instant::now();
        let FailureDisposition::Bounce(old_queue) =
            fixture
                .remote
                .inner
                .failed(old.queue, 3, RemoteFailure::Timeout, now, 1000)
        else {
            return Err("failure without a standby did not publish backoff".into());
        };
        {
            let state = fixture.remote.inner.state.lock();
            let Some(Entry::Backoff {
                started_at,
                delay,
                condition,
                failures,
            }) = state.entries.get(&old_queue.pair)
            else {
                return Err("missing backoff".into());
            };
            assert_eq!(*started_at, now);
            assert_eq!(*delay, Duration::from_secs(240));
            assert_eq!(*condition, RemoteFailure::Timeout);
            assert_eq!(*failures, 4);
        }
        let registration = fixture.register()?;
        assert_eq!(fixture.snapshot().backoff, 0);
        assert!(fixture.remote.inner.state.lock().entries.is_empty());
        let replacement = fixture.remote.admit(
            "localhost",
            "remote.test",
            stanza("<message from='alice@localhost/desk' to='bob@remote.test/phone' id='replacement'/>").await?,
        ).map_err(|error| format!("{error:?}"))?.ok_or("missing replacement launch")?;
        assert!(!Arc::ptr_eq(
            &old_queue.counters,
            &replacement.queue.counters
        ));
        let replacement_counters = Arc::clone(&replacement.queue.counters);
        assert!(
            fixture
                .remote
                .inner
                .offer_standby(replacement.queue)
                .is_ok()
        );
        let queue = registration
            .assigned()
            .await
            .ok_or("missing replacement queue")?;
        assert!(Arc::ptr_eq(&queue.counters, &replacement_counters));
        old_queue.receiver.close();
        assert!(old_queue.current.is_none());
        let received = old_queue.receiver.try_recv()?.into_stanza();
        assert_eq!(received.resolve()?.id()?, Some("old"));
        assert!(old_queue.is_drained());
        fixture
            .remote
            .inner
            .remove(&old_queue.pair, &old_queue.counters);
        assert!(
            fixture
                .remote
                .inner
                .state
                .lock()
                .owns(&queue.pair, &queue.counters)
        );
        assert_eq!(fixture.snapshot().connecting, 1);
        let received = queue.receiver.try_recv()?.into_stanza();
        assert_eq!(received.resolve()?.id()?, Some("replacement"));
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"inbound_stream\"} 1",
        );
        registration.release(Some(queue));
        drop(old_queue);
        drop((old.guard, replacement.guard));
        fixture.finish().await
    })
}

#[test]
fn dropping_a_registration_releases_its_queue() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let registration = fixture.register()?;
        let task = fixture
            .remote
            .admit("localhost", "remote.test", message().await?)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("missing launch")?;
        assert!(fixture.remote.inner.offer_standby(task.queue).is_ok());
        drop(task.guard);
        drop(registration);
        assert_sample(
            &fixture.render()?,
            "lonewolf_s2s_bidi_handoffs_total{target=\"dialed_link\"} 1",
        );
        fixture.remote.inner.group.lock().await.drain().await;
        fixture.finish().await
    })
}

#[test]
fn release_after_stop_drops_and_counts_queued_stanzas() -> TestResult {
    run(async {
        for release_first in [false, true] {
            let fixture = Fixture::new()?;
            let registration = fixture.register()?;
            fixture.route().await?;
            fixture.route().await?;
            let queue = registration
                .assigned()
                .await
                .ok_or("missing assigned queue")?;
            assert_eq!(queue.receiver.len(), 2);
            if release_first {
                registration.release(Some(queue));
                fixture.remote.stop();
                let join = fixture.remote.join(Instant::now() + TIMEOUT);
                let mut join = pin!(join);
                assert!(poll!(join.as_mut()).is_pending());
                join.await?;
            } else {
                fixture.remote.stop();
                registration.release(Some(queue));
                fixture.remote.join(Instant::now() + TIMEOUT).await?;
            }
            let output = fixture.render()?;
            assert_sample(
                &output,
                "lonewolf_s2s_dropped_stanzas_total{reason=\"shutdown\"} 2",
            );
            if release_first {
                assert_sample(
                    &output,
                    "lonewolf_s2s_bidi_handoffs_total{target=\"dialed_link\"} 1",
                );
            } else {
                assert!(!output.contains("target=\"dialed_link\""));
            }
            assert!(!output.contains("lonewolf_s2s_dns_resolutions_total"));
            assert!(!output.contains("lonewolf_s2s_authentications_total"));
            let snapshot = fixture.snapshot();
            assert_eq!(snapshot.connecting + snapshot.ready + snapshot.backoff, 0);
            assert_eq!(snapshot.queued_stanzas, 0);
            assert_eq!(snapshot.queued_bytes, 0);
            fixture.finish().await?;
        }
        Ok(())
    })
}

#[test]
fn stop_closes_standby_channels() -> TestResult {
    run(async {
        let fixture = Fixture::new()?;
        let registration = fixture.register()?;
        {
            let assigned = registration.assigned();
            let mut assigned = pin!(assigned);
            assert!(poll!(assigned.as_mut()).is_pending());
            fixture.remote.stop();
            assert!(assigned.await.is_none());
        }
        drop(registration);
        fixture.finish().await
    })
}

#[test]
fn handoff_rechecks_an_unwritten_head_against_only_the_destination_writer() -> TestResult {
    use crate::s2s::stream::limits::StreamLimits;
    use crate::s2s::validity::LinkValidity;
    use std::time::SystemTime;
    run(async {
        for (old_maximum, next_maximum) in [(0, None), (4096, Some(0)), (0, Some(4096))] {
            let fixture = Fixture::new()?;
            let first = fixture.register()?;
            fixture.route().await?;
            let mut queue = first.assigned().await.ok_or("assigned queue")?;
            queue.current = Some(queue.receiver.recv().await?);
            let counters = Arc::clone(&queue.counters);
            let mut old_writer = S2sWriter::new(Vec::new());
            old_writer.update_peer_limits(Some(StreamLimits {
                max_bytes: Some(old_maximum),
                idle_seconds: Some(1),
            }));
            let expired = LinkValidity::fixed(SystemTime::now() - Duration::from_secs(1));
            let mut buffered = false;
            assert!(matches!(
                link::write(
                    &mut old_writer,
                    queue.current.as_mut().ok_or("head")?,
                    &fixture.remote.inner,
                    &expired,
                    true,
                    &mut buffered
                )
                .await,
                Err(StreamClose::CertificateExpired)
            ));
            assert!(queue.current.as_ref().ok_or("head")?.reservation.is_some());
            let next = fixture.register()?;
            first.release(Some(queue));
            let mut queue = next.assigned().await.ok_or("handoff queue")?;
            assert!(Arc::ptr_eq(&queue.counters, &counters));
            assert_eq!(queue.counters.count.load(Ordering::Relaxed), 1);
            let mut writer = S2sWriter::new(Vec::new());
            assert_eq!(writer.peer_limits(), StreamLimits::default());
            if let Some(max_bytes) = next_maximum {
                writer.update_peer_limits(Some(StreamLimits {
                    max_bytes: Some(max_bytes),
                    idle_seconds: None,
                }));
            }
            let validity = LinkValidity::fixed(SystemTime::now() + Duration::from_secs(60));
            let result = link::write(
                &mut writer,
                queue.current.as_mut().ok_or("head")?,
                &fixture.remote.inner,
                &validity,
                true,
                &mut buffered,
            )
            .await;
            if next_maximum == Some(0) {
                assert!(matches!(result, Ok(link::WriteOutcome::PeerSizeRejected)));
                link::reject_peer_size(&fixture.router.handle(), &mut queue.current);
                assert_sample(
                    &fixture.render()?,
                    "lonewolf_s2s_peer_size_rejections_total 1",
                );
            } else {
                assert!(matches!(result, Ok(link::WriteOutcome::Written { .. })));
                queue.current = None;
                assert_sample(
                    &fixture.render()?,
                    "lonewolf_s2s_stanzas_sent_total{kind=\"message\"} 1",
                );
                assert!(
                    !fixture
                        .render()?
                        .contains("lonewolf_s2s_peer_size_rejections_total")
                );
            }
            assert_eq!(queue.counters.count.load(Ordering::Relaxed), 0);
            assert_eq!(queue.counters.bytes.load(Ordering::Relaxed), 0);
            assert!(!fixture.render()?.contains("reason=\"connection_lost\""));
            fixture.remote.stop();
            next.release(Some(queue));
            fixture.finish().await?;
        }
        Ok(())
    })
}
