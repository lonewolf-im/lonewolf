// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::io::Read as _;
use std::net::{Ipv4Addr, TcpStream as StdTcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;

use compio::io::AsyncRead as _;
use compio::runtime::Runtime;
use futures_util::poll;
use lonewolf_util::core_dispatcher::CoreDispatcher;
use parking_lot::Mutex as PlMutex;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum Event {
    Served(ListenerSlot),
    Rejected(ListenerSlot, bool),
}

struct RejectionCheck {
    gate: async_channel::Receiver<()>,
    peer: Arc<PlMutex<Option<StdTcpStream>>>,
}

struct FakeHandler {
    events: async_channel::Sender<Event>,
    reject: Option<RejectionCheck>,
    hold: bool,
}

impl AcceptHandler for FakeHandler {
    type Permit = ();
    type Rejection = ();
    async fn admit(&self, _: IpAddr) -> Result<(), ()> {
        if let Some(check) = &self.reject {
            check.gate.recv().await.map_err(|_| ())?;
            Err(())
        } else {
            Ok(())
        }
    }
    fn rejected(&self, slot: ListenerSlot, _: ()) {
        let mut socket = self.reject.as_ref().unwrap().peer.lock().take().unwrap();
        let closed = match socket.read(&mut [0; 1]) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ),
            _ => false,
        };
        assert!(self.events.try_send(Event::Rejected(slot, closed)).is_ok());
    }
    fn serve(
        &self,
        slot: ListenerSlot,
        socket: TcpStream,
        _: (),
        _: ShutdownSignal,
    ) -> impl Future<Output = ()> + 'static {
        assert!(socket.nodelay().unwrap());
        assert!(self.events.try_send(Event::Served(slot)).is_ok());
        let hold = self.hold;
        async move {
            let _socket = socket;
            if hold {
                pending::<()>().await;
            }
        }
    }
}

fn dispatcher() -> io::Result<CoreDispatcher> {
    let two = NonZeroUsize::MIN.saturating_add(1);
    match CoreDispatcher::new(two, two) {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
            CoreDispatcher::new(NonZeroUsize::MIN, two)
        }
        result => result,
    }
}

#[test]
fn port_zero_reports_each_listener_after_every_worker_binds() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let dispatcher = dispatcher()?;
        let (events, observed) = async_channel::bounded(8);
        let specs = (0..2)
            .map(|_| ListenerSpec {
                address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                handler: {
                    let events = events.clone();
                    move |_| FakeHandler {
                        events: events.clone(),
                        reject: None,
                        hold: false,
                    }
                },
            })
            .collect();
        let mut listeners =
            ListenerSet::start(ListenerKind::C2s, &dispatcher.handle(), specs).await?;
        assert_eq!(listeners.addresses().len(), 2);
        assert_ne!(listeners.addresses()[0], listeners.addresses()[1]);
        assert_eq!(
            listeners.test_tasks().len(),
            2 * dispatcher.handle().worker_count()
        );
        for (listener_id, address) in listeners.addresses().iter().enumerate() {
            assert_ne!(address.port(), 0);
            let mut client = TcpStream::connect(*address).await?;
            let Event::Served(slot) = observed.recv().await? else {
                return Err("unexpected rejection".into());
            };
            assert_eq!(slot.listener_id, listener_id);
            assert!(slot.worker_id < dispatcher.handle().worker_count());
            assert_eq!(client.read([0; 1]).await.0?, 0);
        }
        listeners.stop(Instant::now() + TIMEOUT);
        listeners.join().await?;
        listeners.join().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    }))?
}

#[test]
fn rejection_callback_observes_the_peer_socket_already_closed() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let dispatcher = dispatcher()?;
        let (events, observed) = async_channel::bounded(1);
        let (release, gate) = async_channel::bounded(1);
        let client = Arc::new(PlMutex::new(None));
        let specs = vec![ListenerSpec {
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            handler: {
                let client = Arc::clone(&client);
                move |_| FakeHandler {
                    events: events.clone(),
                    reject: Some(RejectionCheck {
                        gate: gate.clone(),
                        peer: Arc::clone(&client),
                    }),
                    hold: false,
                }
            },
        }];
        let mut listeners =
            ListenerSet::start(ListenerKind::S2s, &dispatcher.handle(), specs).await?;
        let socket = StdTcpStream::connect(listeners.addresses()[0])?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        *client.lock() = Some(socket);
        release.send(()).await?;
        let Event::Rejected(slot, closed) = observed.recv().await? else {
            return Err("unexpected acceptance".into());
        };
        assert_eq!(slot.listener_id, 0);
        assert!(closed);
        listeners.stop(Instant::now() + TIMEOUT);
        listeners.join().await?;
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    }))?
}

#[test]
fn fatal_accept_is_reported_before_a_pending_connection_drains() -> TestResult {
    Runtime::new()?.block_on(compio::time::timeout(TIMEOUT, async {
        let dispatcher = dispatcher()?;
        let (ready, readiness) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let (report_failure, failures) = async_channel::bounded(1);
        let (events, observed) = async_channel::bounded(1);
        let task = dispatcher
            .handle()
            .dispatch_at(0, move |context| async move {
                let listener = bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
                let _ = ready.send(listener.local_addr()?);
                let failed = Cell::new(false);
                let result = run_listener_with_accept(
                    &listener,
                    context,
                    ListenerControl {
                        stop: async move { stopped.await.unwrap() }.boxed().shared(),
                        report_failure,
                    },
                    ListenerKind::C2s,
                    0,
                    FakeHandler {
                        events,
                        reject: None,
                        hold: true,
                    },
                    || {
                        let failed = failed.replace(true);
                        let listener = &listener;
                        async move {
                            if failed {
                                Err(io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "injected fatal accept",
                                ))
                            } else {
                                listener.accept().await
                            }
                        }
                    },
                )
                .await;
                let closed = listener.close().await;
                result.and(closed)
            })
            .await?;
        let address = readiness.await?;
        let _client = TcpStream::connect(address).await?;
        assert!(matches!(observed.recv().await?, Event::Served(_)));
        assert_eq!(failures.recv().await?.kind(), io::ErrorKind::BrokenPipe);
        let mut task = Box::pin(task);
        assert!(poll!(task.as_mut()).is_pending());
        stop.send(Instant::now()).map_err(|_| "stop dropped")?;
        assert_eq!(task.await?.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        dispatcher.shutdown(TIMEOUT).await?;
        Ok(())
    }))?
}

#[test]
fn deadline_errors_keep_each_protocols_exact_text() -> TestResult {
    Runtime::new()?.block_on(async {
        for (kind, message) in [
            (
                ListenerKind::C2s,
                "c2s connections exceeded shutdown deadline",
            ),
            (ListenerKind::S2s, "s2s listener shutdown timed out"),
        ] {
            let active = FuturesUnordered::new();
            active.push(ConnectionTask {
                _socket: (),
                future: Box::pin(pending::<()>()),
            });
            let error = drain_connections(active, Instant::now(), kind, |_| {})
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), message);
        }
        Ok(())
    })
}

#[test]
fn stop_keeps_the_first_deadline_and_is_idempotent() -> TestResult {
    Runtime::new()?.block_on(async {
        let (stop, stopped) = oneshot::channel();
        let mut listeners = ListenerSet::with_test_channels(
            ListenerKind::S2s,
            stop,
            async_channel::bounded(1).1,
            1,
        );
        let first = Instant::now();
        listeners.stop(first);
        listeners.stop(first + TIMEOUT);
        assert_eq!(stopped.await?, first);
        listeners.join().await?;
        listeners.join().await?;
        Ok(())
    })
}
