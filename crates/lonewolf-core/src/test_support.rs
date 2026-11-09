// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::Poll;
use std::time::Duration;

use futures_util::task::AtomicWaker;
use lonewolf_util::arena::{Arena, ArenaConfig};
use lonewolf_xmpp::jid::Jid;
use parking_lot::Mutex as PlMutex;

mod process;

pub use process::spawn_child;

static S2S_REVALIDATION_MILLIS: AtomicU64 = AtomicU64::new(0);
static S2S_CRL_PUBLIC_ONLY: AtomicBool = AtomicBool::new(false);

/// Uses whole milliseconds; zero restores the default interval.
pub fn set_s2s_revalidation_interval(interval: Duration) {
    S2S_REVALIDATION_MILLIS.store(
        interval.as_millis().min(u128::from(u64::MAX)) as u64,
        Ordering::Release,
    );
}

pub fn set_s2s_crl_public_destinations_only(enabled: bool) {
    S2S_CRL_PUBLIC_ONLY.store(enabled, Ordering::Release);
}

pub(crate) fn s2s_revalidation_interval() -> Option<Duration> {
    match S2S_REVALIDATION_MILLIS.load(Ordering::Acquire) {
        0 => None,
        millis => Some(Duration::from_millis(millis)),
    }
}

pub(crate) fn s2s_crl_public_destinations_only() -> bool {
    S2S_CRL_PUBLIC_ONLY.load(Ordering::Acquire)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct S2sShutdownState {
    pub dropped_shutdown: u64,
    pub dropped_connection_lost: u64,
    pub queued_stanzas: u64,
    pub queued_bytes: u64,
    /// Indices are inbound/outbound, then starttls/direct.
    pub transport_cancelled: [[u64; 2]; 2],
    pub transport_connections: [[u64; 2]; 2],
    pub connections: [u64; 2],
    pub streams: [u64; 2],
    pub bidi_streams: [u64; 2],
    pub authentication_protocol: [u64; 2],
    pub c2s_connections: u64,
    pub c2s_unauthenticated: u64,
    pub router_sessions: u64,
}

pub fn run_with_extensions_and_s2s_shutdown_state(
    config_path: Option<&std::path::Path>,
    build: crate::BuildInfo,
    extensions: lonewolf_extension::Extensions<
        Arc<lonewolf_util::pool::PooledChunkAllocator>,
        lonewolf_storage::RedbStorage,
    >,
) -> Result<Option<S2sShutdownState>, crate::RunError> {
    let mut state = None;
    crate::run_internal(
        config_path,
        build,
        extensions,
        crate::acme::LoadOptions::default(),
        Some(&mut state),
    )?;
    Ok(state)
}

pub(crate) fn shutdown_gauges(
    registry: &prometheus_client::registry::Registry,
) -> std::io::Result<[u64; 3]> {
    let mut output = String::new();
    prometheus_client::encoding::text::encode(&mut output, registry)
        .map_err(std::io::Error::other)?;
    let mut connections = None;
    let mut unauthenticated = None;
    let mut sessions = None;
    for line in output.lines() {
        let Some((sample, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let target = if sample.starts_with("lonewolf_c2s_connections{") {
            &mut connections
        } else if sample == "lonewolf_c2s_unauthenticated_connections" {
            &mut unauthenticated
        } else if sample == "lonewolf_router_sessions" {
            &mut sessions
        } else {
            continue;
        };
        let value = value.parse::<u64>().map_err(std::io::Error::other)?;
        *target = Some(target.unwrap_or(0) + value);
    }
    match (connections, unauthenticated, sessions) {
        (Some(c), Some(u), Some(s)) => Ok([c, u, s]),
        _ => Err(std::io::Error::other("missing lifecycle shutdown gauge")),
    }
}

static PROBES: LazyLock<PlMutex<BTreeMap<String, Weak<State>>>> =
    LazyLock::new(|| PlMutex::new(BTreeMap::new()));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamProbeEvent {
    IqGetAdmitted,
    UnavailablePresenceAdmitted,
    WriteHeld,
    WriteCancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeError {
    InvalidTarget,
    DuplicateTarget,
    WriteAlreadyArmed,
    WriteNotHeld,
    Closed,
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTarget => "probe requires a full account JID",
            Self::DuplicateTarget => "stream already has a probe",
            Self::WriteAlreadyArmed => "a pending write is already armed or held",
            Self::WriteNotHeld => "probe has no held write",
            Self::Closed => "stream probe was dropped",
        })
    }
}

impl std::error::Error for ProbeError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriteState {
    Idle,
    Armed,
    Held,
    Released,
}

struct State {
    active: AtomicBool,
    events: async_channel::Sender<StreamProbeEvent>,
    write: PlMutex<WriteState>,
    writer: AtomicWaker,
}

/// Dropping the owner unregisters its target and releases a held write.
pub struct StreamProbe {
    target: String,
    state: Arc<State>,
    events: async_channel::Receiver<StreamProbeEvent>,
}

pub fn install_stream_probe(full_jid: &str) -> Result<StreamProbe, ProbeError> {
    let mut arena =
        Arena::try_new(ArenaConfig::default()).map_err(|_| ProbeError::InvalidTarget)?;
    let jid = Jid::parse_in(full_jid, &mut arena).map_err(|_| ProbeError::InvalidTarget)?;
    let jid = jid.resolve(&arena).map_err(|_| ProbeError::InvalidTarget)?;
    if jid.localpart().is_none() || jid.resourcepart().is_none() {
        return Err(ProbeError::InvalidTarget);
    }
    let target = jid.as_str().to_owned();
    let mut probes = PROBES.lock();
    if probes.get(&target).and_then(Weak::upgrade).is_some() {
        return Err(ProbeError::DuplicateTarget);
    }
    let (sender, events) = async_channel::unbounded();
    let state = Arc::new(State {
        active: AtomicBool::new(true),
        events: sender,
        write: PlMutex::new(WriteState::Idle),
        writer: AtomicWaker::new(),
    });
    probes.insert(target.clone(), Arc::downgrade(&state));
    Ok(StreamProbe {
        target,
        state,
        events,
    })
}

impl StreamProbe {
    pub fn hold_next_pending_write(&self) -> Result<(), ProbeError> {
        let mut write = self.state.write.lock();
        if *write != WriteState::Idle {
            return Err(ProbeError::WriteAlreadyArmed);
        }
        *write = WriteState::Armed;
        Ok(())
    }

    pub fn release_write(&self) -> Result<(), ProbeError> {
        {
            let mut write = self.state.write.lock();
            if *write != WriteState::Held {
                return Err(ProbeError::WriteNotHeld);
            }
            *write = WriteState::Released;
        }
        self.state.writer.wake();
        Ok(())
    }

    /// The wait does not retain the owner and ends when the owner is dropped.
    pub fn next_event(
        &self,
    ) -> impl Future<Output = Result<StreamProbeEvent, ProbeError>> + Send + 'static + use<> {
        let events = self.events.clone();
        async move { events.recv().await.map_err(|_| ProbeError::Closed) }
    }
}

impl Drop for StreamProbe {
    fn drop(&mut self) {
        PROBES.lock().remove(&self.target);
        self.state.active.store(false, Ordering::Release);
        *self.state.write.lock() = WriteState::Released;
        self.state.events.close();
        self.state.writer.wake();
    }
}

fn state(target: &str) -> Option<Arc<State>> {
    PROBES.lock().get(target).and_then(Weak::upgrade)
}

pub(crate) fn stream_event(target: &str, event: StreamProbeEvent) {
    if let Some(state) = state(target) {
        let _ = state.events.try_send(event);
    }
}

struct WriteGuard {
    state: Option<Arc<State>>,
    held: bool,
    completed: bool,
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        if self.held
            && let Some(state) = &self.state
        {
            *state.write.lock() = WriteState::Idle;
            if !self.completed {
                let _ = state.events.try_send(StreamProbeEvent::WriteCancelled);
            }
        }
    }
}

pub(crate) async fn observe_write<F: Future>(target: Option<&str>, future: F) -> F::Output {
    let mut guard = WriteGuard {
        state: target.and_then(state),
        held: false,
        completed: false,
    };
    let mut future = pin!(future);
    let result = poll_fn(|context| {
        if guard.held
            && let Some(state) = &guard.state
        {
            state.writer.register(context.waker());
            if *state.write.lock() == WriteState::Held {
                return Poll::Pending;
            }
        }
        let result = future.as_mut().poll(context);
        if result.is_pending()
            && let Some(state) = &guard.state
        {
            let held = {
                let mut write = state.write.lock();
                if *write == WriteState::Armed && state.active.load(Ordering::Acquire) {
                    state.writer.register(context.waker());
                    *write = WriteState::Held;
                    true
                } else {
                    false
                }
            };
            if held {
                guard.held = true;
                let _ = state.events.try_send(StreamProbeEvent::WriteHeld);
            }
        }
        result
    })
    .await;
    guard.completed = true;
    result
}

#[cfg(test)]
mod tests;
