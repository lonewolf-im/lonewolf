// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::{Context, Poll};

use futures_util::io::AsyncWrite;
use futures_util::task::AtomicWaker;
use parking_lot::Mutex as PlMutex;

use super::ProbeError;

static PROBES: LazyLock<PlMutex<BTreeMap<SocketAddr, Weak<State>>>> =
    LazyLock::new(|| PlMutex::new(BTreeMap::new()));

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentWriteProbeEvent {
    Held,
}

enum WriteState {
    Idle,
    Armed(usize),
    Held,
}

struct State {
    peer: SocketAddr,
    active: AtomicBool,
    bound: AtomicBool,
    write: PlMutex<WriteState>,
    writer: AtomicWaker,
    events: async_channel::Sender<ComponentWriteProbeEvent>,
}

impl State {
    fn close(&self) {
        {
            let mut probes = PROBES.lock();
            if probes
                .get(&self.peer)
                .is_some_and(|registered| std::ptr::eq(registered.as_ptr(), self))
            {
                probes.remove(&self.peer);
            }
        }
        self.active.store(false, Ordering::Release);
        self.events.close();
        self.writer.wake();
    }
}

/// Dropping the owner releases its writer and ends pending event waits.
pub struct ComponentWriteProbe {
    state: Arc<State>,
    events: async_channel::Receiver<ComponentWriteProbeEvent>,
}

/// Install before the peer sends its component opening and handshake.
pub fn install_component_write_probe(peer: SocketAddr) -> Result<ComponentWriteProbe, ProbeError> {
    let mut probes = PROBES.lock();
    if probes.get(&peer).and_then(Weak::upgrade).is_some() {
        return Err(ProbeError::DuplicateTarget);
    }
    let (events, receiver) = async_channel::unbounded();
    let state = Arc::new(State {
        peer,
        active: AtomicBool::new(true),
        bound: AtomicBool::new(false),
        write: PlMutex::new(WriteState::Idle),
        writer: AtomicWaker::new(),
        events,
    });
    probes.insert(peer, Arc::downgrade(&state));
    Ok(ComponentWriteProbe {
        state,
        events: receiver,
    })
}

impl ComponentWriteProbe {
    pub fn hold_after_bytes(&self, allowance: usize) -> Result<(), ProbeError> {
        let mut write = self.state.write.lock();
        if !self.state.active.load(Ordering::Acquire) {
            return Err(ProbeError::Closed);
        }
        if !matches!(*write, WriteState::Idle) {
            return Err(ProbeError::WriteAlreadyArmed);
        }
        *write = WriteState::Armed(allowance);
        Ok(())
    }

    pub fn release_write(&self) -> Result<(), ProbeError> {
        {
            let mut write = self.state.write.lock();
            if !self.state.active.load(Ordering::Acquire) {
                return Err(ProbeError::Closed);
            }
            if !matches!(*write, WriteState::Held) {
                return Err(ProbeError::WriteNotHeld);
            }
            *write = WriteState::Idle;
        }
        self.state.writer.wake();
        Ok(())
    }

    pub fn next_event(
        &self,
    ) -> impl Future<Output = Result<ComponentWriteProbeEvent, ProbeError>> + Send + 'static + use<>
    {
        let events = self.events.clone();
        async move { events.recv().await.map_err(|_| ProbeError::Closed) }
    }
}

impl Drop for ComponentWriteProbe {
    fn drop(&mut self) {
        self.state.close();
    }
}

pub(crate) struct ComponentOutput<W> {
    inner: W,
    state: Option<Arc<State>>,
}

impl<W> ComponentOutput<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, state: None }
    }

    pub(crate) fn bind(&mut self, peer: SocketAddr) {
        self.state = PROBES
            .lock()
            .get(&peer)
            .and_then(Weak::upgrade)
            .filter(|state| {
                state.active.load(Ordering::Acquire) && !state.bound.swap(true, Ordering::AcqRel)
            });
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ComponentOutput<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let Some(state) = &this.state else {
            return Pin::new(&mut this.inner).poll_write(context, bytes);
        };
        state.writer.register(context.waker());
        let mut write = state.write.lock();
        if !state.active.load(Ordering::Acquire) {
            return Pin::new(&mut this.inner).poll_write(context, bytes);
        }
        let remaining = match *write {
            WriteState::Armed(0) => {
                *write = WriteState::Held;
                let _ = state.events.try_send(ComponentWriteProbeEvent::Held);
                return Poll::Pending;
            }
            WriteState::Held => return Poll::Pending,
            WriteState::Armed(remaining) => remaining,
            WriteState::Idle => return Pin::new(&mut this.inner).poll_write(context, bytes),
        };
        let result =
            Pin::new(&mut this.inner).poll_write(context, &bytes[..bytes.len().min(remaining)]);
        if let Poll::Ready(Ok(count)) = result {
            *write = WriteState::Armed(remaining - count);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_close(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(context)
    }
}

impl<W> Drop for ComponentOutput<W> {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            state.close();
        }
    }
}
