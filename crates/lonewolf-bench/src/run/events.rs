// SPDX-License-Identifier: Apache-2.0

use crate::{
    client::{OperationId, ReceivedEvent},
    report::PhaseName,
};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{Notify, mpsc},
    time::Instant,
};

#[derive(Clone, Debug)]
pub enum RunEvent {
    WriteStarted {
        index: u32,
        operation: OperationId,
        at: Instant,
    },
    WriteFinished {
        index: u32,
        operation: OperationId,
        at: Instant,
        succeeded: bool,
        bytes: usize,
    },
    Received {
        index: u32,
        event: ReceivedEvent,
    },
    ConnectionClosed {
        index: u32,
        at: Instant,
    },
    Invalid {
        index: u32,
        at: Instant,
    },
}

pub(crate) struct EventSender {
    sender: Option<SyncSender<RunEvent>>,
    notify: Arc<Notify>,
    invalid: Arc<AtomicBool>,
}

impl EventSender {
    pub(crate) fn new(capacity: usize, invalid: Arc<AtomicBool>) -> (Self, EventReceiver) {
        let (sender, receiver) = sync_channel(capacity);
        let notify = Arc::new(Notify::new());
        (
            Self {
                sender: Some(sender),
                notify: notify.clone(),
                invalid,
            },
            EventReceiver { receiver, notify },
        )
    }

    pub(crate) fn emit(&self, event: RunEvent) {
        if self
            .sender
            .as_ref()
            .is_none_or(|sender| sender.try_send(event).is_err())
        {
            self.invalid.store(true, Ordering::Release);
        }
        self.notify.notify_one();
    }
}

impl Clone for EventSender {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            notify: self.notify.clone(),
            invalid: self.invalid.clone(),
        }
    }
}

impl Drop for EventSender {
    fn drop(&mut self) {
        self.sender.take();
        self.notify.notify_one();
    }
}

pub(crate) struct EventReceiver {
    receiver: Receiver<RunEvent>,
    notify: Arc<Notify>,
}
impl EventReceiver {
    pub(crate) fn try_recv(&mut self) -> Result<RunEvent, TryRecvError> {
        self.receiver.try_recv()
    }
    pub(crate) async fn recv(&mut self) -> Option<RunEvent> {
        loop {
            let notified = self.notify.notified();
            match self.receiver.try_recv() {
                Ok(event) => return Some(event),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => notified.await,
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ObserverEvent {
    PhaseStarted(PhaseName),
    PhaseFinished(PhaseName),
    ActiveConnections(u64),
}

#[derive(Clone, Default)]
pub struct RunObserver {
    sender: Option<mpsc::Sender<ObserverEvent>>,
}

impl RunObserver {
    pub fn bounded(capacity: NonZeroUsize) -> (Self, mpsc::Receiver<ObserverEvent>) {
        let (sender, receiver) = mpsc::channel(capacity.get());
        (
            Self {
                sender: Some(sender),
            },
            receiver,
        )
    }

    fn emit(&self, event: ObserverEvent) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(event);
        }
    }

    pub fn phase_started(&self, phase: PhaseName) {
        self.emit(ObserverEvent::PhaseStarted(phase));
    }
    pub fn phase_finished(&self, phase: PhaseName) {
        self.emit(ObserverEvent::PhaseFinished(phase));
    }
    pub fn active_connections(&self, count: u64) {
        self.emit(ObserverEvent::ActiveConnections(count));
    }
}
