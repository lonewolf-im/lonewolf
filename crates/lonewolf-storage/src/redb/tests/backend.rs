// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, ThreadId};

use ::redb::StorageBackend;
use ::redb::backends::InMemoryBackend;
use parking_lot::Mutex as PlMutex;

use crate::tests::TIMEOUT;

/// Shares its memory between clones, so a database can be reopened over it.
#[derive(Clone, Debug, Default)]
pub(super) struct FailingSyncBackend {
    inner: Arc<InMemoryBackend>,
    fail_next_sync: Arc<AtomicBool>,
}

impl FailingSyncBackend {
    pub(super) fn fail_next_sync(&self) {
        self.fail_next_sync.store(true, Ordering::SeqCst);
    }
}

impl StorageBackend for FailingSyncBackend {
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()?;
        if self.fail_next_sync.swap(false, Ordering::SeqCst) {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.inner.write(offset, data)
    }
}

/// Records the thread of every backend call and can hold the next sync open.
#[derive(Clone, Debug, Default)]
pub(super) struct ObservedBackend {
    inner: Arc<InMemoryBackend>,
    threads: Arc<PlMutex<Vec<ThreadId>>>,
    sync_gate: Arc<PlMutex<Option<SyncGate>>>,
}

#[derive(Debug)]
struct SyncGate {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl ObservedBackend {
    pub(super) fn take_threads(&self) -> Result<Vec<ThreadId>, Box<dyn Error>> {
        Ok(std::mem::take(&mut *self.threads.lock()))
    }

    /// Returns a receiver that fires when the sync starts and a sender that lets it finish.
    pub(super) fn block_next_sync(
        &self,
    ) -> Result<(mpsc::Receiver<()>, mpsc::Sender<()>), Box<dyn Error>> {
        let (entered, started) = mpsc::channel();
        let (release, released) = mpsc::channel();
        *self.sync_gate.lock() = Some(SyncGate {
            entered,
            release: released,
        });
        Ok((started, release))
    }

    fn record_thread(&self) -> io::Result<()> {
        self.threads.lock().push(thread::current().id());
        Ok(())
    }
}

impl StorageBackend for ObservedBackend {
    fn len(&self) -> io::Result<u64> {
        self.record_thread()?;
        self.inner.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.record_thread()?;
        self.inner.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.record_thread()?;
        self.inner.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.record_thread()?;
        let gate = self.sync_gate.lock().take();
        if let Some(gate) = gate {
            gate.entered.send(()).map_err(io::Error::other)?;
            gate.release
                .recv_timeout(TIMEOUT)
                .map_err(io::Error::other)?;
        }
        self.inner.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.record_thread()?;
        self.inner.write(offset, data)
    }
}
