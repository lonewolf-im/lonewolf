// SPDX-License-Identifier: Apache-2.0

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Default)]
pub struct WireCounters(Arc<Counters>);

#[derive(Default)]
struct Counters {
    read: AtomicU64,
    written: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireSnapshot {
    pub read: u64,
    pub written: u64,
}

impl WireCounters {
    pub fn snapshot(&self) -> WireSnapshot {
        WireSnapshot {
            read: self.0.read.load(Ordering::Relaxed),
            written: self.0.written.load(Ordering::Relaxed),
        }
    }
}

pub struct WireIo<T> {
    inner: T,
    counters: WireCounters,
}

impl<T> WireIo<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            counters: WireCounters::default(),
        }
    }

    pub fn counters(&self) -> WireCounters {
        self.counters.clone()
    }
}

impl<T: Read> Read for WireIo<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(output)?;
        self.counters
            .0
            .read
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    fn read_vectored(&mut self, output: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let count = self.inner.read_vectored(output)?;
        self.counters
            .0
            .read
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}

impl<T: Write> Write for WireIo<T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(input)?;
        self.counters
            .0
            .written
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    fn write_vectored(&mut self, input: &[IoSlice<'_>]) -> io::Result<usize> {
        let count = self.inner.write_vectored(input)?;
        self.counters
            .0
            .written
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
