// SPDX-License-Identifier: Apache-2.0

use super::{BenchResult, failure};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io::{self, Read},
    process::ChildStderr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const LINE_LIMIT: usize = 8192;
const LOG_LIMIT: usize = 1024 * 1024;
const TRUNCATED: &[u8] = b"[server log truncated]\n";

/// Copies the server's stderr into a bounded log.
pub(super) struct Collector {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Vec<u8>>>,
}
impl Collector {
    pub(super) fn start(mut stderr: ChildStderr) -> BenchResult<Self> {
        let flags =
            fcntl(&stderr, FcntlArg::F_GETFL).map_err(|_| failure("fixture_capture_flags"))?;
        fcntl(
            &stderr,
            FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
        )
        .map_err(|_| failure("fixture_capture_flags"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::Builder::new()
            .name("bench-server-log".into())
            .spawn(move || collect(&mut stderr, &stopped))
            .map_err(|_| failure("fixture_capture_thread"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    pub(super) fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub(super) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub(super) fn join(&mut self) -> BenchResult<Vec<u8>> {
        match self.thread.take() {
            Some(thread) => thread.join().map_err(|_| failure("fixture_capture_panic")),
            None => Err(failure("fixture_capture_joined")),
        }
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn collect(reader: &mut impl Read, stop: &AtomicBool) -> Vec<u8> {
    let mut capture = Capture::new();
    let mut chunk = [0; 8192];
    let mut draining = None;
    let mut drained = 0;
    loop {
        if stop.load(Ordering::Acquire) && draining.is_none() {
            draining = Some(Instant::now());
        }
        // Another process may keep the pipe open, so the final drain is bounded.
        if draining.is_some_and(|start: Instant| start.elapsed() >= Duration::from_millis(100))
            || drained >= LOG_LIMIT
        {
            break;
        }
        match reader.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(count) => {
                capture.push(&chunk[..count]);
                if draining.is_some() {
                    drained += count;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if draining.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                capture.record(b"[server log read failed]\n");
                break;
            }
        }
    }
    if !capture.line.is_empty() {
        capture.finish_line();
    }
    capture.output
}

struct Capture {
    line: Vec<u8>,
    oversized: bool,
    output: Vec<u8>,
    truncated: bool,
}
impl Capture {
    fn new() -> Self {
        Self {
            line: Vec::with_capacity(LINE_LIMIT),
            oversized: false,
            output: Vec::new(),
            truncated: false,
        }
    }
    fn record(&mut self, bytes: &[u8]) {
        if self.truncated {
            return;
        }
        if self.output.len() + bytes.len() + TRUNCATED.len() > LOG_LIMIT {
            self.output.extend_from_slice(TRUNCATED);
            self.truncated = true;
        } else {
            self.output.extend_from_slice(bytes);
        }
    }
    fn finish_line(&mut self) {
        if self.oversized {
            self.record(b"[oversized line omitted]\n");
        } else {
            let line = std::mem::take(&mut self.line);
            self.record(&line);
            self.record(b"\n");
            self.line = line;
        }
        self.line.clear();
        self.oversized = false;
    }
    fn push(&mut self, data: &[u8]) {
        for &byte in data {
            if byte == b'\n' {
                self.finish_line();
            } else if !self.oversized {
                if self.line.len() == LINE_LIMIT {
                    self.line.clear();
                    self.oversized = true;
                } else {
                    self.line.push(byte);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_drain_is_finite_when_another_owner_keeps_pipe_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        let stop = AtomicBool::new(true);
        let start = Instant::now();
        let output = collect(&mut reader, &stop);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(output.is_empty());
        drop(writer);
        Ok(())
    }

    #[test]
    fn fragmented_logs_keep_every_line() {
        let mut capture = Capture::new();
        let input =
            b"2026:10:19 12:00:00  INFO lonewolf_core: core dispatcher started\nother line\n";
        for chunk in input.chunks(3) {
            capture.push(chunk);
        }
        assert_eq!(capture.output, input);
    }

    #[test]
    fn oversized_and_saturated_logs_remain_bounded() {
        let mut capture = Capture::new();
        capture.push(&vec![b'x'; LINE_LIMIT + 1]);
        capture.push(b"\n");
        for _ in 0..20_000 {
            capture.push(b"2026:10:19 12:00:00 INFO lonewolf_core: core dispatcher stopped\n");
        }
        assert!(capture.output.len() <= LOG_LIMIT);
        assert!(capture.output.starts_with(b"[oversized line omitted]\n"));
        assert!(capture.output.ends_with(TRUNCATED));
    }
}
