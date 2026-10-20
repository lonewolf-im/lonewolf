// SPDX-License-Identifier: Apache-2.0

use super::{BenchResult, failure};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::{
    io::{self, Read},
    process::ChildStderr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const LINE_LIMIT: usize = 8192;
const LOG_LIMIT: usize = 1024 * 1024;
const TRUNCATED: &[u8] = b"[server log truncated]\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Startup {
    C2s(u16),
    Metrics(u16),
    Ready,
    Failed,
}

/// Copies the server's stderr into a bounded log and reports startup events.
pub(super) struct Collector {
    pub(super) receiver: Receiver<Startup>,
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
        let (sender, receiver) = mpsc::sync_channel(4);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::Builder::new()
            .name("bench-server-log".into())
            .spawn(move || collect(&mut stderr, &stopped, sender))
            .map_err(|_| failure("fixture_capture_thread"))?;
        Ok(Self {
            receiver,
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

fn collect(reader: &mut impl Read, stop: &AtomicBool, sender: SyncSender<Startup>) -> Vec<u8> {
    let mut capture = Capture::new(sender);
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
                capture.notify(Startup::Failed);
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
    sender: SyncSender<Startup>,
    c2s: Option<u16>,
    metrics: Option<u16>,
    ready: bool,
    failed: bool,
}
impl Capture {
    fn new(sender: SyncSender<Startup>) -> Self {
        Self {
            line: Vec::with_capacity(LINE_LIMIT),
            oversized: false,
            output: Vec::new(),
            truncated: false,
            sender,
            c2s: None,
            metrics: None,
            ready: false,
            failed: false,
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
    fn notify(&mut self, event: Startup) {
        let fresh = match event {
            Startup::C2s(port) => match self.c2s.replace(port) {
                None => true,
                Some(old) if old == port => false,
                Some(_) => {
                    self.notify(Startup::Failed);
                    false
                }
            },
            Startup::Metrics(port) => match self.metrics.replace(port) {
                None => true,
                Some(old) if old == port => false,
                Some(_) => {
                    self.notify(Startup::Failed);
                    false
                }
            },
            Startup::Ready => !std::mem::replace(&mut self.ready, true),
            Startup::Failed => !std::mem::replace(&mut self.failed, true),
        };
        if fresh {
            let _ = self.sender.try_send(event);
        }
    }
    fn finish_line(&mut self) {
        if self.oversized {
            self.record(b"[oversized line omitted]\n");
        } else {
            let line = std::mem::take(&mut self.line);
            if let Some(event) = std::str::from_utf8(&line).ok().and_then(parse) {
                self.notify(event);
            }
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

fn parse(line: &str) -> Option<Startup> {
    if line.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let mut words = line.split_whitespace();
    let date = words.next()?;
    let time = words.next()?;
    if date.len() != 10 || time.len() != 8 || words.next()? != "INFO" {
        return None;
    }
    let digits_with = |value: &str, separators: [usize; 2]| {
        value.bytes().enumerate().all(|(index, byte)| {
            if separators.contains(&index) {
                byte == b':'
            } else {
                byte.is_ascii_digit()
            }
        })
    };
    if !digits_with(date, [4, 7]) || !digits_with(time, [2, 5]) {
        return None;
    }
    let target = words.next()?;
    let (_, message) = line.split_once(target)?;
    let message = message.strip_prefix(' ')?;
    match target {
        "lonewolf_core::c2s:" => {
            let fields = message.strip_prefix("c2s TCP listener started ")?;
            let [listener, workers, port] =
                numeric_fields(fields, ["listener_id", "worker_count", "port"])?;
            if listener != 0 || workers == 0 {
                return None;
            }
            u16::try_from(port)
                .ok()
                .filter(|port| *port != 0)
                .map(Startup::C2s)
        }
        "lonewolf_metrics::server:" => {
            let [port] =
                numeric_fields(message.strip_prefix("metrics service started ")?, ["port"])?;
            u16::try_from(port)
                .ok()
                .filter(|port| *port != 0)
                .map(Startup::Metrics)
        }
        "lonewolf_core:" => (message
            == "waiting for stop signal... (press Ctrl+C to stop the server)")
            .then_some(Startup::Ready),
        _ => None,
    }
}

fn numeric_fields<const N: usize>(fields: &str, keys: [&str; N]) -> Option<[u64; N]> {
    let mut values = [None; N];
    for field in fields.split_whitespace() {
        let (key, text) = field.split_once('=')?;
        let index = keys.iter().position(|expected| *expected == key)?;
        if values[index].is_some()
            || text.is_empty()
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        values[index] = Some(text.parse().ok()?);
    }
    let mut output = [0; N];
    for (value, stored) in output.iter_mut().zip(values) {
        *value = stored?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_drain_is_finite_when_another_owner_keeps_pipe_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        let (sender, _) = mpsc::sync_channel(4);
        let stop = AtomicBool::new(true);
        let start = Instant::now();
        let output = collect(&mut reader, &stop, sender);
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(output.is_empty());
        drop(writer);
        Ok(())
    }

    #[test]
    fn fragmented_logs_report_startup_once_and_keep_every_line() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut capture = Capture::new(sender);
        let input = b"2026:10:19 12:00:00  INFO lonewolf_core::c2s: c2s TCP listener started listener_id=0 worker_count=2 port=1234\n2026:10:19 12:00:00  INFO lonewolf_metrics::server: metrics service started port=2345\n2026:10:19 12:00:00  INFO lonewolf_core: waiting for stop signal... (press Ctrl+C to stop the server)\nother line\n";
        for chunk in input.chunks(3) {
            capture.push(chunk);
        }
        assert_eq!(
            receiver.try_iter().collect::<Vec<_>>(),
            [Startup::C2s(1234), Startup::Metrics(2345), Startup::Ready]
        );
        assert_eq!(capture.output, input);
    }

    #[test]
    fn startup_fields_reject_malformed_and_duplicate_tokens() {
        for message in [
            "lonewolf_metrics::server: metrics service started port=4 port=5",
            "lonewolf_metrics::server: metrics service started port=0",
            "lonewolf_metrics::server: metrics service started",
            r#"lonewolf_metrics::server: metrics service started detail=" port=2345 ""#,
            "lonewolf_metrics::server: metrics service started port=2345 extra",
            "lonewolf_metrics::server: metrics service started port=65536",
            "lonewolf_core::c2s: c2s TCP listener started worker_count=2 port=1234",
            "lonewolf_core::c2s: c2s TCP listener started listener_id=0 worker_count=2 port=1234 other=1",
            "other: waiting for stop signal... (press Ctrl+C to stop the server)",
        ] {
            assert_eq!(parse(&format!("2026:10:19 12:00:00 INFO {message}")), None);
        }
        assert_eq!(
            parse(
                "2026:10:19 12:00:00 INFO lonewolf_metrics::server: metrics service started port=2345"
            ),
            Some(Startup::Metrics(2345))
        );
    }

    #[test]
    fn oversized_and_saturated_logs_remain_bounded_and_keep_detecting_startup() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut capture = Capture::new(sender);
        capture.push(&vec![b'x'; LINE_LIMIT + 1]);
        capture.push(b"\n");
        for _ in 0..20_000 {
            capture.push(b"2026:10:19 12:00:00 INFO lonewolf_core: core dispatcher stopped\n");
        }
        capture.push(b"2026:10:19 12:00:00 INFO lonewolf_core: waiting for stop signal... (press Ctrl+C to stop the server)\n");
        assert!(capture.output.len() <= LOG_LIMIT);
        assert!(capture.output.starts_with(b"[oversized line omitted]\n"));
        assert!(capture.output.ends_with(TRUNCATED));
        assert_eq!(receiver.try_recv(), Ok(Startup::Ready));
    }
}
