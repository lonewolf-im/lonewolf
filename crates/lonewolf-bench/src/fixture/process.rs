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
use zeroize::{Zeroize, Zeroizing};

const LINE_LIMIT: usize = 8192;
const LOG_LIMIT: usize = 64 * 1024;
const MARKER_RESERVE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Startup {
    C2s(u16),
    Metrics(u16),
    Ready,
    Failed,
}

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
    let mut parser = Projection::new(sender);
    let mut chunk = Zeroizing::new([0; 8192]);
    let mut draining = None;
    let mut drained = 0;
    loop {
        if stop.load(Ordering::Acquire) && draining.is_none() {
            draining = Some(Instant::now());
        }
        if draining.is_some_and(|start: Instant| start.elapsed() >= Duration::from_millis(100))
            || drained >= LOG_LIMIT
        {
            break;
        }
        match reader.read(&mut chunk[..]) {
            Ok(0) => break,
            Ok(count) => {
                parser.push(&chunk[..count]);
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
                parser.status(8, b"capture_read_failure\n");
                parser.notify(Startup::Failed);
                break;
            }
        }
    }
    if !parser.line.is_empty() || parser.oversized {
        parser.status(2, b"input_omitted\n");
    }
    parser.output
}

struct Projection {
    line: Zeroizing<Vec<u8>>,
    oversized: bool,
    output: Vec<u8>,
    status_flags: u8,
    sender: SyncSender<Startup>,
    c2s: Option<u16>,
    metrics: Option<u16>,
    ready: bool,
    failed: bool,
}
impl Projection {
    fn new(sender: SyncSender<Startup>) -> Self {
        Self {
            line: Zeroizing::new(Vec::with_capacity(LINE_LIMIT)),
            oversized: false,
            output: Vec::with_capacity(LOG_LIMIT),
            status_flags: 0,
            sender,
            c2s: None,
            metrics: None,
            ready: false,
            failed: false,
        }
    }
    fn marker(&mut self, token: &[u8]) {
        if self.output.len() + token.len() <= LOG_LIMIT - MARKER_RESERVE {
            self.output.extend_from_slice(token);
        } else {
            self.status(1, b"capture_truncated\n");
        }
    }
    fn status(&mut self, bit: u8, token: &[u8]) {
        if self.status_flags & bit == 0 {
            self.status_flags |= bit;
            self.output.extend_from_slice(token);
        }
    }
    fn notify(&mut self, event: Startup) {
        let fresh = match event {
            Startup::C2s(port) => match self.c2s {
                None => {
                    self.c2s = Some(port);
                    true
                }
                Some(old) if old == port => false,
                Some(_) => {
                    self.notify(Startup::Failed);
                    false
                }
            },
            Startup::Metrics(port) => match self.metrics {
                None => {
                    self.metrics = Some(port);
                    true
                }
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
    fn push(&mut self, data: &[u8]) {
        for &byte in data {
            if byte == b'\n' {
                if self.oversized {
                    self.status(4, b"oversized_line_omitted\n");
                } else {
                    let parsed = std::str::from_utf8(&self.line).ok().and_then(parse);
                    match parsed {
                        Some((event, token)) => {
                            self.marker(token);
                            if let Some(event) = event {
                                self.notify(event);
                            }
                        }
                        None => self.status(2, b"input_omitted\n"),
                    }
                }
                self.line.zeroize();
                self.oversized = false;
            } else if !self.oversized {
                if self.line.len() == LINE_LIMIT {
                    self.line.zeroize();
                    self.oversized = true;
                } else {
                    self.line.push(byte);
                }
            }
        }
    }
}

type Parsed = (Option<Startup>, &'static [u8]);
fn parse(line: &str) -> Option<Parsed> {
    if line.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let mut words = line.split_whitespace();
    let date = words.next()?;
    let time = words.next()?;
    if date.len() != 10 || time.len() != 8 || words.next()? != "INFO" {
        return None;
    }
    if !date.bytes().enumerate().all(|(index, byte)| {
        if index == 4 || index == 7 {
            byte == b':'
        } else {
            byte.is_ascii_digit()
        }
    }) || !time.bytes().enumerate().all(|(index, byte)| {
        if index == 2 || index == 5 {
            byte == b':'
        } else {
            byte.is_ascii_digit()
        }
    }) {
        return None;
    }
    let target = words.next()?;
    let (_, message) = line.split_once(target)?;
    let message = message.strip_prefix(' ')?;
    match target {
        "lonewolf_core::c2s:" => {
            if let Some(fields) = message.strip_prefix("c2s TCP listener stopped ") {
                let [listener, workers] = numeric_fields(fields, ["listener_id", "worker_count"])?;
                if listener == 0 && workers > 0 {
                    return Some((None, b"c2s_listener_stopped\n"));
                }
                return None;
            }
            let fields = message.strip_prefix("c2s TCP listener started ")?;
            let [listener, workers, port] =
                numeric_fields(fields, ["listener_id", "worker_count", "port"])?;
            if listener != 0 || workers == 0 {
                return None;
            }
            let port = u16::try_from(port).ok()?;
            if port == 0 {
                return None;
            }
            Some((Some(Startup::C2s(port)), b"c2s_listener_started\n"))
        }
        "lonewolf_metrics::server:" => {
            if message == "metrics service stopped" {
                return Some((None, b"metrics_service_stopped\n"));
            }
            let [port] =
                numeric_fields(message.strip_prefix("metrics service started ")?, ["port"])?;
            let port = u16::try_from(port).ok()?;
            if port == 0 {
                return None;
            }
            Some((Some(Startup::Metrics(port)), b"metrics_service_started\n"))
        }
        "lonewolf_core:" => match message {
            "waiting for stop signal... (press Ctrl+C to stop the server)" => {
                Some((Some(Startup::Ready), b"server_ready\n"))
            }
            "core dispatcher stopped" => Some((None, b"core_dispatcher_stopped\n")),
            _ => None,
        },
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
    fn fragmented_logs_project_only_known_tokens_and_unique_ports() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut projection = Projection::new(sender);
        let input = b"2026:10:19 12:00:00  INFO lonewolf_core::c2s: c2s TCP listener started listener_id=0 worker_count=2 port=1234\n2026:10:19 12:00:00  INFO lonewolf_metrics::server: metrics service started port=2345\n2026:10:19 12:00:00  INFO lonewolf_core: waiting for stop signal... (press Ctrl+C to stop the server)\nsecret-password\n";
        for chunk in input.chunks(3) {
            projection.push(chunk);
        }
        assert_eq!(
            receiver.try_iter().collect::<Vec<_>>(),
            [Startup::C2s(1234), Startup::Metrics(2345), Startup::Ready]
        );
        assert_eq!(
            projection.output,
            b"c2s_listener_started\nmetrics_service_started\nserver_ready\ninput_omitted\n"
        );
        assert!(parse("2026:10:19 12:00:00 INFO lonewolf_metrics::server: metrics service started port=4 port=5").is_none());
        assert!(
            parse(
                "2026:10:19 12:00:00 INFO lonewolf_metrics::server: metrics service started port=0"
            )
            .is_none()
        );
        assert!(
            parse("2026:10:19 12:00:00 INFO lonewolf_metrics::server: metrics service started")
                .is_none()
        );
        assert!(parse("2026:10:19 12:00:00 INFO lonewolf_core::c2s: c2s TCP listener started worker_count=2 port=1234").is_none());
        assert!(parse("2026:10:19 12:00:00 INFO other: waiting for stop signal... (press Ctrl+C to stop the server)").is_none());
    }
    #[test]
    fn startup_fields_reject_quoted_embedded_unknown_malformed_and_duplicate_tokens() {
        for message in [
            r#"metrics service started detail=" port=2345 ""#,
            r#"metrics service started port=2345 detail="secret""#,
            "metrics service started port=2345 port=2345",
            "metrics service started port=2345 extra",
            "metrics service started port=2345=1234",
            "metrics service started port=65536",
        ] {
            assert!(
                parse(&format!(
                    "2026:10:19 12:00:00 INFO lonewolf_metrics::server: {message}"
                ))
                .is_none()
            );
        }
        for message in [
            r#"c2s TCP listener started listener_id=0 worker_count=2 detail=" port=1234 ""#,
            r#"c2s TCP listener started detail=" listener_id=0 worker_count=2 port=1234 ""#,
            "c2s TCP listener started listener_id=0 worker_count=2 port=1234 other=1",
            "c2s TCP listener started listener_id=0 listener_id=0 worker_count=2 port=1234",
        ] {
            assert!(
                parse(&format!(
                    "2026:10:19 12:00:00 INFO lonewolf_core::c2s: {message}"
                ))
                .is_none()
            );
        }
        assert_eq!(
            parse(
                "2026:10:19 12:00:00 INFO lonewolf_metrics::server: metrics service started port=2345"
            ),
            Some((
                Some(Startup::Metrics(2345)),
                b"metrics_service_started\n".as_slice()
            ))
        );
        assert_eq!(
            parse(
                "2026:10:19 12:00:00 INFO lonewolf_core::c2s: c2s TCP listener started listener_id=0 worker_count=2 port=1234"
            ),
            Some((
                Some(Startup::C2s(1234)),
                b"c2s_listener_started\n".as_slice()
            ))
        );
    }
    #[test]
    fn oversized_and_saturated_logs_remain_bounded_and_keep_draining() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut projection = Projection::new(sender);
        projection.push(&vec![b'x'; LINE_LIMIT + 1]);
        projection.push(b"\n");
        for _ in 0..10000 {
            projection.push(b"2026:10:19 12:00:00 INFO lonewolf_core: core dispatcher stopped\n");
        }
        projection.push(b"secret\n");
        projection.push(b"2026:10:19 12:00:00 INFO lonewolf_core: waiting for stop signal... (press Ctrl+C to stop the server)\n");
        assert!(projection.output.len() <= LOG_LIMIT);
        assert!(projection.output.starts_with(b"oversized_line_omitted\n"));
        assert!(
            projection
                .output
                .windows(b"capture_truncated\n".len())
                .any(|chunk| chunk == b"capture_truncated\n")
        );
        assert_eq!(receiver.try_recv(), Ok(Startup::Ready));
        assert!(!projection.output.windows(6).any(|chunk| chunk == b"secret"));
    }
}
