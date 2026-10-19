// SPDX-License-Identifier: Apache-2.0

pub mod openmetrics;
#[cfg(test)]
mod tests;

use crate::{
    config::MetricsConfig,
    error::{BenchError, BenchResult, ErrorCode},
    report::*,
};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use openmetrics::{MetricSnapshot, derive_interval, parse_snapshot};
use prometheus_client::{encoding::text::encode, registry::Registry};
use serde::Serialize;
use std::{
    io::{self, Write},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};

pub const RAW_CAPACITY: usize = 64 * 1024 * 1024;
pub const CONTROL_CAPACITY: usize = 8;
const BODY_CAPACITY: usize = 1024 * 1024;

#[derive(Clone)]
pub struct MetricsEndpoint {
    address: SocketAddr,
    host: String,
}
impl MetricsEndpoint {
    pub async fn resolve(url: &str) -> BenchResult<Self> {
        crate::config::validate_metrics_url(url)?;
        let uri: http::Uri = url.parse().map_err(|_| failure("metrics_url"))?;
        let authority = uri
            .authority()
            .ok_or_else(|| failure("metrics_authority"))?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let address = tokio::net::lookup_host((host, authority.port_u16().unwrap_or(80)))
            .await
            .map_err(|_| failure("metrics_resolution"))?
            .next()
            .ok_or_else(|| failure("metrics_resolution_empty"))?;
        Ok(Self {
            address,
            host: authority.as_str().to_owned(),
        })
    }
}

pub struct SamplerConfig {
    pub endpoint: Option<MetricsEndpoint>,
    pub timing: MetricsConfig,
}

#[derive(Clone, Copy)]
pub struct PhaseSampleRequest {
    pub phase: PhaseName,
    pub scheduled_at: Instant,
    pub window: Option<(Instant, Instant)>,
    pub achieved_connections: u64,
}

#[derive(Debug)]
pub struct TelemetryQueueFull;

pub struct TelemetrySampler {
    control: mpsc::Sender<PhaseSampleRequest>,
    stop: watch::Sender<Option<Instant>>,
    ready: Option<oneshot::Receiver<()>>,
    overflows: Arc<AtomicU64>,
    task: JoinHandle<(TelemetryReport, Vec<u8>, Option<MetricSnapshot>)>,
}

fn failure(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::Runtime, context)
}

pub fn allocate_buffer() -> BenchResult<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(RAW_CAPACITY)
        .map_err(|_| failure("telemetry_allocation"))?;
    buffer.resize(RAW_CAPACITY, 0);
    for page in buffer.chunks_mut(4096) {
        page[0] = std::hint::black_box(1);
    }
    buffer.clear();
    Ok(buffer)
}

impl TelemetrySampler {
    pub fn start(config: SamplerConfig, epoch: Instant, buffer: Vec<u8>) -> BenchResult<Self> {
        if buffer.capacity() != RAW_CAPACITY
            || !buffer.is_empty()
            || !(1000..=60_000).contains(&config.timing.interval_ms)
            || !(1..=10_000).contains(&config.timing.timeout_ms)
        {
            return Err(failure("telemetry_configuration"));
        }
        let (control, receiver) = mpsc::channel(CONTROL_CAPACITY);
        let (stop, stopped) = watch::channel(None);
        let (ready_send, ready) = oneshot::channel();
        let overflows = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(sample_loop(
            config,
            epoch,
            buffer,
            receiver,
            stopped,
            overflows.clone(),
            ready_send,
        ));
        Ok(Self {
            control,
            stop,
            overflows,
            task,
            ready: Some(ready),
        })
    }
    pub(crate) async fn ready(&mut self) {
        if let Some(ready) = self.ready.take() {
            let _ = ready.await;
        }
    }
    pub fn try_notify(&self, event: PhaseSampleRequest) -> Result<(), TelemetryQueueFull> {
        self.control.try_send(event).map_err(|_| {
            self.overflows.fetch_add(1, Ordering::Relaxed);
            TelemetryQueueFull
        })
    }
    pub async fn stop(self, deadline: Instant) -> BenchResult<(TelemetryReport, Vec<u8>)> {
        let (report, raw, _) = self.stop_observed(deadline).await?;
        Ok((report, raw))
    }
    pub(crate) async fn stop_observed(
        self,
        deadline: Instant,
    ) -> BenchResult<(TelemetryReport, Vec<u8>, Option<MetricSnapshot>)> {
        self.stop.send_replace(Some(deadline));
        self.task.await.map_err(|_| failure("telemetry_join"))
    }
}

struct Driver(JoinHandle<Result<(), hyper::Error>>);
impl Driver {
    async fn close(&mut self) {
        self.0.abort();
        let _ = (&mut self.0).await;
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn scrape(
    endpoint: &MetricsEndpoint,
    timeout: Duration,
    stopped: &mut watch::Receiver<Option<Instant>>,
) -> Result<String, &'static str> {
    let mut driver = None;
    let mut deadline = stopped
        .borrow()
        .unwrap_or_else(|| Instant::now() + timeout)
        .min(Instant::now() + timeout);
    if deadline <= Instant::now() {
        return Err("stop_deadline");
    }
    let result = {
        let work = async {
            let stream = TcpStream::connect(endpoint.address)
                .await
                .map_err(|_| "connect")?;
            let (mut sender, connection) =
                http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
                    .await
                    .map_err(|_| "handshake")?;
            driver = Some(Driver(tokio::spawn(connection)));
            let request = Request::builder()
                .uri("/metrics")
                .header("host", &endpoint.host)
                .header("accept", "application/openmetrics-text")
                .header("connection", "close")
                .body(Empty::new())
                .map_err(|_| "request")?;
            let response = sender.send_request(request).await.map_err(|_| "headers")?;
            if response.status() != http::StatusCode::OK {
                return Err("http_status");
            }
            if !response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.split(';').next() == Some("application/openmetrics-text"))
            {
                return Err("content_type");
            }
            let mut incoming = response.into_body();
            let mut body = Vec::with_capacity(BODY_CAPACITY);
            while let Some(frame) = incoming.frame().await {
                if let Ok(data) = frame.map_err(|_| "body")?.into_data() {
                    append_body(&mut body, &data)?;
                }
            }
            let body = String::from_utf8(body).map_err(|_| "utf8")?;
            if !openmetrics::has_eof(&body) {
                return Err("missing_eof");
            }
            Ok(body)
        };
        tokio::pin!(work);
        let mut stopping = stopped.borrow().is_some();
        loop {
            tokio::select! {
                biased;
                change = stopped.changed(), if !stopping => {
                    stopping = true;
                    if change.is_err() { break Err("stopped"); }
                    if let Some(stop_deadline) = *stopped.borrow_and_update() { deadline = deadline.min(stop_deadline); }
                    if deadline <= Instant::now() { break Err("stopped"); }
                },
                result = timeout_at(deadline, &mut work) => break result.unwrap_or(Err("timeout")),
            }
        }
    };
    if let Some(driver) = &mut driver {
        driver.close().await;
    }
    result
}

fn append_body(body: &mut Vec<u8>, data: &[u8]) -> Result<(), &'static str> {
    if data.len() > BODY_CAPACITY.saturating_sub(body.len()) {
        return Err("body_limit");
    }
    body.extend_from_slice(data);
    Ok(())
}

#[derive(Serialize)]
struct Sample<'a> {
    scope: &'static str,
    scheduled_offset_ns: u64,
    start_offset_ns: u64,
    end_offset_ns: u64,
    phase: PhaseName,
    status: &'static str,
    error: Option<&'static str>,
    bytes: usize,
    duration_ns: u64,
    openmetrics: Option<&'a str>,
}

struct FixedWriter<'a> {
    bytes: &'a mut Vec<u8>,
    limit: usize,
}
impl Write for FixedWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("output_limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn append_raw(raw: &mut Vec<u8>, limit: usize, sample: &Sample<'_>) -> bool {
    let before = raw.len();
    let mut writer = FixedWriter { bytes: raw, limit };
    if serde_json::to_writer(&mut writer, sample).is_err() || writer.write_all(b"\n").is_err() {
        writer.bytes.truncate(before);
        false
    } else {
        true
    }
}

#[derive(Default)]
struct Population {
    sum: f64,
    peak: u64,
    count: u64,
    start: Option<u64>,
    end: Option<u64>,
}
impl Population {
    fn add(&mut self, value: u64, start: u64, end: u64) {
        self.sum += value as f64;
        self.peak = self.peak.max(value);
        self.count += 1;
        self.start.get_or_insert(start);
        self.end = Some(end);
    }
    fn mean(&self) -> SampledValue {
        SampledValue {
            value: (self.count > 0).then(|| self.sum / self.count as f64),
            sample_count: self.count,
            start_offset_ns: self.start,
            end_offset_ns: self.end,
        }
    }
    fn peak(&self) -> SampledIntegerValue {
        SampledIntegerValue {
            value: (self.count > 0).then_some(self.peak),
            sample_count: self.count,
            start_offset_ns: self.start,
            end_offset_ns: self.end,
        }
    }
}
#[derive(Default)]
struct Resources {
    previous_cpu: Option<(f64, u64, u64)>,
    previous_policies: std::collections::BTreeMap<String, u64>,
    previous_dropped: Option<u64>,
    identity: MetricSnapshot,
    rss: Population,
    fds: Population,
    baseline: Option<(u64, f64)>,
    cpu: SampledValue,
    cpu_seconds: f64,
    cpu_elapsed: f64,
    steal: SampledValue,
    previous_steal: Option<(f64, u64)>,
}
impl Resources {
    fn observe(
        &mut self,
        snapshot: MetricSnapshot,
        (start, end): (u64, u64),
        window: Option<(u64, u64)>,
        preconnect: bool,
        server: bool,
        report: &mut TelemetryReport,
    ) {
        let identity_changed = derive_interval(&self.identity, &snapshot).identity_changed;
        if identity_changed {
            self.baseline = None;
            self.previous_cpu = None;
            self.previous_policies.clear();
            self.previous_dropped = None;
        }
        if identity_changed && server {
            report.identity_changes += 1;
            reason(report, ReasonCode::ServerRestarted, "server_restarted");
        }
        if let Some(value) = snapshot.process_start {
            self.identity.process_start = Some(value);
        }
        if snapshot.build.is_some() {
            self.identity.build = snapshot.build.clone();
        }
        if snapshot.invalid_samples
            || snapshot.process_start.is_none()
            || snapshot.cpu_seconds.is_none()
        {
            reason(report, ReasonCode::TelemetryPartial, "unavailable_metrics");
        }
        if preconnect && let Some(rss) = snapshot.rss_bytes {
            self.baseline = snapshot.process_start.map(|identity| (rss, identity));
        }
        if let Some((ws, we)) = window
            && ws <= start
            && end <= we
        {
            if let Some(value) = snapshot.rss_bytes {
                self.rss.add(value, start, end);
            }
            if let Some(value) = snapshot.open_fds {
                self.fds.add(value, start, end);
            }
        }
        if let Some(cpu) = snapshot.cpu_seconds {
            if let Some((previous, ps, pe)) = self.previous_cpu {
                if cpu < previous {
                    reason(report, ReasonCode::TelemetryPartial, "counter_decreased");
                } else if let Some((ws, we)) = window
                    && ws <= ps
                    && end <= we
                    && end > pe
                {
                    let seconds = self.cpu_seconds + (cpu - previous);
                    let elapsed = self.cpu_elapsed + (end - pe) as f64 / 1e9;
                    let average = seconds / elapsed;
                    if average.is_finite() {
                        self.cpu_seconds = seconds;
                        self.cpu_elapsed = elapsed;
                        self.cpu.value = Some(average);
                        self.cpu.sample_count += 1;
                        self.cpu.start_offset_ns.get_or_insert(pe);
                        self.cpu.end_offset_ns = Some(end);
                    } else {
                        reason(report, ReasonCode::TelemetryPartial, "nonfinite_derivation");
                    }
                }
            }
            self.previous_cpu = Some((cpu, start, end));
        }
        for (key, current) in snapshot.policy_rejections {
            if let Some(previous) = self.previous_policies.insert(key.clone(), current) {
                if let Some(delta) = current.checked_sub(previous) {
                    if server {
                        let previous = report.policy_rejections.entry(key).or_default();
                        if let Some(total) = previous.checked_add(delta) {
                            *previous = total;
                        } else {
                            reason(report, ReasonCode::TelemetryPartial, "counter_overflow");
                        }
                    }
                } else {
                    reason(report, ReasonCode::TelemetryPartial, "counter_decreased");
                }
            }
        }
        if let Some(current) = snapshot.dropped_logs {
            if self
                .previous_dropped
                .is_some_and(|previous| previous > current)
            {
                reason(report, ReasonCode::TelemetryPartial, "counter_decreased");
            }
            self.previous_dropped = Some(current);
        }
    }
    fn finish(self, achieved: u64) -> ResourceSummary {
        let mut incremental = if achieved > 0 {
            self.rss.mean()
        } else {
            SampledValue::default()
        };
        incremental.value = self
            .baseline
            .zip(self.identity.process_start)
            .filter(|((_, start), end)| start == end)
            .and_then(|((baseline, _), _)| {
                self.rss
                    .mean()
                    .value
                    .filter(|_| achieved > 0)
                    .map(|mean| (mean - baseline as f64) / achieved as f64)
            });
        ResourceSummary {
            cpu_average_cores: self.cpu,
            rss_mean_bytes: self.rss.mean(),
            rss_peak_bytes: self.rss.peak(),
            open_fds_mean: self.fds.mean(),
            open_fds_peak: self.fds.peak(),
            incremental_rss_per_connection_bytes: incremental,
            generator_host_steal_seconds: self.steal,
        }
    }
}

fn reason(report: &mut TelemetryReport, code: ReasonCode, context: &'static str) {
    if !report
        .reasons
        .iter()
        .any(|r| r.context.as_deref() == Some(context))
    {
        report.reasons.push(RunReason {
            code,
            context: Some(context.into()),
        });
    }
    report.quality = TelemetryStatus::Partial;
}
fn offset(epoch: Instant, at: Instant) -> u64 {
    at.saturating_duration_since(epoch)
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

struct ReadyBoundary {
    completion: Option<oneshot::Sender<()>>,
}
impl ReadyBoundary {
    fn observe_server(
        &self,
        resources: &mut Resources,
        snapshot: MetricSnapshot,
        interval: (u64, u64),
        window: Option<(u64, u64)>,
        report: &mut TelemetryReport,
    ) {
        resources.observe(
            snapshot,
            interval,
            window,
            self.completion.is_some(),
            true,
            report,
        );
    }
    fn complete(&mut self) {
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(());
        }
    }
}

async fn sample_loop(
    config: SamplerConfig,
    epoch: Instant,
    mut raw: Vec<u8>,
    mut control: mpsc::Receiver<PhaseSampleRequest>,
    mut stopped: watch::Receiver<Option<Instant>>,
    overflows: Arc<AtomicU64>,
    ready_send: oneshot::Sender<()>,
) -> (TelemetryReport, Vec<u8>, Option<MetricSnapshot>) {
    let mut registry = Registry::default();
    registry.register_collector(Box::new(lonewolf_metrics::ProcessCollector::new()));
    let mut report = TelemetryReport {
        quality: TelemetryStatus::Complete,
        samples_ok: 0,
        samples_failed: 0,
        missed_ticks: 0,
        queue_overflows: 0,
        bytes: 0,
        total_scrape_duration_ms: 0,
        server: ResourceSummary::default(),
        generator: ResourceSummary::default(),
        policy_rejections: Default::default(),
        identity_changes: 0,
        reasons: Vec::new(),
    };
    let interval = Duration::from_millis(config.timing.interval_ms);
    let mut next_tick = Instant::now() + interval;
    let mut initial_sample = true;
    let mut current = PhaseSampleRequest {
        phase: PhaseName::TargetSetup,
        scheduled_at: Instant::now(),
        window: None,
        achieved_connections: 0,
    };
    let mut server = Resources::default();
    let mut generator = Resources::default();
    let mut output_limited = false;
    let mut end_sampled = false;
    let mut encoding = String::with_capacity(4096);
    let mut ready = ReadyBoundary {
        completion: Some(ready_send),
    };
    let mut total_duration_ns = 0u128;
    loop {
        let nominal_end = current.window.map(|(_, end)| end).filter(|_| !end_sampled);
        if !initial_sample {
            report.missed_ticks += skip_ticks(&mut next_tick, Instant::now(), interval);
        }
        let scheduled = if initial_sample {
            initial_sample = false;
            Instant::now()
        } else if stopped.borrow().is_some() {
            match control.try_recv() {
                Ok(event) => {
                    current = event;
                    current.scheduled_at
                }
                Err(_) => break,
            }
        } else {
            tokio::select! {
                biased;
                _ = stopped.changed() => continue,
                event = control.recv() => match event { Some(event) => { current = event; current.scheduled_at }, None => break },
                _ = async { if let Some(end) = nominal_end { tokio::time::sleep_until(end).await; } else { std::future::pending::<()>().await; } } => { end_sampled = true; nominal_end.unwrap_or_else(Instant::now) },
                _ = tokio::time::sleep_until(next_tick) => { let scheduled = next_tick; next_tick += interval; scheduled },
            }
        };
        let start = Instant::now();
        let window = current
            .window
            .map(|(a, b)| (offset(epoch, a), offset(epoch, b)));
        for scope in ["generator", "server"] {
            let sample_start = Instant::now();
            let body = if scope == "generator" {
                encoding.clear();
                encode(&mut encoding, &registry)
                    .map(|()| encoding.clone())
                    .map_err(|_| "generator_encode")
            } else if let Some(endpoint) = &config.endpoint {
                scrape(
                    endpoint,
                    Duration::from_millis(config.timing.timeout_ms),
                    &mut stopped,
                )
                .await
            } else {
                Err("endpoint_unavailable")
            };
            let steal = if scope == "generator" {
                host_steal()
            } else {
                None
            };
            let sample_end = Instant::now();
            let (ss, se) = (offset(epoch, sample_start), offset(epoch, sample_end));
            let parsed = body
                .as_ref()
                .ok()
                .and_then(|body| parse_snapshot(body).ok());
            let error = body
                .as_ref()
                .err()
                .copied()
                .or_else(|| parsed.is_none().then_some("parse"));
            if let Some(snapshot) = parsed {
                report.samples_ok += 1;
                if scope == "server" {
                    ready.observe_server(&mut server, snapshot, (ss, se), window, &mut report);
                } else {
                    generator.observe(snapshot, (ss, se), window, false, false, &mut report);
                    if let Some(value) = steal {
                        if let Some((previous, at)) = generator.previous_steal
                            && let Some((ws, we)) = window
                            && ws <= at
                            && se <= we
                            && value >= previous
                        {
                            generator.steal.value =
                                Some(generator.steal.value.unwrap_or(0.0) + value - previous);
                            generator.steal.sample_count += 1;
                            generator.steal.start_offset_ns.get_or_insert(at);
                            generator.steal.end_offset_ns = Some(se);
                        }
                        generator.previous_steal = Some((value, se));
                    }
                }
            } else {
                report.samples_failed += 1;
                reason(
                    &mut report,
                    ReasonCode::TelemetryPartial,
                    error.unwrap_or("parse"),
                );
            }
            let bytes = body.as_ref().map_or(0, String::len);
            report.bytes += bytes as u64;
            if !output_limited
                && !append_raw(
                    &mut raw,
                    RAW_CAPACITY,
                    &Sample {
                        scope,
                        scheduled_offset_ns: offset(epoch, scheduled),
                        start_offset_ns: ss,
                        end_offset_ns: se,
                        phase: current.phase,
                        status: if error.is_some() { "failed" } else { "ok" },
                        error,
                        bytes,
                        duration_ns: se - ss,
                        openmetrics: if error.is_none() {
                            body.as_deref().ok()
                        } else {
                            None
                        },
                    },
                )
            {
                output_limited = true;
                reason(&mut report, ReasonCode::TelemetryPartial, "output_limit");
            }
            total_duration_ns += Instant::now().duration_since(sample_start).as_nanos();
        }
        ready.complete();
        if Instant::now().duration_since(start) > interval {
            reason(&mut report, ReasonCode::TelemetryPartial, "slow_scrape");
        }
    }
    report.total_scrape_duration_ms =
        (total_duration_ns / 1_000_000).min(u128::from(u64::MAX)) as u64;
    report.queue_overflows = overflows.load(Ordering::Relaxed);
    if report.queue_overflows > 0 {
        reason(&mut report, ReasonCode::TelemetryPartial, "queue_overflow");
    }
    if report.missed_ticks > 0 {
        reason(&mut report, ReasonCode::TelemetryPartial, "missed_ticks");
    }
    if report.samples_ok == 0 {
        report.quality = TelemetryStatus::Unavailable;
    }
    let identity = server.identity.clone();
    report.server = server.finish(current.achieved_connections);
    report.generator = generator.finish(0);
    (report, raw, Some(identity))
}

fn skip_ticks(next: &mut Instant, now: Instant, interval: Duration) -> u64 {
    if now < *next {
        return 0;
    }
    let skipped = (now.duration_since(*next).as_nanos() / interval.as_nanos() + 1) as u64;
    *next += interval * skipped.min(u64::from(u32::MAX)) as u32;
    skipped
}

fn host_steal() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut buffer = [0; 4096];
        let n = std::fs::File::open("/proc/stat")
            .ok()?
            .read(&mut buffer)
            .ok()?;
        let text = std::str::from_utf8(&buffer[..n]).ok()?;
        let ticks = text
            .lines()
            .next()?
            .split_ascii_whitespace()
            .nth(8)?
            .parse::<u64>()
            .ok()?;
        // sysconf has no pointer arguments and reports failure with -1.
        let hz = unsafe { nix::libc::sysconf(nix::libc::_SC_CLK_TCK) };
        (hz > 0).then(|| ticks as f64 / hz as f64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
