// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_bench::{
    config::MetricsConfig,
    report::{PhaseName, ReasonCode, TelemetryStatus},
    telemetry::{MetricsEndpoint, PhaseSampleRequest, SamplerConfig, TelemetrySampler},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Instant, timeout},
};

#[test]
fn scripted_scram_and_bind_failures_are_nonzero_and_sanitized() -> TestResult {
    for behavior in [
        peer::Behavior::NoMechanism,
        peer::Behavior::BadNonce,
        peer::Behavior::BadProof,
        peer::Behavior::BindError,
        peer::Behavior::WrongBind,
    ] {
        let directory = tempfile::tempdir()?;
        let peer = peer::Peer::start(directory.path(), behavior)?;
        let config = inputs(
            directory.path(),
            peer.address,
            &directory.path().join("certificate.pem"),
            ScenarioConfig::Idle { connections: 1 },
        )?;
        let path = config_file(directory.path(), "config", &config)?;
        let out = directory.path().join("result");
        let output = run_cli(&path, &out)?;
        assert_eq!(output.status.code(), Some(1), "{behavior:?}");
        let report = artifacts::complete(&out, RunStatus::Failed)?;
        let expected = match behavior {
            peer::Behavior::NoMechanism => "scram_mechanism_missing",
            peer::Behavior::BadNonce => "scram_nonce",
            peer::Behavior::BadProof => "scram_server_signature",
            peer::Behavior::BindError => "binding_failed",
            peer::Behavior::WrongBind => "binding_identity",
            _ => unreachable!(),
        };
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.context.as_deref() == Some(expected)),
            "{behavior:?}: {:?}",
            report.reasons
        );
        bench_support::assert_no_secret(
            &out,
            Some(&output),
            &[SECRET, "PRIVATE KEY", "<auth", "c2FsdHNhbHQ="],
        )?;
        peer.finish()?;
    }
    Ok(())
}

#[test]
fn scripted_socket_delivery_faults_preserve_accounting_and_reader_identity() -> TestResult {
    for behavior in [
        peer::Behavior::Normal,
        peer::Behavior::Fragmented,
        peer::Behavior::Delayed,
        peer::Behavior::Duplicate,
        peer::Behavior::WrongBody,
        peer::Behavior::WrongRoute,
        peer::Behavior::StanzaError,
        peer::Behavior::Late,
        peer::Behavior::Disconnect,
        peer::Behavior::NoRead,
        peer::Behavior::NoReceipt,
    ] {
        let directory = tempfile::tempdir()?;
        let peer = peer::Peer::start(directory.path(), behavior)?;
        let mut config = inputs(
            directory.path(),
            peer.address,
            &directory.path().join("certificate.pem"),
            ScenarioConfig::Messages {
                pairs: 1,
                rate_per_second: 1,
                body_bytes: 64,
            },
        )?;
        config.measurement.operation_timeout_ms = 300;
        config.measurement.max_schedule_lag_ms = 100;
        config.measurement.shutdown_timeout_ms = 300;
        let path = config_file(directory.path(), "config", &config)?;
        let out = directory.path().join("result");
        let output = run_cli(&path, &out)?;
        let report = lonewolf_bench::report::RunReport::read(&out)?;
        let c = &report.counters;
        assert_eq!(c.planned, 1, "{behavior:?}: {:?}", report.reasons);
        assert_eq!(c.dispatched, 1, "{behavior:?}");
        assert_eq!(
            c.write_succeeded + c.write_failed + c.write_cancelled,
            1,
            "{behavior:?}"
        );
        assert_eq!(
            c.received_on_time
                + c.unreceived_timeout
                + c.unreceived_connection_closed
                + c.unreceived_send_failed
                + c.unreceived_cancelled,
            1,
            "{behavior:?}"
        );
        match behavior {
            peer::Behavior::Normal | peer::Behavior::Fragmented | peer::Behavior::Delayed => {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{behavior:?}: {:?}",
                    report.reasons
                );
                assert_eq!(c.received_on_time, 1);
                assert_eq!(c.write_succeeded, 1);
                assert_eq!(c.wrong_recipient, 0);
            }
            peer::Behavior::Duplicate => {
                assert_eq!(c.duplicates, 1);
                assert_eq!(output.status.code(), Some(3));
            }
            peer::Behavior::WrongRoute | peer::Behavior::WrongBody => {
                assert_eq!(c.wrong_recipient, 1);
                assert_eq!(c.received_on_time, 0);
            }
            peer::Behavior::Late => {
                assert_eq!(c.late_receipts, 1);
                assert_eq!(c.unreceived_timeout, 1);
            }
            peer::Behavior::Disconnect => {
                assert!(c.unreceived_connection_closed > 0);
            }
            peer::Behavior::StanzaError => {
                assert_eq!(c.unreceived_send_failed, 1);
            }
            _ => {
                assert_eq!(c.received_on_time, 0);
                assert!(c.unreceived_timeout > 0);
            }
        }
        if !matches!(
            behavior,
            peer::Behavior::Normal | peer::Behavior::Fragmented | peer::Behavior::Delayed
        ) {
            assert_ne!(output.status.code(), Some(0), "{behavior:?}");
        }
        bench_support::assert_no_secret(&out, Some(&output), &[SECRET, "PRIVATE KEY"])?;
        if behavior != peer::Behavior::NoRead {
            assert_eq!(peer.messages.load(Ordering::Relaxed), 1);
        }
        peer.finish()?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum HttpFault {
    Valid,
    Missing,
    Oversized,
    SlowHeaders,
    SlowBody,
    BadStatus,
    BadEof,
    Restart,
    BuildChange,
    CounterDrop,
    Large,
}
impl HttpFault {
    fn allows_response_disconnect(self) -> bool {
        matches!(
            self,
            Self::SlowHeaders | Self::SlowBody | Self::Oversized | Self::BadStatus
        )
    }
}

#[derive(Clone, Copy)]
enum ResponseStart {
    Immediate,
    AfterReset,
}

fn peer_disconnected(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    )
}

async fn wait_for_http_close(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await? {
        0 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected HTTP request bytes",
        )),
    }
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    fault: HttpFault,
    sequence: usize,
    partial_body: &tokio::sync::mpsc::UnboundedSender<()>,
) -> io::Result<()> {
    let response = async {
        if matches!(fault, HttpFault::SlowHeaders) {
            return wait_for_http_close(stream).await;
        }
        let cpu = if matches!(fault, HttpFault::CounterDrop) && sequence > 0 {
            0
        } else {
            10 + sequence
        };
        let start = if matches!(fault, HttpFault::Restart) && sequence > 0 {
            2
        } else {
            1
        };
        let build = if matches!(fault, HttpFault::BuildChange) && sequence > 0 {
            "b"
        } else {
            "a"
        };
        let mut body = format!("process_start_time_seconds {start}\nprocess_cpu_seconds_total {cpu}\nprocess_resident_memory_bytes 1000\nprocess_open_fds 5\nlonewolf_build_info{{commit=\"{build}\",branch=\"test\",version=\"test\"}} 1\nlonewolf_c2s_connections{{listener=\"0\"}} 2\nlonewolf_c2s_connections{{listener=\"1\"}} 3\n# EOF\n");
        match fault {
            HttpFault::Missing => body = "# EOF\n".into(),
            HttpFault::BadEof => body = "process_cpu_seconds_total 1\n".into(),
            HttpFault::Oversized => body = "x".repeat(1_048_577),
            HttpFault::Large => body = format!("# {}\n{body}", "x".repeat(1_000_000)),
            _ => {}
        }
        let length = if matches!(fault, HttpFault::SlowBody) {
            body.len() + 10000
        } else {
            body.len()
        };
        let status = if matches!(fault, HttpFault::BadStatus) {
            "503 Unavailable"
        } else {
            "200 OK"
        };
        stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/openmetrics-text\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        if matches!(fault, HttpFault::SlowBody) {
            stream.write_all(b"partial-secret-body-sentinel").await?;
            let _ = partial_body.send(());
            wait_for_http_close(stream).await
        } else {
            stream.write_all(body.as_bytes()).await
        }
    }
    .await;
    match response {
        Err(error) if fault.allows_response_disconnect() && peer_disconnected(&error) => Ok(()),
        other => other,
    }
}

async fn http_exchange(
    stream: &mut tokio::net::TcpStream,
    fault: HttpFault,
    sequence: usize,
    requests: &tokio::sync::mpsc::UnboundedSender<String>,
    partial_body: &tokio::sync::mpsc::UnboundedSender<()>,
    response_start: ResponseStart,
) -> io::Result<()> {
    let mut request = Vec::new();
    loop {
        let mut bytes = [0; 1024];
        let count = stream.read(&mut bytes).await?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&bytes[..count]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if request.len() > 8192 {
            return Err(io::Error::other("request bound"));
        }
    }
    let _ = requests.send(String::from_utf8_lossy(&request).into_owned());
    if matches!(response_start, ResponseStart::AfterReset) {
        let mut byte = [0];
        let result = timeout(Duration::from_secs(5), stream.read(&mut byte)).await?;
        if !matches!(result, Err(error) if error.kind() == io::ErrorKind::ConnectionReset) {
            return Err(io::Error::other("expected TCP reset before HTTP response"));
        }
    }
    write_http_response(stream, fault, sequence, partial_body).await
}

struct HttpServer {
    url: String,
    stop: tokio::sync::watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    requests: tokio::sync::mpsc::UnboundedReceiver<String>,
    partial_bodies: tokio::sync::mpsc::UnboundedReceiver<()>,
    closed: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
}
impl HttpServer {
    async fn start(fault: HttpFault) -> TestResult<Self> {
        Self::with_response_start(fault, ResponseStart::Immediate).await
    }
    async fn with_response_start(
        fault: HttpFault,
        response_start: ResponseStart,
    ) -> TestResult<Self> {
        let address = tokio::net::lookup_host(("localhost", 0))
            .await?
            .next()
            .ok_or("localhost")?;
        assert!(address.ip().is_loopback());
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let (send, requests) = tokio::sync::mpsc::unbounded_channel();
        let (partial_body, partial_bodies) = tokio::sync::mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let (task_active, task_closed) = (active.clone(), closed.clone());
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            let mut sequence = 0;
            loop {
                tokio::select! {
                    _ = stopped.changed() => break,
                    connection = listener.accept() => {
                        let (mut stream, _) = connection?;
                        let (send, partial_body) = (send.clone(), partial_body.clone());
                        let (active, closed) = (task_active.clone(), task_closed.clone());
                        let current = sequence;
                        sequence += 1;
                        children.spawn(async move {
                            active.fetch_add(1, Ordering::AcqRel);
                            let result = http_exchange(&mut stream, fault, current, &send, &partial_body, response_start).await;
                            active.fetch_sub(1, Ordering::AcqRel);
                            closed.fetch_add(1, Ordering::AcqRel);
                            result
                        });
                    }
                }
            }
            while let Some(result) = children.join_next().await {
                result.map_err(io::Error::other)??;
            }
            Ok(())
        });
        Ok(Self {
            url: format!("http://localhost:{}/metrics", address.port()),
            stop,
            task: Some(task),
            requests,
            partial_bodies,
            closed,
            active,
        })
    }
    async fn request(&mut self) -> TestResult<String> {
        Ok(timeout(Duration::from_secs(10), self.requests.recv())
            .await?
            .ok_or("HTTP request")?)
    }
    async fn partial_body(&mut self) -> TestResult {
        timeout(Duration::from_secs(10), self.partial_bodies.recv())
            .await?
            .ok_or("HTTP partial body")?;
        Ok(())
    }
    async fn finish(mut self) -> TestResult {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            timeout(Duration::from_secs(10), task).await???;
        }
        assert_eq!(self.active.load(Ordering::Acquire), 0);
        Ok(())
    }
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn phase() -> PhaseSampleRequest {
    PhaseSampleRequest {
        phase: PhaseName::Measurement,
        scheduled_at: Instant::now(),
        window: None,
        achieved_connections: 0,
    }
}

#[tokio::test]
async fn pre_response_reset_is_allowed_only_for_intentionally_interrupted_http() -> TestResult {
    for fault in [HttpFault::SlowBody, HttpFault::Valid] {
        let mut http = HttpServer::with_response_start(fault, ResponseStart::AfterReset).await?;
        let authority = http
            .url
            .strip_prefix("http://")
            .and_then(|url| url.strip_suffix("/metrics"))
            .ok_or("authority")?
            .to_owned();
        let mut client = timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&authority),
        )
        .await??;
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        assert!(
            http.request()
                .await?
                .starts_with("GET /metrics HTTP/1.1\r\n")
        );
        assert_eq!(http.active.load(Ordering::Acquire), 1);
        socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO))?;
        drop(client);
        let active = http.active.clone();
        let closed = http.closed.clone();
        let result = http.finish().await;
        if matches!(fault, HttpFault::SlowBody) {
            result?;
        } else {
            let error = result.err().ok_or("normal HTTP response hid TCP reset")?;
            assert!(
                error
                    .downcast_ref::<io::Error>()
                    .is_some_and(peer_disconnected)
            );
        }
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(closed.load(Ordering::Acquire), 1);
    }
    Ok(())
}

#[tokio::test]
async fn http_metrics_preserve_host_pin_address_and_degrade_without_changing_workload() -> TestResult
{
    for fault in [
        HttpFault::Valid,
        HttpFault::Missing,
        HttpFault::Oversized,
        HttpFault::SlowHeaders,
        HttpFault::SlowBody,
        HttpFault::BadStatus,
        HttpFault::BadEof,
    ] {
        let mut http = HttpServer::start(fault).await?;
        let endpoint = MetricsEndpoint::resolve(&http.url).await?;
        let sampler = TelemetrySampler::start(
            SamplerConfig {
                endpoint: Some(endpoint),
                timing: MetricsConfig {
                    interval_ms: 1000,
                    timeout_ms: 200,
                },
            },
            Instant::now(),
        )?;
        let request = http.request().await?;
        let authority = http
            .url
            .strip_prefix("http://")
            .and_then(|s| s.strip_suffix("/metrics"))
            .ok_or("authority")?;
        assert!(
            request
                .to_ascii_lowercase()
                .contains(&format!("host: {authority}\r\n"))
        );
        assert!(request.starts_with("GET /metrics HTTP/1.1\r\n"));
        let (report, raw) = sampler
            .stop(Instant::now() + Duration::from_millis(300))
            .await?;
        assert!(!raw.is_empty());
        assert!(!String::from_utf8_lossy(&raw).contains("partial-secret-body-sentinel"));
        if matches!(fault, HttpFault::Valid) {
            assert!(report.samples_ok > 0);
        } else {
            assert_ne!(report.quality, TelemetryStatus::Complete);
        }
        http.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn mid_body_cancellation_joins_http_driver_before_artifact_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut http = HttpServer::start(HttpFault::SlowBody).await?;
    let sampler = TelemetrySampler::start(
        SamplerConfig {
            endpoint: Some(MetricsEndpoint::resolve(&http.url).await?),
            timing: MetricsConfig {
                interval_ms: 1000,
                timeout_ms: 10000,
            },
        },
        Instant::now(),
    )?;
    http.request().await?;
    http.partial_body().await?;
    let (report, raw) = sampler.stop(Instant::now()).await?;
    assert_ne!(report.quality, TelemetryStatus::Complete);
    timeout(Duration::from_secs(2), async {
        while http.active.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(http.closed.load(Ordering::Acquire) > 0);
    let file = directory.path().join("telemetry.ndjson");
    fs::write(&file, &raw)?;
    let before = fs::read(&file)?;
    http.finish().await?;
    assert_eq!(fs::read(file)?, before);
    Ok(())
}

#[tokio::test]
async fn sampler_restart_build_and_counter_changes_survive_complete_http_exchanges() -> TestResult {
    for fault in [
        HttpFault::Restart,
        HttpFault::BuildChange,
        HttpFault::CounterDrop,
    ] {
        let mut http = HttpServer::start(fault).await?;
        let sampler = TelemetrySampler::start(
            SamplerConfig {
                endpoint: Some(MetricsEndpoint::resolve(&http.url).await?),
                timing: MetricsConfig {
                    interval_ms: 1000,
                    timeout_ms: 1000,
                },
            },
            Instant::now(),
        )?;
        http.request().await?;
        sampler.try_notify(phase()).map_err(|_| "control full")?;
        http.request().await?;
        let (report, _) = sampler
            .stop(Instant::now() + Duration::from_secs(1))
            .await?;
        if matches!(fault, HttpFault::CounterDrop) {
            assert_ne!(report.quality, TelemetryStatus::Complete);
        } else {
            assert!(report.identity_changes > 0);
            assert!(
                report
                    .reasons
                    .iter()
                    .any(|r| r.code == ReasonCode::ServerRestarted)
            );
        }
        http.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn bounded_control_saturation_does_not_block_and_is_retained_after_join() -> TestResult {
    let mut http = HttpServer::start(HttpFault::SlowBody).await?;
    let sampler = TelemetrySampler::start(
        SamplerConfig {
            endpoint: Some(MetricsEndpoint::resolve(&http.url).await?),
            timing: MetricsConfig {
                interval_ms: 1000,
                timeout_ms: 10000,
            },
        },
        Instant::now(),
    )?;
    http.request().await?;
    let mut refused = 0;
    for _ in 0..100 {
        refused += u64::from(sampler.try_notify(phase()).is_err());
    }
    assert!(refused > 0);
    let (report, raw) = sampler.stop(Instant::now()).await?;
    assert_eq!(report.queue_overflows, refused);
    assert!(raw.len() <= lonewolf_bench::telemetry::RAW_CAPACITY);
    http.finish().await?;
    Ok(())
}

#[tokio::test]
async fn raw_output_saturation_keeps_complete_records_and_continues_collection() -> TestResult {
    let mut http = HttpServer::start(HttpFault::Large).await?;
    let sampler = TelemetrySampler::start(
        SamplerConfig {
            endpoint: Some(MetricsEndpoint::resolve(&http.url).await?),
            timing: MetricsConfig {
                interval_ms: 60000,
                timeout_ms: 3000,
            },
        },
        Instant::now(),
    )?;
    for index in 0..75 {
        http.request().await?;
        if index != 74 {
            sampler.try_notify(phase()).map_err(|_| "control full")?;
        }
    }
    let (report, raw) = sampler
        .stop(Instant::now() + Duration::from_secs(3))
        .await?;
    assert!(raw.len() <= lonewolf_bench::telemetry::RAW_CAPACITY);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.context.as_deref() == Some("output_limit"))
    );
    assert!(report.samples_ok > 75);
    assert_eq!(raw.last(), Some(&b'\n'));
    for line in raw.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        serde_json::from_slice::<serde_json::Value>(line)?;
    }
    http.finish().await?;
    Ok(())
}

#[tokio::test]
async fn real_workload_restart_invalidates_comparison_while_missing_metrics_only_degrade()
-> TestResult {
    for fault in [
        HttpFault::Restart,
        HttpFault::BuildChange,
        HttpFault::Missing,
        HttpFault::BadStatus,
    ] {
        let directory = tempfile::tempdir()?;
        let peer = peer::Peer::start(directory.path(), peer::Behavior::Normal)?;
        let mut http = HttpServer::start(fault).await?;
        let mut config = inputs(
            directory.path(),
            peer.address,
            &directory.path().join("certificate.pem"),
            ScenarioConfig::Idle { connections: 1 },
        )?;
        if let TargetConfig::Remote { metrics_url, .. } = &mut config.target {
            *metrics_url = Some(http.url.clone());
        }
        let out = directory.path().join("result");
        let report = lonewolf_bench::run(config, &out).await?;
        http.request().await?;
        if matches!(fault, HttpFault::Restart | HttpFault::BuildChange) {
            assert_eq!(report.status, RunStatus::Invalid);
            assert!(!lonewolf_bench::compare::compare_runs(&report, &report).comparable);
        } else {
            assert_eq!(report.status, RunStatus::Passed);
            assert_ne!(report.telemetry.quality, TelemetryStatus::Complete);
            assert!(lonewolf_bench::compare::compare_runs(&report, &report).comparable);
        }
        http.finish().await?;
        peer.finish()?;
    }
    Ok(())
}

#[test]
fn ctrl_c_in_observed_setup_measurement_and_pending_drain_finalizes_partial_reports() -> TestResult
{
    use bench_support::{Process, wait_for_file};
    for phase in [
        PhaseName::TargetSetup,
        PhaseName::Measurement,
        PhaseName::MeasurementDrain,
    ] {
        let directory = tempfile::tempdir()?;
        let peer = peer::Peer::start(directory.path(), peer::Behavior::NoReceipt)?;
        let marker = directory.path().join("phase");
        let input = directory.path().join("input.json");
        let output = directory.path().join("result");
        private_write(
            &input,
            &serde_json::to_vec(
                &serde_json::json!({"root":directory.path(),"port":peer.address.port(),"marker":marker,"output":output,"phase":phase}),
            )?,
        )?;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "faults::phase_signal_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BENCHMARK_SIGNAL_INPUT", &input);
        let process = Process::spawn_command(&mut command)?;
        wait_for_file(&marker)?;
        process.signal()?;
        let result = process.wait()?;
        assert_eq!(
            result.status.code(),
            Some(130),
            "{phase:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report = artifacts::complete(&output, RunStatus::Interrupted)?;
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.code == ReasonCode::Interrupted)
        );
        let measured = report
            .phases
            .iter()
            .any(|p| p.name == PhaseName::Measurement);
        assert_eq!(measured, phase != PhaseName::TargetSetup);
        if measured {
            assert_eq!(
                report.rates.window_seconds,
                Some(if phase == PhaseName::Measurement {
                    10.0
                } else {
                    1.0
                })
            );
        }
        bench_support::assert_no_secret(&output, Some(&result), &[SECRET, "PRIVATE KEY"])?;
        peer.finish()?;
    }
    Ok(())
}

#[test]
#[ignore = "subprocess entry point for phase signal workflows"]
fn phase_signal_child() -> TestResult {
    let input = std::env::var_os("BENCHMARK_SIGNAL_INPUT").ok_or("input")?;
    let value: serde_json::Value = serde_json::from_slice(&fs::read(input)?)?;
    let root = PathBuf::from(value["root"].as_str().ok_or("root")?);
    let marker = PathBuf::from(value["marker"].as_str().ok_or("marker")?);
    let output = PathBuf::from(value["output"].as_str().ok_or("output")?);
    let phase: PhaseName = serde_json::from_value(value["phase"].clone())?;
    let port = u16::try_from(value["port"].as_u64().ok_or("port")?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let report=runtime.block_on(async {
        let mut config=inputs(&root,SocketAddr::from(([127,0,0,1],port)),&root.join("certificate.pem"),ScenarioConfig::Messages{pairs:1,rate_per_second:1,body_bytes:64})?;
        config.measurement.operation_timeout_ms=30000;
        config.measurement.duration_ms=if phase==PhaseName::Measurement{10000}else{1000};
        let mut http=if phase==PhaseName::TargetSetup{Some(HttpServer::start(HttpFault::SlowHeaders).await?)}else{None};
        if let (Some(http),TargetConfig::Remote{metrics_url,..})=(&http,&mut config.target){*metrics_url=Some(http.url.clone());config.metrics.timeout_ms=10000;}
        let (observer,mut events)=lonewolf_bench::run::events::RunObserver::bounded(std::num::NonZeroUsize::new(128).ok_or("capacity")?);
        let signals=tokio::spawn(async move {
            while let Some(event)=events.recv().await {
                if matches!(event,lonewolf_bench::run::events::ObserverEvent::PhaseStarted(observed) if observed==phase){
                    fs::write(&marker,b"ready")?;
                    return Ok::<_,std::io::Error>(());
                }
            }
            Err(std::io::Error::other("phase not entered"))
        });
        let report=lonewolf_bench::run::run_with_observer(config,&output,observer).await?;
        signals.await??;
        if let Some(http)=http.take(){http.finish().await?;}
        Ok::<_,Box<dyn std::error::Error>>(report)
    })?;
    std::process::exit(i32::from(report.status.exit_code()));
}

#[tokio::test]
async fn actual_cli_ctrl_c_during_pending_setup_closes_http_before_returning() -> TestResult {
    let directory = tempfile::tempdir()?;
    let peer = peer::Peer::start(directory.path(), peer::Behavior::Normal)?;
    let mut http = HttpServer::start(HttpFault::SlowBody).await?;
    let mut config = inputs(
        directory.path(),
        peer.address,
        &directory.path().join("certificate.pem"),
        ScenarioConfig::Idle { connections: 1 },
    )?;
    if let TargetConfig::Remote { metrics_url, .. } = &mut config.target {
        *metrics_url = Some(http.url.clone());
    }
    config.metrics.timeout_ms = 10000;
    let path = config_file(directory.path(), "config", &config)?;
    let out = directory.path().join("result");
    let process = bench_support::Process::spawn(
        binary(),
        &[
            "run".as_ref(),
            "--config".as_ref(),
            path.as_os_str(),
            "--output".as_ref(),
            out.as_os_str(),
        ],
    )?;
    http.request().await?;
    http.partial_body().await?;
    process.signal()?;
    let result = tokio::task::spawn_blocking(move || process.wait().map_err(|e| e.to_string()))
        .await?
        .map_err(|e| e.to_string())?;
    assert_eq!(result.status.code(), Some(130));
    artifacts::complete(&out, RunStatus::Interrupted)?;
    timeout(Duration::from_secs(2), async {
        while http.active.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    http.finish().await?;
    peer.finish()?;
    Ok(())
}

#[tokio::test]
async fn destination_receipt_can_be_consumed_before_queued_sender_completion() -> TestResult {
    use lonewolf_bench::cpu::CpuPool;
    use lonewolf_bench::{
        client::{
            self, EventSink, KeyMode, MessageCommand, MessageRoute, PreparedAccount, ReceiveRoute,
            ReceivedKind, TrafficPhase, WriteCommand,
        },
        measurement::{
            FinishReason, Ledger, LedgerContext, LedgerTopology, OperationEvent, PhaseBarrier,
            RouteIdentity, ScheduledSlot, Termination,
        },
    };
    use std::num::{NonZeroU32, NonZeroUsize};
    let directory = tempfile::tempdir()?;
    let peer = peer::Peer::start(directory.path(), peer::Behavior::Fragmented)?;
    let target = client::ResolvedTarget {
        address: peer.address,
        xmpp_domain: "localhost".into(),
        tls: client::remote_tls_config(Some(&fs::read(directory.path().join("certificate.pem"))?))?,
    };
    let cpu = CpuPool::new(NonZeroUsize::MIN);
    let mut sender = PreparedAccount::new("bench-000000@localhost", SECRET.into())?;
    let mut recipient = PreparedAccount::new("bench-000001@localhost", SECRET.into())?;
    let (sender, _) = client::connect(
        &target,
        &mut sender,
        "bench",
        KeyMode::Prime,
        Instant::now() + Duration::from_secs(10),
        &cpu,
    )
    .await?;
    let (mut recipient, _) = client::connect(
        &target,
        &mut recipient,
        "bench",
        KeyMode::Prime,
        Instant::now() + Duration::from_secs(10),
        &cpu,
    )
    .await?;
    recipient.set_receive_route(ReceiveRoute {
        from: sender.identity().bound_jid.clone(),
        body_bytes: 3,
    })?;
    let to = recipient.identity().bound_jid.clone();
    let (mut sender_reader, mut sender_writer, _) = sender.into_parts();
    let (mut reader, mut writer, _) = recipient.into_parts();
    sender_writer.configure_messages(Arc::from([MessageRoute { to }]), Arc::from("xxx"))?;
    let start = Instant::now();
    let route = RouteIdentity::Message {
        sender_index: 0,
        receiver_index: 1,
    };
    let mut ledger = Ledger::new(
        1,
        16,
        Duration::from_secs(10),
        LedgerContext {
            run_nonce: [1; 16],
            phase: TrafficPhase::Measurement,
            start,
            end: start + Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(5),
            topology: LedgerTopology::Messages {
                pairs: NonZeroU32::MIN,
            },
        },
    )?;
    let operation = ledger
        .reserve(
            ScheduledSlot {
                sequence: 0,
                scheduled_at: start,
            },
            route,
        )
        .map_err(|_| "reservation")?;
    ledger.commit_dispatch(operation, Instant::now())?;
    let (events, mut queue) = EventSink::bounded(
        NonZeroUsize::new(4).ok_or("capacity")?,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    sender_writer
        .send(
            &WriteCommand::Message(MessageCommand {
                operation,
                scheduled_at: start,
                route_index: 0,
                phase: TrafficPhase::Measurement,
            }),
            &events,
        )
        .await?;
    let received = timeout(Duration::from_secs(10), reader.next()).await??;
    assert!(
        matches!(received.kind,ReceivedKind::Chat{correlation:Some(id),route_valid:true,..} if id==operation)
    );
    ledger.observe(OperationEvent::Receipt {
        operation,
        at: received.at,
        route,
    })?;
    assert!(!ledger.is_settled());
    while let Ok(event) = queue.try_recv() {
        ledger.observe(OperationEvent::Writer(event))?;
    }
    assert!(ledger.is_settled());
    client::shutdown(
        &mut sender_reader,
        &mut sender_writer,
        Duration::from_secs(5),
        &mut |_| Ok(()),
    )
    .await?;
    client::shutdown(
        &mut reader,
        &mut writer,
        Duration::from_secs(5),
        &mut |_| Ok(()),
    )
    .await?;
    let result = ledger.finish(FinishReason {
        termination: Termination::Completed,
        barrier: PhaseBarrier::RetiredAndDrained,
    });
    assert_eq!(result.counters.write_succeeded, 1);
    assert_eq!(result.counters.received_on_time, 1);
    assert_eq!(result.status(), RunStatus::Passed);
    peer.finish()?;
    Ok(())
}

#[tokio::test]
async fn nonreading_tls_peer_forces_write_cancellation_and_forbids_connection_reuse() -> TestResult
{
    use lonewolf_bench::client::{
        self, CorrelationId, EventSink, KeyMode, MessageCommand, MessageRoute, PreparedAccount,
        TrafficPhase, WriteCommand,
    };
    use lonewolf_bench::cpu::CpuPool;
    let directory = tempfile::tempdir()?;
    let peer = peer::Peer::start(directory.path(), peer::Behavior::NoRead)?;
    let target = client::ResolvedTarget {
        address: peer.address,
        xmpp_domain: "localhost".into(),
        tls: client::remote_tls_config(Some(&fs::read(directory.path().join("certificate.pem"))?))?,
    };
    let cpu = CpuPool::new(std::num::NonZeroUsize::MIN);
    let mut account = PreparedAccount::new("bench-000000@localhost", SECRET.into())?;
    let (session, _) = client::connect(
        &target,
        &mut account,
        "bench",
        KeyMode::Prime,
        Instant::now() + Duration::from_secs(10),
        &cpu,
    )
    .await?;
    let (mut reader, mut writer, _) = session.into_parts();
    writer.configure_messages(
        Arc::from([MessageRoute {
            to: "bench-000001@localhost/bench".into(),
        }]),
        Arc::from("x".repeat(200000)),
    )?;
    let (events, mut queue) = EventSink::bounded(
        std::num::NonZeroUsize::new(4).ok_or("capacity")?,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let command = |sequence| {
        WriteCommand::Message(MessageCommand {
            operation: CorrelationId {
                run_nonce: [1; 16],
                phase: TrafficPhase::Measurement,
                sequence,
            },
            scheduled_at: Instant::now(),
            route_index: 0,
            phase: TrafficPhase::Measurement,
        })
    };
    let stopped = timeout(Duration::from_secs(2), async {
        for sequence in 0..10_000_000 {
            writer.send(&command(sequence), &events).await?;
            while queue.try_recv().is_ok() {}
        }
        Ok::<_, lonewolf_bench::error::BenchError>(())
    })
    .await;
    assert!(stopped.is_err());
    assert!(!events.run_invalid());
    assert_eq!(
        writer
            .send(&command(0), &events)
            .await
            .err()
            .ok_or("reused cancelled transport")?
            .context(),
        "connection_retired"
    );
    writer.retire();
    reader.retire_and_drain(&mut |_| Ok(())).await?;
    peer.finish()?;
    Ok(())
}
