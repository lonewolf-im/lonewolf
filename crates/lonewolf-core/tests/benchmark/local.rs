// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod bench_support;

use bench_support::{TestResult, artifacts, local_config};
use lonewolf_bench::{
    client::{self, KeyMode},
    compare::compare_runs,
    config::ScenarioConfig,
    fixture::{LocalFixture, StopOutcome},
    report::RunStatus,
    run::{
        events::{ObserverEvent, RunObserver},
        run_with_observer,
    },
};
use lonewolf_util::blocking::BlockingExecutor;
use std::{fs, num::NonZeroUsize, path::Path, time::Duration};
use tokio::time::{Instant, timeout};

fn server() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_lonewolf"))
}

#[tokio::test]
async fn all_local_scenarios_persist_complete_accounting_and_release_sessions() -> TestResult {
    let directory = tempfile::tempdir()?;
    for (name, scenario) in [
        ("idle", ScenarioConfig::Idle { connections: 2 }),
        (
            "messages",
            ScenarioConfig::Messages {
                pairs: 1,
                rate_per_second: 2,
                body_bytes: 256,
            },
        ),
        (
            "churn",
            ScenarioConfig::Churn {
                accounts: 2,
                rate_per_second: 2,
            },
        ),
    ] {
        let config = local_config(server(), scenario);
        let output = directory.path().join(name);
        let (observer, mut events) =
            RunObserver::bounded(NonZeroUsize::new(128).ok_or("capacity")?);
        let report = timeout(
            bench_support::TIMEOUT,
            run_with_observer(config, &output, observer),
        )
        .await??;
        assert_eq!(
            report.status,
            RunStatus::Passed,
            "{name}: {:?}",
            report.reasons
        );
        let persisted = artifacts::complete(&output, RunStatus::Passed)?;
        assert_eq!(persisted.phases.len(), 10);
        assert!(persisted.target.negotiated_tls.is_some());
        assert!(persisted.target.cipher.is_some());
        assert!(persisted.target.observed_scram_iterations.is_some());
        let settings = &persisted
            .environment
            .as_ref()
            .ok_or("environment")?
            .server_settings;
        assert_eq!(settings.workers, 2);
        assert_eq!(settings.stanza_pool_size_mib, 8);
        assert_eq!(
            persisted
                .target
                .declared_build
                .as_ref()
                .ok_or("build")?
                .profile,
            "test"
        );
        assert_eq!(
            persisted
                .target
                .declared_build
                .as_ref()
                .ok_or("build")?
                .features,
            Some(vec![])
        );
        let mut peak_observed = None;
        while let Ok(event) = events.try_recv() {
            if let ObserverEvent::ActiveConnections(count) = event {
                peak_observed = Some(peak_observed.unwrap_or(0).max(count));
            }
        }
        if name != "churn" {
            assert_eq!(peak_observed, Some(2));
        }
        match name {
            "idle" => {
                assert_eq!(persisted.counters.requested_connections, 2);
                assert_eq!(persisted.counters.connections_at_measurement_start, 2);
                assert_eq!(persisted.counters.connections_at_measurement_end, 2);
                assert_eq!(persisted.counters.write_succeeded, 0);
                assert!(persisted.latencies.is_empty());
            }
            "messages" => {
                assert_eq!(persisted.dataset.account_count, 2);
                assert_eq!(persisted.dataset.pair_count, Some(1));
                assert_eq!(persisted.counters.planned, 2);
                assert_eq!(persisted.counters.received_on_time, 2);
                assert_eq!(persisted.counters.write_succeeded, 2);
                assert_eq!(persisted.counters.message_body_bytes_write_succeeded, 512);
            }
            _ => {
                assert_eq!(persisted.counters.connection_attempts, 2);
                assert_eq!(persisted.counters.login_succeeded, 2);
                assert_eq!(persisted.counters.closed_cleanly, 2);
            }
        }
        let comparison = compare_runs(&persisted, &persisted);
        assert!(comparison.eligible, "{:?}", comparison.refusals);
        bench_support::assert_no_secret(
            &output,
            None,
            &["PRIVATE KEY", "password", "<auth", "<message"],
        )?;
        let log = fs::read_to_string(output.join("server.log"))?;
        assert!(log.contains("c2s_listener_stopped"));
        assert!(log.contains("metrics_service_stopped"));
        assert!(persisted.phases.iter().any(|phase| phase.name
            == lonewolf_bench::report::PhaseName::LocalChildShutdown
            && phase.status == lonewolf_bench::report::PhaseStatus::Completed));
    }
    Ok(())
}

#[tokio::test]
async fn simultaneous_fresh_fixtures_get_distinct_assigned_ports_and_reap_children() -> TestResult {
    let config = local_config(server(), ScenarioConfig::Idle { connections: 1 });
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut first = LocalFixture::prepare(&config, &cpu).await?;
    let mut second = LocalFixture::prepare(&config, &cpu).await?;
    let (a, b) = tokio::join!(
        first.start(Instant::now() + Duration::from_secs(30)),
        second.start(Instant::now() + Duration::from_secs(30))
    );
    let (a, b) = (a?, b?);
    assert_ne!(a.address, b.address);
    assert_ne!(first.metrics_url(), second.metrics_url());
    for (fixture, target) in [(&mut first, &a), (&mut second, &b)] {
        let (session, _) = client::connect(
            target,
            &mut fixture.credentials()[0],
            "bench",
            KeyMode::Prime,
            Instant::now() + Duration::from_secs(10),
            &cpu,
        )
        .await?;
        let (mut reader, mut writer, _) = session.into_parts();
        client::shutdown(
            &mut reader,
            &mut writer,
            Duration::from_secs(5),
            &mut |_| Ok(()),
        )
        .await?;
        assert_eq!(
            fixture.stop(Duration::from_secs(10)).await?,
            StopOutcome::Graceful
        );
        assert!(fixture.credentials().is_empty());
        assert!(
            tokio::net::TcpStream::connect(target.address)
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn repeated_real_runs_have_fresh_fixtures_and_eligible_a_a_comparisons() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = local_config(
        server(),
        ScenarioConfig::Messages {
            pairs: 1,
            rate_per_second: 2,
            body_bytes: 64,
        },
    );
    let a = lonewolf_bench::run(config.clone(), &directory.path().join("a")).await?;
    let b = lonewolf_bench::run(config, &directory.path().join("b")).await?;
    assert_eq!(a.status, RunStatus::Passed);
    assert_eq!(b.status, RunStatus::Passed);
    assert_ne!(a.run_id, b.run_id);
    assert_eq!(a.dataset.account_jids_sha256, b.dataset.account_jids_sha256);
    let comparison = compare_runs(&a, &b);
    assert!(
        comparison.eligible,
        "{:?} {:?}",
        comparison.refusals, comparison.mismatches
    );
    Ok(())
}

#[tokio::test]
async fn startup_failure_and_forced_stop_remove_private_fixture_and_reap_child() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    for forced in [false, true] {
        let script = directory
            .path()
            .join(if forced { "forced" } else { "failure" });
        let record = directory.path().join(if forced {
            "forced-record"
        } else {
            "failure-record"
        });
        let c2s_marker = std::net::TcpListener::bind("127.0.0.1:0")?;
        let metrics_marker = std::net::TcpListener::bind("127.0.0.1:0")?;
        let body = if forced {
            format!(
                "trap '' TERM\nprintf '2026:01:01 00:00:00 INFO lonewolf_core::c2s: c2s TCP listener started listener_id=0 worker_count=2 port={c2s_port}\\n2026:01:01 00:00:00 INFO lonewolf_metrics::server: metrics service started port={metrics_port}\\n2026:01:01 00:00:00 INFO lonewolf_core: waiting for stop signal... (press Ctrl+C to stop the server)\\n' >&2\nwhile :; do :; done",
                c2s_port = c2s_marker.local_addr()?.port(),
                metrics_port = metrics_marker.local_addr()?.port()
            )
        } else {
            "exit 1".into()
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n%s\\n' \"$PWD\" \"$$\" > '{}'\n{body}\n",
                record.display()
            ),
        )?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        let config = local_config(&script, ScenarioConfig::Idle { connections: 1 });
        let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
        let mut fixture = LocalFixture::prepare(&config, &cpu).await?;
        let started = fixture
            .start(Instant::now() + Duration::from_secs(10))
            .await;
        assert_eq!(started.is_ok(), forced);
        let captured = fs::read_to_string(&record)?;
        let mut lines = captured.lines();
        let private_root = lines.next().ok_or("fixture path")?;
        let pid: i32 = lines.next().ok_or("pid")?.parse()?;
        assert!(Path::new(private_root).is_dir());
        let outcome = fixture.stop(Duration::from_millis(20)).await?;
        assert_eq!(
            outcome,
            if forced {
                StopOutcome::Forced
            } else {
                StopOutcome::Graceful
            }
        );
        assert!(!Path::new(private_root).exists());
        assert!(fixture.credentials().is_empty());
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }
    Ok(())
}
