// SPDX-License-Identifier: Apache-2.0

use lonewolf_bench::{
    client::{self, KeyMode},
    config::RunConfig,
    fixture::{LocalFixture, StopOutcome},
};
use lonewolf_util::blocking::BlockingExecutor;
use std::{num::NonZeroUsize, time::Duration};
use tokio::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn fresh_fixture_authenticates_on_assigned_ports_and_stops_owned_server() -> TestResult {
    let mut config: RunConfig = toml_config()?;
    if let lonewolf_bench::config::TargetConfig::Local { server_binary, .. } = &mut config.target {
        *server_binary = env!("CARGO_BIN_EXE_lonewolf").into();
    }
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut fixture = LocalFixture::prepare(&config, &cpu).await?;
    let target = fixture
        .start(Instant::now() + Duration::from_secs(20))
        .await?;
    assert!(target.address.ip().is_loopback());
    assert_ne!(target.address.port(), 0);
    assert!(fixture.metrics_url().starts_with("http://127.0.0.1:"));
    let settings = fixture.sanitized_server_settings();
    assert_eq!(settings.max_connections_per_ip, 100_000);
    assert_eq!(settings.offered_auth_mechanisms, ["SCRAM-SHA-256"]);
    let (session, _) = client::connect(
        &target,
        &mut fixture.credentials()[0],
        "bench",
        KeyMode::Prime,
        Instant::now() + Duration::from_secs(10),
        &cpu,
    )
    .await?;
    assert_eq!(session.identity().bound_jid, "bench-000000@localhost/bench");
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
    let log = std::str::from_utf8(fixture.sanitized_server_log().ok_or("log missing")?)?;
    assert!(log.contains("server_ready\n"));
    assert!(!log.contains("localhost"));
    assert!(!log.contains("bench-"));
    assert!(!log.contains("PRIVATE KEY"));
    assert!(fixture.credentials().is_empty());
    Ok(())
}

fn toml_config() -> Result<RunConfig, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.toml");
    std::fs::write(
        &path,
        "schema_version=1\nenvironment_id='local-test'\n[target]\nmode='local'\nserver_binary='placeholder'\nserver_workers=1\nstanza_pool_size_mib=8\n[scenario]\nkind='idle'\nconnections=1\n[measurement]\nsetup_timeout_ms=20000",
    )?;
    Ok(RunConfig::load(&path, None)?)
}
