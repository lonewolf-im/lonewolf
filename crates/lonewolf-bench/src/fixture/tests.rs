// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_storage::{account::AccountReads, offline::OfflineReads, roster::RosterReads};
use std::{num::NonZeroUsize, os::unix::fs::PermissionsExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> BenchResult<RunConfig> {
    toml::from_str("schema_version=1\nenvironment_id='fixture-test'\n[target]\nmode='local'\nserver_binary='/usr/bin/true'\nserver_workers=1\nstanza_pool_size_mib=8\n[scenario]\nkind='idle'\nconnections=1\n[measurement]\nsetup_timeout_ms=10000").map_err(|_| failure("test_config"))
}

#[tokio::test]
async fn fixture_seeds_exactly_requested_accounts_and_releases_storage() -> TestResult {
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut fixture = LocalFixture::prepare(&config()?, &cpu).await?;
    let directory = fixture
        .directory
        .as_ref()
        .ok_or("directory")?
        .path()
        .to_owned();
    assert_eq!(
        std::fs::metadata(&directory)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(directory.join("key.pem"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let storage = RedbStorage::open(directory.join("accounts.redb"))?;
    let read = storage.begin_read().await?;
    let accounts = read
        .accounts_after(None, const { NonZeroUsize::new(2).unwrap() })
        .await?;
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].key.as_str(), "bench-000000@localhost");
    assert_eq!(read.offline_count(&accounts[0].key).await?, 0);
    assert!(
        read.roster(&accounts[0].key, Default::default())
            .await?
            .items
            .is_empty()
    );
    drop(read);
    drop(storage);
    assert_eq!(fixture.credentials().len(), 1);
    assert!(fixture.sanitized_server_log().is_none());
    assert_eq!(
        fixture.stop(Duration::from_secs(1)).await?,
        StopOutcome::NotStarted
    );
    assert!(!directory.exists());
    assert!(fixture.credentials().is_empty());
    Ok(())
}

#[test]
fn fixture_profile_rejects_workloads_above_declared_limits() -> TestResult {
    let mut config = config()?;
    config.scenario = ScenarioConfig::Churn {
        accounts: 1,
        rate_per_second: 1_000_001,
    };
    assert!(validate_limits(&config).is_err());
    config.scenario = ScenarioConfig::Messages {
        pairs: 1,
        rate_per_second: 1_000_000,
        body_bytes: 65_536,
    };
    assert!(validate_limits(&config).is_err());
    Ok(())
}

#[tokio::test]
async fn failed_start_remains_owned_until_stop() -> TestResult {
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut fixture = LocalFixture::prepare(&config()?, &cpu).await?;
    let directory = fixture
        .directory
        .as_ref()
        .ok_or("directory")?
        .path()
        .to_owned();
    assert!(
        fixture
            .start(Instant::now() + Duration::from_secs(2))
            .await
            .is_err()
    );
    fixture.stop(Duration::from_secs(1)).await?;
    assert!(fixture.sanitized_server_log().is_some());
    assert!(!directory.exists());
    Ok(())
}

#[test]
#[ignore]
fn owned_child_helper() -> TestResult {
    let Some(ready) = std::env::var_os("LONEWOLF_BENCH_TEST_READY") else {
        return Ok(());
    };
    // This helper must ignore SIGTERM to exercise the owner's force-kill path.
    unsafe {
        nix::libc::signal(nix::libc::SIGTERM, nix::libc::SIG_IGN);
    }
    std::fs::write(ready, b"ready")?;
    std::thread::sleep(Duration::from_secs(5));
    Ok(())
}

async fn attach_ignoring_child(fixture: &mut LocalFixture) -> TestResult {
    let directory = fixture.directory.as_ref().ok_or("directory")?;
    let ready = directory.path().join("helper-ready");
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "fixture::tests::owned_child_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("LONEWOLF_BENCH_TEST_READY", &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("stderr")?;
    fixture.child = Some(child);
    fixture.collector = Some(Collector::start(stderr)?);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready.exists() {
        if Instant::now() >= deadline {
            return Err("helper readiness deadline".into());
        }
        sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_stop_keeps_owners_for_resumed_force_kill_and_reap() -> TestResult {
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut fixture = LocalFixture::prepare(&config()?, &cpu).await?;
    attach_ignoring_child(&mut fixture).await?;
    let directory = fixture
        .directory
        .as_ref()
        .ok_or("directory")?
        .path()
        .to_owned();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            fixture.stop(Duration::from_secs(2))
        )
        .await
        .is_err()
    );
    assert!(fixture.child.is_some());
    assert!(fixture.collector.is_some());
    assert_eq!(
        fixture.stop(Duration::from_millis(10)).await?,
        StopOutcome::Forced
    );
    assert!(fixture.reaped);
    assert!(!directory.exists());
    assert!(
        fixture
            .sanitized_server_log()
            .is_some_and(|log| log.ends_with(b"forced_termination\n"))
    );
    Ok(())
}

#[tokio::test]
async fn drop_kills_and_reaps_after_cancelled_stop() -> TestResult {
    let cpu = BlockingExecutor::new(NonZeroUsize::MIN);
    let mut fixture = LocalFixture::prepare(&config()?, &cpu).await?;
    attach_ignoring_child(&mut fixture).await?;
    let directory = fixture
        .directory
        .as_ref()
        .ok_or("directory")?
        .path()
        .to_owned();
    let pid = i32::try_from(fixture.child.as_ref().ok_or("child")?.id())?;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            fixture.stop(Duration::from_secs(2))
        )
        .await
        .is_err()
    );
    drop(fixture);
    assert!(!directory.exists());
    let mut status = 0;
    assert_eq!(
        unsafe { nix::libc::waitpid(pid, &mut status, nix::libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::ECHILD)
    );
    Ok(())
}
