// SPDX-License-Identifier: Apache-2.0

use super::*;
use lonewolf_storage::{account::AccountReads, offline::OfflineReads, roster::RosterReads};
use std::{num::NonZeroUsize, os::unix::fs::PermissionsExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> BenchResult<RunConfig> {
    toml::from_str("[target]\nmode='local'\nserver_binary='/usr/bin/true'\nserver_workers=1\nstanza_pool_size_mib=8\n[scenario]\nkind='idle'\nconnections=1\n[measurement]\nsetup_timeout_ms=10000").map_err(|_| failure("test_config"))
}

#[tokio::test]
async fn fixture_seeds_exactly_requested_accounts_and_releases_storage() -> TestResult {
    let cpu = CpuPool::new(NonZeroUsize::MIN);
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
    assert!(fixture.server_log().is_none());
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
    let cpu = CpuPool::new(NonZeroUsize::MIN);
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
    assert!(fixture.server_log().is_some());
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
    let cpu = CpuPool::new(NonZeroUsize::MIN);
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
            .server_log()
            .is_some_and(|log| log.ends_with(b"[server killed after the shutdown timeout]\n"))
    );
    Ok(())
}

#[tokio::test]
async fn drop_kills_and_reaps_after_cancelled_stop() -> TestResult {
    let cpu = CpuPool::new(NonZeroUsize::MIN);
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

#[derive(Default)]
pub(super) struct PreparationProbe {
    directory: std::sync::Mutex<Option<PathBuf>>,
    dropped: AtomicBool,
    cpu_steps: std::sync::atomic::AtomicUsize,
    transactions: std::sync::atomic::AtomicUsize,
    commits: std::sync::atomic::AtomicUsize,
    pause_cpu: Option<usize>,
    admission: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    cpu_release: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    transaction_release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<BenchResult<()>>>>,
}

pub(super) struct PreparationOwners(Arc<PreparationProbe>);
impl Drop for PreparationOwners {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Release);
    }
}

impl PreparationProbe {
    pub(super) fn owners(
        self: &Arc<Self>,
        directory: &std::path::Path,
    ) -> BenchResult<PreparationOwners> {
        *self
            .directory
            .lock()
            .map_err(|_| failure("test_probe_lock"))? = Some(directory.to_owned());
        Ok(PreparationOwners(self.clone()))
    }
    fn admit(&self) -> BenchResult<()> {
        let sender = self
            .admission
            .lock()
            .map_err(|_| failure("test_probe_lock"))?
            .take()
            .ok_or_else(|| failure("test_probe_admission"))?;
        sender.send(()).map_err(|_| failure("test_probe_admission"))
    }
    pub(super) fn cpu_started(&self) -> BenchResult<()> {
        let step = self.cpu_steps.fetch_add(1, Ordering::AcqRel) + 1;
        if self.pause_cpu == Some(step) {
            self.admit()?;
            let release = self
                .cpu_release
                .lock()
                .map_err(|_| failure("test_probe_lock"))?
                .take()
                .ok_or_else(|| failure("test_probe_release"))?;
            release.recv().map_err(|_| failure("test_probe_release"))?;
        }
        Ok(())
    }
    pub(super) async fn transaction_started(&self) -> BenchResult<()> {
        self.transactions.fetch_add(1, Ordering::AcqRel);
        let release = self
            .transaction_release
            .lock()
            .map_err(|_| failure("test_probe_lock"))?
            .take();
        if let Some(release) = release {
            self.admit()?;
            release.await.map_err(|_| failure("test_probe_release"))??;
        }
        Ok(())
    }
    pub(super) fn transaction_finished(&self) {
        self.commits.fetch_add(1, Ordering::AcqRel);
    }
}

async fn poll_once<F: std::future::Future>(
    mut work: std::pin::Pin<&mut F>,
) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(work.as_mut().poll(cx))).await
}

async fn poll_to_admission<F: std::future::Future<Output = BenchResult<LocalFixture>>>(
    mut work: std::pin::Pin<&mut F>,
    admission: &mut tokio::sync::oneshot::Receiver<()>,
) -> TestResult {
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        match admission.try_recv() {
            Ok(()) => return Ok(()),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                return Err("admission closed".into());
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }
        if let std::task::Poll::Ready(result) = poll_once(work.as_mut()).await {
            return Err(match result {
                Err(error) => error.into(),
                Ok(_) => "preparation completed before admission".into(),
            });
        }
        if std::time::Instant::now() >= deadline {
            return Err("admission wall deadline".into());
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn preparation_stops_retain_resources_until_the_admitted_cpu_unit_finishes() -> TestResult {
    for mode in ["standalone_deadline", "run_deadline", "interruption"] {
        let config = config()?;
        let cpu = CpuPool::new(NonZeroUsize::MIN);
        let (admission, mut admitted) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let probe = Arc::new(PreparationProbe {
            pause_cpu: Some(3),
            admission: std::sync::Mutex::new(Some(admission)),
            cpu_release: std::sync::Mutex::new(Some(blocked)),
            ..Default::default()
        });
        let (signal, mut interruption) = watch::channel(false);
        let context = if mode == "standalone_deadline" {
            "fixture_setup_deadline"
        } else {
            "setup_deadline"
        };
        let mut control = PreparationControl {
            deadline: Instant::now() + Duration::from_secs(10),
            interruption: (mode != "standalone_deadline").then_some(&mut interruption),
            deadline_context: context,
            cancelled: Arc::new(AtomicBool::new(false)),
            probe: Some(probe.clone()),
        };
        let cancelled = control.cancelled.clone();
        let mut work = Box::pin(LocalFixture::prepare_inner(&config, &cpu, &mut control));
        poll_to_admission(work.as_mut(), &mut admitted).await?;
        let directory = probe
            .directory
            .lock()
            .map_err(|_| "probe lock")?
            .clone()
            .ok_or("directory")?;
        if mode == "interruption" {
            signal.send_replace(true);
        } else {
            tokio::time::advance(Duration::from_secs(11)).await;
        }
        assert!(poll_once(work.as_mut()).await.is_pending());
        assert!(cancelled.load(Ordering::Acquire));
        assert!(directory.exists());
        assert!(!probe.dropped.load(Ordering::Acquire));
        assert!(RedbStorage::open(directory.join("accounts.redb")).is_err());
        release.send(())?;
        let error = match work.await {
            Err(error) => error,
            Ok(_) => return Err("stopped preparation succeeded".into()),
        };
        assert_eq!(
            error.context(),
            if mode == "interruption" {
                "interrupted"
            } else {
                context
            }
        );
        assert!(probe.dropped.load(Ordering::Acquire));
        assert!(!directory.exists());
        assert_eq!(probe.cpu_steps.load(Ordering::Acquire), 3);
        assert_eq!(probe.transactions.load(Ordering::Acquire), 0);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn standalone_expiry_and_queued_cancellation_do_not_run_unadmitted_cpu_work() -> TestResult {
    for standalone in [true, false] {
        let cpu = CpuPool::new(NonZeroUsize::MIN);
        let occupied_cpu = cpu.clone();
        let (entered, mut started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let occupied = tokio::spawn(async move {
            let _ = occupied_cpu
                .run(move || {
                    let _ = entered.send(());
                    let _ = blocked.recv();
                    Ok(())
                })
                .await;
        });
        while started.try_recv().is_err() {
            tokio::task::yield_now().await;
        }
        if standalone {
            let mut config = config()?;
            config.measurement.setup_timeout_ms = 1;
            let mut work = Box::pin(LocalFixture::prepare(&config, &cpu));
            assert!(poll_once(work.as_mut()).await.is_pending());
            tokio::time::advance(Duration::from_millis(2)).await;
            assert!(poll_once(work.as_mut()).await.is_pending());
            release.send(())?;
            let error = match work.await {
                Err(error) => error,
                Ok(_) => return Err("expired preparation succeeded".into()),
            };
            assert_eq!(error.context(), "fixture_setup_deadline");
        } else {
            let (signal, mut interruption) = watch::channel(false);
            let mut control = PreparationControl {
                deadline: Instant::now() + Duration::from_secs(10),
                interruption: Some(&mut interruption),
                deadline_context: "setup_deadline",
                cancelled: Arc::new(AtomicBool::new(false)),
                probe: None,
            };
            let meaningful = Arc::new(AtomicBool::new(false));
            let ran = meaningful.clone();
            let mut work = Box::pin(control.run_cpu(&cpu, move |_| {
                ran.store(true, Ordering::Release);
                Ok(())
            }));
            assert!(poll_once(work.as_mut()).await.is_pending());
            signal.send_replace(true);
            assert!(poll_once(work.as_mut()).await.is_pending());
            release.send(())?;
            assert!(
                work.await
                    .is_err_and(|error| error.context() == "interrupted")
            );
            assert!(!meaningful.load(Ordering::Acquire));
        }
        occupied.await?;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn stopped_preparation_finishes_the_whole_transaction_without_starting_the_next_batch()
-> TestResult {
    for (interrupt, storage_error) in [(true, false), (true, true), (false, true)] {
        let mut config = config()?;
        config.scenario = ScenarioConfig::Idle { connections: 257 };
        config.measurement.setup_timeout_ms = 120_000;
        let cpu = CpuPool::new(NonZeroUsize::MIN);
        let (admission, mut admitted) = tokio::sync::oneshot::channel();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let probe = Arc::new(PreparationProbe {
            admission: std::sync::Mutex::new(Some(admission)),
            transaction_release: std::sync::Mutex::new(Some(blocked)),
            ..Default::default()
        });
        let (signal, mut interruption) = watch::channel(false);
        let mut control = PreparationControl {
            deadline: Instant::now() + Duration::from_secs(120),
            interruption: Some(&mut interruption),
            deadline_context: "setup_deadline",
            cancelled: Arc::new(AtomicBool::new(false)),
            probe: Some(probe.clone()),
        };
        let mut work = Box::pin(LocalFixture::prepare_inner(&config, &cpu, &mut control));
        poll_to_admission(work.as_mut(), &mut admitted).await?;
        let directory = probe
            .directory
            .lock()
            .map_err(|_| "probe lock")?
            .clone()
            .ok_or("directory")?;
        if interrupt {
            signal.send_replace(true);
        }
        assert!(poll_once(work.as_mut()).await.is_pending());
        assert!(directory.exists());
        assert!(!probe.dropped.load(Ordering::Acquire));
        assert!(!directory.join("lonewolf.toml").exists());
        release
            .send(if storage_error {
                Err(failure("test_storage_failure"))
            } else {
                Ok(())
            })
            .map_err(|_| "release closed")?;
        let error = match work.await {
            Err(error) => error,
            Ok(_) => return Err("stopped transaction succeeded".into()),
        };
        assert_eq!(
            error.context(),
            if interrupt {
                "interrupted"
            } else {
                "test_storage_failure"
            }
        );
        assert!(!directory.exists());
        assert!(probe.dropped.load(Ordering::Acquire));
        assert_eq!(probe.cpu_steps.load(Ordering::Acquire), 3);
        assert_eq!(probe.transactions.load(Ordering::Acquire), 1);
        assert_eq!(
            probe.commits.load(Ordering::Acquire),
            usize::from(!storage_error)
        );
    }
    Ok(())
}
