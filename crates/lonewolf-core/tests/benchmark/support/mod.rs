// SPDX-License-Identifier: Apache-2.0

pub mod artifacts;

use lonewolf_bench::config::{
    MeasurementConfig, MetricsConfig, RunConfig, ScenarioConfig, TargetConfig,
};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SECRET: &str = "benchmark sentinel password copper moonlight";
pub const TIMEOUT: Duration = Duration::from_secs(60);

pub fn local_config(server: &Path, scenario: ScenarioConfig) -> RunConfig {
    RunConfig {
        schema_version: 1,
        environment_id: "benchmark-test".into(),
        target: TargetConfig::Local {
            server_binary: server.into(),
            server_revision: "test".into(),
            server_profile: "test".into(),
            server_toolchain: None,
            server_features: Some(vec![]),
            server_workers: 2,
            stanza_pool_size_mib: 8,
        },
        scenario,
        measurement: MeasurementConfig {
            warmup_ms: 0,
            duration_ms: 1000,
            setup_timeout_ms: 30000,
            operation_timeout_ms: 3000,
            shutdown_timeout_ms: 5000,
            ramp_rate_per_second: 20,
            connect_concurrency: 2,
            driver_workers: 2,
            max_in_flight: 16,
            dispatch_quantum_us: 1000,
            max_dispatch_batch: 16,
            max_schedule_lag_ms: 1000,
        },
        metrics: MetricsConfig {
            interval_ms: 1000,
            timeout_ms: 1000,
        },
    }
}

pub fn private_write(path: &Path, bytes: &[u8]) -> TestResult {
    use std::io::Write;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

pub struct Process {
    child: Child,
    stdout: std::fs::File,
    stderr: std::fs::File,
}
impl Process {
    pub fn spawn(binary: &Path, args: &[&OsStr]) -> TestResult<Self> {
        Self::spawn_command(Command::new(binary).args(args))
    }
    pub fn spawn_command(command: &mut Command) -> TestResult<Self> {
        let stdout = tempfile::tempfile()?;
        let stderr = tempfile::tempfile()?;
        let child = command
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?))
            .spawn()?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }
    pub fn signal(&self) -> TestResult {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(self.child.id())?),
            nix::sys::signal::Signal::SIGINT,
        )?;
        Ok(())
    }
    pub fn wait(mut self) -> TestResult<Output> {
        use std::io::{Read, Seek};
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err("benchmark subprocess deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        self.stdout.rewind()?;
        self.stderr.rewind()?;
        let mut stdout = vec![];
        let mut stderr = vec![];
        (&mut self.stdout)
            .take(1024 * 1024)
            .read_to_end(&mut stdout)?;
        (&mut self.stderr)
            .take(1024 * 1024)
            .read_to_end(&mut stderr)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn cli(binary: &Path, args: &[&OsStr]) -> TestResult<Output> {
    Process::spawn(binary, args)?.wait()
}

pub fn wait_for_file(path: &Path) -> TestResult {
    let deadline = Instant::now() + TIMEOUT;
    while !path.is_file() {
        if Instant::now() >= deadline {
            return Err("phase readiness deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

pub fn assert_no_secret(
    directory: &Path,
    output: Option<&Output>,
    sentinels: &[&str],
) -> TestResult {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let bytes = fs::read(entry.path())?;
            for sentinel in sentinels {
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|w| w == sentinel.as_bytes()),
                    "secret in {:?}",
                    entry.file_name()
                );
            }
        }
    }
    if let Some(output) = output {
        for bytes in [&output.stdout, &output.stderr] {
            for sentinel in sentinels {
                assert!(
                    !bytes
                        .windows(sentinel.len())
                        .any(|w| w == sentinel.as_bytes())
                );
            }
        }
    }
    Ok(())
}
