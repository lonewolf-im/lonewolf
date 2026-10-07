// SPDX-License-Identifier: Apache-2.0

use super::TestResult;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

fn command(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn metadata() -> TestResult<Value> {
    let cpu = fs::read_to_string("/proc/cpuinfo")?;
    let memory = fs::read_to_string("/proc/meminfo")?;
    Ok(
        json!({"kernel":command("uname", &["-srmo"]), "rustc":command("rustc", &["-vV"]),
        "page_bytes":command("getconf", &["PAGESIZE"]), "clock_ticks_per_second":command("getconf", &["CLK_TCK"]),
        "cpu_model":cpu.lines().find_map(|line| line.strip_prefix("model name\t: ")),
        "logical_cpus":thread::available_parallelism()?.get(),
        "physical_memory":memory.lines().find(|line| line.starts_with("MemTotal:")),
        "driver_placement":"same Linux host, separate process, loopback; no CPU pinning",
        "build":"cargo --release; default workspace release profile; same toolchain and options for both binaries",
        "active_sample_interval_ms":100, "idle_sample_interval_ms":200,
        "rss_source":"/proc/PID/smaps_rollup Rss, fallback /proc/PID/status VmRSS",
        "socket_source":"ss -tnme, filtered by process-owned /proc/PID/fd socket inodes",
        "socket_accounting":"components reported separately; r, t, w, f, o, bl are not an additive total; rb/tb limits excluded",
        "allocator_accounting":"pool reserve and cumulative allocation counters only; other allocation/live heap unavailable",
        "cold":"fresh server process and storage, not a cold kernel page cache"}),
    )
}

fn kib(text: &str, field: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .map(|value| value * 1024)
}

pub fn cpu(pid: u32) -> Option<[u64; 2]> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = text.rsplit_once(')')?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    Some([fields.get(11)?.parse().ok()?, fields.get(12)?.parse().ok()?])
}

fn socket_memory(pid: u32) -> Value {
    let entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) => {
            return json!({"available":false,"reason":format!("process socket fd inventory: {error}"),"components":null});
        }
    };
    let inodes: BTreeSet<_> = entries
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|path| {
            path.to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect();
    let output = match Command::new("ss").arg("-tnme").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Ok(output) => {
            let detail: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(256)
                .collect();
            return json!({"available":false,"reason":format!("ss -tnme exited {}: {}",output.status,detail.trim()),"components":null});
        }
        Err(error) => {
            return json!({"available":false,"reason":format!("ss -tnme: {error}"),"components":null});
        }
    };
    let mut totals = [0u64; 6];
    let mut count = 0;
    let mut owned = false;
    for line in output.lines() {
        if !line.starts_with(char::is_whitespace) {
            owned = line
                .split_whitespace()
                .filter_map(|field| field.strip_prefix("ino:"))
                .any(|inode| inodes.contains(inode));
        }
        if !owned {
            continue;
        }
        let Some((_, memory)) = line.split_once("skmem:(") else {
            continue;
        };
        let Some((memory, _)) = memory.split_once(')') else {
            continue;
        };
        count += 1;
        for item in memory.split(',') {
            for (index, prefix) in ["r", "t", "w", "f", "o", "bl"].iter().enumerate() {
                if let Some(value) = item
                    .strip_prefix(prefix)
                    .and_then(|value| value.parse::<u64>().ok())
                {
                    totals[index] += value;
                }
            }
        }
    }
    json!({"available":true,"connected_socket_count":count,"components":{
        "receive_allocation_bytes":totals[0],"transmit_allocation_bytes":totals[1],"queued_transmit_bytes":totals[2],
        "forward_allocation_bytes":totals[3],"option_memory_bytes":totals[4],"backlog_memory_bytes":totals[5]}})
}

pub fn sample(pid: u32, elapsed_ms: u128) -> Value {
    let rollup = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok();
    let primary = rollup.as_deref().and_then(|text| kib(text, "Rss:"));
    let rss = primary.or_else(|| {
        fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|text| kib(&text, "VmRSS:"))
    });
    json!({"elapsed_ms":elapsed_ms,"rss_bytes":rss,"rss_source":if primary.is_some(){"smaps_rollup"}else if rss.is_some(){"status_VmRSS"}else{"unavailable"},
        "server_cpu_ticks":cpu(pid),"driver_cpu_ticks":cpu(std::process::id()),"socket_memory":socket_memory(pid)})
}

pub fn idle(pid: u32) -> Vec<Value> {
    thread::sleep(Duration::from_secs(5));
    let start = Instant::now();
    (0..10)
        .map(|_| {
            let value = sample(pid, start.elapsed().as_millis());
            thread::sleep(Duration::from_millis(200));
            value
        })
        .collect()
}

pub struct Monitor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Vec<Value>>>,
    server_cpu: Option<[u64; 2]>,
    driver_cpu: Option<[u64; 2]>,
    pid: u32,
}

impl Monitor {
    pub fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let start = Instant::now();
            let mut samples = Vec::new();
            while !stopped.load(Ordering::Relaxed) {
                samples.push(sample(pid, start.elapsed().as_millis()));
                thread::sleep(Duration::from_millis(100));
            }
            samples
        });
        Self {
            stop,
            thread: Some(thread),
            server_cpu: cpu(pid),
            driver_cpu: cpu(std::process::id()),
            pid,
        }
    }

    pub fn finish(mut self) -> Value {
        let delta = |before: Option<[u64; 2]>, after: Option<[u64; 2]>| {
            before.zip(after).map(|(before, after)| {
                [
                    after[0].saturating_sub(before[0]),
                    after[1].saturating_sub(before[1]),
                ]
            })
        };
        let server_cpu = delta(self.server_cpu, cpu(self.pid));
        let driver_cpu = delta(self.driver_cpu, cpu(std::process::id()));
        self.stop.store(true, Ordering::Relaxed);
        let samples = self
            .thread
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default();
        let peak = samples
            .iter()
            .filter_map(|value| value["rss_bytes"].as_u64())
            .max();
        json!({"samples":samples,"observed_peak_rss_bytes":peak,"server_user_system_cpu_ticks":server_cpu,"driver_user_system_cpu_ticks":driver_cpu,
            "peak_limit":"100ms sampling may miss short bursts; observed peak is a lower bound"})
    }
}

pub fn latency(mut microseconds: Vec<u64>) -> Value {
    microseconds.sort_unstable();
    let quantile = |numerator: usize| {
        if microseconds.is_empty() {
            return None;
        }
        let index = (microseconds.len() * numerator)
            .div_ceil(100)
            .saturating_sub(1);
        microseconds.get(index).copied()
    };
    json!({"sample_count":microseconds.len(),"p50_us":quantile(50),"p95_us":quantile(95),"p99_us":quantile(99),"maximum_us":microseconds.last()})
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
