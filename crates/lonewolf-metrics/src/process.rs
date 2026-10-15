// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::sys::resource::{Resource, UsageWho, getrlimit, getrusage};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::{MetricType, counter::ConstCounter, gauge::ConstGauge};
use prometheus_client::registry::Unit;

#[derive(Debug)]
pub struct ProcessCollector {
    start_time_seconds: f64,
}

impl ProcessCollector {
    /// Uses the creation time as the process start time.
    pub fn new() -> Self {
        Self {
            start_time_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
        }
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ProcessCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        ConstGauge::new(self.start_time_seconds).encode(encoder.encode_descriptor(
            "process_start_time",
            "Start time of the process since the Unix epoch.",
            Some(&Unit::Seconds),
            MetricType::Gauge,
        )?)?;
        if let Ok(usage) = getrusage(UsageWho::RUSAGE_SELF) {
            let user = usage.user_time();
            let system = usage.system_time();
            let seconds = user.tv_sec() as f64
                + user.tv_usec() as f64 / 1e6
                + system.tv_sec() as f64
                + system.tv_usec() as f64 / 1e6;
            ConstCounter::new(seconds).encode(encoder.encode_descriptor(
                "process_cpu",
                "Total user and system CPU time spent by the process.",
                Some(&Unit::Seconds),
                MetricType::Counter,
            )?)?;
        }
        if let Ok((soft, _)) = getrlimit(Resource::RLIMIT_NOFILE) {
            ConstGauge::new(soft).encode(encoder.encode_descriptor(
                "process_max_fds",
                "Maximum number of open file descriptors allowed by the soft limit.",
                None,
                MetricType::Gauge,
            )?)?;
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(bytes) = resident_memory_bytes() {
                ConstGauge::new(bytes).encode(encoder.encode_descriptor(
                    "process_resident_memory",
                    "Resident memory size of the process.",
                    Some(&Unit::Bytes),
                    MetricType::Gauge,
                )?)?;
            }
            if let Some(count) = open_fds() {
                ConstGauge::new(count).encode(encoder.encode_descriptor(
                    "process_open_fds",
                    "Number of open file descriptors.",
                    None,
                    MetricType::Gauge,
                )?)?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn resident_memory_bytes() -> Option<u64> {
    use std::fs::File;
    use std::io::Read;

    use nix::unistd::{SysconfVar, sysconf};

    let mut buffer = [0; 256];
    let length = File::open("/proc/self/statm")
        .ok()?
        .read(&mut buffer)
        .ok()?;
    let pages = std::str::from_utf8(&buffer[..length])
        .ok()?
        .split_ascii_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?;
    let page_size = u64::try_from(sysconf(SysconfVar::PAGE_SIZE).ok()??).ok()?;
    pages.checked_mul(page_size)
}

#[cfg(target_os = "linux")]
fn open_fds() -> Option<u64> {
    count_directory_entries(c"/proc/self/fd")
}

#[cfg(target_os = "linux")]
struct DirectoryStream(std::ptr::NonNull<nix::libc::DIR>);

#[cfg(target_os = "linux")]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // This guard owns the live stream and closes it exactly once.
        unsafe { nix::libc::closedir(self.0.as_ptr()) };
    }
}

#[cfg(target_os = "linux")]
fn count_directory_entries(path: &std::ffi::CStr) -> Option<u64> {
    use std::ffi::CStr;
    use std::ptr::{NonNull, addr_of};

    use nix::errno::Errno;

    // The C string stays valid for the duration of this call.
    let directory = DirectoryStream(NonNull::new(unsafe { nix::libc::opendir(path.as_ptr()) })?);
    let mut count = 0u64;
    loop {
        Errno::clear();
        // The guard keeps this stream live and only this loop reads it.
        let entry = unsafe { nix::libc::readdir(directory.0.as_ptr()) };
        if entry.is_null() {
            let error = Errno::last_raw();
            return (error == 0).then_some(count);
        }
        // The terminated name stays valid until the next read or close.
        let name = unsafe { CStr::from_ptr(addr_of!((*entry).d_name).cast()) }.to_bytes();
        count = count.checked_add(u64::from(name != b"." && name != b".."))?;
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;

    use super::*;

    fn sample(output: &str, name: &str) -> f64 {
        output
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|line| line.strip_prefix(' '))
            })
            .expect("missing process metric")
            .parse()
            .expect("invalid process metric")
    }

    #[test]
    fn process_metrics_are_encoded() -> Result<(), fmt::Error> {
        let mut registry = Registry::default();
        registry.register_collector(Box::new(ProcessCollector::new()));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        assert!(output.contains("# TYPE process_cpu_seconds counter\n"));
        assert!(sample(&output, "process_cpu_seconds_total") >= 0.0);
        assert!(sample(&output, "process_start_time_seconds") > 0.0);
        assert!(sample(&output, "process_max_fds") > 0.0);
        assert!(output.ends_with("# EOF\n"));
        #[cfg(target_os = "linux")]
        {
            assert!(sample(&output, "process_resident_memory_bytes") > 0.0);
            assert!(sample(&output, "process_open_fds") > 0.0);
        }
        Ok(())
    }

    #[test]
    fn start_time_is_captured_at_creation() -> Result<(), Box<dyn std::error::Error>> {
        let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let collector = ProcessCollector::new();
        let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let mut registry = Registry::default();
        registry.register_collector(Box::new(collector));
        let mut output = String::new();
        encode(&mut output, &registry)?;
        assert!((before..=after).contains(&sample(&output, "process_start_time_seconds")));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_reads_do_not_allocate_in_rust() {
        assert_eq!(
            crate::test_allocator::allocations_during(|| {
                assert!(resident_memory_bytes().is_some());
                assert!(open_fds().is_some());
            }),
            0
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_directory_paths_are_omitted() {
        assert_eq!(count_directory_entries(c""), None);
        assert_eq!(count_directory_entries(c"/dev/null"), None);
    }
}
