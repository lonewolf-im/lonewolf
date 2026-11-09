// SPDX-License-Identifier: Apache-2.0

use crate::error::{BenchError, BenchResult, ErrorCode};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetricSnapshot {
    pub process_start: Option<f64>,
    pub cpu_seconds: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub open_fds: Option<u64>,
    pub max_fds: Option<u64>,
    pub build: Option<BTreeMap<String, String>>,
    pub policy_rejections: BTreeMap<String, u64>,
    pub connections: Option<u64>,
    pub router_sessions: Option<u64>,
    pub dropped_logs: Option<u64>,
    pub invalid_samples: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct DerivedMetrics {
    pub cpu_seconds: Option<f64>,
    pub identity_changed: bool,
    pub counter_decreased: bool,
    pub policy_rejections: BTreeMap<String, u64>,
}

fn invalid() -> BenchError {
    BenchError::new(ErrorCode::Runtime, "metrics_syntax")
}

fn labels(input: &str) -> BenchResult<(BTreeMap<String, String>, &str)> {
    let mut rest = input;
    let mut output = BTreeMap::new();
    if !rest.starts_with('{') {
        return Ok((output, rest));
    }
    rest = &rest[1..];
    loop {
        rest = rest.trim_start();
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((output, tail));
        }
        let end = rest.find('=').ok_or_else(invalid)?;
        let key = rest[..end].trim();
        if key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || output.len() >= 32
        {
            return Err(invalid());
        }
        rest = rest[end + 1..]
            .trim_start()
            .strip_prefix('"')
            .ok_or_else(invalid)?;
        let mut value = String::new();
        let mut chars = rest.char_indices();
        let tail = loop {
            let (at, ch) = chars.next().ok_or_else(invalid)?;
            match ch {
                '"' => break &rest[at + 1..],
                '\\' => value.push(match chars.next().ok_or_else(invalid)?.1 {
                    'n' => '\n',
                    '\\' => '\\',
                    '"' => '"',
                    _ => return Err(invalid()),
                }),
                '\n' | '\r' => return Err(invalid()),
                ch => value.push(ch),
            }
            if value.len() > 1024 {
                return Err(invalid());
            }
        };
        if output.insert(key.to_owned(), value).is_some() {
            return Err(invalid());
        }
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(',') {
            rest = tail;
        } else if !rest.starts_with('}') {
            return Err(invalid());
        }
    }
}

pub(crate) fn has_eof(body: &str) -> bool {
    body.trim_end().lines().last() == Some("# EOF")
}

pub fn parse_snapshot(body: &str) -> BenchResult<MetricSnapshot> {
    if body.len() > 1_048_576 || !has_eof(body) {
        return Err(invalid());
    }
    let mut result = MetricSnapshot::default();
    let mut seen = BTreeSet::new();
    let mut duplicate = BTreeSet::new();
    let mut policies = BTreeSet::new();
    let mut bad_policies = BTreeSet::new();
    let mut connection_listeners = BTreeSet::new();
    let mut connection_total = 0u64;
    let mut invalid_connections = false;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let end = line.find(['{', ' ', '\t']).unwrap_or(line.len());
        let name = &line[..end];
        if !matches!(
            name,
            "process_start_time_seconds"
                | "process_cpu_seconds_total"
                | "process_resident_memory_bytes"
                | "process_open_fds"
                | "process_max_fds"
                | "lonewolf_build_info"
                | "lonewolf_c2s_connections_rejected_total"
                | "lonewolf_c2s_connections"
                | "lonewolf_router_sessions"
                | "lonewolf_log_dropped_lines_total"
        ) {
            continue;
        }
        let (labels, value) = labels(&line[end..])?;
        let mut values = value.split_ascii_whitespace();
        let token = values.next();
        let number = token
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0);
        let number = if values.next().is_some() {
            None
        } else {
            number
        };
        let integer = number.and_then(|number| {
            token
                .and_then(|token| token.parse::<u64>().ok())
                .or_else(|| {
                    (number.fract() == 0.0 && number <= (1u64 << 53) as f64)
                        .then_some(number as u64)
                })
        });
        if name == "lonewolf_c2s_connections" {
            let listener = (labels.len() == 1)
                .then(|| labels.get("listener"))
                .flatten()
                .and_then(|listener| listener.parse::<u64>().ok());
            if let Some((listener, value)) = listener.zip(integer) {
                if !connection_listeners.insert(listener) {
                    invalid_connections = true;
                }
                if let Some(total) = connection_total.checked_add(value) {
                    connection_total = total;
                } else {
                    invalid_connections = true;
                }
            } else {
                invalid_connections = true;
            }
            continue;
        }
        if name == "lonewolf_c2s_connections_rejected_total" {
            if let Some(reason) = labels.get("reason").filter(|v| {
                matches!(
                    v.as_str(),
                    "connection_attempts_per_ip"
                        | "attempt_tracking_full"
                        | "max_unauthenticated_connections"
                        | "max_connections_per_ip"
                        | "connection_tracking_full"
                )
            }) {
                let key = (reason.clone(), labels.get("listener").cloned());
                if !policies.insert(key) || integer.is_none() {
                    bad_policies.insert(reason.clone());
                    result.invalid_samples = true;
                } else if let Some(number) = integer {
                    let previous = result.policy_rejections.entry(reason.clone()).or_default();
                    if let Some(sum) = previous.checked_add(number) {
                        *previous = sum;
                    } else {
                        bad_policies.insert(reason.clone());
                    }
                }
            }
            continue;
        }
        if !seen.insert(name) {
            duplicate.insert(name);
            result.invalid_samples = true;
        }
        if number.is_none() {
            result.invalid_samples = true;
        }
        match name {
            "process_start_time_seconds" if labels.is_empty() => result.process_start = number,
            "process_cpu_seconds_total" if labels.is_empty() => result.cpu_seconds = number,
            "process_resident_memory_bytes" if labels.is_empty() => result.rss_bytes = integer,
            "process_open_fds" if labels.is_empty() => result.open_fds = integer,
            "process_max_fds" if labels.is_empty() => result.max_fds = integer,
            "lonewolf_build_info" => {
                if number == Some(1.0)
                    && ["version", "branch", "commit"].iter().all(|key| {
                        labels
                            .get(*key)
                            .is_some_and(|v| crate::config::printable(v, 1024))
                    })
                {
                    result.build = Some(labels);
                } else {
                    result.invalid_samples = true;
                }
            }
            "lonewolf_router_sessions" => result.router_sessions = integer,
            "lonewolf_log_dropped_lines_total" if labels.is_empty() => {
                result.dropped_logs = integer
            }
            _ => result.invalid_samples = true,
        }
    }
    if invalid_connections {
        result.invalid_samples = true;
    } else if !connection_listeners.is_empty() {
        result.connections = Some(connection_total);
    }
    for name in duplicate {
        match name {
            "process_start_time_seconds" => result.process_start = None,
            "process_cpu_seconds_total" => result.cpu_seconds = None,
            "process_resident_memory_bytes" => result.rss_bytes = None,
            "process_open_fds" => result.open_fds = None,
            "process_max_fds" => result.max_fds = None,
            "lonewolf_build_info" => result.build = None,
            "lonewolf_router_sessions" => result.router_sessions = None,
            "lonewolf_log_dropped_lines_total" => result.dropped_logs = None,
            _ => {}
        }
    }
    for reason in bad_policies {
        result.policy_rejections.remove(&reason);
    }
    Ok(result)
}

pub fn derive_interval(previous: &MetricSnapshot, current: &MetricSnapshot) -> DerivedMetrics {
    let mut result = DerivedMetrics {
        identity_changed: previous
            .process_start
            .zip(current.process_start)
            .is_some_and(|(a, b)| a != b)
            || previous
                .build
                .as_ref()
                .zip(current.build.as_ref())
                .is_some_and(|(a, b)| a != b),
        ..DerivedMetrics::default()
    };
    if let Some((a, b)) = previous.cpu_seconds.zip(current.cpu_seconds) {
        result.counter_decreased |= b < a;
        if !result.identity_changed && b >= a {
            result.cpu_seconds = Some(b - a);
        }
    }
    for (reason, &current) in &current.policy_rejections {
        if let Some(&previous) = previous.policy_rejections.get(reason) {
            if let Some(delta) = current.checked_sub(previous) {
                result.policy_rejections.insert(reason.clone(), delta);
            } else {
                result.counter_decreased = true;
            }
        }
    }
    if result.identity_changed {
        result.policy_rejections.clear();
    }
    result.counter_decreased |= previous
        .dropped_logs
        .zip(current.dropped_logs)
        .is_some_and(|(a, b)| b < a);
    result
}
