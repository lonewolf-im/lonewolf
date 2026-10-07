// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[path = "../support/client.rs"]
mod client;
mod measurement;
mod setup;
#[allow(dead_code)]
#[path = "../support/tls.rs"]
mod tls;
mod workloads;
#[allow(dead_code)]
#[path = "../support/xml.rs"]
mod xml;

use serde_json::json;
use setup::C2sSuite;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
const STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";
const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const ROSTER_VERSIONING_NAMESPACE: &str = "urn:xmpp:features:rosterver";
const PRE_APPROVAL_NAMESPACE: &str = "urn:xmpp:features:pre-approval";

#[test]
#[ignore = "Linux release workload baseline; see docs/capacity.md"]
fn server_capacity_baseline() -> TestResult {
    if !cfg!(target_os = "linux") || cfg!(debug_assertions) {
        return Err("run this Linux measurement profile with cargo test --release".into());
    }
    let binary = std::env::var_os("LONEWOLF_CAPACITY_SERVER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_lonewolf")));
    let case = std::env::var("LONEWOLF_CAPACITY_CASE").unwrap_or_else(|_| "all".into());
    let repetitions: usize = std::env::var("LONEWOLF_CAPACITY_REPETITIONS")
        .unwrap_or_else(|_| "3".into())
        .parse()?;
    let multiplier: usize = std::env::var("LONEWOLF_CAPACITY_MULTIPLIER")
        .unwrap_or_else(|_| "1".into())
        .parse()?;
    assert!(repetitions > 0 && multiplier > 0);
    let poll = std::env::var_os("LONEWOLF_CAPACITY_POLL").is_some();
    let provenance =
        std::env::var("LONEWOLF_CAPACITY_PROVENANCE").unwrap_or_else(|_| "unspecified".into());
    let output = PathBuf::from(
        std::env::var_os("LONEWOLF_CAPACITY_OUTPUT")
            .unwrap_or_else(|| "/tmp/lonewolf-capacity.json".into()),
    );
    let mut results = Vec::new();
    for name in [
        "cold_idle",
        "post_large_idle",
        "live_routing",
        "slow_reader",
        "storage_contention",
        "reconnect_replay",
    ] {
        if case != "all" && case != name {
            continue;
        }
        for repetition in 0..repetitions {
            eprintln!(
                "capacity case={name} repetition={} binary={}",
                repetition + 1,
                binary.display()
            );
            let mut server = C2sSuite::start(&binary)?;
            let result = workloads::run(name, &server, multiplier, poll);
            let cleanup = server.stop();
            if server.timed_out() {
                return Err(format!("{name} exceeded 60s work deadline").into());
            }
            cleanup?;
            let result = result?;
            results
                .push(json!({"case": name, "repetition": repetition + 1, "measurement": result}));
        }
    }
    assert!(!results.is_empty(), "unknown workload case");
    let report = json!({"schema_version": 1, "provenance": provenance, "server_binary": binary,
        "server_binary_sha256": std::process::Command::new("sha256sum").arg(&binary).output().ok().filter(|result|result.status.success()).map(|result|String::from_utf8_lossy(&result.stdout).split_whitespace().next().unwrap_or_default().to_owned()),
        "metadata": measurement::metadata()?, "configuration": setup::CONFIG, "message_multiplier": multiplier,
        "diagnostics_poll_hz": if poll {1} else {0}, "results": results});
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    eprintln!("capacity results={}", output.display());
    Ok(())
}
