// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod bench_support;
mod faults;
#[path = "support/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use bench_support::{SECRET, TestResult, artifacts, cli, private_write};
use lonewolf_bench::{
    config::{RunConfig, ScenarioConfig, TargetConfig},
    report::RunStatus,
};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use support::C2sSuite;

const LIMITS: &str = "max_connections_per_ip=100000\nconnection_attempts_per_ip={per_second=1000000,burst=1000000}\nincoming_stanzas_per_connection={per_second=1000000,burst=1000000}\nnew_recipients_per_connection={per_second=1000000,burst=1000000}\nincoming_xml_per_connection={bytes_per_second=1073741824,burst_bytes=1073741824}";
fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_lonewolf-bench"))
}

fn server() -> TestResult<C2sSuite> {
    C2sSuite::with_extensions_limits_and_setup("'roster', 'offline'", LIMITS, |path| {
        fs::OpenOptions::new()
            .append(true)
            .open(path.join("lonewolf.toml"))?
            .write_all(b"\n[metrics]\nenabled=true\naddress='127.0.0.1:0'\n")?;
        Ok(())
    })
}
use std::io::Write;

fn inputs(
    directory: &Path,
    address: SocketAddr,
    ca: &Path,
    scenario: ScenarioConfig,
) -> TestResult<RunConfig> {
    let credentials = directory.join("credentials.json");
    if !credentials.exists() {
        private_write(
            &credentials,
            &serde_json::to_vec(&serde_json::json!({
                "schema_version":1,"domain":"localhost","accounts":[
                    {"jid":"bench-000000@localhost","password":SECRET},
                    {"jid":"bench-000001@localhost","password":SECRET}
                ]
            }))?,
        )?;
    }
    let mut config = bench_support::local_config(Path::new("unused"), scenario);
    config.target = TargetConfig::Remote {
        connect_host: address.ip().to_string(),
        port: address.port(),
        xmpp_domain: "localhost".into(),
        credentials_file: credentials,
        ca_pem: Some(ca.into()),
        metrics_url: None,
    };
    Ok(config)
}
fn config_file(directory: &Path, name: &str, config: &RunConfig) -> TestResult<PathBuf> {
    let path = directory.join(format!("{name}.toml"));
    let TargetConfig::Remote {
        connect_host,
        port,
        xmpp_domain,
        credentials_file,
        ca_pem,
        metrics_url,
    } = &config.target
    else {
        return Err("remote config".into());
    };
    let q = |value: &str| serde_json::to_string(value);
    let mut text = format!(
        "[target]\nmode='remote'\nconnect_host={connect_host:?}\nport={port}\nxmpp_domain={xmpp_domain:?}\ncredentials_file={}\n",
        q(&credentials_file.to_string_lossy())?,
    );
    if let Some(ca) = ca_pem {
        text += &format!("ca_pem={}\n", q(&ca.to_string_lossy())?);
    }
    if let Some(url) = metrics_url {
        text += &format!("metrics_url={}\n", q(url)?);
    }
    text += "[scenario]\n";
    match config.scenario {
        ScenarioConfig::Idle { connections } => {
            text += &format!("kind='idle'\nconnections={connections}\n")
        }
        ScenarioConfig::Messages {
            pairs,
            rate_per_second,
            body_bytes,
        } => {
            text += &format!(
                "kind='messages'\npairs={pairs}\nrate_per_second={rate_per_second}\nbody_bytes={body_bytes}\n"
            )
        }
        ScenarioConfig::Churn {
            accounts,
            rate_per_second,
        } => {
            text +=
                &format!("kind='churn'\naccounts={accounts}\nrate_per_second={rate_per_second}\n")
        }
    }
    text += "[measurement]\n";
    let measurement = serde_json::to_value(&config.measurement)?;
    for (key, value) in measurement.as_object().ok_or("measurement")? {
        text += &format!("{key}={value}\n");
    }
    text += &format!(
        "[metrics]\ninterval_ms={}\ntimeout_ms={}\n",
        config.metrics.interval_ms, config.metrics.timeout_ms
    );
    fs::write(&path, text)?;
    Ok(path)
}
fn run_cli(config: &Path, output: &Path) -> TestResult<std::process::Output> {
    cli(
        binary(),
        &[
            "run".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
            "--output".as_ref(),
            output.as_os_str(),
        ],
    )
}
fn compare_cli(
    a: &Path,
    b: &Path,
    out: &Path,
) -> TestResult<lonewolf_bench::compare::ComparisonReport> {
    let output = cli(
        binary(),
        &[
            "compare".as_ref(),
            a.as_os_str(),
            b.as_os_str(),
            "--output".as_ref(),
            out.as_os_str(),
        ],
    )?;
    let report: lonewolf_bench::compare::ComparisonReport =
        serde_json::from_slice(&fs::read(out.join("comparison.json"))?)?;
    assert_eq!(
        output.status.code(),
        Some(if report.comparable { 0 } else { 2 })
    );
    assert!(fs::metadata(out.join("comparison.md"))?.len() > 0);
    bench_support::assert_no_secret(
        out,
        Some(&output),
        &[SECRET, "PRIVATE KEY", "secret-auth-sentinel"],
    )?;
    Ok(report)
}

#[test]
fn remote_cli_verifies_dns_over_loopback_and_runs_all_topologies_without_admin_effects()
-> TestResult {
    let mut server = server()?;
    server.create_account("bench-000000", SECRET)?;
    server.create_account("bench-000001", SECRET)?;
    let directory = tempfile::tempdir()?;
    let admin = server.fixture_path().join("run/lonewolf/admin.sock");
    let admin_metadata = fs::metadata(&admin)?;
    for (name, scenario) in [
        ("idle", ScenarioConfig::Idle { connections: 2 }),
        (
            "messages",
            ScenarioConfig::Messages {
                pairs: 1,
                rate_per_second: 2,
                body_bytes: 64,
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
        let mut config = inputs(
            directory.path(),
            server.address,
            &server.fixture_path().join("certificate.pem"),
            scenario,
        )?;
        if let TargetConfig::Remote { metrics_url, .. } = &mut config.target {
            *metrics_url = Some(format!("http://{}/metrics", server.metrics_address()?));
        }
        let path = config_file(directory.path(), name, &config)?;
        let output_path = directory.path().join(name);
        let output = run_cli(&path, &output_path)?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = artifacts::complete(&output_path, RunStatus::Passed)?;
        assert_eq!(report.target.xmpp_domain, "localhost");
        assert!(report.target.negotiated_tls.is_some());
        assert_eq!(report.phases.len(), 10);
        assert!(report.target.server_build.is_some());
        assert!(report.target.server_binary_sha256.is_none());
        assert!(!output_path.join("server.log").exists());
        bench_support::assert_no_secret(
            &output_path,
            Some(&output),
            &[SECRET, "PRIVATE KEY", "<auth", "<message"],
        )?;
        server.wait_for_metric("lonewolf_c2s_connections{listener=\"0\"} 0")?;
        assert!(
            compare_cli(
                &output_path,
                &output_path,
                &directory.path().join(format!("compare-{name}"))
            )?
            .comparable
        );
    }
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::metadata(&admin)?.ino(), admin_metadata.ino());
    server.stop()?;
    Ok(())
}

#[test]
fn real_run_reports_compare_and_refuse_unmeasured_corrupt_or_different_workloads() -> TestResult {
    let mut server = server()?;
    server.create_account("bench-000000", SECRET)?;
    server.create_account("bench-000001", SECRET)?;
    let directory = tempfile::tempdir()?;
    let config = inputs(
        directory.path(),
        server.address,
        &server.fixture_path().join("certificate.pem"),
        ScenarioConfig::Messages {
            pairs: 1,
            rate_per_second: 2,
            body_bytes: 64,
        },
    )?;
    let path = config_file(directory.path(), "config", &config)?;
    for name in ["a", "b"] {
        assert!(
            run_cli(&path, &directory.path().join(name))?
                .status
                .success()
        );
    }
    let a = directory.path().join("a");
    let b = directory.path().join("b");
    let before = fs::read(a.join("result.json"))?;
    assert!(compare_cli(&a, &b, &directory.path().join("a-b"))?.comparable);
    assert!(compare_cli(&a, &a, &directory.path().join("self"))?.comparable);
    for (name, comparable) in [
        ("degraded", true),
        ("other-driver", true),
        ("failed", false),
        ("different-rate", false),
        ("different-duration", false),
        ("missing-field", false),
        ("corrupt", false),
    ] {
        let candidate = directory.path().join(name);
        artifacts::copy_run(&b, &candidate)?;
        match name {
            "corrupt" => fs::write(candidate.join("result.json"), b"{secret-auth-sentinel")?,
            _ => artifacts::edit_report(&candidate, |v| match name {
                "degraded" => {
                    v["status"] = "degraded".into();
                    v["reasons"] = serde_json::json!([{"code":"driver_limited","context":"message_operations_skipped"}]);
                }
                "other-driver" => v["driver"]["executable_sha256"] = "f".repeat(64).into(),
                "failed" => v["status"] = "failed".into(),
                "different-rate" => v["config"]["scenario"]["rate_per_second"] = 3.into(),
                "different-duration" => v["config"]["measurement"]["duration_ms"] = 999.into(),
                _ => {
                    v["config"]["measurement"]
                        .as_object_mut()
                        .map(|m| m.remove("duration_ms"));
                }
            })?,
        }
        let unchanged = artifacts::contents(&candidate)?;
        let comparison = compare_cli(
            &a,
            &candidate,
            &directory.path().join(format!("comparison-{name}")),
        )?;
        assert_eq!(
            comparison.comparable, comparable,
            "{name}: {:?}",
            comparison.refusals
        );
        assert_eq!(comparison.metrics.is_empty(), !comparable);
        if comparable {
            assert!(!comparison.warnings.is_empty());
        }
        assert_eq!(artifacts::contents(&candidate)?, unchanged);
    }
    assert_eq!(fs::read(a.join("result.json"))?, before);
    server.stop()?;
    Ok(())
}

#[test]
fn cli_generates_private_credentials_and_provisions_only_on_explicit_command() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let mut server = server()?;
    let directory = tempfile::tempdir()?;
    let credentials = directory.path().join("credentials.json");
    let generated = cli(
        binary(),
        &[
            "accounts".as_ref(),
            "generate".as_ref(),
            "--domain".as_ref(),
            "localhost".as_ref(),
            "--prefix".as_ref(),
            "bench".as_ref(),
            "--count".as_ref(),
            "2".as_ref(),
            "--output".as_ref(),
            credentials.as_os_str(),
        ],
    )?;
    assert!(generated.status.success());
    assert_eq!(fs::metadata(&credentials)?.permissions().mode() & 0o077, 0);
    let original = fs::read(&credentials)?;
    let config = inputs(
        directory.path(),
        server.address,
        &server.fixture_path().join("certificate.pem"),
        ScenarioConfig::Idle { connections: 2 },
    )?;
    let config_path = config_file(directory.path(), "config", &config)?;
    let missing = run_cli(&config_path, &directory.path().join("unprovisioned"))?;
    assert_ne!(missing.status.code(), Some(0));
    let socket = server.fixture_path().join("run/lonewolf/admin.sock");
    let args = [
        "accounts".as_ref(),
        "provision".as_ref(),
        "--socket".as_ref(),
        socket.as_os_str(),
        "--credentials".as_ref(),
        credentials.as_os_str(),
    ];
    let provisioned = cli(binary(), &args)?;
    assert!(provisioned.status.success());
    assert_eq!(
        std::str::from_utf8(&provisioned.stdout)?,
        "confirmed_created=2; uncertain_last_create=false\n"
    );
    let conflict = cli(binary(), &args)?;
    assert_eq!(conflict.status.code(), Some(2));
    assert!(
        std::str::from_utf8(&conflict.stderr)?
            .contains("confirmed_created=0; uncertain_last_create=false")
    );
    let output = run_cli(&config_path, &directory.path().join("provisioned"))?;
    assert!(output.status.success());
    assert_eq!(fs::read(&credentials)?, original);
    let value: serde_json::Value = serde_json::from_slice(&original)?;
    for account in value["accounts"].as_array().ok_or("accounts")? {
        let password = account["password"].as_str().ok_or("password")?;
        bench_support::assert_no_secret(
            &directory.path().join("provisioned"),
            Some(&output),
            &[password],
        )?;
    }
    server.stop()?;
    Ok(())
}

#[test]
fn remote_cli_rejects_wrong_ca_and_password_without_secret_echo() -> TestResult {
    let mut server = server()?;
    server.create_account("bench-000000", SECRET)?;
    let directory = tempfile::tempdir()?;
    let base = inputs(
        directory.path(),
        server.address,
        &server.fixture_path().join("certificate.pem"),
        ScenarioConfig::Idle { connections: 1 },
    )?;
    for name in ["ca", "password"] {
        let mut config = base.clone();
        if let TargetConfig::Remote {
            ca_pem,
            credentials_file,
            ..
        } = &mut config.target
        {
            match name {
                "ca" => *ca_pem = None,
                _ => {
                    let credentials = directory.path().join("wrong-password.json");
                    private_write(
                        &credentials,
                        &serde_json::to_vec(
                            &serde_json::json!({"schema_version":1,"domain":"localhost","accounts":[{"jid":"bench-000000@localhost","password":"secret-auth-sentinel"}]}),
                        )?,
                    )?;
                    *credentials_file = credentials;
                }
            }
        }
        let path = config_file(directory.path(), name, &config)?;
        let out = directory.path().join(name);
        let output = run_cli(&path, &out)?;
        assert_eq!(output.status.code(), Some(1));
        artifacts::complete(&out, RunStatus::Failed)?;
        bench_support::assert_no_secret(
            &out,
            Some(&output),
            &[SECRET, "secret-auth-sentinel", "PRIVATE KEY"],
        )?;
    }
    server.stop()?;
    Ok(())
}

#[test]
fn operator_examples_parse_without_accessing_remote_endpoints() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/bench");
    for name in ["idle", "messages", "churn", "remote"] {
        RunConfig::load(&root.join(format!("{name}.toml")), None)?;
    }
    Ok(())
}

#[test]
fn remote_cli_rejects_certificate_name_after_trusting_the_same_peer_certificate() -> TestResult {
    let directory = tempfile::tempdir()?;
    let peer = peer::Peer::start(directory.path(), peer::Behavior::Normal)?;
    let certificate = directory.path().join("certificate.pem");
    let mut config = inputs(
        directory.path(),
        peer.address,
        &certificate,
        ScenarioConfig::Idle { connections: 1 },
    )?;
    let trusted_path = config_file(directory.path(), "trusted", &config)?;
    let trusted_output = directory.path().join("trusted");
    let trusted = run_cli(&trusted_path, &trusted_output)?;
    assert_eq!(trusted.status.code(), Some(0));
    let report = artifacts::complete(&trusted_output, RunStatus::Passed)?;
    assert!(report.target.negotiated_tls.is_some());
    bench_support::assert_no_secret(&trusted_output, Some(&trusted), &[SECRET, "PRIVATE KEY"])?;

    let credentials = directory.path().join("wrong-domain.json");
    private_write(
        &credentials,
        &serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "domain": "wrong.example.test",
            "accounts": [{"jid": "bench-000000@wrong.example.test", "password": SECRET}]
        }))?,
    )?;
    if let TargetConfig::Remote {
        xmpp_domain,
        credentials_file,
        ca_pem,
        ..
    } = &mut config.target
    {
        *xmpp_domain = "wrong.example.test".into();
        *credentials_file = credentials;
        assert_eq!(ca_pem.as_deref(), Some(certificate.as_path()));
    }
    let path = config_file(directory.path(), "wrong-name", &config)?;
    let output_path = directory.path().join("wrong-name");
    let output = run_cli(&path, &output_path)?;
    assert_eq!(output.status.code(), Some(1));
    let report = artifacts::complete(&output_path, RunStatus::Failed)?;
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.context.as_deref() == Some("tls_handshake"))
    );
    assert!(report.target.negotiated_tls.is_none());
    bench_support::assert_no_secret(&output_path, Some(&output), &[SECRET, "PRIVATE KEY"])?;
    peer.finish()?;
    Ok(())
}
