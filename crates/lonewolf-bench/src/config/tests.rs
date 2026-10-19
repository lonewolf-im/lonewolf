// SPDX-License-Identifier: Apache-2.0

use super::*;

fn local(scenario: &str) -> String {
    format!(
        "schema_version = 1\nenvironment_id = 'test'\n[target]\nmode = 'local'\nserver_binary = 'server'\n[scenario]\nkind = '{scenario}'\n"
    )
}
fn parse(text: &str) -> BenchResult<RunConfig> {
    let config: RunConfig =
        toml::from_str(text).map_err(|_| invalid("invalid configuration syntax or fields"))?;
    config.validate()?;
    Ok(config)
}

#[test]
fn all_scenarios_and_target_defaults() -> BenchResult<()> {
    for (kind, count) in [("idle", 100), ("messages", 100), ("churn", 64)] {
        let config = parse(&local(kind))?;
        assert_eq!(config.account_count(), count);
        assert_eq!(config.measurement, MeasurementConfig::default());
        if let TargetConfig::Local {
            server_revision,
            server_profile,
            server_features,
            server_toolchain,
            ..
        } = config.target
        {
            assert_eq!(server_revision, "unknown");
            assert_eq!(server_profile, "unknown");
            assert_eq!(server_features, None);
            assert_eq!(server_toolchain, None);
        }
    }
    Ok(())
}

#[test]
fn strict_missing_unknown_and_irrelevant_fields() {
    let text = local("idle");
    for changed in [
        text.replace("schema_version = 1", "schema_version = 2"),
        text.replace("schema_version = 1", "unexpected = 1\nschema_version = 1"),
        text.replace(
            "server_binary = 'server'",
            "credentials_file = 'secret'\nserver_binary = 'server'",
        ),
        text.replace("server_binary = 'server'", ""),
        text.replace("kind = 'idle'", "kind = 'idle'\npairs = 1"),
        text.replace("environment_id = 'test'", ""),
        text + "[measurement]\nunexpected = 1\n",
    ] {
        assert!(parse(&changed).is_err());
    }
}

#[test]
fn numeric_bounds_and_overflow() -> BenchResult<()> {
    for kind in ["idle", "messages", "churn"] {
        let mut config = parse(&local(kind))?;
        config.scenario = match kind {
            "idle" => ScenarioConfig::Idle { connections: 0 },
            "messages" => ScenarioConfig::Messages {
                pairs: usize::MAX,
                rate_per_second: 1000,
                body_bytes: 256,
            },
            _ => ScenarioConfig::Churn {
                accounts: 100_001,
                rate_per_second: 20,
            },
        };
        assert!(config.validate().is_err());
    }
    let text = local("messages");
    for setting in [
        "duration_ms = 0",
        "duration_ms = 3600001",
        "warmup_ms = 18446744073709551615",
        "driver_workers = 0",
        "driver_workers = 257",
        "max_in_flight = 65537",
        "connect_concurrency = 0",
        "operation_timeout_ms = 0",
        "shutdown_timeout_ms = 600001",
        "setup_timeout_ms = 86400001",
        "ramp_rate_per_second = 0",
        "ramp_rate_per_second = 1000001",
        "dispatch_quantum_us = 999",
        "max_dispatch_batch = 0",
        "max_schedule_lag_ms = 0",
        "max_schedule_lag_ms = 1001",
        "dispatch_quantum_us = 100000\nmax_schedule_lag_ms = 99",
        "operation_timeout_ms = 100",
        "dispatch_quantum_us = 100000\nmax_dispatch_batch = 99",
    ] {
        assert!(
            parse(&format!("{text}[measurement]\n{setting}\n")).is_err(),
            "{setting}"
        );
    }
    assert!(parse(&format!("{text}[measurement]\nwarmup_ms = 0\n")).is_ok());
    assert!(
        parse(&format!(
            "{}[measurement]\nduration_ms = 3600000\n",
            text.replace(
                "kind = 'messages'",
                "kind = 'messages'\nrate_per_second = 10000"
            )
        ))
        .is_err()
    );
    assert!(
        parse(&text.replace("kind = 'messages'", "kind = 'messages'\nbody_bytes = 65537")).is_err()
    );
    assert!(
        parse(&text.replace(
            "kind = 'messages'",
            "kind = 'messages'\nrate_per_second = 0"
        ))
        .is_err()
    );
    assert!(
        parse(&text.replace(
            "server_binary = 'server'",
            "server_binary = 'server'\nstanza_pool_size_mib = 9"
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn remote_syntax_and_metrics_policy() -> BenchResult<()> {
    let text = "schema_version=1\nenvironment_id='remote'\n[target]\nmode='remote'\nconnect_host='127.0.0.1'\nport=5222\nxmpp_domain='example.org'\ncredentials_file='credentials.json'\nenvironment_file='environment.json'\n[scenario]\nkind='idle'";
    parse(text)?;
    for change in [
        text.replace("port=5222", "port=0"),
        text.replace("example.org", "127.0.0.1"),
        text.replace("example.org", "bad_name"),
        text.replace("mode='remote'", "mode='remote'\nserver_workers=2"),
    ] {
        assert!(parse(&change).is_err());
    }
    for value in [
        "https://example.org/metrics",
        "http://u:p@example.org/metrics",
        "http://example.org/metrics?x=1",
        "http://example.org/metrics#x",
        "http://example.org/",
        "example.org/metrics",
        "http://example.org:0/metrics",
        "http://example.org:99999/metrics",
        "http://example.org:bad/metrics",
        "http://example.org:/metrics",
        "http://[invalid]/metrics",
    ] {
        assert!(validate_metrics_url(value).is_err());
    }
    validate_metrics_url("http://[::1]:9000/metrics")?;
    assert_eq!(normalize_dns("EXAMPLE.Org.")?, "example.org");
    Ok(())
}

#[test]
fn declared_build_fields_and_secret_free_errors() -> BenchResult<()> {
    let text = local("idle");
    for profile in ["release", "production-custom"] {
        let config = parse(&text.replace(
            "server_binary = 'server'",
            &format!(
                "server_binary = 'server'\nserver_profile = '{profile}'\nserver_features = []"
            ),
        ))?;
        assert!(
            matches!(config.target, TargetConfig::Local { server_features: Some(features), .. } if features.is_empty())
        );
    }
    for features in [
        vec!["duplicate".into(), "duplicate".into()],
        vec!["x".repeat(129)],
        (0..257).map(|i| format!("f{i}")).collect(),
    ] {
        assert!(validate_build("release", None, Some(&features)).is_err());
    }
    assert!(validate_build(&"x".repeat(65), None, None).is_err());
    assert!(validate_build("release", Some(&"x".repeat(1025)), None).is_err());
    let secret = "TOP_SECRET_PASSWORD";
    let failure = parse(&text.replace("kind = 'idle'", &format!("kind = '{secret}'")))
        .err()
        .ok_or_else(|| invalid("expected error"))?;
    assert!(!format!("{failure:?} {failure}").contains(secret));
    Ok(())
}

#[test]
fn config_relative_paths_caller_override_and_new_output() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("bench.toml");
    fs::write(
        &path,
        local("idle").replace(
            "server_binary = 'server'",
            "server_binary = 'server'\nserver_features = ['z', 'a']",
        ),
    )?;
    let config = RunConfig::load(&path, None)?;
    assert!(
        matches!(config.target, TargetConfig::Local { server_binary, server_features: Some(features), .. }
        if server_binary == directory.path().join("server") && features == ["a", "z"])
    );
    let config = RunConfig::load(&path, Some(Path::new("caller-server")))?;
    assert!(
        matches!(config.target, TargetConfig::Local { server_binary, .. } if server_binary == std::env::current_dir()?.join("caller-server"))
    );
    let remote = local("idle").replace("mode = 'local'\nserver_binary = 'server'", "mode='remote'\nconnect_host='EXAMPLE.org'\nport=5222\nxmpp_domain='EXAMPLE.org.'\ncredentials_file='creds'\nenvironment_file='env'\nca_pem='ca'");
    fs::write(&path, remote)?;
    let config = RunConfig::load(&path, None)?;
    assert!(
        matches!(config.target, TargetConfig::Remote { credentials_file, environment_file, ca_pem: Some(ca), xmpp_domain, .. }
        if credentials_file == directory.path().join("creds") && environment_file == directory.path().join("env") && ca == directory.path().join("ca") && xmpp_domain == "example.org")
    );
    assert!(RunConfig::load(&path, Some(Path::new("server"))).is_err());
    validate_new_output(&directory.path().join("new"))?;
    assert!(validate_new_output(&path).is_err());
    assert!(validate_new_output(&directory.path().join("absent/new")).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            directory.path().join("missing"),
            directory.path().join("dangling"),
        )?;
        assert!(validate_new_output(&directory.path().join("dangling")).is_err());
    }
    Ok(())
}
