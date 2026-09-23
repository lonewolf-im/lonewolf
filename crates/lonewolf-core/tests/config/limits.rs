// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use lonewolf_core::config::limits::{C2sLimitProfile, LimitsConfig};
use lonewolf_core::config::{Config, ConfigError};
use toml::Value;

use super::{TestResult, config_file};

const TABLES: &[&str] = &[
    "limits",
    "limits.c2s",
    "limits.c2s.profiles.default",
    "limits.c2s.profiles.default.connection_attempts_per_ip",
    "limits.c2s.profiles.default.incoming_stanzas_per_connection",
    "limits.c2s.profiles.default.incoming_xml_per_connection",
    "limits.c2s.profiles.default.distinct_recipients_per_connection",
];

fn defaults() -> Result<Value, toml::ser::Error> {
    Value::try_from(Config::default().limits)
}

fn scalar_values(value: &Value, path: &str, entries: &mut Vec<(String, i64)>) {
    if let Some(table) = value.as_table() {
        for (key, child) in table {
            let path = if path.is_empty() {
                key.to_owned()
            } else {
                format!("{path}.{key}")
            };
            scalar_values(child, &path, entries);
        }
    } else if let Some(value) = value.as_integer() {
        entries.push((path.into(), value));
    }
}

fn limit_values() -> Result<Vec<(String, i64)>, toml::ser::Error> {
    let mut entries = Vec::new();
    scalar_values(&defaults()?, "", &mut entries);
    Ok(entries)
}

fn setting(path: &str, value: impl std::fmt::Display) -> std::io::Result<tempfile::NamedTempFile> {
    config_file(&format!("limits.{path} = {value}\n"))
}

#[test]
fn limits_defaults_match_the_policy() -> TestResult {
    let expected = [
        ("max_connections_per_ip", 256),
        ("max_stanza_bytes", 262_144),
        ("connection_attempts_per_ip.per_second", 10),
        ("connection_attempts_per_ip.burst", 50),
        ("incoming_stanzas_per_connection.per_second", 20),
        ("incoming_stanzas_per_connection.burst", 100),
        ("incoming_xml_per_connection.bytes_per_second", 262_144),
        ("incoming_xml_per_connection.burst_bytes", 1_048_576),
        ("distinct_recipients_per_connection.max", 100),
        ("distinct_recipients_per_connection.window_secs", 60),
    ];
    let actual = limit_values()?;
    assert_eq!(actual.len(), expected.len() + 2);
    assert!(actual.contains(&("c2s.max_unauthenticated_connections".into(), 1_024)));
    assert!(actual.contains(&("c2s.max_resources_per_account".into(), 10)));
    for (path, value) in expected {
        assert!(
            actual.contains(&(format!("c2s.profiles.default.{path}"), value)),
            "unexpected default for {path}"
        );
    }
    let config = Config::default();
    assert_eq!(config.limits.c2s.default, "default");
    assert_eq!(config.limits.c2s.profiles.len(), 1);
    assert_eq!(config.c2s.listeners[0].limits, None);
    Ok(())
}

#[test]
fn every_limit_can_be_overridden_without_changing_other_defaults() -> TestResult {
    for (path, default) in limit_values()? {
        let replacement = default + 1;
        let config = Config::load(Some(setting(&path, replacement)?.path()))?;
        let mut expected = defaults()?;
        let mut leaf = &mut expected;
        for key in path.split('.') {
            leaf = leaf.get_mut(key).ok_or("missing limit field")?;
        }
        *leaf = Value::Integer(replacement);
        assert_eq!(Value::try_from(config.limits)?, expected, "{path}");
    }
    Ok(())
}

#[test]
fn omitted_tables_and_empty_buckets_preserve_defaults() -> TestResult {
    for path in TABLES {
        for contents in [format!("[{path}]\n"), format!("{path} = {{}}\n")] {
            let file = config_file(&contents)?;
            assert_eq!(
                Config::load(Some(file.path()))?,
                Config::default(),
                "{contents}"
            );
        }
    }
    Ok(())
}

#[test]
fn every_numeric_limit_requires_a_positive_integer() -> TestResult {
    for (path, _) in limit_values()? {
        for value in [
            "0",
            "-1",
            "1.5",
            "'1'",
            "true",
            "[]",
            "{}",
            "18446744073709551616",
        ] {
            let result = Config::load(Some(setting(&path, value)?.path()));
            assert!(
                matches!(result, Err(ConfigError::Parse { .. })),
                "{path} = {value}: {result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn unknown_fields_are_rejected_at_every_limits_table() -> TestResult {
    for path in TABLES {
        let file = config_file(&format!("[{path}]\nunknown = 1\n"))?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Parse { .. })),
            "{path}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn unrelated_limits_and_profile_inheritance_are_not_configurable() -> TestResult {
    for contents in [
        "[limits.xml]",
        "[limits.memory]",
        "[limits.processing]",
        "[limits.c2s.connections]",
        "[limits.c2s.authentication]",
        "[limits.c2s.sessions]",
        "[limits.c2s.timeouts]",
        "[limits.c2s.iq]",
        "[limits.c2s.queues]",
        "[limits.c2s.sources]",
        "[limits.c2s.stream_management]",
        "[limits.c2s.profiles.default.stream_management]",
        "[limits.c2s.profiles.default]\nmax_resources_per_account = 10",
        "[limits.c2s.profiles.default]\nmax_unauthenticated_connections = 10",
        "[limits.c2s.profiles.default]\nextends = 'other'",
        "[[c2s.listeners]]\nlimits = { max_stanza_bytes = 262144 }",
    ] {
        let file = config_file(contents)?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Parse { .. })),
            "{contents}: {result:?}"
        );
    }
    Ok(())
}

#[test]
fn one_named_profile_replaces_the_builtin_and_is_selected_automatically() -> TestResult {
    let file = config_file("[limits.c2s.profiles.public]\nmax_stanza_bytes = 524288")?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(config.limits.c2s.default, "public");
    assert_eq!(config.limits.c2s.profiles.len(), 1);
    assert!(!config.limits.c2s.profiles.contains_key("default"));
    let mut profile = config
        .limits
        .c2s
        .profiles
        .into_values()
        .next()
        .ok_or("missing profile")?;
    assert_eq!(profile.max_stanza_bytes.get(), 524_288);
    profile.max_stanza_bytes = C2sLimitProfile::default().max_stanza_bytes;
    assert_eq!(profile, C2sLimitProfile::default());
    assert_eq!(config.c2s.listeners[0].limits, None);
    Ok(())
}

#[test]
fn listeners_can_select_profiles_or_inherit_the_default() -> TestResult {
    let file = config_file(
        r#"
[limits.c2s]
default = "public"
max_resources_per_account = 12
[limits.c2s.profiles.public]
[limits.c2s.profiles.internal]
max_stanza_bytes = 524288
[[c2s.listeners]]
address = "0.0.0.0:5222"
limits = "public"
[[c2s.listeners]]
address = "127.0.0.1:5223"
limits = "internal"
[[c2s.listeners]]
address = "[::]:5222"
"#,
    )?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(config.limits.c2s.default, "public");
    assert_eq!(config.limits.c2s.max_resources_per_account.get(), 12);
    assert_eq!(config.limits.c2s.profiles.len(), 2);
    assert_eq!(config.c2s.listeners[0].limits.as_deref(), Some("public"));
    assert_eq!(config.c2s.listeners[1].limits.as_deref(), Some("internal"));
    assert_eq!(config.c2s.listeners[2].limits, None);
    Ok(())
}

#[test]
fn multiple_profiles_require_a_default_even_when_listeners_select_profiles() -> TestResult {
    let file = config_file(
        r#"
[limits.c2s.profiles.public]
[limits.c2s.profiles.internal]
[[c2s.listeners]]
limits = "public"
"#,
    )?;
    let error = Config::load(Some(file.path()))
        .err()
        .ok_or("missing default accepted")?;
    assert!(
        error
            .to_string()
            .contains("limits.c2s.default is required when multiple profiles are defined")
    );
    Ok(())
}

#[test]
fn profiles_do_not_inherit_values_from_the_selected_default() -> TestResult {
    let file = config_file(
        r#"
[limits.c2s]
default = "public"
[limits.c2s.profiles.public]
max_connections_per_ip = 1
incoming_stanzas_per_connection = { per_second = 1, burst = 1 }
[limits.c2s.profiles.internal]
"#,
    )?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(
        config.limits.c2s.profiles.get("internal"),
        Some(&C2sLimitProfile::default())
    );
    Ok(())
}

#[test]
fn empty_profile_maps_and_blank_names_are_rejected() -> TestResult {
    for contents in [
        "[limits.c2s]\nprofiles = {}",
        "[limits.c2s]\ndefault = 'default'\nprofiles = {}",
        "[limits.c2s.profiles]",
        "[limits.c2s.profiles.'']",
        "[limits.c2s.profiles.'   ']",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path()))
            .err()
            .ok_or("invalid profiles accepted")?;
        assert!(
            error.to_string().contains("at least one profile")
                || error.to_string().contains("must not be blank"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn unknown_profile_references_are_rejected_including_on_automatic_ports() -> TestResult {
    for (contents, field) in [
        ("[limits.c2s]\ndefault = 'missing'", "limits.c2s.default"),
        ("[limits.c2s]\ndefault = ''", "limits.c2s.default"),
        (
            "[limits.c2s]\ndefault = 'default'\n[limits.c2s.profiles.public]",
            "limits.c2s.default",
        ),
        (
            "[[c2s.listeners]]\nlimits = 'missing'",
            "c2s.listeners[0].limits",
        ),
        ("[[c2s.listeners]]\nlimits = ''", "c2s.listeners[0].limits"),
        (
            "[[c2s.listeners]]\naddress = '127.0.0.1:0'\nlimits = 'missing'",
            "c2s.listeners[0].limits",
        ),
        (
            "[limits.c2s.profiles.public]\n[[c2s.listeners]]\nlimits = 'default'",
            "c2s.listeners[0].limits",
        ),
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path()))
            .err()
            .ok_or("unknown profile accepted")?;
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(error.to_string().contains(field), "{error}");
        assert!(error.to_string().contains("unknown profile"), "{error}");
    }
    Ok(())
}

#[test]
fn profile_selection_and_definitions_reject_wrong_types() -> TestResult {
    for contents in [
        "[limits.c2s]\ndefault = 1",
        "[limits.c2s]\nprofiles = []",
        "[limits.c2s.profiles]\npublic = 1",
        "[[c2s.listeners]]\nlimits = 1",
        "[[c2s.listeners]]\nlimits = []",
    ] {
        let file = config_file(contents)?;
        assert!(
            matches!(
                Config::load(Some(file.path())),
                Err(ConfigError::Parse { .. })
            ),
            "{contents}"
        );
    }
    Ok(())
}

#[test]
fn stanza_size_requires_at_least_ten_thousand_bytes() -> TestResult {
    for size in [1, 9_999] {
        let file = setting("c2s.profiles.default.max_stanza_bytes", size)?;
        let error = Config::load(Some(file.path()))
            .err()
            .ok_or("small stanza size accepted")?;
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(
            error
                .to_string()
                .contains("max_stanza_bytes must be between 10000")
        );
    }
    for size in [10_000, isize::MAX as usize] {
        let file = setting("c2s.profiles.default.max_stanza_bytes", size)?;
        Config::load(Some(file.path()))?;
    }
    let file = setting(
        "c2s.profiles.default.max_stanza_bytes",
        isize::MAX as u64 + 1,
    )?;
    assert!(Config::load(Some(file.path())).is_err());
    Ok(())
}

#[test]
fn unused_profiles_are_validated() -> TestResult {
    let file = config_file(
        r#"
[limits.c2s]
default = "public"
[limits.c2s.profiles.public]
[limits.c2s.profiles.unused]
max_stanza_bytes = 1
"#,
    )?;
    let error = Config::load(Some(file.path()))
        .err()
        .ok_or("invalid unused profile accepted")?;
    assert!(
        error
            .to_string()
            .contains("limits.c2s.profiles.unused.max_stanza_bytes")
    );
    Ok(())
}

#[test]
fn recipient_windows_must_fit_the_platform_clock() -> TestResult {
    let seconds = i64::MAX as u64;
    let file = setting(
        "c2s.profiles.default.distinct_recipients_per_connection.window_secs",
        seconds,
    )?;
    let result = Config::load(Some(file.path()));
    if usize::try_from(seconds).is_err() {
        assert!(matches!(result, Err(ConfigError::Parse { .. })));
    } else if Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .is_none()
    {
        let error = result.err().ok_or("unsupported window accepted")?;
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(
            error
                .to_string()
                .contains("window_secs exceeds the platform clock range")
        );
    } else {
        result?;
    }
    Ok(())
}

#[test]
fn bucket_capacities_can_be_smaller_than_refill_rates() -> TestResult {
    let file = config_file(
        r#"
[limits.c2s.profiles.default]
connection_attempts_per_ip = { burst = 1 }
incoming_stanzas_per_connection = { burst = 1 }
incoming_xml_per_connection = { burst_bytes = 1 }
"#,
    )?;
    Config::load(Some(file.path()))?;
    Ok(())
}

#[test]
fn serialized_limits_round_trip_with_profile_specific_defaults() -> TestResult {
    let decoded: LimitsConfig = defaults()?.try_into()?;
    assert_eq!(decoded, Config::default().limits);
    Ok(())
}
