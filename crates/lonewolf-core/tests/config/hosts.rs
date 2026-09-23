// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use lonewolf_core::config::{Config, ConfigError};

use super::{TestResult, config_file};

#[test]
fn localhost_is_the_only_default_host_without_tls_files() {
    let config = Config::default();

    assert_eq!(config.hosts.len(), 1);
    assert!(config.hosts["localhost"].tls.is_none());
}

#[test]
fn configured_hosts_replace_localhost_and_keep_tls_per_host() -> TestResult {
    let file = config_file(
        r#"
[hosts."example.com"]

[hosts."chat.example.org".tls]
certificate_chain_path = "certs/chat.pem"
private_key_path = "certs/chat.key"
"#,
    )?;
    let config = Config::load(Some(file.path()))?;

    assert_eq!(config.hosts.len(), 2);
    assert!(!config.hosts.contains_key("localhost"));
    assert!(config.hosts["example.com"].tls.is_none());
    let tls = config.hosts["chat.example.org"]
        .tls
        .as_ref()
        .ok_or("missing TLS settings")?;
    assert_eq!(tls.certificate_chain_path, Path::new("certs/chat.pem"));
    assert_eq!(tls.private_key_path, Path::new("certs/chat.key"));
    Ok(())
}

#[test]
fn hosts_must_be_nonempty_normalized_xmpp_domains() -> TestResult {
    for contents in [
        "hosts = {}",
        "[hosts.\"\"]",
        "[hosts.\"user@example.com\"]",
        "[hosts.\"example.com/resource\"]",
        "[hosts.\"EXAMPLE.COM\"]",
        "[hosts.\"bad domain\"]",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err(contents);
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error}");
    }
    Ok(())
}

#[test]
fn tls_paths_must_be_present_and_nonempty() -> TestResult {
    for contents in [
        "[hosts.localhost.tls]",
        "[hosts.localhost.tls]\ncertificate_chain_path = 'cert.pem'",
        "[hosts.localhost.tls]\nprivate_key_path = 'key.pem'",
    ] {
        let file = config_file(contents)?;
        assert!(matches!(
            Config::load(Some(file.path())),
            Err(ConfigError::Parse { .. })
        ));
    }
    for contents in [
        "[hosts.localhost.tls]\ncertificate_chain_path = ''\nprivate_key_path = 'key.pem'",
        "[hosts.localhost.tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = ''",
    ] {
        let file = config_file(contents)?;
        assert!(matches!(
            Config::load(Some(file.path())),
            Err(ConfigError::Invalid { .. })
        ));
    }
    Ok(())
}

#[test]
fn unknown_host_and_tls_keys_are_rejected() -> TestResult {
    for contents in [
        "[hosts.localhost]\nname = 'other'",
        "[hosts.localhost.tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'\nenabled = true",
    ] {
        let file = config_file(contents)?;
        assert!(matches!(
            Config::load(Some(file.path())),
            Err(ConfigError::Parse { .. })
        ));
    }
    Ok(())
}
