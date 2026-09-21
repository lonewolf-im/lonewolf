// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use lonewolf::config::{Config, ConfigError};

type TestResult = Result<(), Box<dyn Error>>;

fn config_file(contents: &str) -> io::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(contents.as_bytes())?;
    Ok(file)
}

#[test]
fn admin_defaults_are_enabled_on_loopback() {
    let config = Config::default();

    assert!(config.admin.enabled);
    assert_eq!(
        config.admin.listen_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))
    );
}

#[test]
fn omitted_settings_use_defaults() -> TestResult {
    for contents in ["", "# defaults\n", "{}", "admin: {}"] {
        let file = config_file(contents)?;
        assert_eq!(Config::load(Some(file.path()))?, Config::default());
    }
    Ok(())
}

#[test]
fn partial_admin_settings_preserve_other_defaults() -> TestResult {
    let file = config_file("admin:\n  enabled: false\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(!config.admin.enabled);
    assert_eq!(
        config.admin.listen_addr,
        Config::default().admin.listen_addr
    );

    let file = config_file("admin:\n  listen_addr: '[::1]:9090'\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(config.admin.enabled);
    assert_eq!(config.admin.listen_addr, "[::1]:9090".parse()?);
    Ok(())
}

#[test]
fn explicit_admin_settings_override_defaults() -> TestResult {
    let file = config_file("admin:\n  enabled: false\n  listen_addr: '127.0.0.2:9090'\n")?;
    let config = Config::load(Some(file.path()))?;

    assert!(!config.admin.enabled);
    assert_eq!(config.admin.listen_addr, "127.0.0.2:9090".parse()?);
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected() -> TestResult {
    for contents in [
        "admni: {}",
        "admin:\n  enable: false",
        "admin:\n  enabled: []",
        "admin:\n  enabled: maybe",
        "admin:\n  listen_addr: 'localhost:8080'",
        "admin:\n  listen_addr: '127.0.0.1'",
        "admin:\n  listen_addr: '127.0.0.1:65536'",
        "admin:\n  listen_addr: '999.0.0.1:8080'",
        "admin:\n  enabled: true\n  enabled: false",
        "admin: {}\nadmin: {}",
        "admin: [",
        "[admin]",
        "{}\n---\nadmin:\n  enabled: false",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err(contents);
        assert!(matches!(error, ConfigError::Parse { .. }), "{error}");
        assert!(error.source().is_some());
        assert!(
            error
                .to_string()
                .contains(&file.path().display().to_string())
        );
    }
    Ok(())
}

#[test]
fn explicit_missing_files_are_errors() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing.yaml");
    let error = Config::load(Some(&path)).expect_err("explicit path must exist");

    assert!(error.source().is_some());
    assert!(matches!(
        error,
        ConfigError::Read { path: error_path, source }
            if error_path == path && source.kind() == io::ErrorKind::NotFound
    ));
    Ok(())
}

#[test]
fn unreadable_configuration_is_an_error() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert!(matches!(
        Config::load(Some(directory.path())),
        Err(ConfigError::Read { .. })
    ));

    let file = config_file("")?;
    fs::write(file.path(), [0xff])?;
    assert!(matches!(
        Config::load(Some(file.path())),
        Err(ConfigError::Read { source, .. }) if source.kind() == io::ErrorKind::InvalidData
    ));
    Ok(())
}

#[test]
fn example_configuration_matches_defaults() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../lonewolf.example.yaml");
    assert_eq!(Config::load(Some(&path))?, Config::default());
    Ok(())
}
