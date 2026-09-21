// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use lonewolf_core::config::{Config, ConfigError};

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
    for contents in ["", "# defaults\n", "admin = {}", "[admin]"] {
        let file = config_file(contents)?;
        assert_eq!(Config::load(Some(file.path()))?, Config::default());
    }
    Ok(())
}

#[test]
fn partial_admin_settings_preserve_other_defaults() -> TestResult {
    let file = config_file("[admin]\nenabled = false\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(!config.admin.enabled);
    assert_eq!(
        config.admin.listen_addr,
        Config::default().admin.listen_addr
    );

    let file = config_file("[admin]\nlisten_addr = '[::1]:9090'\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(config.admin.enabled);
    assert_eq!(config.admin.listen_addr, "[::1]:9090".parse()?);
    Ok(())
}

#[test]
fn explicit_admin_settings_override_defaults() -> TestResult {
    let file = config_file("[admin]\nenabled = false\nlisten_addr = '127.0.0.2:9090'\n")?;
    let config = Config::load(Some(file.path()))?;

    assert!(!config.admin.enabled);
    assert_eq!(config.admin.listen_addr, "127.0.0.2:9090".parse()?);
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected() -> TestResult {
    for contents in [
        "[admni]",
        "[admin]\nenable = false",
        "[admin]\nenabled = []",
        "[admin]\nenabled = maybe",
        "[admin]\nenabled = 'false'",
        "[admin]\nlisten_addr = 'localhost:8080'",
        "[admin]\nlisten_addr = '127.0.0.1'",
        "[admin]\nlisten_addr = '127.0.0.1:65536'",
        "[admin]\nlisten_addr = '999.0.0.1:8080'",
        "[admin]\nenabled = true\nenabled = false",
        "[admin]\n[admin]",
        "admin = [",
        "[[admin]]",
        "admin:\n  enabled: false",
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
    let path = directory.path().join("missing.toml");
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
fn reference_configuration_matches_defaults() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/lonewolf.toml");
    let reference = fs::read_to_string(&path)?;
    assert!(
        reference
            .lines()
            .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
    );
    assert_eq!(Config::load(Some(&path))?, Config::default());

    let mut uncommented = String::with_capacity(reference.len());
    for line in reference.lines() {
        if let Some(setting) = line.strip_prefix("# ")
            && (setting.starts_with('[') || setting.contains(" = "))
        {
            uncommented.push_str(setting);
            uncommented.push('\n');
        }
    }
    assert!(!uncommented.is_empty());
    let file = config_file(&uncommented)?;
    assert_eq!(Config::load(Some(file.path()))?, Config::default());
    Ok(())
}
