// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use lonewolf_core::config::{AccountConfig, Config, ConfigError, StoreConfig};

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
    for contents in [
        "",
        "# defaults\n",
        "account = {}",
        "[account]",
        "admin = {}",
        "[admin]",
        "logging = {}",
        "[logging]",
        "storage = {}",
        "[storage]",
    ] {
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
fn named_stores_replace_builtins_and_select_the_default() -> TestResult {
    let file = config_file(
        r#"
[storage]
default = "accounts"

[storage.stores.accounts]
backend = "redb"
path = "db/accounts.redb"

[storage.stores.archive]
backend = "redb"
path = "db/archive.redb"
"#,
    )?;
    let config = Config::load(Some(file.path()))?;

    assert_eq!(config.storage.default, "accounts");
    assert_eq!(config.account.storage, None);
    assert_eq!(config.storage.stores.len(), 2);
    assert!(!config.storage.stores.contains_key("primary"));
    assert!(matches!(
        config.storage.stores.get("accounts"),
        Some(StoreConfig::Redb { path }) if path == Path::new("db/accounts.redb")
    ));
    assert!(matches!(
        config.storage.stores.get("archive"),
        Some(StoreConfig::Redb { path }) if path == Path::new("db/archive.redb")
    ));
    Ok(())
}

#[test]
fn single_store_is_selected_when_default_is_omitted() -> TestResult {
    for name in ["primary", "accounts"] {
        let file = config_file(&format!(
            "[storage.stores.{name}]\nbackend = 'redb'\npath = 'db/accounts.redb'"
        ))?;
        let config = Config::load(Some(file.path()))?;

        assert_eq!(config.storage.default, name);
        assert_eq!(config.account.storage, None);
        assert_eq!(config.storage.stores.len(), 1);
        assert!(matches!(
            config.storage.stores.get(name),
            Some(StoreConfig::Redb { path }) if path == Path::new("db/accounts.redb")
        ));
    }
    Ok(())
}

#[test]
fn multiple_stores_require_an_explicit_default() -> TestResult {
    for name in ["primary", "accounts"] {
        let file = config_file(&format!(
            r#"
[account]
storage = "{name}"

[storage.stores.{name}]
backend = "redb"
path = "db/accounts.redb"

[storage.stores.archive]
backend = "redb"
path = "db/archive.redb"
"#
        ))?;
        let error = Config::load(Some(file.path())).expect_err("default must be explicit");
        assert!(
            error
                .to_string()
                .contains("storage.default is required when multiple stores are defined")
        );
        assert!(
            error
                .to_string()
                .contains(&file.path().display().to_string())
        );
    }
    Ok(())
}

#[test]
fn empty_store_lists_are_rejected() -> TestResult {
    for contents in [
        "[storage]\nstores = {}",
        "[storage]\ndefault = 'primary'\nstores = {}",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err("at least one store is required");
        assert!(
            error
                .to_string()
                .contains("storage.stores must define at least one store")
        );
    }
    Ok(())
}

#[test]
fn account_storage_can_select_a_nondefault_store() -> TestResult {
    let file = config_file(
        r#"
[account]
storage = "accounts"

[storage]
default = "primary"

[storage.stores.primary]
backend = "redb"
path = "db/primary.redb"

[storage.stores.accounts]
backend = "redb"
path = "db/accounts.redb"
"#,
    )?;
    let config = Config::load(Some(file.path()))?;

    assert_eq!(config.account.storage.as_deref(), Some("accounts"));
    assert_eq!(config.storage.default, "primary");
    Ok(())
}

#[test]
fn invalid_storage_references_and_empty_values_are_rejected() -> TestResult {
    for contents in [
        "[account]\nstorage = 'missing'",
        "[account]\nstorage = ''",
        "[storage]\ndefault = 'missing'",
        "[storage]\ndefault = ''",
        "[storage]\ndefault = 'primary'\n[storage.stores.archive]\nbackend = 'redb'\npath = 'archive.redb'",
        "[storage]\ndefault = ''\n[storage.stores.'']\nbackend = 'redb'\npath = 'db.redb'",
        "[storage.stores.primary]\nbackend = 'redb'\npath = ''",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err(contents);
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error}");
        assert!(
            error
                .to_string()
                .contains(&file.path().display().to_string())
        );
    }
    Ok(())
}

#[test]
fn invalid_configuration_is_rejected() -> TestResult {
    for contents in [
        "[admni]",
        "[account]\nstroage = 'primary'",
        "[account]\nstorage = 1",
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
        "[logging]\nlevle = 'debug'",
        "[logging]\nlevel = 'verbose'",
        "[logging]\nlevel = 'INFO'",
        "[logging]\nlevel = 3",
        "[logging]\nlevel = false",
        "[storage]\ndefualt = 'primary'",
        "[storage]\ndefault = 1",
        "[storage.stores.primary]\nbackend = 'postgresql'\npath = 'db.redb'",
        "[storage.stores.primary]\nbackend = 'redb'",
        "[storage.stores.primary]\npath = 'db.redb'",
        "[storage.stores.primary]\nbackend = 'redb'\npath = 'db.redb'\nunknown = true",
        "[storage.stores.primary]\nbackend = 'redb'\npath = 1",
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
fn reference_configuration_documents_defaults_and_valid_examples() -> TestResult {
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
    assert_eq!(
        Config::load(Some(file.path()))?,
        Config {
            account: AccountConfig {
                storage: Some("primary".into()),
            },
            ..Config::default()
        }
    );
    Ok(())
}
