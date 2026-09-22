// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use lonewolf_core::config::{AccountConfig, Config, ConfigError, StoreConfig, TcpListenerConfig};

type TestResult = Result<(), Box<dyn Error>>;

fn config_file(contents: &str) -> io::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(contents.as_bytes())?;
    Ok(file)
}

#[test]
fn admin_defaults_are_enabled_on_a_unix_socket() {
    let config = Config::default();

    assert!(config.admin.enabled);
    assert_eq!(
        config.admin.socket_path,
        Path::new("./run/lonewolf/admin.sock")
    );
}

#[test]
fn xmpp_defaults_reserve_256_mib_for_stanza_arenas() {
    assert_eq!(Config::default().xmpp.stanza_pool_size_mib, 256);
}

#[test]
fn c2s_defaults_to_one_ipv4_endpoint_on_port_5222() -> TestResult {
    let config = Config::default();
    assert_eq!(config.c2s.listeners.len(), 1);
    assert_eq!(config.c2s.listeners[0].address, "0.0.0.0:5222".parse()?);
    Ok(())
}

#[test]
fn configured_c2s_endpoints_replace_the_default_and_allow_ipv6() -> TestResult {
    let file = config_file(
        "[[c2s.listeners]]\naddress = '127.0.0.1:6222'\n[[c2s.listeners]]\naddress = '[::1]:6222'\n",
    )?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(
        config.c2s.listeners,
        vec![
            TcpListenerConfig {
                address: "127.0.0.1:6222".parse()?
            },
            TcpListenerConfig {
                address: "[::1]:6222".parse()?
            },
        ]
    );
    let file = config_file("[c2s]\nlisteners = []\n")?;
    assert!(Config::load(Some(file.path()))?.c2s.listeners.is_empty());
    Ok(())
}

#[test]
fn overlapping_c2s_endpoints_are_rejected() -> TestResult {
    for (first, second) in [
        ("127.0.0.1:5222", "127.0.0.1:5222"),
        ("0.0.0.0:5222", "127.0.0.1:5222"),
        ("127.0.0.1:5222", "0.0.0.0:5222"),
        ("[::]:5222", "[::1]:5222"),
        ("[::1]:5222", "[::]:5222"),
        ("[::1]:5222", "[::1]:5222"),
    ] {
        let file = config_file(&format!(
            "[[c2s.listeners]]\naddress = '{first}'\n[[c2s.listeners]]\naddress = '{second}'\n"
        ))?;
        let error = Config::load(Some(file.path()))
            .err()
            .ok_or("overlapping endpoints accepted")?;
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(
            error
                .to_string()
                .contains("c2s.listeners[1] overlaps c2s.listeners[0]")
        );
    }
    Ok(())
}

#[test]
fn distinct_c2s_endpoints_and_automatic_ports_are_valid() -> TestResult {
    for (first, second) in [
        ("127.0.0.1:5222", "127.0.0.1:6222"),
        ("0.0.0.0:5222", "[::]:5222"),
        ("127.0.0.1:5222", "127.0.0.2:5222"),
        ("127.0.0.1:0", "127.0.0.1:0"),
    ] {
        let file = config_file(&format!(
            "[[c2s.listeners]]\naddress = '{first}'\n[[c2s.listeners]]\naddress = '{second}'\n"
        ))?;
        assert_eq!(Config::load(Some(file.path()))?.c2s.listeners.len(), 2);
    }
    Ok(())
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
        "xmpp = {}",
        "[xmpp]",
        "c2s = {}",
        "[c2s]",
        "[[c2s.listeners]]",
    ] {
        let file = config_file(contents)?;
        assert_eq!(Config::load(Some(file.path()))?, Config::default());
    }
    Ok(())
}

#[test]
fn valid_stanza_pool_sizes_override_the_default() -> TestResult {
    for size_mib in [8, 16, 128, 1024] {
        let file = config_file(&format!("[xmpp]\nstanza_pool_size_mib = {size_mib}\n"))?;
        assert_eq!(
            Config::load(Some(file.path()))?.xmpp.stanza_pool_size_mib,
            size_mib
        );
    }
    Ok(())
}

#[test]
fn stanza_pool_size_requires_a_power_of_two_of_at_least_8_mib() -> TestResult {
    for size_mib in [0, 1, 7, 9, 12, 255, 257] {
        let file = config_file(&format!("[xmpp]\nstanza_pool_size_mib = {size_mib}\n"))?;
        let error = Config::load(Some(file.path())).expect_err("invalid stanza pool size");
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(
            error
                .to_string()
                .contains("must be a power of two of at least 8 MiB")
        );
    }
    Ok(())
}

#[test]
fn stanza_pool_size_must_fit_the_platform_address_space() -> TestResult {
    let size_mib = 1_usize << (usize::BITS - 2);
    let file = config_file(&format!("[xmpp]\nstanza_pool_size_mib = {size_mib}\n"))?;
    let error = Config::load(Some(file.path())).expect_err("stanza pool size must fit");

    assert!(matches!(error, ConfigError::Invalid { .. }));
    assert!(error.to_string().contains("is too large for this platform"));
    Ok(())
}

#[test]
fn partial_admin_settings_preserve_other_defaults() -> TestResult {
    let file = config_file("[admin]\nenabled = false\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(!config.admin.enabled);
    assert_eq!(
        config.admin.socket_path,
        Config::default().admin.socket_path
    );

    let file = config_file("[admin]\nsocket_path = 'private/admin.sock'\n")?;
    let config = Config::load(Some(file.path()))?;
    assert!(config.admin.enabled);
    assert_eq!(config.admin.socket_path, Path::new("private/admin.sock"));
    Ok(())
}

#[test]
fn explicit_admin_settings_override_defaults() -> TestResult {
    let file = config_file("[admin]\nenabled = false\nsocket_path = 'private/custom.sock'\n")?;
    let config = Config::load(Some(file.path()))?;

    assert!(!config.admin.enabled);
    assert_eq!(config.admin.socket_path, Path::new("private/custom.sock"));
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
        "[admin]\nsocket_path = ''",
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
        "[admin]\nsocket_path = 42",
        "[admin]\nlisten_addr = '127.0.0.1:8080'",
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
        "[xmpp]\nstanza_pool_size_mb = 256",
        "[xmpp]\nstanza_pool_size_mib = '256'",
        "[xmpp]\nstanza_pool_size_mib = -1",
        "[xmpp]\nstanza_pool_size_mib = 1.5",
        "[c2s]\nlistener = []",
        "[c2s]\nlisteners = {}",
        "[[c2s.listeners]]\nadress = '127.0.0.1:5222'",
        "[[c2s.listeners]]\naddress = 'localhost:5222'",
        "[[c2s.listeners]]\naddress = '127.0.0.1'",
        "[[c2s.listeners]]\naddress = '127.0.0.1:65536'",
        "[[c2s.listeners]]\naddress = '::1:5222'",
        "[[c2s.listeners]]\naddress = 5222",
        "[[c2s.listeners]]\ntransport = 'udp'",
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
