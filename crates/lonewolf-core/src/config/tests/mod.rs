// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::limits::C2sLimitProfile;
use crate::config::{
    AccountConfig, ClientCertificateConfig, Config, ConfigError, HostConfig, HostTlsConfig,
    HostTlsSource, MetricsConfig, StoreConfig, TcpListenerConfig, XmppConfig,
};
use lonewolf_auth::server::Mechanism;
use lonewolf_extension::{Extensions, HostSelection};
use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::GlobalChunkAllocator;

mod hosts;
mod limits;

type TestResult = Result<(), Box<dyn Error>>;

fn config_file(contents: &str) -> io::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(contents.as_bytes())?;
    Ok(file)
}

#[test]
fn host_extensions_default_to_roster_offline_disco_ping_and_vcard() -> TestResult {
    assert_eq!(
        HostConfig::default().extensions,
        ["roster", "offline", "disco", "ping", "vcard"]
    );
    assert_eq!(
        Config::default().hosts["localhost"].extensions,
        ["roster", "offline", "disco", "ping", "vcard"]
    );
    for contents in ["", "[hosts.localhost]"] {
        let file = config_file(contents)?;
        assert_eq!(
            Config::load(Some(file.path()))?.hosts["localhost"].extensions,
            ["roster", "offline", "disco", "ping", "vcard"]
        );
    }
    Ok(())
}

#[test]
fn configured_host_extensions_replace_the_default_list() -> TestResult {
    let mut catalog = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    for factory in lonewolf_extension::builtin() {
        catalog.register_factory(factory)?;
    }
    for (setting, expected) in [
        ("[]", [].as_slice()),
        ("['roster']", ["roster"].as_slice()),
        ("['offline']", ["offline"].as_slice()),
        ("['ping']", ["ping"].as_slice()),
        ("['disco']", ["disco"].as_slice()),
        ("['ping', 'disco']", ["ping", "disco"].as_slice()),
        ("['disco', 'ping']", ["disco", "ping"].as_slice()),
        ("['disco', 'vcard']", ["disco", "vcard"].as_slice()),
        ("['vcard', 'disco']", ["vcard", "disco"].as_slice()),
        (
            "['roster', 'offline', 'disco']",
            ["roster", "offline", "disco"].as_slice(),
        ),
        ("['offline', 'roster']", ["offline", "roster"].as_slice()),
    ] {
        let file = config_file(&format!("[hosts.localhost]\nextensions = {setting}"))?;
        let config = Config::load(Some(file.path()))?;
        let host = &config.hosts["localhost"];
        assert_eq!(host.extensions, expected);
        let prepared = catalog.enable(&[HostSelection {
            domain: "localhost",
            extensions: &host.extensions,
            options: &host.options,
        }]);
        let prepared = prepared?;
        let registry = &prepared["localhost"];
        assert_eq!(registry.enabled(), expected);
        for scope in [
            lonewolf_extension::discovery::DiscoScope::Server,
            lonewolf_extension::discovery::DiscoScope::Account,
        ] {
            for (extension, feature) in [("ping", "urn:xmpp:ping"), ("vcard", "vcard-temp")] {
                assert_eq!(
                    registry.discovery().features(scope).contains(&feature),
                    expected.contains(&extension),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn no_configuration_file_enables_default_extensions() -> TestResult {
    const CHILD: &str = "LONEWOLF_CONFIG_DEFAULTS_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(!Path::new(super::DEFAULT_CONFIG_PATH).exists());
        let config = Config::load(None)?;
        assert_eq!(config, Config::default());
        assert_eq!(
            config.hosts["localhost"].extensions,
            ["roster", "offline", "disco", "ping", "vcard"]
        );
    } else {
        let directory = tempfile::tempdir()?;
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "config::tests::no_configuration_file_enables_default_extensions",
            ])
            .env(CHILD, "1")
            .current_dir(directory.path())
            .output()?;
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)?.contains("1 passed;"));
    }
    Ok(())
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
fn metrics_defaults_are_disabled_on_loopback() -> TestResult {
    assert_eq!(
        Config::default().metrics,
        MetricsConfig {
            enabled: false,
            address: "127.0.0.1:9520".parse()?,
        }
    );
    Ok(())
}

#[test]
fn explicit_metrics_settings_override_defaults() -> TestResult {
    let file = config_file("[metrics]\nenabled = true\naddress = '[::1]:9100'\n")?;
    assert_eq!(
        Config::load(Some(file.path()))?.metrics,
        MetricsConfig {
            enabled: true,
            address: "[::1]:9100".parse()?,
        }
    );
    Ok(())
}

#[test]
fn partial_metrics_settings_preserve_other_defaults() -> TestResult {
    let file = config_file("[metrics]\nenabled = true\n")?;
    assert_eq!(
        Config::load(Some(file.path()))?.metrics,
        MetricsConfig {
            enabled: true,
            ..MetricsConfig::default()
        }
    );
    Ok(())
}

#[test]
fn unknown_metrics_keys_are_rejected() -> TestResult {
    let file = config_file("[metrics]\npath = '/metrics'\n")?;
    assert!(matches!(
        Config::load(Some(file.path())),
        Err(ConfigError::Parse { .. })
    ));
    Ok(())
}

#[test]
fn enabled_metrics_address_must_not_overlap_client_endpoints() -> TestResult {
    let file = config_file(
        "[[c2s.listeners]]\naddress = '0.0.0.0:5222'\n[metrics]\nenabled = true\naddress = '127.0.0.1:5222'\n",
    )?;
    assert!(matches!(
        Config::load(Some(file.path())),
        Err(ConfigError::Invalid { reason, .. })
            if reason.contains("metrics.address overlaps c2s.listeners[0]")
    ));

    for contents in [
        "[[c2s.listeners]]\naddress = '0.0.0.0:5222'\n[metrics]\nenabled = false\naddress = '127.0.0.1:5222'\n",
        "[[c2s.listeners]]\naddress = '127.0.0.1:0'\n[metrics]\nenabled = true\naddress = '127.0.0.1:0'\n",
    ] {
        let file = config_file(contents)?;
        Config::load(Some(file.path()))?;
    }
    Ok(())
}

#[test]
fn xmpp_defaults_reserve_256_mib_for_stanza_arenas() {
    assert_eq!(Config::default().xmpp.stanza_pool_size_mib, 256);
}

#[test]
fn c2s_defaults_to_one_ipv4_endpoint_on_port_5222() -> TestResult {
    let config = Config::default();
    assert_eq!(config.c2s.listeners.len(), 1);
    assert!(config.c2s.listeners[0].auth_mechanisms.allows_external());
    assert_eq!(config.c2s.listeners[0].address, "0.0.0.0:5222".parse()?);
    for mechanism in [
        Mechanism::Sha1,
        Mechanism::Sha1Plus,
        Mechanism::Sha256,
        Mechanism::Sha256Plus,
    ] {
        assert!(config.c2s.listeners[0].auth_mechanisms.allows(mechanism));
    }
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
                address: "127.0.0.1:6222".parse()?,
                ..TcpListenerConfig::default()
            },
            TcpListenerConfig {
                address: "[::1]:6222".parse()?,
                ..TcpListenerConfig::default()
            },
        ]
    );
    Ok(())
}

#[test]
fn empty_c2s_listener_list_is_rejected() -> TestResult {
    let file = config_file("[c2s]\nlisteners = []\n")?;
    let error = Config::load(Some(file.path()))
        .err()
        .ok_or("empty listener list accepted")?;

    assert!(matches!(error, ConfigError::Invalid { .. }));
    assert!(
        error
            .to_string()
            .contains("c2s.listeners must define at least one listener")
    );
    Ok(())
}

#[test]
fn auth_mechanisms_are_configured_per_listener() -> TestResult {
    let file = config_file(
        "[[c2s.listeners]]\naddress = '127.0.0.1:5222'\nauth_mechanisms = ['SCRAM-SHA-256']\n[[c2s.listeners]]\naddress = '127.0.0.1:5223'\nauth_mechanisms = ['SCRAM-SHA-1-PLUS']\n",
    )?;
    let config = Config::load(Some(file.path()))?;
    let first = config.c2s.listeners[0].auth_mechanisms;
    let second = config.c2s.listeners[1].auth_mechanisms;
    assert!(!first.allows_external());
    assert!(!second.allows_external());

    assert!(first.allows(Mechanism::Sha256));
    assert!(!first.allows(Mechanism::Sha1Plus));
    assert!(!first.has_plus());
    assert!(second.allows(Mechanism::Sha1Plus));
    assert!(!second.allows(Mechanism::Sha256));
    assert!(second.has_plus());
    Ok(())
}

#[test]
fn empty_auth_mechanisms_are_rejected() -> TestResult {
    let file = config_file("[[c2s.listeners]]\nauth_mechanisms = []\n")?;
    let error = Config::load(Some(file.path())).expect_err("empty mechanism list accepted");

    assert!(matches!(error, ConfigError::Invalid { .. }));
    assert!(
        error
            .to_string()
            .contains("auth_mechanisms must define at least one mechanism")
    );
    Ok(())
}

#[test]
fn unsupported_or_duplicate_auth_mechanisms_are_rejected() -> TestResult {
    for (names, reason) in [
        ("['PLAIN']", "unsupported auth mechanism"),
        ("['EXTERNAL', 'EXTERNAL']", "duplicate auth mechanism"),
        (
            "['SCRAM-SHA-256', 'SCRAM-SHA-256']",
            "duplicate auth mechanism",
        ),
    ] {
        let file = config_file(&format!("[[c2s.listeners]]\nauth_mechanisms = {names}\n"))?;
        let error = Config::load(Some(file.path())).expect_err("invalid mechanism list accepted");
        assert!(matches!(error, ConfigError::Parse { .. }));
        assert!(error.to_string().contains(reason));
    }
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
        "[hosts.localhost]",
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
    for constraint in [
        "vcard requires disco in the same host's extension list",
        "public to authenticated local C2S users",
        "serialized UTF-8 XML",
        "namespace, language, and whitespace-context markup",
        "1 to 1048576 bytes",
        "complete-stanza limit can be smaller",
        "Reducing this budget does not delete or hide stored profiles",
        "new documents must fit",
    ] {
        assert!(
            reference.contains(constraint),
            "missing operator constraint: {constraint}"
        );
    }

    let mut uncommented = String::with_capacity(reference.len());
    let mut example = None;
    let mut examples = Vec::new();
    for line in reference.lines() {
        if line == "# ```toml" {
            assert!(example.is_none());
            example = Some(String::new());
            continue;
        }
        if line == "# ```" {
            examples.push(example.take().ok_or("missing example start")?);
            continue;
        }
        if let Some(setting) = line.strip_prefix("# ")
            && (setting.starts_with('[') || setting.contains(" = "))
        {
            let contents = example.as_mut().unwrap_or(&mut uncommented);
            contents.push_str(setting);
            contents.push('\n');
        }
    }
    assert!(example.is_none());
    assert_eq!(examples.len(), 5);
    for example in examples {
        let contents = if example.starts_with("[letsencrypt]") {
            format!("[hosts.'example.com'.tls]\nprovider = 'letsencrypt'\n{example}")
        } else {
            example
        };
        let file = config_file(&contents)?;
        Config::load(Some(file.path()))?;
    }
    assert!(!uncommented.is_empty());
    let mut documented: toml::Value = toml::from_str(&uncommented)?;
    let example_profile = documented
        .get_mut("limits")
        .and_then(|value| value.get_mut("c2s"))
        .and_then(|value| value.get_mut("profiles"))
        .and_then(toml::Value::as_table_mut)
        .and_then(|profiles| profiles.remove("internal"))
        .ok_or("missing example profile")?;
    assert_eq!(
        example_profile,
        toml::from_str::<toml::Value>("max_stanza_bytes = 524_288")?
    );
    assert_eq!(
        documented.get("limits"),
        Some(&toml::Value::try_from(Config::default().limits)?)
    );
    let file = config_file(&uncommented)?;
    let mut expected = Config {
        account: AccountConfig {
            storage: Some("primary".into()),
        },
        ..Config::default()
    };
    expected.hosts.insert(
        "example.com".into(),
        HostConfig {
            extensions: vec![
                "roster".into(),
                "offline".into(),
                "disco".into(),
                "ping".into(),
                "vcard".into(),
            ],
            options: BTreeMap::from([
                (
                    "vcard".into(),
                    toml::Table::from_iter([("max_bytes".into(), toml::Value::Integer(262144))]),
                ),
                (
                    "roster".into(),
                    toml::Table::from_iter([
                        ("max_items".into(), toml::Value::Integer(1000)),
                        ("max_bytes".into(), toml::Value::Integer(2097152)),
                        (
                            "max_pending_subscription_requests".into(),
                            toml::Value::Integer(100),
                        ),
                    ]),
                ),
                (
                    "offline".into(),
                    toml::Table::from_iter([(
                        "max_messages_per_account".into(),
                        toml::Value::Integer(100),
                    )]),
                ),
            ]),
            tls: Some(HostTlsConfig {
                source: HostTlsSource::Files {
                    certificate_chain_path: PathBuf::from("./certs/example.com.crt"),
                    private_key_path: PathBuf::from("./certs/example.com.key"),
                },
                client_auth: Some(ClientCertificateConfig {
                    trust_anchors_path: PathBuf::from("./certs/client-roots.pem"),
                    crls_path: PathBuf::from("./certs/client-crls.pem"),
                }),
            }),
        },
    );
    expected.xmpp.default_host = Some("localhost".into());
    expected.c2s.listeners[0].limits = Some("default".into());
    expected.c2s.listeners.push(TcpListenerConfig {
        address: "127.0.0.1:5223".parse()?,
        limits: Some("internal".into()),
        ..TcpListenerConfig::default()
    });
    expected.limits.c2s.profiles.insert(
        "internal".into(),
        C2sLimitProfile {
            max_stanza_bytes: NonZeroUsize::new(524_288).ok_or("invalid example stanza size")?,
            ..C2sLimitProfile::default()
        },
    );
    let loaded = Config::load(Some(file.path()))?;
    assert_eq!(loaded, expected);
    let mut extensions = Extensions::<GlobalChunkAllocator, RedbStorage>::default();
    for factory in lonewolf_extension::builtin() {
        extensions.register_factory(factory)?;
    }
    let selections = loaded
        .hosts
        .iter()
        .map(|(domain, host)| HostSelection {
            domain,
            extensions: &host.extensions,
            options: &host.options,
        })
        .collect::<Vec<_>>();
    extensions.enable(&selections)?;
    Ok(())
}

#[test]
fn stanza_pool_shard_count_matches_worker_count() -> Result<(), Box<dyn Error>> {
    let worker_count = NonZeroUsize::new(3).ok_or("worker count must be nonzero")?;

    let config = XmppConfig::default().stanza_pool_config(worker_count)?;

    assert_eq!(config.shards_per_bucket, worker_count);
    Ok(())
}

#[test]
fn external_only_listener_requires_client_auth_for_every_host() -> TestResult {
    let file = config_file("[[c2s.listeners]]\nauth_mechanisms = ['EXTERNAL']\n")?;
    assert!(
        matches!(Config::load(Some(file.path())), Err(ConfigError::Invalid { reason, .. })
        if reason == "c2s.listeners[0].auth_mechanisms offers only EXTERNAL, but host \"localhost\" does not configure tls.client_auth")
    );

    for missing in ["localhost", "example.com"] {
        let mut contents = String::from(
            "[xmpp]\ndefault_host = 'localhost'\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nauth_mechanisms = ['SCRAM-SHA-256']\n[[c2s.listeners]]\naddress = '127.0.0.1:0'\nauth_mechanisms = ['EXTERNAL']\n",
        );
        for host in ["localhost", "example.com"] {
            contents.push_str(&format!("[hosts.'{host}'.tls]\ncertificate_chain_path = 'server.pem'\nprivate_key_path = 'server.key'\n"));
            if host != missing {
                contents.push_str(&format!("[hosts.'{host}'.tls.client_auth]\ntrust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'\n"));
            }
        }
        let file = config_file(&contents)?;
        assert!(
            matches!(Config::load(Some(file.path())), Err(ConfigError::Invalid { reason, .. })
            if reason == format!("c2s.listeners[1].auth_mechanisms offers only EXTERNAL, but host {missing:?} does not configure tls.client_auth"))
        );
    }
    Ok(())
}

#[test]
fn external_only_listener_accepts_client_auth_for_every_host_and_preserves_scram_bits() -> TestResult
{
    let mut contents = String::from(
        "[xmpp]\ndefault_host = 'localhost'\n[[c2s.listeners]]\nauth_mechanisms = ['EXTERNAL']\n",
    );
    for host in ["localhost", "example.com"] {
        contents.push_str(&format!("[hosts.'{host}'.tls]\ncertificate_chain_path = 'server.pem'\nprivate_key_path = 'server.key'\n[hosts.'{host}'.tls.client_auth]\ntrust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'\n"));
    }
    let file = config_file(&contents)?;
    let config = Config::load(Some(file.path()))?;
    let mechanisms = config.c2s.listeners[0].auth_mechanisms;
    assert!(mechanisms.allows_external());
    assert!(!mechanisms.is_empty());
    assert!(!mechanisms.has_plus());
    for mechanism in [
        Mechanism::Sha1,
        Mechanism::Sha1Plus,
        Mechanism::Sha256,
        Mechanism::Sha256Plus,
    ] {
        assert!(!mechanisms.allows(mechanism));
    }
    Ok(())
}

#[test]
fn letsencrypt_defaults_and_partial_settings_preserve_exact_directory_identity() -> TestResult {
    let defaults = Config::default().letsencrypt;
    assert_eq!(
        defaults.listen,
        vec!["0.0.0.0:80".parse::<std::net::SocketAddr>()?]
    );
    assert_eq!(defaults.state_path, Path::new("./data/lonewolf/acme.redb"));
    assert_eq!(
        defaults.directory_url,
        "https://acme-v02.api.letsencrypt.org/directory"
    );
    assert_eq!(defaults.ca_certificates_path, None);
    for url in [
        "https://acme-v02.api.letsencrypt.org/directory",
        "https://acme-staging-v02.api.letsencrypt.org/directory",
        "https://ca.example:8443/acme/directory?profile=test&mode=1",
        "https://localhost:443/directory",
        "https://ca.example:65535/directory",
        "https://127.0.0.1:9443/directory",
        "https://[::1]:9443/directory",
        "https://[::1]/directory",
        "https://ca.example",
        "https://ca.example/",
        "https://ca.example?profile=test",
        "https://CA.example:0443/Directory?profile=%23test",
    ] {
        let file = config_file(&format!("[letsencrypt]\ndirectory_url = '{url}'"))?;
        let config = Config::load(Some(file.path()))?;
        assert_eq!(
            config.letsencrypt,
            crate::config::LetsEncryptConfig {
                directory_url: url.into(),
                ..defaults.clone()
            }
        );
    }
    Ok(())
}

#[test]
fn invalid_directory_urls_are_rejected_even_without_managed_hosts() -> TestResult {
    for url in [
        "",
        "http://ca.example/directory",
        "/directory",
        "ca.example/directory",
        "https:///directory",
        "https://:443/directory",
        "https://user@ca.example/directory",
        "https://user:password@ca.example/directory",
        "https://@ca.example/directory",
        "https://@/directory",
        "https://user@/directory",
        "https://ca.example/directory#fragment",
        "https://ca.example/directory#",
        "https://ca.example/#/directory",
        "https://ca.example:0/directory",
        "https://ca.example:65536/directory",
        "https://ca.example:abc/directory",
        "https://ca.example:/directory",
        "https://ca.example:-1/directory",
        "https://ca.example:+443/directory",
        "https://ca.example:1x/directory",
        "https://[::1]:0/directory",
        "https://[::1]:abc/directory",
        "https://[not-an-ip]/directory",
        "https://[::1]extra:443/directory",
        "https://ca.example\\other/directory",
        " https://ca.example/directory",
        "https://ca.example/directory ",
        "https://ca.example/dir ectory",
        "https://ca.example/\u{a0}directory",
    ] {
        let file = config_file(&format!("[letsencrypt]\ndirectory_url = '{url}'"))?;
        assert!(Config::load(Some(file.path())).is_err(), "accepted {url:?}");
    }
    Ok(())
}

#[test]
fn letsencrypt_rejects_invalid_shapes_paths_and_overlapping_listeners_while_inactive() -> TestResult
{
    for fields in [
        "listen = ['127.0.0.1:0']",
        "listen = ['[::1]:0']",
        "listen = ['127.0.0.1:8080', '127.0.0.1:8080']",
        "listen = ['0.0.0.0:8080', '127.0.0.1:8080']",
        "listen = ['127.0.0.1:8080', '0.0.0.0:8080']",
        "listen = ['[::]:8080', '[::1]:8080']",
        "listen = ['[::1]:8080', '[::]:8080']",
        "listen = ['localhost:8080']",
        "listen = '0.0.0.0:80'",
        "listen = ['[::1]']",
        "state_path = ''",
        "ca_certificates_path = ''",
        "enabled = false",
        "email = 'a@example.com'",
        "terms = true",
        "challenge = 'http-01'",
        "renewal_interval_secs = 60",
    ] {
        let file = config_file(&format!("[letsencrypt]\n{fields}"))?;
        assert!(
            Config::load(Some(file.path())).is_err(),
            "accepted {fields}"
        );
    }
    let file = config_file("[letsencrypt]\nlisten = []")?;
    Config::load(Some(file.path()))?;
    Ok(())
}

#[test]
fn letsencrypt_listener_conflicts_require_an_active_managed_host() -> TestResult {
    let managed = "[hosts.'example.com'.tls]\nprovider = 'letsencrypt'\n";
    for (rest, conflict) in [
        ("[letsencrypt]\nlisten = []", true),
        ("[letsencrypt]\nlisten = ['0.0.0.0:5222']", true),
        ("[letsencrypt]\nlisten = ['127.0.0.1:5222']", true),
        ("[[c2s.listeners]]\naddress = '127.0.0.1:80'", true),
        (
            "[letsencrypt]\nlisten = ['[::]:8080']\n[[c2s.listeners]]\naddress = '[::1]:8080'",
            true,
        ),
        (
            "[letsencrypt]\nlisten = ['[::1]:8080']\n[[c2s.listeners]]\naddress = '[::]:8080'",
            true,
        ),
        ("[metrics]\nenabled = true\naddress = '127.0.0.1:80'", true),
        (
            "[letsencrypt]\nlisten = ['[::1]:8080']\n[metrics]\nenabled = true\naddress = '[::]:8080'",
            true,
        ),
        (
            "[letsencrypt]\nlisten = ['127.0.0.1:8080']\n[metrics]\nenabled = true\naddress = '0.0.0.0:8080'",
            true,
        ),
        (
            "[letsencrypt]\nlisten = ['127.0.0.1:8080', '127.0.0.2:8080', '[::1]:8080']",
            false,
        ),
        ("[letsencrypt]\nlisten = ['0.0.0.0:80', '[::]:80']", false),
        ("[[c2s.listeners]]\naddress = '[::]:80'", false),
        ("[[c2s.listeners]]\naddress = '127.0.0.1:0'", false),
        (
            "[metrics]\nenabled = false\naddress = '127.0.0.1:80'",
            false,
        ),
        ("[metrics]\nenabled = true\naddress = '[::]:80'", false),
        (
            "[letsencrypt]\nlisten = ['127.0.0.1:8080']\n[[c2s.listeners]]\naddress = '127.0.0.2:8080'",
            false,
        ),
    ] {
        let file = config_file(rest)?;
        Config::load(Some(file.path()))?;
        let file = config_file(&format!("{managed}{rest}"))?;
        assert_eq!(Config::load(Some(file.path())).is_err(), conflict, "{rest}");
    }
    Ok(())
}

#[test]
fn inactive_letsencrypt_configuration_does_not_bind_or_create_state() -> TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("absent/acme.redb");
    let trust = directory.path().join("absent/ca.pem");
    let file = config_file(&format!(
        "[letsencrypt]\nlisten = ['{}']\nstate_path = '{}'\nca_certificates_path = '{}'",
        listener.local_addr()?,
        state.display(),
        trust.display()
    ))?;
    let config = Config::load(Some(file.path()))?;
    let hosts = crate::hosts::Hosts::new(&config.hosts, None)?;
    assert!(hosts.is_local_host("localhost"));
    assert!(!state.exists());
    assert!(!trust.exists());
    assert!(!directory.path().join("absent").exists());
    Ok(())
}
