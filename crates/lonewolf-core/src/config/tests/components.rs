// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use lonewolf_auth::component::ComponentSecret;

use crate::config::{ComponentBalancing, ComponentSecretSource, Config, ConfigError};

use super::{TestResult, config_file};

#[test]
fn components_default_to_one_loopback_listener_and_no_domains() -> TestResult {
    let config = Config::default();
    assert_eq!(config.components.listeners.len(), 1);
    assert_eq!(
        config.components.listeners[0].address,
        "127.0.0.1:5347".parse()?
    );
    assert!(config.components.domains.is_empty());
    Ok(())
}

#[test]
fn component_secret_sources_load_without_reading_secret_files() -> TestResult {
    let file = config_file(
        "[components.domains.'muc.example.com']\nsecret_file = './missing-component-secret'\n\
         [components.domains.'pubsub.example.com']\nsecret = '1234567890abcdef'\ndiscoverable = false\n",
    )?;
    let config = Config::load(Some(file.path()))?;
    let file_domain = &config.components.domains["muc.example.com"];
    assert_eq!(
        file_domain.secret,
        ComponentSecretSource::File("./missing-component-secret".into())
    );
    assert!(file_domain.discoverable);
    assert_eq!(file_domain.max_connections.get(), 1);
    assert_eq!(file_domain.balancing, ComponentBalancing::Source);
    let inline_domain = &config.components.domains["pubsub.example.com"];
    assert_eq!(
        inline_domain.secret,
        ComponentSecretSource::Inline(ComponentSecret::new("1234567890abcdef")?)
    );
    assert!(!inline_domain.discoverable);
    assert_eq!(inline_domain.max_connections.get(), 1);
    assert_eq!(inline_domain.balancing, ComponentBalancing::Source);
    assert!(!format!("{config:?}").contains("1234567890abcdef"));
    Ok(())
}

#[test]
fn every_component_balancing_policy_accepts_multiple_connections() -> TestResult {
    for (name, expected) in [
        ("source", ComponentBalancing::Source),
        ("bare_source", ComponentBalancing::BareSource),
        ("destination", ComponentBalancing::Destination),
        ("bare_destination", ComponentBalancing::BareDestination),
        ("random", ComponentBalancing::Random),
    ] {
        let file = config_file(&format!(
            "[components.domains.'muc.example.com']\nsecret_file = './secret'\n\
             max_connections = 2\nbalancing = '{name}'\n"
        ))?;
        let config = Config::load(Some(file.path()))?;
        let domain = &config.components.domains["muc.example.com"];
        assert_eq!(domain.max_connections.get(), 2);
        assert_eq!(domain.balancing, expected);
    }
    Ok(())
}

#[test]
fn component_connection_allowances_are_positive_and_bounded_by_the_global_limit() -> TestResult {
    for (global, domain, valid) in [(1, 1, true), (2, 2, true), (1, 2, false), (64, 65, false)] {
        let file = config_file(&format!(
            "[limits.components]\nmax_inbound_connections = {global}\n\
             [components.domains.'muc.example.com']\nsecret_file = './secret'\n\
             max_connections = {domain}\n"
        ))?;
        let result = Config::load(Some(file.path()));
        if valid {
            assert_eq!(
                result?.components.domains["muc.example.com"]
                    .max_connections
                    .get(),
                domain
            );
        } else {
            assert!(
                matches!(result, Err(ConfigError::Invalid { ref reason, .. })
                    if reason == "components.domains.muc.example.com.max_connections must not exceed limits.components.max_inbound_connections"),
                "{result:?}"
            );
        }
    }
    for settings in ["max_connections = 0", "balancing = 'round_robin'"] {
        let file = config_file(&format!(
            "[components.domains.'muc.example.com']\nsecret_file = './secret'\n{settings}\n"
        ))?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Parse { .. })),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn component_domain_allowances_are_validated_before_listener_requirements() -> TestResult {
    let file = config_file(
        "[components]\nlisteners = []\n\
         [components.domains.'muc.example.com']\nsecret_file = './secret'\nmax_connections = 65\n",
    )?;
    let result = Config::load(Some(file.path()));
    assert!(
        matches!(result, Err(ConfigError::Invalid { ref reason, .. })
            if reason == "components.domains.muc.example.com.max_connections must not exceed limits.components.max_inbound_connections"),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn component_domains_require_exactly_one_valid_secret_source() -> TestResult {
    for (settings, message) in [
        ("", "set exactly one of secret or secret_file"),
        (
            "secret = '1234567890abcdef'\nsecret_file = './secret'",
            "set exactly one of secret or secret_file",
        ),
        (
            "secret = '1234567890abcde'",
            "component secret must be 16 to 1024 bytes",
        ),
        ("secret = true", "component secret must be a string"),
    ] {
        let file = config_file(&format!(
            "[components.domains.'muc.example.com']\n{settings}\n"
        ))?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Parse { ref source, .. }) if source.message() == message),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn component_tables_reject_unknown_fields() -> TestResult {
    for contents in [
        "[components]\nunknown = true",
        "[[components.listeners]]\nunknown = true",
        "[components.domains.'muc.example.com']\nsecret_file = './secret'\nunknown = true",
    ] {
        let file = config_file(contents)?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Parse { ref source, .. }) if source.message().contains("unknown field `unknown`")),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn component_domain_validation_reports_the_configuration_key() -> TestResult {
    for (prefix, domain, settings, expected) in [
        (
            "",
            "localhost",
            "secret_file = './secret'",
            "components.domains.localhost must not be a configured host",
        ),
        (
            "[s2s.routes]\n'muc.example.com' = ['127.0.0.1:5269']\n",
            "muc.example.com",
            "secret_file = './secret'",
            "components.domains.muc.example.com must not have an s2s.routes entry",
        ),
        (
            "",
            "MUC.example.com",
            "secret_file = './secret'",
            "components.domains.MUC.example.com must use the normalized form \"muc.example.com\"",
        ),
        (
            "",
            "muc.example.com",
            "secret_file = ''",
            "components.domains.muc.example.com.secret_file must not be empty",
        ),
    ] {
        let file = config_file(&format!(
            "{prefix}[components.domains.'{domain}']\n{settings}\n"
        ))?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Invalid { ref reason, .. }) if reason == expected),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn configured_component_listeners_reject_each_active_endpoint_conflict() -> TestResult {
    for (settings, expected) in [
        (
            "[components]\nlisteners = []\n",
            "components.listeners must define at least one listener when component domains are configured",
        ),
        (
            "[[components.listeners]]\naddress = '127.0.0.1:5347'\n\
             [[components.listeners]]\naddress = '127.0.0.1:5347'\n",
            "components.listeners[1] overlaps components.listeners[0]",
        ),
        (
            "[[components.listeners]]\naddress = '127.0.0.1:5222'\n",
            "components.listeners[0] overlaps c2s.listeners[0]",
        ),
        (
            "[[components.listeners]]\naddress = '127.0.0.1:5269'\n",
            "components.listeners[0] overlaps s2s.listeners[0]",
        ),
        (
            "[metrics]\nenabled = true\n\
             [[components.listeners]]\naddress = '127.0.0.1:9520'\n",
            "components.listeners[0] overlaps metrics.address",
        ),
        (
            "[hosts.'example.com'.tls]\nprovider = 'letsencrypt'\n\
             [[components.listeners]]\naddress = '127.0.0.1:80'\n",
            "components.listeners[0] overlaps letsencrypt.listen[0]",
        ),
    ] {
        let file = config_file(&format!(
            "{settings}[components.domains.'muc.example.com']\nsecret_file = './secret'\n"
        ))?;
        let result = Config::load(Some(file.path()));
        assert!(
            matches!(result, Err(ConfigError::Invalid { ref reason, .. }) if reason == expected),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn component_listeners_ignore_inactive_endpoints_and_port_zero() -> TestResult {
    for settings in [
        "[s2s]\nenabled = false\n[[components.listeners]]\naddress = '127.0.0.1:5269'\n",
        "[[components.listeners]]\naddress = '127.0.0.1:9520'\n",
        "[[components.listeners]]\naddress = '127.0.0.1:80'\n",
        "[[components.listeners]]\naddress = '127.0.0.1:0'\n\
         [[components.listeners]]\naddress = '127.0.0.1:0'\n",
    ] {
        let file = config_file(&format!(
            "{settings}[components.domains.'muc.example.com']\nsecret_file = './secret'\n"
        ))?;
        Config::load(Some(file.path()))?;
    }
    for settings in [
        "[components]\nlisteners = []",
        "[[components.listeners]]\naddress = '127.0.0.1:5222'",
    ] {
        let file = config_file(settings)?;
        assert!(
            Config::load(Some(file.path()))?
                .components
                .domains
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn component_parse_errors_never_retain_secret_values() -> TestResult {
    let overlong = "SYNTHETIC-OVERLONG-SECRET".repeat(50);
    for (synthetic, settings, message, key) in [
        (
            "1234567890123456",
            "secret = 1234567890123456".into(),
            "component secret must be a string",
            "secret",
        ),
        (
            "SYNTHETIC-KEY",
            "secret = 'SYNTHETIC-KEY'".into(),
            "component secret must be 16 to 1024 bytes",
            "components.domains",
        ),
        (
            overlong.as_str(),
            format!("secret = '{overlong}'"),
            "component secret must be 16 to 1024 bytes",
            "components.domains",
        ),
        (
            "SYNTHETIC-ARRAY-SECRET",
            "secret = ['SYNTHETIC-ARRAY-SECRET']".into(),
            "component secret must be a string",
            "secret",
        ),
        (
            "SYNTHETIC-TABLE-SECRET",
            "secret = { value = 'SYNTHETIC-TABLE-SECRET' }".into(),
            "component secret must be a string",
            "secret",
        ),
        (
            "SYNTHETIC-DOUBLE-SECRET",
            "secret = 'SYNTHETIC-DOUBLE-SECRET'\nsecret_file = 'unused'".into(),
            "set exactly one of secret or secret_file",
            "components.domains",
        ),
        (
            "SYNTHETIC-SYNTAX-SECRET",
            "secret = 'SYNTHETIC-SYNTAX-SECRET' invalid".into(),
            "expected newline",
            "",
        ),
        (
            "SYNTHETIC-VALID-SECRET",
            "secret = 'SYNTHETIC-VALID-SECRET'\n[metrics]\nenabled = 'invalid'".into(),
            "expected a boolean",
            "metrics.enabled",
        ),
    ] {
        let file = config_file(&format!(
            "[components.domains.'muc.example.com']\n{settings}\n"
        ))?;
        let error = Config::load(Some(file.path()))
            .err()
            .ok_or("expected failure")?;
        let display = error.to_string();
        assert!(!display.contains(synthetic));
        assert!(display.contains(file.path().to_str().ok_or("non-UTF8 path")?));
        assert!(!format!("{error:?}").contains(synthetic));
        let source = error.source().ok_or("missing parse source")?;
        assert!(!source.to_string().contains(synthetic));
        assert!(!format!("{source:?}").contains(synthetic));
        assert!(source.to_string().contains(key));
        let ConfigError::Parse { source, .. } = error else {
            return Err("expected parse error".into());
        };
        assert!(!source.message().contains(synthetic));
        assert!(source.message().contains(message), "{}", source.message());
    }
    Ok(())
}
