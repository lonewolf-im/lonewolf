// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::config::{Config, ConfigError};

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
[xmpp]
default_host = "chat.example.org"

[hosts."example.com".tls]
certificate_chain_path = "certs/example.pem"
private_key_path = "certs/example.key"

[hosts."chat.example.org".tls]
certificate_chain_path = "certs/chat.pem"
private_key_path = "certs/chat.key"
"#,
    )?;
    let config = Config::load(Some(file.path()))?;

    assert_eq!(config.hosts.len(), 2);
    assert_eq!(
        config.xmpp.default_host.as_deref(),
        Some("chat.example.org")
    );
    assert!(!config.hosts.contains_key("localhost"));
    assert!(config.hosts["example.com"].tls.is_some());
    let tls = config.hosts["chat.example.org"]
        .tls
        .as_ref()
        .ok_or("missing TLS settings")?;
    assert_eq!(tls.certificate_chain_path, Path::new("certs/chat.pem"));
    assert_eq!(tls.private_key_path, Path::new("certs/chat.key"));
    assert!(tls.client_auth.is_none());
    Ok(())
}

#[test]
fn non_localhost_hosts_require_tls() -> TestResult {
    for contents in [
        "[hosts.\"example.com\"]",
        "[xmpp]\ndefault_host = 'localhost'\n[hosts.localhost]\n[hosts.\"example.com\"]",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err(contents);
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error}");
        assert!(
            error
                .to_string()
                .contains("hosts.example.com.tls is required")
        );
    }
    Ok(())
}

#[test]
fn multiple_hosts_require_a_selected_default() -> TestResult {
    for contents in [
        "[hosts.localhost]\n[hosts.\"example.com\"]",
        "[xmpp]\ndefault_host = 'missing.example'\n[hosts.localhost]",
        "[xmpp]\ndefault_host = ''\n[hosts.localhost]",
    ] {
        let file = config_file(contents)?;
        let error = Config::load(Some(file.path())).expect_err(contents);
        assert!(matches!(error, ConfigError::Invalid { .. }), "{error}");
    }
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
fn configured_hosts_and_default_host_reject_ipv6_zones() -> TestResult {
    for domain in ["[fe80::1%eth0]", "[FE80::1%25Eth0]", "[fe80::1%25eth%32]"] {
        let host = format!(
            "[hosts.\"{domain}\".tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'"
        );
        for contents in [
            host.clone(),
            format!("[xmpp]\ndefault_host = '{domain}'\n{host}"),
        ] {
            let file = config_file(&contents)?;
            let error = Config::load(Some(file.path())).expect_err(&contents);
            assert!(
                matches!(error, ConfigError::Invalid { ref reason, .. }
                if reason.starts_with(&format!("hosts.{domain} is not a valid XMPP domain:"))),
                "{error}"
            );
        }
    }
    Ok(())
}

#[test]
fn pure_ipv6_literals_are_usable_as_configured_hosts() -> TestResult {
    let file = config_file(
        "[xmpp]\ndefault_host = '[2001:db8::1]'\n[hosts.\"[2001:db8::1]\".tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'",
    )?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(config.xmpp.default_host.as_deref(), Some("[2001:db8::1]"));
    assert!(config.hosts.contains_key("[2001:db8::1]"));
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

#[test]
fn roster_limits_default_and_override_per_host() -> TestResult {
    assert!(Config::default().hosts["localhost"].roster.is_none());
    for (section, expected) in [
        ("", None),
        ("[hosts.localhost.roster]", Some(100)),
        (
            "[hosts.localhost.roster]\nmax_pending_subscription_requests = 7",
            Some(7),
        ),
    ] {
        let file = config_file(section)?;
        let config = Config::load(Some(file.path()))?;
        assert_eq!(
            config.hosts["localhost"]
                .roster
                .map(|limits| limits.max_pending_subscription_requests.get()),
            expected
        );
    }
    assert_eq!(
        lonewolf_extension::roster::RosterLimits::default()
            .max_pending_subscription_requests
            .get(),
        100
    );
    Ok(())
}

#[test]
fn invalid_roster_limits_are_rejected() -> TestResult {
    for setting in [
        "max_pending_subscription_requests = 0",
        "max_pending_subscription_requests = -1",
        "max_pending_subscription_requests = '100'",
        "max_pending_subscription_requests = 1.5",
        "max_pending_subscription_requests = 18446744073709551616",
        "unknown = 1",
    ] {
        let file = config_file(&format!("[hosts.localhost.roster]\n{setting}"))?;
        assert!(
            matches!(
                Config::load(Some(file.path())),
                Err(ConfigError::Parse { .. })
            ),
            "{setting}"
        );
    }
    for extensions in ["[]", "['offline']"] {
        let file = config_file(&format!(
            "[hosts.localhost]\nextensions = {extensions}\n[hosts.localhost.roster]"
        ))?;
        assert!(
            matches!(Config::load(Some(file.path())), Err(ConfigError::Invalid { reason, .. }) if reason == "hosts.localhost.roster requires the roster extension")
        );
    }
    Ok(())
}

#[test]
fn client_auth_paths_are_required_only_when_configured() -> TestResult {
    let tls = "[hosts.localhost.tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'\n";
    let file = config_file(&format!(
        "{tls}[hosts.localhost.tls.client_auth]\ntrust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'"
    ))?;
    let config = Config::load(Some(file.path()))?;
    let client = config.hosts["localhost"]
        .tls
        .as_ref()
        .and_then(|tls| tls.client_auth.as_ref())
        .ok_or("missing client auth")?;
    assert_eq!(client.trust_anchors_path, Path::new("roots.pem"));
    assert_eq!(client.crls_path, Path::new("crls.pem"));
    for paths in [
        "",
        "trust_anchors_path = 'roots.pem'",
        "crls_path = 'crls.pem'",
        "trust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'\nunknown = true",
    ] {
        let file = config_file(&format!("{tls}[hosts.localhost.tls.client_auth]\n{paths}"))?;
        assert!(matches!(
            Config::load(Some(file.path())),
            Err(ConfigError::Parse { .. })
        ));
    }
    for paths in [
        "trust_anchors_path = ''\ncrls_path = 'crls.pem'",
        "trust_anchors_path = 'roots.pem'\ncrls_path = ''",
    ] {
        let file = config_file(&format!("{tls}[hosts.localhost.tls.client_auth]\n{paths}"))?;
        assert!(matches!(
            Config::load(Some(file.path())),
            Err(ConfigError::Invalid { .. })
        ));
    }
    Ok(())
}
