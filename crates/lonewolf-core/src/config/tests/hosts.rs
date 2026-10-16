// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::config::{
    Config, ConfigError, HostConfig, HostTlsConfig, HostTlsSource, managed_dns_name,
};

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
    assert_eq!(
        tls.source,
        HostTlsSource::Files {
            certificate_chain_path: "certs/chat.pem".into(),
            private_key_path: "certs/chat.key".into(),
        }
    );
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
fn extension_option_tables_are_kept_per_host() -> TestResult {
    let file = config_file("[hosts.localhost.roster]\nmax_pending_subscription_requests = 7")?;
    let config = Config::load(Some(file.path()))?;
    assert_eq!(
        config.hosts["localhost"].options["roster"]["max_pending_subscription_requests"],
        toml::Value::Integer(7),
    );
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

#[test]
fn certificate_providers_preserve_file_defaults_and_reject_conflicting_fields() -> TestResult {
    for provider in ["", "provider = 'files'\n"] {
        let file = config_file(&format!(
            "[hosts.'example.com'.tls]\n{provider}certificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'"
        ))?;
        let config = Config::load(Some(file.path()))?;
        assert_eq!(
            config.hosts["example.com"]
                .tls
                .as_ref()
                .ok_or("missing TLS")?
                .source,
            HostTlsSource::Files {
                certificate_chain_path: "cert.pem".into(),
                private_key_path: "key.pem".into(),
            }
        );
    }
    for fields in [
        "provider = 'unknown'",
        "provider = 'Files'\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'",
        "provider = 'files'",
        "provider = 'files'\ncertificate_chain_path = 'cert.pem'",
        "provider = 'files'\nprivate_key_path = 'key.pem'",
        "provider = 'letsencrypt'\ncertificate_chain_path = 'cert.pem'",
        "provider = 'letsencrypt'\ncertificate_chain_path = ''",
        "provider = 'letsencrypt'\nprivate_key_path = 'key.pem'",
        "provider = 'letsencrypt'\nprivate_key_path = ''",
        "provider = 'letsencrypt'\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'",
        "provider = 'letsencrypt'\nenabled = true",
        "provider = 'letsencrypt'\nsource = 'files'",
    ] {
        let file = config_file(&format!("[hosts.'example.com'.tls]\n{fields}"))?;
        assert!(
            matches!(
                Config::load(Some(file.path())),
                Err(ConfigError::Parse { .. })
            ),
            "{fields}"
        );
    }
    Ok(())
}

#[test]
fn managed_host_names_use_strict_dns_identities_and_keep_unicode_routing() -> TestResult {
    for (domain, ascii) in [
        ("example.com", "example.com"),
        ("chat.example", "chat.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("a-b.example", "a-b.example"),
    ] {
        let file = config_file(&format!("[hosts.'{domain}'.tls]\nprovider = 'letsencrypt'"))?;
        let config = Config::load(Some(file.path()))?;
        assert_eq!(managed_dns_name(domain)?, ascii);
        assert!(matches!(
            config.hosts[domain]
                .tls
                .as_ref()
                .ok_or("missing TLS")?
                .source,
            HostTlsSource::LetsEncrypt
        ));
    }
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63)
    );
    for domain in [
        "",
        "localhost",
        "chat.localhost",
        "a.b.localhost",
        "singlelabel",
        "192.0.2.1",
        "[2001:db8::1]",
        "*.example",
        "chat.*.example",
        "a..example",
        ".example",
        "example.com.",
        "bad_name.example",
        "-bad.example",
        "bad-.example",
        "EXAMPLE.COM",
        "xn--bcher-kva.example",
        "example/com",
        "example@com",
        &long_label,
        &long_name,
    ] {
        let file = config_file(&format!("[hosts.'{domain}'.tls]\nprovider = 'letsencrypt'"))?;
        assert!(
            Config::load(Some(file.path())).is_err(),
            "accepted {domain:?}"
        );
    }
    Ok(())
}

#[test]
fn managed_alias_collisions_include_file_sources_in_either_order() -> TestResult {
    for (ascii_managed, unicode_managed) in
        [(true, true), (true, false), (false, true), (false, false)]
    {
        let source = |managed| {
            if managed {
                HostTlsSource::LetsEncrypt
            } else {
                HostTlsSource::Files {
                    certificate_chain_path: "cert.pem".into(),
                    private_key_path: "key.pem".into(),
                }
            }
        };
        let hosts = std::collections::BTreeMap::from([
            (
                "xn--bcher-kva.example".into(),
                HostConfig {
                    tls: Some(HostTlsConfig {
                        source: source(ascii_managed),
                        client_auth: None,
                    }),
                    ..HostConfig::default()
                },
            ),
            (
                "bücher.example".into(),
                HostConfig {
                    tls: Some(HostTlsConfig {
                        source: source(unicode_managed),
                        client_auth: None,
                    }),
                    ..HostConfig::default()
                },
            ),
        ]);
        let config = Config::default();
        let validation = config
            .letsencrypt
            .validate(&hosts, &config.c2s, &config.metrics);
        assert_eq!(validation.is_err(), ascii_managed || unicode_managed);
        if let Err(reason) = validation {
            assert!(reason.contains("same managed DNS identity"), "{reason}");
        }
    }
    let file = config_file(
        "[xmpp]\ndefault_host = 'bücher.example'\n[hosts.'bücher.example'.tls]\nprovider = 'letsencrypt'\n[hosts.'xn--bcher-kva.example'.tls]\nprovider = 'letsencrypt'",
    )?;
    assert!(Config::load(Some(file.path())).is_err());
    Ok(())
}

#[test]
fn managed_hosts_can_share_configuration_with_file_ip_and_localhost_hosts() -> TestResult {
    let file = config_file(
        "[xmpp]\ndefault_host = 'chat.example'\n[hosts.'chat.example'.tls]\nprovider = 'letsencrypt'\n[hosts.'other.example'.tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'\n[hosts.'192.0.2.1'.tls]\ncertificate_chain_path = 'cert.pem'\nprivate_key_path = 'key.pem'\n[hosts.localhost]",
    )?;
    assert_eq!(Config::load(Some(file.path()))?.hosts.len(), 4);
    Ok(())
}

#[test]
fn managed_client_auth_uses_the_existing_path_contract() -> TestResult {
    let prefix = "[hosts.'example.com'.tls]\nprovider = 'letsencrypt'\n[hosts.'example.com'.tls.client_auth]\n";
    let file = config_file(&format!(
        "{prefix}trust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'"
    ))?;
    let config = Config::load(Some(file.path()))?;
    let client = config.hosts["example.com"]
        .tls
        .as_ref()
        .and_then(|tls| tls.client_auth.as_ref())
        .ok_or("missing client auth")?;
    assert_eq!(client.trust_anchors_path, Path::new("roots.pem"));
    assert_eq!(client.crls_path, Path::new("crls.pem"));
    for fields in [
        "",
        "trust_anchors_path = 'roots.pem'",
        "crls_path = 'crls.pem'",
        "trust_anchors_path = ''\ncrls_path = 'crls.pem'",
        "trust_anchors_path = 'roots.pem'\ncrls_path = ''",
        "trust_anchors_path = 'roots.pem'\ncrls_path = 'crls.pem'\nunknown = true",
    ] {
        let file = config_file(&format!("{prefix}{fields}"))?;
        assert!(Config::load(Some(file.path())).is_err(), "{fields}");
    }
    Ok(())
}
