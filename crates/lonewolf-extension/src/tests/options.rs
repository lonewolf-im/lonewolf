// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;

use lonewolf_storage::RedbStorage;
use lonewolf_util::arena::GlobalChunkAllocator;

use super::{Fake, PlMutex, TestExtensions, extension};
use crate::{
    EnableError, Extension, ExtensionFactory, HostOptions, HostSelection, OptionsError,
    RegistrationError,
};

type TestResult = Result<(), Box<dyn Error>>;

struct BuildCall {
    name: &'static str,
    hosts: Vec<(String, Option<toml::Table>)>,
}

struct RecordingFactory {
    instance: Arc<Fake>,
    builds: Arc<PlMutex<Vec<BuildCall>>>,
}

impl ExtensionFactory<GlobalChunkAllocator, RedbStorage> for RecordingFactory {
    fn name(&self) -> &'static str {
        self.instance.name
    }

    fn build(
        &self,
        hosts: &[HostOptions<'_>],
    ) -> Result<Arc<dyn Extension<GlobalChunkAllocator, RedbStorage>>, OptionsError> {
        self.builds.lock().push(BuildCall {
            name: self.instance.name,
            hosts: hosts
                .iter()
                .map(|host| (host.domain.into(), host.options.cloned()))
                .collect(),
        });
        Ok(self.instance.clone())
    }
}

#[test]
fn factories_build_once_in_name_order_and_register_in_host_selection_order() -> TestResult {
    let builds = Arc::new(PlMutex::new(Vec::new()));
    let a = Arc::new(Fake {
        name: "a",
        accounts: true,
        ..Fake::default()
    });
    let b = extension("b", &[], &[]);
    let mut catalog = TestExtensions::default();
    for instance in [b.clone(), a.clone(), extension("unused", &[], &[])] {
        catalog.register_factory(Box::new(RecordingFactory {
            instance,
            builds: Arc::clone(&builds),
        }))?;
    }
    let empty = BTreeMap::new();
    let options = BTreeMap::from([("a".into(), toml::from_str("value = 7")?)]);
    let selections = [
        HostSelection {
            domain: "z.example",
            extensions: &["b".into(), "a".into()],
            options: &options,
        },
        HostSelection {
            domain: "empty.example",
            extensions: &[],
            options: &empty,
        },
        HostSelection {
            domain: "a.example",
            extensions: &["a".into()],
            options: &empty,
        },
    ];
    let enabled = catalog.enable(&selections)?;
    let calls = builds.lock();
    assert_eq!(
        calls.iter().map(|call| call.name).collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(
        calls[0].hosts,
        [
            ("z.example".into(), Some(options["a"].clone())),
            ("a.example".into(), None),
        ]
    );
    assert_eq!(calls[1].hosts, [("z.example".into(), None)]);
    assert_eq!(*a.hosts.lock(), ["z.example", "a.example"]);
    assert_eq!(*b.hosts.lock(), ["z.example"]);
    assert_eq!(enabled["z.example"].enabled(), ["b", "a"]);
    assert!(enabled["empty.example"].enabled().is_empty());
    assert_eq!(enabled["a.example"].enabled(), ["a"]);
    assert!(Arc::ptr_eq(
        &enabled["z.example"].account_handlers()[0].1,
        &enabled["a.example"].account_handlers()[0].1,
    ));
    assert!(catalog.enable(&[])?.is_empty());
    Ok(())
}

#[test]
fn factory_names_share_instance_registration_checks() -> TestResult {
    let builds = Arc::new(PlMutex::new(Vec::new()));
    let mut catalog = TestExtensions::default();
    for name in ["", " ", " leading", "trailing "] {
        assert_eq!(
            catalog.register_factory(Box::new(RecordingFactory {
                instance: extension(name, &[], &[]),
                builds: Arc::clone(&builds),
            })),
            Err(RegistrationError::InvalidExtensionName)
        );
    }
    catalog.register_factory(Box::new(RecordingFactory {
        instance: extension("a", &[], &[]),
        builds: Arc::clone(&builds),
    }))?;
    assert_eq!(
        catalog.register(extension("a", &[], &[])),
        Err(RegistrationError::DuplicateExtension("a"))
    );
    catalog.register(extension("b", &[], &[]))?;
    assert_eq!(
        catalog.register_factory(Box::new(RecordingFactory {
            instance: extension("b", &[], &[]),
            builds,
        })),
        Err(RegistrationError::DuplicateExtension("b"))
    );
    Ok(())
}

#[test]
fn invalid_builtin_options_identify_the_host_and_extension() -> TestResult {
    let mut catalog = TestExtensions::default();
    for factory in crate::builtin() {
        catalog.register_factory(factory)?;
    }
    for (name, key) in [
        ("roster", "max_pending_subscription_requests"),
        ("offline", "max_messages_per_account"),
    ] {
        let names = [name.into()];
        for setting in [
            format!("{key} = 0"),
            format!("{key} = -1"),
            format!("{key} = '100'"),
            format!("{key} = 1.5"),
            "unknown = 1".into(),
        ] {
            let options = BTreeMap::from([(name.into(), toml::from_str(&setting)?)]);
            let error = catalog
                .enable(&[
                    HostSelection {
                        domain: "valid.example",
                        extensions: &names,
                        options: &BTreeMap::new(),
                    },
                    HostSelection {
                        domain: "invalid.example",
                        extensions: &names,
                        options: &options,
                    },
                ])
                .err()
                .ok_or("invalid options accepted")?;
            assert_eq!(error.host, "invalid.example", "{setting}");
            assert!(
                matches!(error.source, RegistrationError::InvalidOptions { extension, ref reason } if extension == name && !reason.is_empty()),
                "{error}"
            );
        }
    }
    let options = BTreeMap::from([(
        "offline".into(),
        toml::from_str("max_messages_per_account = 4294967296")?,
    )]);
    assert!(matches!(
        catalog.enable(&[HostSelection {
            domain: "example.com",
            extensions: &["offline".into()],
            options: &options
        }]),
        Err(EnableError {
            source: RegistrationError::InvalidOptions {
                extension: "offline",
                ..
            },
            ..
        })
    ));
    Ok(())
}

#[test]
fn options_require_an_enabled_known_extension() -> TestResult {
    let mut catalog = TestExtensions::default();
    for factory in crate::builtin() {
        catalog.register_factory(factory)?;
    }
    for (name, names, expected) in [
        (
            "roster",
            vec![],
            RegistrationError::OptionsWithoutExtension("roster".into()),
        ),
        (
            "roster",
            vec!["offline".into()],
            RegistrationError::OptionsWithoutExtension("roster".into()),
        ),
        (
            "offline",
            vec![],
            RegistrationError::OptionsWithoutExtension("offline".into()),
        ),
        (
            "offline",
            vec!["roster".into()],
            RegistrationError::OptionsWithoutExtension("offline".into()),
        ),
        (
            "unknown",
            vec![],
            RegistrationError::UnknownOptions("unknown".into()),
        ),
        (
            "unknown",
            vec!["unknown".into()],
            RegistrationError::UnknownOptions("unknown".into()),
        ),
    ] {
        let options = BTreeMap::from([(name.into(), toml::Table::new())]);
        let error = catalog
            .enable(&[HostSelection {
                domain: "example.com",
                extensions: &names,
                options: &options,
            }])
            .err()
            .ok_or("invalid options accepted")?;
        assert_eq!(
            error,
            EnableError {
                host: "example.com".into(),
                source: expected
            }
        );
    }
    Ok(())
}

#[test]
fn all_option_checks_precede_builds_and_unknown_extensions() -> TestResult {
    let builds = Arc::new(PlMutex::new(Vec::new()));
    let mut catalog = TestExtensions::default();
    catalog.register_factory(Box::new(RecordingFactory {
        instance: extension("a", &[], &[]),
        builds: Arc::clone(&builds),
    }))?;
    let options = BTreeMap::from([("a".into(), toml::Table::new())]);
    let error = catalog
        .enable(&[
            HostSelection {
                domain: "first.example",
                extensions: &["a".into(), "missing".into()],
                options: &BTreeMap::new(),
            },
            HostSelection {
                domain: "z.example",
                extensions: &[],
                options: &options,
            },
            HostSelection {
                domain: "a.example",
                extensions: &[],
                options: &options,
            },
        ])
        .err()
        .ok_or("disabled options accepted")?;
    assert_eq!(
        error,
        EnableError {
            host: "z.example".into(),
            source: RegistrationError::OptionsWithoutExtension("a".into())
        }
    );
    assert!(builds.lock().is_empty());
    Ok(())
}

#[test]
fn unknown_extension_reports_the_first_host_that_selects_it() -> TestResult {
    let catalog = TestExtensions::default();
    let names = ["missing".into()];
    let empty = BTreeMap::new();
    let error = catalog
        .enable(&[
            HostSelection {
                domain: "empty.example",
                extensions: &[],
                options: &empty,
            },
            HostSelection {
                domain: "z.example",
                extensions: &names,
                options: &empty,
            },
            HostSelection {
                domain: "a.example",
                extensions: &names,
                options: &empty,
            },
        ])
        .err()
        .ok_or("unknown extension accepted")?;
    assert_eq!(
        error,
        EnableError {
            host: "z.example".into(),
            source: RegistrationError::UnknownExtension("missing".into())
        }
    );
    Ok(())
}

#[test]
fn shared_instances_reject_the_first_host_with_any_options() -> TestResult {
    let mut catalog = TestExtensions::default();
    let instance = extension("a", &[], &[]);
    catalog.register(instance.clone())?;
    let names = ["a".into()];
    for table in [toml::Table::new(), toml::from_str("value = 7")?] {
        let options = BTreeMap::from([("a".into(), table)]);
        let error = catalog
            .enable(&[
                HostSelection {
                    domain: "empty.example",
                    extensions: &names,
                    options: &BTreeMap::new(),
                },
                HostSelection {
                    domain: "z.example",
                    extensions: &names,
                    options: &options,
                },
                HostSelection {
                    domain: "a.example",
                    extensions: &names,
                    options: &options,
                },
            ])
            .err()
            .ok_or("instance options accepted")?;
        assert_eq!(
            error,
            EnableError {
                host: "z.example".into(),
                source: RegistrationError::InvalidOptions {
                    extension: "a",
                    reason: "this extension has no options".into()
                }
            }
        );
        assert!(instance.hosts.lock().is_empty());
    }
    Ok(())
}

#[test]
fn option_errors_preserve_display_and_source() {
    for (source, expected) in [
        (
            RegistrationError::InvalidOptions {
                extension: "roster",
                reason: "invalid limit".into(),
            },
            "invalid roster options: invalid limit",
        ),
        (
            RegistrationError::OptionsWithoutExtension("roster".into()),
            "options for \"roster\" require enabling that extension",
        ),
        (
            RegistrationError::UnknownOptions("missing".into()),
            "unknown host setting \"missing\"",
        ),
    ] {
        let error = EnableError {
            host: "example.com".into(),
            source,
        };
        assert_eq!(error.to_string(), expected);
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some(expected)
        );
    }
}
