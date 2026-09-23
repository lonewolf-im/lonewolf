// SPDX-License-Identifier: Apache-2.0

//! Policy configuration only; these values do not enforce runtime limits.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub c2s: C2sLimits,
}

impl LimitsConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        self.c2s.validate()
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(try_from = "C2sLimitsInput")]
pub struct C2sLimits {
    /// A sole profile is selected automatically when the default is omitted.
    pub default: String,
    /// Counts bound resources across all listeners for each account.
    pub max_resources_per_account: NonZeroUsize,
    /// Replaces the built-in profiles when present in TOML.
    pub profiles: BTreeMap<String, C2sLimitProfile>,
}

impl Default for C2sLimits {
    fn default() -> Self {
        Self {
            default: "default".into(),
            max_resources_per_account: default_max_resources_per_account(),
            profiles: default_profiles(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct C2sLimitsInput {
    default: Option<String>,
    #[serde(default = "default_max_resources_per_account")]
    max_resources_per_account: NonZeroUsize,
    #[serde(default = "default_profiles")]
    profiles: BTreeMap<String, C2sLimitProfile>,
}

impl TryFrom<C2sLimitsInput> for C2sLimits {
    type Error = &'static str;

    fn try_from(input: C2sLimitsInput) -> Result<Self, Self::Error> {
        let (first_name, _) = input
            .profiles
            .first_key_value()
            .ok_or("limits.c2s.profiles must define at least one profile")?;
        let default = match input.default {
            Some(default) => default,
            None if input.profiles.len() == 1 => first_name.clone(),
            None => {
                return Err("limits.c2s.default is required when multiple profiles are defined");
            }
        };
        Ok(Self {
            default,
            max_resources_per_account: input.max_resources_per_account,
            profiles: input.profiles,
        })
    }
}

impl C2sLimits {
    fn validate(&self) -> Result<(), String> {
        if !self.profiles.contains_key(&self.default) {
            return Err(format!(
                "limits.c2s.default references unknown profile {:?}",
                self.default
            ));
        }
        for (name, profile) in &self.profiles {
            if name.trim().is_empty() {
                return Err("limits.c2s profile names must not be blank".into());
            }
            if !(10_000..=isize::MAX as usize).contains(&profile.max_stanza_bytes.get()) {
                return Err(format!(
                    "limits.c2s.profiles.{name}.max_stanza_bytes must be between 10000 and {}",
                    isize::MAX
                ));
            }
            if Instant::now()
                .checked_add(Duration::from_secs(
                    profile.distinct_recipients_per_connection.window_secs.get() as u64,
                ))
                .is_none()
            {
                return Err(format!(
                    "limits.c2s.profiles.{name}.distinct_recipients_per_connection.window_secs exceeds the platform clock range"
                ));
            }
        }
        Ok(())
    }
}

fn default_profiles() -> BTreeMap<String, C2sLimitProfile> {
    BTreeMap::from([("default".into(), C2sLimitProfile::default())])
}

const fn default_max_resources_per_account() -> NonZeroUsize {
    nonzero(10)
}

/// Reusing a profile shares policy values, not counters, between listeners.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(from = "C2sLimitProfileInput")]
pub struct C2sLimitProfile {
    /// Counts connections across all workers of one listener.
    pub max_connections_per_ip: NonZeroUsize,
    /// Includes XML markup and must allow at least 10,000 bytes (RFC 6120 section 13.12).
    pub max_stanza_bytes: NonZeroUsize,
    /// Shares one bucket per IP across all workers of one listener.
    pub connection_attempts_per_ip: EventRate,
    pub incoming_stanzas_per_connection: EventRate,
    /// Measures XML bytes, including control elements and whitespace, without TCP or TLS overhead.
    pub incoming_xml_per_connection: ByteRate,
    pub distinct_recipients_per_connection: RecipientLimit,
}

impl Default for C2sLimitProfile {
    fn default() -> Self {
        Self {
            max_connections_per_ip: const { nonzero(256) },
            max_stanza_bytes: const { nonzero(262_144) },
            connection_attempts_per_ip: EventRate {
                per_second: const { nonzero(10) },
                burst: const { nonzero(50) },
            },
            incoming_stanzas_per_connection: EventRate {
                per_second: const { nonzero(20) },
                burst: const { nonzero(100) },
            },
            incoming_xml_per_connection: ByteRate::default(),
            distinct_recipients_per_connection: RecipientLimit::default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct C2sLimitProfileInput {
    max_connections_per_ip: Option<NonZeroUsize>,
    max_stanza_bytes: Option<NonZeroUsize>,
    connection_attempts_per_ip: EventRateInput,
    incoming_stanzas_per_connection: EventRateInput,
    incoming_xml_per_connection: ByteRate,
    distinct_recipients_per_connection: RecipientLimit,
}

impl From<C2sLimitProfileInput> for C2sLimitProfile {
    fn from(input: C2sLimitProfileInput) -> Self {
        let defaults = Self::default();
        Self {
            max_connections_per_ip: input
                .max_connections_per_ip
                .unwrap_or(defaults.max_connections_per_ip),
            max_stanza_bytes: input.max_stanza_bytes.unwrap_or(defaults.max_stanza_bytes),
            connection_attempts_per_ip: input
                .connection_attempts_per_ip
                .with_defaults(defaults.connection_attempts_per_ip),
            incoming_stanzas_per_connection: input
                .incoming_stanzas_per_connection
                .with_defaults(defaults.incoming_stanzas_per_connection),
            incoming_xml_per_connection: input.incoming_xml_per_connection,
            distinct_recipients_per_connection: input.distinct_recipients_per_connection,
        }
    }
}

/// Token-bucket refill rate and capacity, measured in events.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventRate {
    pub per_second: NonZeroUsize,
    pub burst: NonZeroUsize,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EventRateInput {
    per_second: Option<NonZeroUsize>,
    burst: Option<NonZeroUsize>,
}

impl EventRateInput {
    fn with_defaults(self, defaults: EventRate) -> EventRate {
        EventRate {
            per_second: self.per_second.unwrap_or(defaults.per_second),
            burst: self.burst.unwrap_or(defaults.burst),
        }
    }
}

/// Token-bucket refill rate and capacity, measured in bytes.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ByteRate {
    pub bytes_per_second: NonZeroUsize,
    pub burst_bytes: NonZeroUsize,
}

impl Default for ByteRate {
    fn default() -> Self {
        const {
            Self {
                bytes_per_second: nonzero(262_144),
                burst_bytes: nonzero(1_048_576),
            }
        }
    }
}

/// Counts distinct recipient bare JIDs within a rolling window for one connection.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RecipientLimit {
    pub max: NonZeroUsize,
    pub window_secs: NonZeroUsize,
}

impl Default for RecipientLimit {
    fn default() -> Self {
        const {
            Self {
                max: nonzero(100),
                window_secs: nonzero(60),
            }
        }
    }
}

const fn nonzero(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("default limit must be positive"),
    }
}
