// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub c2s: C2sLimits,
    pub s2s: S2sLimits,
}

impl LimitsConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        self.c2s.validate()?;
        self.s2s.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(from = "S2sLimitsInput")]
pub struct S2sLimits {
    pub max_inbound_connections: NonZeroUsize,
    pub max_connections_per_ip: NonZeroUsize,
    pub connection_attempts_per_ip: EventRate,
    pub max_inbound_streams_per_domain: NonZeroUsize,
    pub negotiation_timeout_secs: NonZeroU64,
    pub connect_timeout_secs: NonZeroU64,
    pub max_stanza_bytes: NonZeroUsize,
    pub incoming_stanzas_per_connection: EventRate,
    pub incoming_xml_per_connection: ByteRate,
    pub max_outbound_links: NonZeroUsize,
    pub max_queued_stanzas_per_link: NonZeroUsize,
    pub max_queued_bytes_per_link: NonZeroUsize,
    pub idle_timeout_secs: NonZeroU64,
    pub stalled_write_timeout_secs: NonZeroU64,
    pub failure_backoff_initial_secs: NonZeroU64,
    pub failure_backoff_max_secs: NonZeroU64,
}

impl Default for S2sLimits {
    fn default() -> Self {
        const {
            Self {
                max_inbound_connections: nonzero(1_024),
                max_connections_per_ip: nonzero(32),
                connection_attempts_per_ip: EventRate {
                    per_second: nonzero(10),
                    burst: nonzero(50),
                },
                max_inbound_streams_per_domain: nonzero(4),
                negotiation_timeout_secs: nonzero_secs(30),
                connect_timeout_secs: nonzero_secs(10),
                max_stanza_bytes: nonzero(524_288),
                incoming_stanzas_per_connection: EventRate {
                    per_second: nonzero(200),
                    burst: nonzero(2_000),
                },
                incoming_xml_per_connection: ByteRate {
                    bytes_per_second: nonzero(1_048_576),
                    burst_bytes: nonzero(4_194_304),
                },
                max_outbound_links: nonzero(1_024),
                max_queued_stanzas_per_link: nonzero(512),
                max_queued_bytes_per_link: nonzero(4_194_304),
                idle_timeout_secs: nonzero_secs(600),
                stalled_write_timeout_secs: nonzero_secs(60),
                failure_backoff_initial_secs: nonzero_secs(30),
                failure_backoff_max_secs: nonzero_secs(900),
            }
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct S2sLimitsInput {
    max_inbound_connections: Option<NonZeroUsize>,
    max_connections_per_ip: Option<NonZeroUsize>,
    connection_attempts_per_ip: Option<EventRateInput>,
    max_inbound_streams_per_domain: Option<NonZeroUsize>,
    negotiation_timeout_secs: Option<NonZeroU64>,
    connect_timeout_secs: Option<NonZeroU64>,
    max_stanza_bytes: Option<NonZeroUsize>,
    incoming_stanzas_per_connection: Option<EventRateInput>,
    incoming_xml_per_connection: Option<ByteRateInput>,
    max_outbound_links: Option<NonZeroUsize>,
    max_queued_stanzas_per_link: Option<NonZeroUsize>,
    max_queued_bytes_per_link: Option<NonZeroUsize>,
    idle_timeout_secs: Option<NonZeroU64>,
    stalled_write_timeout_secs: Option<NonZeroU64>,
    failure_backoff_initial_secs: Option<NonZeroU64>,
    failure_backoff_max_secs: Option<NonZeroU64>,
}

impl From<S2sLimitsInput> for S2sLimits {
    fn from(input: S2sLimitsInput) -> Self {
        let defaults = Self::default();
        Self {
            max_inbound_connections: input
                .max_inbound_connections
                .unwrap_or(defaults.max_inbound_connections),
            max_connections_per_ip: input
                .max_connections_per_ip
                .unwrap_or(defaults.max_connections_per_ip),
            connection_attempts_per_ip: input
                .connection_attempts_per_ip
                .unwrap_or_default()
                .with_defaults(defaults.connection_attempts_per_ip),
            max_inbound_streams_per_domain: input
                .max_inbound_streams_per_domain
                .unwrap_or(defaults.max_inbound_streams_per_domain),
            negotiation_timeout_secs: input
                .negotiation_timeout_secs
                .unwrap_or(defaults.negotiation_timeout_secs),
            connect_timeout_secs: input
                .connect_timeout_secs
                .unwrap_or(defaults.connect_timeout_secs),
            max_stanza_bytes: input.max_stanza_bytes.unwrap_or(defaults.max_stanza_bytes),
            incoming_stanzas_per_connection: input
                .incoming_stanzas_per_connection
                .unwrap_or_default()
                .with_defaults(defaults.incoming_stanzas_per_connection),
            incoming_xml_per_connection: input
                .incoming_xml_per_connection
                .unwrap_or_default()
                .with_defaults(defaults.incoming_xml_per_connection),
            max_outbound_links: input
                .max_outbound_links
                .unwrap_or(defaults.max_outbound_links),
            max_queued_stanzas_per_link: input
                .max_queued_stanzas_per_link
                .unwrap_or(defaults.max_queued_stanzas_per_link),
            max_queued_bytes_per_link: input
                .max_queued_bytes_per_link
                .unwrap_or(defaults.max_queued_bytes_per_link),
            idle_timeout_secs: input
                .idle_timeout_secs
                .unwrap_or(defaults.idle_timeout_secs),
            stalled_write_timeout_secs: input
                .stalled_write_timeout_secs
                .unwrap_or(defaults.stalled_write_timeout_secs),
            failure_backoff_initial_secs: input
                .failure_backoff_initial_secs
                .unwrap_or(defaults.failure_backoff_initial_secs),
            failure_backoff_max_secs: input
                .failure_backoff_max_secs
                .unwrap_or(defaults.failure_backoff_max_secs),
        }
    }
}

impl S2sLimits {
    fn validate(&self) -> Result<(), String> {
        if !(10_000..=isize::MAX as usize).contains(&self.max_stanza_bytes.get()) {
            return Err(format!(
                "limits.s2s.max_stanza_bytes must be between 10000 and {}",
                isize::MAX
            ));
        }
        for (field, value) in [
            ("negotiation_timeout_secs", self.negotiation_timeout_secs),
            ("connect_timeout_secs", self.connect_timeout_secs),
            ("idle_timeout_secs", self.idle_timeout_secs),
            (
                "stalled_write_timeout_secs",
                self.stalled_write_timeout_secs,
            ),
            (
                "failure_backoff_initial_secs",
                self.failure_backoff_initial_secs,
            ),
            ("failure_backoff_max_secs", self.failure_backoff_max_secs),
        ] {
            if Instant::now()
                .checked_add(Duration::from_secs(value.get()))
                .is_none()
            {
                return Err(format!(
                    "limits.s2s.{field} exceeds the platform clock range"
                ));
            }
        }
        if self.failure_backoff_initial_secs > self.failure_backoff_max_secs {
            return Err("limits.s2s.failure_backoff_initial_secs must not exceed limits.s2s.failure_backoff_max_secs".into());
        }
        Ok(())
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ByteRateInput {
    bytes_per_second: Option<NonZeroUsize>,
    burst_bytes: Option<NonZeroUsize>,
}

impl ByteRateInput {
    fn with_defaults(self, defaults: ByteRate) -> ByteRate {
        ByteRate {
            bytes_per_second: self.bytes_per_second.unwrap_or(defaults.bytes_per_second),
            burst_bytes: self.burst_bytes.unwrap_or(defaults.burst_bytes),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(try_from = "C2sLimitsInput")]
pub struct C2sLimits {
    /// A sole profile is selected automatically when the default is omitted.
    pub default: String,
    /// Counts unauthenticated connections across all listeners.
    pub max_unauthenticated_connections: NonZeroUsize,
    /// Counts bound resources across all listeners for each account.
    pub max_resources_per_account: NonZeroUsize,
    pub max_directed_presence_recipients_per_resource: NonZeroUsize,
    /// Replaces the built-in profiles when present in TOML.
    pub profiles: BTreeMap<String, C2sLimitProfile>,
}

impl Default for C2sLimits {
    fn default() -> Self {
        Self {
            default: "default".into(),
            max_unauthenticated_connections: default_max_unauthenticated_connections(),
            max_resources_per_account: default_max_resources_per_account(),
            max_directed_presence_recipients_per_resource:
                default_max_directed_presence_recipients_per_resource(),
            profiles: default_profiles(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct C2sLimitsInput {
    default: Option<String>,
    #[serde(default = "default_max_unauthenticated_connections")]
    max_unauthenticated_connections: NonZeroUsize,
    #[serde(default = "default_max_resources_per_account")]
    max_resources_per_account: NonZeroUsize,
    #[serde(default = "default_max_directed_presence_recipients_per_resource")]
    max_directed_presence_recipients_per_resource: NonZeroUsize,
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
            max_unauthenticated_connections: input.max_unauthenticated_connections,
            max_resources_per_account: input.max_resources_per_account,
            max_directed_presence_recipients_per_resource: input
                .max_directed_presence_recipients_per_resource,
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
            for (field, value, minimum, maximum) in [
                (
                    "authentication_retries",
                    profile.authentication_retries,
                    2,
                    5,
                ),
                (
                    "resource_binding_retries",
                    profile.resource_binding_retries,
                    5,
                    10,
                ),
            ] {
                if !(minimum..=maximum).contains(&value.get()) {
                    return Err(format!(
                        "limits.c2s.profiles.{name}.{field} must be between {minimum} and {maximum}"
                    ));
                }
            }
            for (field, value) in [
                (
                    "connection_establishment_timeout_secs",
                    profile.connection_establishment_timeout_secs,
                ),
                (
                    "authentication_timeout_secs",
                    profile.authentication_timeout_secs,
                ),
                (
                    "resource_binding_timeout_secs",
                    profile.resource_binding_timeout_secs,
                ),
            ] {
                if Instant::now()
                    .checked_add(Duration::from_secs(value.get()))
                    .is_none()
                {
                    return Err(format!(
                        "limits.c2s.profiles.{name}.{field} exceeds the platform clock range"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_profiles() -> BTreeMap<String, C2sLimitProfile> {
    BTreeMap::from([("default".into(), C2sLimitProfile::default())])
}

const fn default_max_unauthenticated_connections() -> NonZeroUsize {
    nonzero(1_024)
}

pub(crate) const fn default_max_directed_presence_recipients_per_resource() -> NonZeroUsize {
    nonzero(256)
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
    pub connection_establishment_timeout_secs: NonZeroU64,
    pub authentication_timeout_secs: NonZeroU64,
    pub resource_binding_timeout_secs: NonZeroU64,
    pub authentication_retries: NonZeroUsize,
    pub resource_binding_retries: NonZeroUsize,
    /// Shares one bucket per IP across all workers of one listener.
    pub connection_attempts_per_ip: EventRate,
    pub incoming_stanzas_per_connection: EventRate,
    pub new_recipients_per_connection: EventRate,
    /// Measures XML bytes, including control elements and whitespace, without TCP or TLS overhead.
    pub incoming_xml_per_connection: ByteRate,
}

impl Default for C2sLimitProfile {
    fn default() -> Self {
        Self {
            max_connections_per_ip: const { nonzero(256) },
            max_stanza_bytes: const { nonzero(524_288) },
            connection_establishment_timeout_secs: nonzero_secs(10),
            authentication_timeout_secs: nonzero_secs(15),
            resource_binding_timeout_secs: nonzero_secs(5),
            authentication_retries: nonzero(2),
            resource_binding_retries: nonzero(5),
            connection_attempts_per_ip: EventRate {
                per_second: const { nonzero(10) },
                burst: const { nonzero(50) },
            },
            incoming_stanzas_per_connection: EventRate {
                per_second: const { nonzero(20) },
                burst: const { nonzero(100) },
            },
            new_recipients_per_connection: EventRate {
                per_second: NonZeroUsize::MIN,
                burst: const { nonzero(100) },
            },
            incoming_xml_per_connection: ByteRate::default(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct C2sLimitProfileInput {
    max_connections_per_ip: Option<NonZeroUsize>,
    max_stanza_bytes: Option<NonZeroUsize>,
    connection_establishment_timeout_secs: Option<NonZeroU64>,
    authentication_timeout_secs: Option<NonZeroU64>,
    resource_binding_timeout_secs: Option<NonZeroU64>,
    authentication_retries: Option<NonZeroUsize>,
    resource_binding_retries: Option<NonZeroUsize>,
    connection_attempts_per_ip: EventRateInput,
    incoming_stanzas_per_connection: EventRateInput,
    new_recipients_per_connection: EventRateInput,
    incoming_xml_per_connection: ByteRate,
}

impl From<C2sLimitProfileInput> for C2sLimitProfile {
    fn from(input: C2sLimitProfileInput) -> Self {
        let defaults = Self::default();
        Self {
            max_connections_per_ip: input
                .max_connections_per_ip
                .unwrap_or(defaults.max_connections_per_ip),
            max_stanza_bytes: input.max_stanza_bytes.unwrap_or(defaults.max_stanza_bytes),
            connection_establishment_timeout_secs: input
                .connection_establishment_timeout_secs
                .unwrap_or(defaults.connection_establishment_timeout_secs),
            authentication_timeout_secs: input
                .authentication_timeout_secs
                .unwrap_or(defaults.authentication_timeout_secs),
            resource_binding_timeout_secs: input
                .resource_binding_timeout_secs
                .unwrap_or(defaults.resource_binding_timeout_secs),
            authentication_retries: input
                .authentication_retries
                .unwrap_or(defaults.authentication_retries),
            resource_binding_retries: input
                .resource_binding_retries
                .unwrap_or(defaults.resource_binding_retries),
            connection_attempts_per_ip: input
                .connection_attempts_per_ip
                .with_defaults(defaults.connection_attempts_per_ip),
            incoming_stanzas_per_connection: input
                .incoming_stanzas_per_connection
                .with_defaults(defaults.incoming_stanzas_per_connection),
            new_recipients_per_connection: input
                .new_recipients_per_connection
                .with_defaults(defaults.new_recipients_per_connection),
            incoming_xml_per_connection: input.incoming_xml_per_connection,
        }
    }
}

/// Token-bucket refill rate and capacity, measured in events.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
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

const fn nonzero(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("default limit must be positive"),
    }
}

const fn nonzero_secs(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("default timeout must be positive"),
    }
}
