// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use lonewolf_admin::{S2sConnection, S2sConnections, S2sDirection, S2sTlsMode};
use parking_lot::Mutex as PlMutex;
use rustls::{CommonState, ProtocolVersion};

use super::metrics::Direction;
use crate::config::TlsMode;

#[derive(Default)]
pub(crate) struct ConnectionTraffic {
    received: AtomicU64,
    sent: AtomicU64,
}

impl ConnectionTraffic {
    pub(crate) fn received(&self, bytes: u64) {
        self.received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn sent(&self, bytes: u64) {
        self.sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(in crate::s2s) fn totals(&self) -> (u64, u64) {
        (
            self.received.load(Ordering::Relaxed),
            self.sent.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TlsSummary {
    pub(crate) version: &'static str,
    pub(crate) cipher_suite: &'static str,
}

impl TlsSummary {
    pub(crate) fn of(state: &CommonState) -> Self {
        Self {
            version: tls_version(state.protocol_version()),
            cipher_suite: state
                .negotiated_cipher_suite()
                .and_then(|suite| suite.suite().as_str())
                .unwrap_or("unknown"),
        }
    }
}

fn tls_version(version: Option<ProtocolVersion>) -> &'static str {
    match version {
        Some(ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "unknown",
    }
}

pub(crate) struct ConnectionFacts {
    pub(crate) connection_id: u64,
    pub(crate) direction: Direction,
    pub(crate) local: Arc<str>,
    pub(crate) remote: Arc<str>,
    pub(crate) remote_address: Option<SocketAddr>,
    pub(crate) tls_mode: TlsMode,
    pub(crate) tls: TlsSummary,
    pub(crate) certificate_expires_at: SystemTime,
    pub(crate) traffic: Arc<ConnectionTraffic>,
}

#[derive(Default)]
pub(crate) struct ConnectionRegistry {
    // Workers share this lock only to insert, remove, or copy one page.
    entries: PlMutex<BTreeMap<u64, Entry>>,
}

struct Entry {
    facts: ConnectionFacts,
    bidirectional: bool,
    established: Instant,
    established_at: SystemTime,
}

impl ConnectionRegistry {
    pub(crate) fn register(
        self: &Arc<Self>,
        facts: ConnectionFacts,
        bidirectional: bool,
    ) -> Registration {
        let connection_id = facts.connection_id;
        let entry = Entry {
            facts,
            bidirectional,
            established: Instant::now(),
            established_at: SystemTime::now(),
        };
        self.entries.lock().insert(connection_id, entry);
        Registration {
            registry: Arc::clone(self),
            connection_id,
        }
    }

    fn page_at(
        &self,
        now: Instant,
        after: Option<u64>,
        remote_domain: Option<&str>,
        limit: NonZeroUsize,
    ) -> Vec<S2sConnection> {
        self.entries
            .lock()
            .range((after.map_or(Unbounded, Excluded), Unbounded))
            .map(|(_, entry)| entry)
            .filter(|entry| remote_domain.is_none_or(|domain| domain == &*entry.facts.remote))
            .take(limit.get())
            .map(|entry| {
                let facts = &entry.facts;
                let (bytes_received, bytes_sent) = facts.traffic.totals();
                S2sConnection {
                    connection_id: facts.connection_id,
                    direction: match facts.direction {
                        Direction::Inbound => S2sDirection::Inbound,
                        Direction::Outbound => S2sDirection::Outbound,
                    },
                    bidirectional: entry.bidirectional,
                    local_domain: Arc::clone(&facts.local),
                    remote_domain: Arc::clone(&facts.remote),
                    remote_address: facts.remote_address,
                    tls_mode: match facts.tls_mode {
                        TlsMode::StartTls => S2sTlsMode::StartTls,
                        TlsMode::Direct => S2sTlsMode::Direct,
                    },
                    tls_version: facts.tls.version,
                    cipher_suite: facts.tls.cipher_suite,
                    established_at: entry.established_at,
                    uptime: now.saturating_duration_since(entry.established),
                    certificate_expires_at: facts.certificate_expires_at,
                    bytes_received,
                    bytes_sent,
                }
            })
            .collect()
    }
}

impl S2sConnections for ConnectionRegistry {
    fn connections(
        &self,
        after: Option<u64>,
        remote_domain: Option<&str>,
        limit: NonZeroUsize,
    ) -> Vec<S2sConnection> {
        self.page_at(Instant::now(), after, remote_domain, limit)
    }
}

#[must_use]
pub(crate) struct Registration {
    registry: Arc<ConnectionRegistry>,
    connection_id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.registry.entries.lock().remove(&self.connection_id);
    }
}

#[cfg(test)]
mod tests;
