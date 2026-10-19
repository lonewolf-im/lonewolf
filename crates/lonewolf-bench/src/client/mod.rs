// SPDX-License-Identifier: Apache-2.0

mod scram;
mod transport;
mod xml;

#[cfg(test)]
mod tests;

use std::{
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{sync::mpsc, time::Instant};

use crate::error::{BenchError, BenchResult, ErrorCode};

pub use scram::{KeyMode, PreparedAccount};
pub(crate) use transport::MessageSetup;
pub use transport::{
    ClientSession, SessionReader, SessionWriter, TlsTransport, connect, local_tls_config,
    remote_tls_config, shutdown,
};

pub struct ResolvedTarget {
    pub address: SocketAddr,
    /// Controls stream addressing, SNI and certificate identity, including through a tunnel.
    pub xmpp_domain: String,
    /// Use local_tls_config or remote_tls_config to select the permitted trust policy and provider.
    pub tls: Arc<rustls::ClientConfig>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectTimings {
    pub tcp_us: u64,
    pub starttls_us: u64,
    pub authenticate_us: u64,
    pub bind_us: u64,
    pub total_us: u64,
}

#[derive(Clone, Debug)]
pub struct NegotiatedTls {
    pub version: rustls::ProtocolVersion,
    pub cipher: rustls::CipherSuite,
}

#[derive(Clone, Debug)]
pub struct SessionIdentity {
    pub bound_jid: String,
    pub tls: NegotiatedTls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TrafficPhase {
    Warmup,
    Measurement,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct CorrelationId {
    pub run_nonce: [u8; 16],
    pub phase: TrafficPhase,
    pub sequence: u64,
}

pub type OperationId = CorrelationId;

impl CorrelationId {
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() > 55 {
            return None;
        }
        let mut parts = value.split('.');
        let nonce = parts.next()?;
        let phase = match parts.next()? {
            "w" => TrafficPhase::Warmup,
            "m" => TrafficPhase::Measurement,
            _ => return None,
        };
        let sequence = parts.next()?;
        if parts.next().is_some()
            || nonce.len() != 32
            || sequence.is_empty()
            || (sequence.len() > 1 && sequence.starts_with('0'))
            || !sequence.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let sequence = sequence.parse().ok()?;
        if sequence >= 10_000_000 {
            return None;
        }
        let mut run_nonce = [0; 16];
        for (i, pair) in nonce.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            fn digit(byte: u8) -> Option<u8> {
                match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    _ => None,
                }
            }
            run_nonce[i] = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Some(Self {
            run_nonce,
            phase,
            sequence,
        })
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CorrelationId([redacted])")
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.run_nonce {
            write!(f, "{byte:02x}")?;
        }
        write!(
            f,
            ".{}.{}",
            match self.phase {
                TrafficPhase::Warmup => 'w',
                TrafficPhase::Measurement => 'm',
            },
            self.sequence
        )
    }
}

#[derive(Clone, Debug)]
pub struct MessageRoute {
    pub to: String,
}

#[derive(Clone, Debug)]
pub struct ReceiveRoute {
    pub from: String,
    pub body_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct MessageCommand {
    pub operation: OperationId,
    pub scheduled_at: Instant,
    pub route_index: u32,
    pub phase: TrafficPhase,
}

#[derive(Clone, Copy, Debug)]
pub enum WriteCommand {
    Message(MessageCommand),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyValidation {
    pub bytes: usize,
    pub ascii_x: bool,
}

#[derive(Clone, Debug)]
pub enum ReceivedKind {
    Chat {
        correlation: Option<CorrelationId>,
        from: Option<String>,
        to: Option<String>,
        body: BodyValidation,
        route_valid: bool,
    },
    StanzaError {
        correlation: Option<CorrelationId>,
        condition: &'static str,
    },
    StreamEnd,
    StreamError,
    Unexpected,
}

#[derive(Clone, Debug)]
pub struct ReceivedEvent {
    pub at: Instant,
    pub kind: ReceivedKind,
}

#[derive(Clone, Debug)]
pub enum WriterEvent {
    WriteStarted {
        operation: OperationId,
        at: Instant,
    },
    WriteCompleted {
        operation: OperationId,
        at: Instant,
        bytes: usize,
    },
    WriteFailed {
        operation: OperationId,
        at: Instant,
    },
}

#[derive(Clone)]
pub struct EventSink {
    sender: mpsc::Sender<WriterEvent>,
    invalid: Arc<AtomicBool>,
}

impl EventSink {
    pub fn bounded(
        capacity: std::num::NonZeroUsize,
        invalid: Arc<AtomicBool>,
    ) -> (Self, mpsc::Receiver<WriterEvent>) {
        let (sender, receiver) = mpsc::channel(capacity.get());
        (Self { sender, invalid }, receiver)
    }

    pub fn emit(&self, event: WriterEvent) -> BenchResult<()> {
        self.sender.try_send(event).map_err(|_| {
            self.invalid.store(true, Ordering::Release);
            failure("event_queue_overflow")
        })
    }

    pub fn run_invalid(&self) -> bool {
        self.invalid.load(Ordering::Acquire)
    }
}

fn failure(context: &'static str) -> BenchError {
    BenchError::new(ErrorCode::Runtime, context)
}

fn micros(duration: Duration) -> u64 {
    duration.as_micros().try_into().unwrap_or(u64::MAX)
}
