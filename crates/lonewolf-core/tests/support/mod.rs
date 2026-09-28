// SPDX-License-Identifier: Apache-2.0

mod client;
mod server;
mod tls;
pub mod xml;

pub use client::{Client, PlainClient};
pub use server::C2sSuite;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
pub const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
pub const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
pub const STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";
