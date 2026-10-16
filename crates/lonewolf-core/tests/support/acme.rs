// SPDX-License-Identifier: Apache-2.0

#[path = "acme/ca.rs"]
mod ca;
#[allow(dead_code)]
#[path = "client.rs"]
mod client;
#[path = "acme/process.rs"]
pub mod process;
#[path = "acme/proxy.rs"]
mod proxy;
#[allow(dead_code)]
#[path = "tls.rs"]
pub mod tls;
#[allow(dead_code)]
#[path = "xml.rs"]
pub mod xml;

pub use ca::{AcmeFault, AcmeStage, FakeAcmeCa, http_get};
pub use client::{Client, PlainClient};
pub use process::AcmeServer as C2sSuite;
pub use proxy::ChallengeProxy;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
pub const PASSWORD: &str = "ocean copper lantern meadow";
pub const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
pub const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
pub const ROSTER_VERSIONING_NAMESPACE: &str = "urn:xmpp:features:rosterver";
pub const PRE_APPROVAL_NAMESPACE: &str = "urn:xmpp:features:pre-approval";
pub const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='xmpp.example.test' version='1.0'>";

pub const STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";
