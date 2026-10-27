// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

mod client;
mod extensions;
mod readiness;
mod server;
pub mod tls;
pub mod xml;

pub use client::{Client, PlainClient};
pub use server::C2sSuite;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub const PASSWORD: &str = "ocean copper lantern meadow";
pub const ALTERNATE_PASSWORD: &str = "forest silver river valley";
pub const OTHER_PASSWORD: &str = "garden cobalt window harbor";
pub const NEW_PASSWORD: &str = "violet cedar cloud orchard";

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub const OPEN: &str = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='localhost' version='1.0'>";
pub const TLS_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-tls";
pub const SASL_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
pub const BIND_NAMESPACE: &str = "urn:ietf:params:xml:ns:xmpp-bind";
pub const ROSTER_VERSIONING_NAMESPACE: &str = "urn:xmpp:features:rosterver";
pub const PRE_APPROVAL_NAMESPACE: &str = "urn:xmpp:features:pre-approval";
pub const STREAM_ERRORS: &str = "urn:ietf:params:xml:ns:xmpp-streams";

const SIGNAL_DIRECTORY: &str = "signals";

#[derive(Clone, Copy, Debug)]
pub enum Signal {
    PrecommitHandlerWaiting,
    PrecommitHandlerCompleted,
    PrecommitHandlerCancelled,
    PrecommitEffectsDelivered,
    PrecommitAudienceWaiting,
    PrecommitBacklogWaiting,
    OfflineStoreWaiting,
    OfflineAcknowledgementWaiting,
    ServicePresenceWaiting,
    ServiceWithdrawalStored,
    ServiceWithdrawalHandled,
}

impl Signal {
    fn file_name(self) -> &'static str {
        match self {
            Self::PrecommitHandlerWaiting => "precommit-handler-waiting",
            Self::PrecommitHandlerCompleted => "precommit-handler-completed",
            Self::PrecommitHandlerCancelled => "precommit-handler-cancelled",
            Self::PrecommitEffectsDelivered => "precommit-effects-delivered",
            Self::PrecommitAudienceWaiting => "precommit-audience-waiting",
            Self::PrecommitBacklogWaiting => "precommit-backlog-waiting",
            Self::OfflineStoreWaiting => "offline-store-waiting",
            Self::OfflineAcknowledgementWaiting => "offline-acknowledgement-waiting",
            Self::ServicePresenceWaiting => "service-presence-waiting",
            Self::ServiceWithdrawalStored => "service-withdrawal-stored",
            Self::ServiceWithdrawalHandled => "service-withdrawal-handled",
        }
    }

    /// Each raise appends one byte, so the file length counts occurrences.
    pub fn path(self, fixture: &Path) -> PathBuf {
        fixture.join(SIGNAL_DIRECTORY).join(self.file_name())
    }

    // The server runs in the fixture directory, so relative paths reach the test.
    fn raise(self) -> std::io::Result<()> {
        fs::create_dir_all(SIGNAL_DIRECTORY)?;
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(Path::new("")))?
            .write_all(b"\n")
    }
}

pub fn barrier(client: &mut Client) -> TestResult {
    client.send("<iq type='get' id='barrier'><query xmlns='urn:test:barrier'/></iq>")?;
    client.expect_xml("<iq xmlns='jabber:client' type='error' id='barrier'><query xmlns='urn:test:barrier'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>The requested service or operation is unavailable for this target. Check the address and requested feature.</text></error></iq>")
}

pub fn mutually_subscribe(
    left: &mut Client,
    left_name: &str,
    right: &mut Client,
    right_name: &str,
) -> TestResult {
    left.send(&format!(
        "<presence type='subscribed' to='{right_name}@localhost'/>"
    ))?;
    barrier(left)?;
    right.send(&format!("<presence type='subscribe' to='{left_name}@localhost'/><presence type='subscribed' to='{left_name}@localhost'/>"))?;
    barrier(right)?;
    left.send(&format!(
        "<presence type='subscribe' to='{right_name}@localhost'/>"
    ))?;
    barrier(left)
}

pub fn toggle(client: &mut Client, enabled: bool) -> TestResult {
    client.send(&format!("<iq type='set' to='localhost' id='toggle'><toggle xmlns='urn:lonewolf:test:policy' enabled='{enabled}'/></iq>"))?;
    let reply = client.receive()?;
    reply.assert_name("jabber:client", "iq");
    assert_eq!(reply.attribute("type"), Some("result"), "{reply:?}");
    assert_eq!(reply.attribute("id"), Some("toggle"), "{reply:?}");
    assert_eq!(reply.attribute("from"), Some("localhost"), "{reply:?}");
    assert!(reply.children.is_empty(), "{reply:?}");
    Ok(())
}
