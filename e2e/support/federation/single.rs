// SPDX-License-Identifier: Apache-2.0

use super::{
    FakeDns, FederatedHost, FederationCa, HostRevocation,
    peer::{self, RawS2sPeer},
};
use crate::support::{C2sSuite, TestResult};
use std::sync::Arc;

pub(crate) struct SingleServer {
    pub suite: C2sSuite,
    pub dns: FakeDns,
    pub ca: Arc<FederationCa>,
    pub directory: tempfile::TempDir,
}

impl SingleServer {
    pub fn start(extra: &str) -> TestResult<Self> {
        Self::start_with(extra, Default::default(), Some(false), "")
    }

    pub fn start_with_revocation(extra: &str, revocation: HostRevocation) -> TestResult<Self> {
        Self::start_with(extra, revocation, Some(false), "")
    }

    pub fn start_bidirectional(extra: &str) -> TestResult<Self> {
        Self::start_with(extra, Default::default(), None, "")
    }

    pub fn start_bidirectional_with_extensions(extra: &str, extensions: &str) -> TestResult<Self> {
        Self::start_with(extra, Default::default(), None, extensions)
    }

    fn start_with(
        extra: &str,
        revocation: HostRevocation,
        bidirectional: Option<bool>,
        extensions: &str,
    ) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let ca = Arc::new(FederationCa::new(directory.path())?);
        let dns = FakeDns::start()?;
        let suite = C2sSuite::federated(FederatedHost {
            domain: "a.test".into(),
            certificate_names: Vec::new(),
            revocation,
            enabled: None,
            bidirectional,
            federation: None,
            extensions: extensions.into(),
            extra_toml: extra.into(),
            ca: Arc::clone(&ca),
            dns: dns.address(),
            completion: None,
        })?;
        Ok(Self {
            suite,
            dns,
            ca,
            directory,
        })
    }

    pub fn set_transport(&mut self, mode: lonewolf_core::config::TlsMode) -> TestResult {
        if mode == lonewolf_core::config::TlsMode::Direct {
            let path = self.suite.fixture_path().join("lonewolf.toml");
            let config = std::fs::read_to_string(&path)?;
            let listeners = "listeners = [{ address = \"127.0.0.1:0\" }]";
            assert!(config.contains(listeners));
            std::fs::write(
                path,
                config.replacen(
                    listeners,
                    "listeners=[{address='127.0.0.1:0',tls_mode='direct'}]",
                    1,
                ),
            )?;
            self.suite.restart()?;
        }
        Ok(())
    }

    pub fn connect(&self) -> TestResult<RawS2sPeer> {
        let config = lonewolf_core::config::Config::load(Some(
            &self.suite.fixture_path().join("lonewolf.toml"),
        ))?;
        Ok(
            RawS2sPeer::connect(self.suite.s2s_addresses()?[0], "b.test", "a.test")?
                .expecting_limits(
                    config.limits.s2s.max_stanza_bytes.get().try_into()?,
                    config.limits.s2s.idle_timeout_secs.get().try_into()?,
                ),
        )
    }

    pub fn client_config(&self) -> TestResult<Arc<rustls::ClientConfig>> {
        peer::client_config(
            &self.ca,
            self.ca.server(self.directory.path(), "peer", &["b.test"])?,
        )
    }

    pub fn stop(&mut self) -> TestResult {
        super::assert_direct_transport_metrics(&self.suite)?;
        let state = self.suite.stop_with_s2s_state()?;
        super::assert_shutdown_empty(state);
        self.dns.stop()
    }
}

pub(crate) fn encrypted(fixture: &SingleServer) -> TestResult<RawS2sPeer> {
    let mut peer = fixture.connect()?;
    peer.expect_starttls_features()?;
    let mut peer = peer.start_tls(fixture.client_config()?)?;
    peer.expect_external_and_bidi_offered()?;
    Ok(peer)
}

pub(crate) fn authenticated(fixture: &SingleServer) -> TestResult<RawS2sPeer> {
    let mut peer = encrypted(fixture)?;
    peer.request_bidi()?;
    peer.auth_external(Some("b.test"))?;
    peer.expect_sasl_success()?;
    let peer = peer.restart("b.test", "a.test")?;
    fixture
        .suite
        .wait_for_metric("lonewolf_s2s_bidi_streams{direction=\"inbound\"} 1")?;
    Ok(peer)
}
