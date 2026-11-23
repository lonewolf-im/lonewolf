// SPDX-License-Identifier: Apache-2.0

use crate::support::{C2sSuite, TestResult};

mod blocking;
mod direct_tls;
mod loss;
mod negotiation;
mod registry;
mod roster;
mod routing;
mod stream;
mod stream_conformance;
mod workflows;

#[test]
fn configured_component_domains_register_the_component_catalog() -> TestResult {
    let mut suite = C2sSuite::with_components(
        "[components.domains.'muc.example.com']\nsecret = 'component-test-secret-0001'",
    )?;
    let body = suite.wait_for_metric("lonewolf_component_domains 1")?;
    for sample in [
        "lonewolf_component_connections 0",
        "lonewolf_component_streams 0",
        "lonewolf_component_queued_stanzas 0",
        "lonewolf_component_queued_bytes 0",
    ] {
        assert!(body.lines().any(|line| line == sample), "{body}");
    }
    assert!(!body.contains("lonewolf_lonewolf_"), "{body}");
    assert!(!body.contains("muc.example.com"), "{body}");
    assert!(!body.contains("component-test-secret-0001"), "{body}");
    suite.stop()
}
