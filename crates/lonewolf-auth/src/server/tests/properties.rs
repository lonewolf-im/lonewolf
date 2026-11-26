// SPDX-License-Identifier: Apache-2.0

use proptest::prelude::*;

use crate::server::{BindingType, ClientFirst, Mechanism, ServerError};

fn sasl_name(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}

proptest! {
    #[test]
    #[ignore = "runs in the XMPP property workflow"]
    fn property_scram_client_first(
        username in "[a-zA-Z,=é李]{1,24}",
        authzid in prop::option::of("[a-zA-Z,=é李]{1,24}"),
        nonce in "[a-zA-Z0-9+=/]{1,32}",
        offered in any::<bool>(),
    ) {
        let authz = authzid.as_deref().map_or_else(String::new, |name| format!("a={}", sasl_name(name)));
        let fields = format!(",{authz},n={},r={nonce}", sasl_name(&username));
        for (flag, mechanism, binding_offered, binding) in [
            ("n", Mechanism::Sha256, offered, None),
            ("y", Mechanism::Sha256, offered, None),
            ("p=tls-exporter", Mechanism::Sha256Plus, true, Some(BindingType::TlsExporter)),
            ("p=tls-server-end-point", Mechanism::Sha256Plus, true, Some(BindingType::TlsServerEndPoint)),
        ] {
            let wire = format!("{flag}{fields}");
            let parsed = ClientFirst::parse(mechanism, wire.as_bytes(), binding_offered);
            if flag == "y" && binding_offered {
                prop_assert_eq!(parsed.err(), Some(ServerError::ChannelBindingMismatch));
                continue;
            }
            let first = parsed.expect("valid SCRAM client-first message");
            prop_assert_eq!(first.username(), username.as_str());
            prop_assert_eq!(first.authzid(), authzid.as_deref());
            prop_assert_eq!(first.nonce.as_str(), nonce.as_str());
            prop_assert_eq!(first.binding(), binding);
        }
    }
}
