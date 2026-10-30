# XMPP support

This page describes the XMPP features available in Lonewolf. The tables show what each feature does, how to enable it, and its main limits.

Lonewolf enables `roster`, `offline`, `disco`, `ping`, `vcard` and `carbons` by default. Set `hosts.<domain>.extensions` to choose a different set. See the [configuration reference](../examples/lonewolf.toml) for available settings.

[`lonewolf.doap`](../lonewolf.doap) provides a summary for software directories in the [XEP-0453](https://xmpp.org/extensions/xep-0453.html) format.

The [v0.2.0 release](https://github.com/lonewolf-im/lonewolf/releases/tag/v0.2.0) introduced local support for XEP-0030, XEP-0054, XEP-0199, XEP-0280 and XEP-0297. The other listed extensions first shipped in v0.1.0. Federation support is not in a release yet.

## XMPP extensions

| Specification and reviewed version | What you can use | Settings | Example tests |
| --- | --- | --- | --- |
| [XEP-0030: Service Discovery, 2.5.0 (2024-04-30)](https://xmpp.org/extensions/attic/xep-0030-2.5.0.html) | Clients and other servers can discover server features, accounts and hosted services. Account resource listings respect presence permissions. | `disco`. | [Discovery queries](../crates/lonewolf-core/tests/protocol/discovery.rs#L12) |
| [XEP-0054: vcard-temp, 1.3.0 (2024-06-27)](https://xmpp.org/extensions/attic/xep-0054-1.3.0.html) | Authenticated users, including users on other servers, can read public vCards even while the owner is offline. Only owners can edit them. Lonewolf does not check the card's contents. vCard4 and avatars are not supported. | `vcard`; `vcard.max_bytes` sets the size limit, which defaults to 256 KiB. | [Reading a remote vCard](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L87) |
| [XEP-0160: Best Practices for Handling Offline Messages, 1.0.1 (2016-10-07)](https://xmpp.org/extensions/xep-0160.html) | Stores normal and chat messages for offline users. Messages arrive when the user becomes available with a session priority of zero or higher. Clients cannot fetch them on demand. | `offline`; `max_messages_per_account` sets the limit, which defaults to 100. | [Receiving stored messages](../crates/lonewolf-core/tests/protocol/offline.rs#L359) |
| [XEP-0178: Best Practices for Use of SASL EXTERNAL with Certificates, 1.2 (2020-08-19)](https://xmpp.org/extensions/attic/xep-0178-1.2.html) | Clients can sign in with a certificate that names an existing account. Other servers authenticate with certificates for their domains, as described below. | `tls.client_auth` for clients; `s2s.tls.trust_anchors_path` for servers. | [Client login](../crates/lonewolf-core/tests/protocol/authentication.rs#L1225); [Server login](../crates/lonewolf-core/tests/protocol/s2s/negotiation.rs#L247) |
| [XEP-0199: XMPP Ping, 2.0.1 (2019-03-26)](https://xmpp.org/extensions/attic/xep-0199-2.0.1.html) | Answers pings from clients and other servers. Account pings respect who may see that user's presence. Lonewolf does not send periodic pings. | `ping`. | [Pinging a remote account](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L41) |
| [XEP-0203: Delayed Delivery, 2.0 (2009-09-15)](https://xmpp.org/extensions/xep-0203.html) | Adds timestamps to offline messages and saved presence replies. | `offline` for stored messages; presence timestamps are built in. | [Offline timestamps](../crates/lonewolf-core/tests/protocol/offline.rs#L359) |
| [XEP-0280: Message Carbons, 1.0.1 (2021-12-26)](https://xmpp.org/extensions/attic/xep-0280-1.0.1.html) | Keeps a user's connected clients in sync by copying sent and received messages, including federated messages. Each client must enable Carbons. Private group-chat messages receive no special handling. | `carbons`; clients opt in for each session. | [Copies across servers](../crates/lonewolf-core/tests/protocol/s2s/messages.rs#L270) |
| [XEP-0297: Stanza Forwarding, 1.0 (2013-10-02)](https://xmpp.org/extensions/xep-0297.html) | Carbons copies include the original message in the standard forwarding format. Lonewolf does not provide a separate forwarding or archive service. | Included with `carbons`. | [Forwarded copies](../crates/lonewolf-extension/src/carbons/tests/copy.rs#L173) |
| [XEP-0440: SASL Channel-Binding Type Capability, 1.0.0 (2025-12-08)](https://xmpp.org/extensions/attic/xep-0440-1.0.0.html) | Tells clients which TLS channel-binding methods are available for SCRAM-PLUS. SASL2 is not supported. | Built in; advertised when a PLUS mechanism is enabled. | [Login features](../crates/lonewolf-core/tests/protocol/stream.rs#L43) |

## Federation

Federation turns on by default for hosts with a configured certificate and a public DNS name. Set `s2s.enabled = false` to disable it globally, or `hosts.<domain>.federation = false` to keep one host local. The default `localhost` does not federate, and no S2S listener opens while federation is inactive.

Peers must use STARTTLS and SASL EXTERNAL with a trusted certificate for their XMPP domain. Certificates must explicitly allow server authentication (`serverAuth`), as proposed for XEP-0178 1.3. Trust uses the bundled public roots or the bundle in `s2s.tls.trust_anchors_path`; certificate revocation is not checked. Dialback, bidirectional streams, Direct TLS, S2S stream management, DANE and POSH are not supported.

Registered hosted services can federate when a federating host's certificate also covers the service domain. Managed certificates cover only their host, not separate service domains. Remote contact subscriptions require an account address such as `user@example.com`, not just a domain. Failed deliveries can return errors; transmissions that have begun are not replayed after a connection breaks. Shutdown discards messages still waiting to be sent.

## Core protocols

These RFCs cover connections, messaging, addresses and authentication. The descriptions below define Lonewolf's supported scope.

| Specification and publication date | What Lonewolf supports | Example tests |
| --- | --- | --- |
| [RFC 6120 (2011-03)](https://www.rfc-editor.org/rfc/rfc6120.html) | Client login, resource binding, and delivery of messages, presence and IQ requests, with protocol errors when needed. Server-to-server connections follow the federation profile above. | [Resource binding](../crates/lonewolf-core/tests/protocol/binding.rs#L8); [Two-server chat](../crates/lonewolf-core/tests/protocol/s2s/mod.rs#L22) |
| [RFC 2782 (2000-02)](https://www.rfc-editor.org/rfc/rfc2782.html) | Finds remote servers through DNS SRV records and honors their priority and weight. Uses the domain's addresses only when no usable SRV answer exists; an SRV target of `.` means no service. | [SRV ordering](../crates/lonewolf-core/src/s2s/dns/tests.rs#L136) |
| [RFC 5280 §4.2.1.12 (2008-05)](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12) / [RFC 9525 (2023-11)](https://www.rfc-editor.org/rfc/rfc9525.html) | Checks that a trusted certificate names the peer's XMPP domain. Connections close when the verified certificate chain expires. Common Name fallback is not supported. | [Server identities](../crates/lonewolf-core/src/hosts/peer_identity/tests.rs#L145); [Certificate purpose](../crates/lonewolf-core/src/hosts/peer_identity/tests.rs#L241) |
| [RFC 6121 (2011-03)](https://www.rfc-editor.org/rfc/rfc6121.html) | Local and federated chat, contact lists, subscriptions and presence updates. Supports pending requests, preapproval and roster versioning. Contact lists require `roster`. | [Adding a remote contact](../crates/lonewolf-core/tests/protocol/s2s/subscriptions.rs#L10); [Remote presence](../crates/lonewolf-core/tests/protocol/s2s/presence.rs#L15) |
| [RFC 7622 (2015-09)](https://www.rfc-editor.org/rfc/rfc7622.html) | Normalizes user and domain names while preserving resource case and spaces. IPv6 zone identifiers are not supported. | [Address preparation](../crates/lonewolf-xmpp/src/jid/tests.rs#L61) |
| [RFC 4422 (2006-06)](https://www.rfc-editor.org/rfc/rfc4422.html) | Supports SCRAM password authentication and certificate-based EXTERNAL. | [Certificate login](../crates/lonewolf-core/tests/protocol/authentication.rs#L1225) |
| [RFC 5802 (2010-07)](https://www.rfc-editor.org/rfc/rfc5802.html) / [RFC 7677 (2015-11)](https://www.rfc-editor.org/rfc/rfc7677.html) | Supports SCRAM-SHA-1 and SCRAM-SHA-256, with and without TLS channel binding (PLUS). | [SHA-1](../crates/lonewolf-auth/src/scram/tests/internal.rs#L12); [SHA-256](../crates/lonewolf-auth/src/scram/tests/mod.rs#L63) |
| [RFC 4013 (2005-02)](https://www.rfc-editor.org/rfc/rfc4013.html) | Prepares SCRAM passwords with SASLprep so equivalent Unicode spellings work consistently. | [Password preparation](../crates/lonewolf-auth/src/scram/tests/mod.rs#L134) |
| [RFC 5929 (2010-07)](https://www.rfc-editor.org/rfc/rfc5929.html) / [RFC 9266 (2022-07)](https://www.rfc-editor.org/rfc/rfc9266.html) | Binds SCRAM-PLUS login to the TLS connection using `tls-server-end-point` or `tls-exporter`. TLS 1.2 exporter binding requires Extended Master Secret; `tls-unique` is not supported. | [Certificate binding](../crates/lonewolf-core/tests/protocol/authentication.rs#L195); [TLS 1.2 exporter](../crates/lonewolf-core/tests/protocol/authentication.rs#L48) |
| [RFC 7590 (2015-06)](https://www.rfc-editor.org/rfc/rfc7590.html) / [RFC 9325 (2022-11)](https://www.rfc-editor.org/rfc/rfc9325.html) | Requires STARTTLS with [TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246.html) or [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html). Older versions and renegotiation are rejected. S2S closes XML before TLS, with a deadline for unresponsive peers. | [TLS and orderly closure](../crates/lonewolf-core/tests/protocol/s2s/mod.rs#L22) |

By default, clients can use SCRAM-SHA-256 or SCRAM-SHA-1, with or without PLUS. EXTERNAL is also enabled by default, but is offered only when the listener allows it and the client presents a verified certificate with a suitable account identity.
