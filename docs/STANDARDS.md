# XMPP support

This page lists the XMPP standards that Lonewolf supports. For each one, it explains what you can do with it, how to turn it on, and where support stops.

Out of the box, Lonewolf enables `roster`, `offline`, `disco`, `ping`, `vcard`, `carbons`, `version` and `private`. To choose a different set, set `hosts.<domain>.extensions`. The [configuration reference](../examples/lonewolf.toml) describes every setting.

If you maintain a software directory, [`lonewolf.doap`](../lonewolf.doap) has the same summary in the [XEP-0453](https://xmpp.org/extensions/xep-0453.html) format.

## XMPP extensions

| Specification and reviewed version | What you get | How to enable it | Example tests |
| --- | --- | --- | --- |
| [XEP-0030: Service Discovery, 2.5.0 (2024-04-30)](https://xmpp.org/extensions/attic/xep-0030-2.5.0.html) | Clients and other servers can ask what the server supports and which accounts and services it hosts. A user's resources are listed only to people allowed to see that user's presence. | `disco`. | [Discovery queries](../crates/lonewolf-core/tests/protocol/discovery.rs#L12) |
| [XEP-0049: Private XML Storage, 1.2 (2004-03-01)](https://xmpp.org/extensions/xep-0049.html) | Clients can keep their own settings and legacy bookmarks on the server and read them back from any device. Only the account owner can read or change this data; requests from other users and other servers are refused. Lonewolf does not check what the stored XML means, but it refuses reserved namespaces, such as ones that start with `jabber:`. | `private`. Use `private.max_items` and `private.max_bytes` to change the per-account limits of 50 elements and 2 MiB. | [Storing and reading private data](../crates/lonewolf-core/tests/protocol/private.rs#L62); [Refusing a remote server](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L419) |
| [XEP-0054: vcard-temp, 1.3.0 (2024-06-27)](https://xmpp.org/extensions/attic/xep-0054-1.3.0.html) | Any signed-in user, including users on other servers, can read a public vCard, even when its owner is offline. Only the owner can change it. Lonewolf does not check what the card contains. vCard4 and avatars are not supported. | `vcard`. Use `vcard.max_bytes` to change the 256 KiB size limit. | [Reading a remote vCard](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L87) |
| [XEP-0092: Software Version, 1.1 (2007-02-15)](https://xmpp.org/extensions/xep-0092.html) | Clients and other servers can ask a domain which server software and release it runs. Lonewolf does not reveal the operating system unless you allow it. A request sent to an account gets an error, and a request sent to a connected client reaches that client. | `version`. Set `version.show_os = true` to include the operating system. | [Querying the server](../crates/lonewolf-core/tests/protocol/version.rs#L16); [Querying a remote server](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L298) |
| [XEP-0160: Best Practices for Handling Offline Messages, 1.0.1 (2016-10-07)](https://xmpp.org/extensions/xep-0160.html) | Normal and chat messages sent to an offline user are kept until they come back. They are delivered once the user is available with a session priority of zero or higher. Clients cannot fetch them on demand. | `offline`. Use `max_messages_per_account` to change the limit of 100 messages. | [Receiving stored messages](../crates/lonewolf-core/tests/protocol/offline.rs#L359) |
| [XEP-0178: Best Practices for Use of SASL EXTERNAL with Certificates, 1.2 (2020-08-19)](https://xmpp.org/extensions/attic/xep-0178-1.2.html) | Clients can sign in with a certificate that names an existing account. Other servers sign in with a certificate for their domain, as described in [Federation](#federation). | `tls.client_auth` for clients. `s2s.tls.trust_anchors_path`, `s2s.tls.fetch_crls` and `s2s.tls.crls_path` for servers. | [Client login](../crates/lonewolf-core/tests/protocol/authentication.rs#L1225); [Server login](../crates/lonewolf-core/tests/protocol/s2s/negotiation.rs#L256) |
| [XEP-0199: XMPP Ping, 2.0.1 (2019-03-26)](https://xmpp.org/extensions/attic/xep-0199-2.0.1.html) | Lonewolf answers pings from clients and other servers. A ping to an account gets an answer only if the sender may see that user's presence. Lonewolf never sends pings on its own. | `ping`. | [Pinging a remote account](../crates/lonewolf-core/tests/protocol/s2s/iq.rs#L41) |
| [XEP-0203: Delayed Delivery, 2.0 (2009-09-15)](https://xmpp.org/extensions/xep-0203.html) | Offline messages and saved presence replies carry the time they were originally sent. | `offline` for stored messages. Presence timestamps are always on. | [Offline timestamps](../crates/lonewolf-core/tests/protocol/offline.rs#L359) |
| [XEP-0280: Message Carbons, 1.0.1 (2021-12-26)](https://xmpp.org/extensions/attic/xep-0280-1.0.1.html) | Every connected client of a user sees the same conversation, because Lonewolf copies each sent and received message to the others. This includes messages from other servers. Each client turns Carbons on for itself. Private group-chat messages get no special treatment. | `carbons`. Each client opts in per session. | [Copies across servers](../crates/lonewolf-core/tests/protocol/s2s/messages.rs#L270) |
| [XEP-0288: Bidirectional Server-to-Server Connections, 1.0.1 (2016-10-17)](https://xmpp.org/extensions/xep-0288.html) | Two servers can share one connection for traffic in both directions, no matter which side opened it. Lonewolf offers this to servers that connect to it and asks for it on connections it opens. Requests can include stream limits. A shared connection only carries traffic between the two signed-in domains. Server Dialback and extra domains on a shared connection are not supported. | `s2s.bidirectional`, on by default. | [Sending over a peer's connection](../crates/lonewolf-core/tests/protocol/s2s/bidi.rs#L45); [Receiving over an outbound connection](../crates/lonewolf-core/tests/protocol/s2s/bidi.rs#L280) |
| [XEP-0297: Stanza Forwarding, 1.0 (2013-10-02)](https://xmpp.org/extensions/xep-0297.html) | Carbons copies wrap the original message in the standard forwarding format. Lonewolf has no separate forwarding or archive service. | Comes with `carbons`. | [Forwarded copies](../crates/lonewolf-extension/src/carbons/tests/copy.rs#L173) |
| [XEP-0368: SRV records for XMPP over TLS, 1.1.0 (2019-08-20)](https://xmpp.org/extensions/xep-0368.html) | Outbound federation discovers STARTTLS and direct TLS together through SRV priorities and weights, or uses explicit routes. Direct TLS keeps domain certificate checks and offers `xmpp-server` ALPN; peers can omit ALPN. Clients and servers can connect to dedicated direct-TLS listeners. Client SNI selects a configured host; server SNI selects a federating host or registered service with a covering certificate. The listener selects role-specific ALPN and allows its omission. | Set `tls_mode = "direct"` on a `c2s.listeners` or `s2s.listeners` table. Outbound federation uses the remote domain's `_xmpps-server._tcp` SRV records or an `s2s.routes` endpoint table. | [Client login](../crates/lonewolf-core/tests/protocol/direct_tls.rs#L17); [Federation discovery](../crates/lonewolf-core/tests/protocol/s2s/direct_tls/discovery.rs#L33); [Inbound federation](../crates/lonewolf-core/tests/protocol/s2s/direct_tls.rs#L298); [Certificate renewal](../crates/lonewolf-core/tests/server/acme/direct_tls.rs#L25); [Deadlines and shutdown](../crates/lonewolf-core/tests/server/s2s_direct_tls.rs#L202) |
| [XEP-0440: SASL Channel-Binding Type Capability, 1.0.0 (2025-12-08)](https://xmpp.org/extensions/attic/xep-0440-1.0.0.html) | Tells clients which TLS channel-binding methods they can use with SCRAM-PLUS. SASL2 is not supported. | Always on. Advertised whenever a PLUS mechanism is enabled. | [Login features](../crates/lonewolf-core/tests/protocol/stream.rs#L43) |
| [XEP-0478: Stream Limits Advertisement, 0.2.0](https://xmpp.org/extensions/xep-0478.html) | When talking to other servers, Lonewolf announces its maximum stanza size and idle timeout, both in stream features and in bidirectional requests. On each connection it respects the size limit the peer announces, and answers an oversized stanza with a `policy-violation` error where the protocol allows. A peer's idle timeout does not make Lonewolf send keepalives. Limits are not announced to clients. | `limits.s2s.max_stanza_bytes` and `limits.s2s.idle_timeout_secs`. | [Peer size limits](../crates/lonewolf-core/tests/protocol/s2s/limits.rs#L9) |

## Federation

Federation lets your users talk to users on other XMPP servers. It turns on by default for any host that has a certificate and a public DNS name. The default `localhost` host never federates. While federation is off, Lonewolf does not open a server-to-server listener.

To turn federation off everywhere, set `s2s.enabled = false`. To keep a single host local, set `hosts.<domain>.federation = false`.

### How other servers sign in

Other servers must use STARTTLS or a dedicated direct-TLS listener and then sign in with SASL EXTERNAL, using a trusted certificate for their XMPP domain. The certificate must explicitly allow server authentication (`serverAuth`), as proposed for XEP-0178 1.3.

Lonewolf trusts the bundled public root certificates by default. To use your own roots instead, point `s2s.tls.trust_anchors_path` at a certificate bundle.

### Revocation checks with downloaded CRLs

By default, Lonewolf downloads certificate revocation lists (CRLs) over HTTP from the addresses listed in the peer's certificates. It keeps them in memory. When a peer connects, Lonewolf checks every certificate in its chain, except the trusted root, against these lists.

- If a certificate is revoked, the peer is rejected.
- An outdated cached CRL can still prove that a certificate is revoked, unless the entry is a `certificateHold`. It never proves that a certificate is good.
- If Lonewolf cannot tell whether a certificate is revoked, it accepts the peer.

Open connections are checked again every hour, whenever a cached CRL is due for refresh, and whenever a pending download finishes. This applies to connections whose certificates list a usable CRL address. If a peer turns out to be revoked, Lonewolf closes the connection with `<reset/>`. If the recheck times out or the status is unknown, the connection stays open.

With the bundled public roots, CRLs are only downloaded from public unicast addresses. To stop downloading CRLs, set `s2s.tls.fetch_crls = false`.

### Revocation checks with a local CRL file

If you use your own trust anchors, you can provide CRLs yourself with `s2s.tls.crls_path`. That file then becomes the only source of revocation data, and the rules are stricter:

- The file must contain a matching, current CRL for every certificate Lonewolf checks. A peer is rejected if it is revoked or if its status is unknown.
- Lonewolf rereads the file on every check.
- Open connections are rechecked every hour and closed no later than the earliest `nextUpdate` time in the file.
- If the file cannot be read or is invalid, Lonewolf does not start. If the file is out of date, Lonewolf still starts and serves clients, but federation stays blocked.

Lonewolf does not support OCSP, delta CRLs, indirect CRLs, or CRLs served over HTTPS or LDAP.

### Connections

Servers that support bidirectional streams (XEP-0288) share a single connection for both directions. To use one connection per direction instead, set `s2s.bidirectional = false`.

Outbound federation combines `_xmpp-server._tcp` and `_xmpps-server._tcp` SRV records in one priority and weight order. Explicit routes can also select direct TLS. Incoming federation uses STARTTLS or an explicit direct-TLS listener. Dialback, server-to-server stream management, DANE and POSH are not supported.

### Hosted services and delivery

A registered hosted service can federate when the certificate of a federating host also covers the service's domain. Managed certificates only cover their own host, not separate service domains.

To add a contact on another server, use a full account address such as `user@example.com`. A bare domain does not work.

If a delivery fails, the sender may get an error back. Lonewolf does not resend a transmission that had already started when a connection broke. Messages still waiting to be sent are dropped at shutdown.

## Core protocols

These specifications cover connections, messaging, addresses and authentication. The descriptions below define what Lonewolf supports.

| Specification and publication date | What Lonewolf supports | Example tests |
| --- | --- | --- |
| [RFC 6120 (2011-03)](https://www.rfc-editor.org/rfc/rfc6120.html) | Client sign-in, resource binding, and delivery of messages, presence and IQ requests, with protocol errors where needed. Server-to-server connections follow the [Federation](#federation) rules above. | [Resource binding](../crates/lonewolf-core/tests/protocol/binding.rs#L8); [Two-server chat](../crates/lonewolf-core/tests/protocol/s2s/mod.rs#L24) |
| [RFC 2782 (2000-02)](https://www.rfc-editor.org/rfc/rfc2782.html) | Combines STARTTLS and direct-TLS SRV records by priority and weight. Falls back to the domain's addresses only when neither service advertises records. A sole `.` disables only its service; unusable advertised records do not trigger address fallback. | [Merged service priorities](../crates/lonewolf-core/tests/protocol/s2s/direct_tls/discovery.rs#L65); [No fallback after advertisement](../crates/lonewolf-core/tests/protocol/s2s/direct_tls/discovery.rs#L242) |
| [RFC 5280 §4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12), [§4.2.1.13](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13) and [§6.3 (2008-05)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3) / [RFC 9525 (2023-11)](https://www.rfc-editor.org/rfc/rfc9525.html) | Checks that a trusted certificate names the peer's XMPP domain. Closes the connection when the verified certificate chain expires. Checks revocation with CRLs for client certificates, and for other servers as described in [Federation](#federation). Delta CRLs, indirect CRLs and Common Name fallback are not supported. | [Server identities](../crates/lonewolf-core/src/hosts/peer_identity/tests.rs#L146); [Certificate purpose](../crates/lonewolf-core/src/hosts/peer_identity/tests.rs#L242); [Revoked peers](../crates/lonewolf-core/tests/protocol/s2s/revocation_fetch.rs#L20) |
| [RFC 6121 (2011-03)](https://www.rfc-editor.org/rfc/rfc6121.html) | Chat, contact lists, subscriptions and presence updates, both locally and across servers. Includes pending requests, preapproval and roster versioning. Contact lists need `roster`. | [Adding a remote contact](../crates/lonewolf-core/tests/protocol/s2s/subscriptions.rs#L10); [Remote presence](../crates/lonewolf-core/tests/protocol/s2s/presence.rs#L15) |
| [RFC 7622 (2015-09)](https://www.rfc-editor.org/rfc/rfc7622.html) | Normalizes user and domain names, but keeps the case and spaces of resources. IPv6 zone identifiers are not supported. | [Address preparation](../crates/lonewolf-xmpp/src/jid/tests.rs#L61) |
| [RFC 4422 (2006-06)](https://www.rfc-editor.org/rfc/rfc4422.html) | SCRAM password sign-in and certificate sign-in with EXTERNAL. | [Certificate login](../crates/lonewolf-core/tests/protocol/authentication.rs#L1225) |
| [RFC 5802 (2010-07)](https://www.rfc-editor.org/rfc/rfc5802.html) / [RFC 7677 (2015-11)](https://www.rfc-editor.org/rfc/rfc7677.html) | SCRAM-SHA-1 and SCRAM-SHA-256, with or without TLS channel binding (PLUS). | [SHA-1](../crates/lonewolf-auth/src/scram/tests/internal.rs#L12); [SHA-256](../crates/lonewolf-auth/src/scram/tests/mod.rs#L63) |
| [draft-melnikov-scram-sha-512-05 (2024-12-02)](https://datatracker.ietf.org/doc/html/draft-melnikov-scram-sha-512-05) | Opt-in SCRAM-SHA-512 and SCRAM-SHA-512-PLUS with 64-byte keys, proofs and signatures. Revision 05 is an expired individual Internet-Draft, not an RFC or an IANA-registered SASL mechanism. | [Independent known answer](../crates/lonewolf-auth/src/server/tests/sha512.rs); [Client workflows](../crates/lonewolf-core/tests/protocol/authentication/sha512.rs) |
| [RFC 4013 (2005-02)](https://www.rfc-editor.org/rfc/rfc4013.html) | Prepares SCRAM passwords with SASLprep, so different Unicode spellings of the same password all work. | [Password preparation](../crates/lonewolf-auth/src/scram/tests/mod.rs#L134) |
| [RFC 5929 (2010-07)](https://www.rfc-editor.org/rfc/rfc5929.html) / [RFC 9266 (2022-07)](https://www.rfc-editor.org/rfc/rfc9266.html) | Ties a SCRAM-PLUS sign-in to its TLS connection with `tls-server-end-point` or `tls-exporter`. On TLS 1.2, `tls-exporter` requires Extended Master Secret. `tls-unique` is not supported. | [Certificate binding](../crates/lonewolf-core/tests/protocol/authentication.rs#L195); [TLS 1.2 exporter](../crates/lonewolf-core/tests/protocol/authentication.rs#L48) |
| [RFC 7590 (2015-06)](https://www.rfc-editor.org/rfc/rfc7590.html) / [RFC 9325 (2022-11)](https://www.rfc-editor.org/rfc/rfc9325.html) | Requires STARTTLS or direct TLS, with [TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246.html) or [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html). Older TLS versions and renegotiation are rejected. On server-to-server connections, Lonewolf closes the XML stream before closing TLS, and gives up on peers that do not respond in time. | [TLS and orderly closure](../crates/lonewolf-core/tests/protocol/s2s/mod.rs#L24) |

By default, clients can sign in with SCRAM-SHA-256 or SCRAM-SHA-1, with or without PLUS. EXTERNAL is on by default too. Lonewolf offers it only when the listener allows it and the client presents a verified certificate with a suitable account identity.

SCRAM-SHA-512 and SCRAM-SHA-512-PLUS are disabled by default. Enable either name independently in a listener's `auth_mechanisms` list after checking client support. The advertised order is EXTERNAL, SCRAM-SHA-512-PLUS, SCRAM-SHA-512, SCRAM-SHA-256-PLUS, SCRAM-SHA-256, SCRAM-SHA-1-PLUS, then SCRAM-SHA-1, filtered by that list and the connection's certificate. SASL is offered only after TLS, using STARTTLS or a direct-TLS listener; SASL2 is not supported. The PLUS mechanisms use the same channel bindings and TLS constraints listed above.

Account creation and password replacement derive all three verifier families with independent 16-byte salts and 100,000 iterations. Existing records stay unchanged when the database opens. A stored SHA-1 or SHA-256 verifier cannot produce a SHA-512 verifier without the password, so replace each existing account's password through the administration API or `lonewolfctl account password` before enabling SHA-512. The current password can be reused if it meets the provisioning policy. An account without the selected verifier receives a normal challenge and then `not-authorized`. Rejected password changes preserve the existing credentials.

Creating an account or replacing its password writes the SHA-512 credential block even when both new mechanisms are disabled. Older binaries cannot read these records. Disabling the mechanisms does not restore storage compatibility: retain a database backup from before those writes for rollback. No account migration or automatic password upgrade occurs at startup.
