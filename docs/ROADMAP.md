# Roadmap to 1.0

Lonewolf's first priority is desktop instant messaging: Basic IM, then Advanced
IM. The final target is a cluster-aware server that satisfies every server
category in the selected XMPP compliance suite.

This roadmap defines capability milestones and their intended implementation
order, with no fixed release dates. Feature dependencies determine the required
order. A milestone may span several releases, and a release may include work from
several milestones. A milestone is complete only after its protocol and
operational checks pass.

Releases ship completed, verified features and receive version numbers when their
scope is agreed. Development releases have no fixed count or assigned milestones;
versions can continue through 0.10.0 and beyond. The 1.0 release requires every
milestone in this roadmap to be complete.

## Compliance baseline

The baseline is [XEP-0479: XMPP Compliance Suites 2023, version
0.1.0](https://xmpp.org/extensions/xep-0479.html). It is Experimental. Desktop
corresponds to Core + IM; the final scope also includes Mobile, Web, and A/V
Calling. The target for every category is Advanced Server.

The XEP tables distinguish three reasons for inclusion:

- **Suite:** a server requirement in the selected compliance suite.
- **Supporting:** a dependency or protocol profile needed by a planned feature.
- **Product:** an additional Lonewolf interoperability requirement.

Every listed requirement is part of the roadmap's 1.0 scope. A compliance claim
requires all applicable requirements and verification checks to pass, regardless
of how many releases deliver them. Support means implementing the applicable
server role and the dependencies required by that role. A client payload needs
correct forwarding and storage where applicable; it does not imply that the
server implements a client interface or decrypts message content.

Implementation trackers must pin specification revisions, namespaces, applicable
requirements, and verification evidence. Reassess this baseline before 1.0 and
record any adopted specification changes explicitly.

## Capability milestones

The order below expresses implementation priority. It does not assign release
numbers or require unrelated features to ship together.

| Milestone | Compliance target |
| --- | --- |
| Current development foundation | Receiving C2S RFC scope |
| Desktop discovery, profiles, and synchronization | Partial Core + IM |
| S2S federation | Authenticated server-to-server interoperability |
| Basic desktop IM | Basic Core + IM, including components, rooms, and uploads |
| Resumption, archives, and blocking | Partial Advanced IM |
| Advanced desktop IM | Advanced Core + IM, including capabilities, PEP, avatars, and bookmarks |
| PostgreSQL storage and two-node cluster | Preserve desktop compliance across nodes |
| Mobile efficiency and push | Advanced Mobile |
| Web transports and calling infrastructure | Advanced Web + A/V Calling |
| Cluster recovery and release qualification | All categories under failure and load |
| 1.0.0: First stable release | All Advanced Server categories + cluster operation |

## Current development foundation

The workspace version is 0.1.0. This describes the implemented foundation, not a
published release or a claim of full server compliance.

The foundation includes local routing, roster and subscriptions, presence,
offline storage and replay, STARTTLS, authentication, resource binding, and
bounded connection limits. Logical sessions, transport ownership, and typed
extension boundaries provide the starting points for later features.

The RFC baseline is [RFC 6120](https://www.rfc-editor.org/rfc/rfc6120.html),
[RFC 6121](https://www.rfc-editor.org/rfc/rfc6121.html),
[RFC 7622](https://www.rfc-editor.org/rfc/rfc7622.html), and
[RFC 7590](https://www.rfc-editor.org/rfc/rfc7590.html), with applicable
[RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) and
[RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) requirements. Federation
remains a separate milestone.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0160](https://xmpp.org/extensions/xep-0160.html) | Offline-message handling profile | Supporting |
| [XEP-0203](https://xmpp.org/extensions/xep-0203.html) | Delay timestamps for stored and replayed messages | Supporting |

Completion evidence must map the implemented RFC and offline profiles to existing
tests and explicit policy choices. The completed [C2S tracker
#136](https://github.com/lonewolf-im/lonewolf/issues/136), [RFC audit tracker
#301](https://github.com/lonewolf-im/lonewolf/issues/301), and [extension tracker
#234](https://github.com/lonewolf-im/lonewolf/issues/234) are starting evidence;
they do not establish S2S or extension compliance.

## Desktop discovery, profiles, and synchronization

Implement discovery first, then vCards and Carbons. Use the existing per-host
extension slots and discovery data.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0030: Service Discovery](https://xmpp.org/extensions/xep-0030.html) | Information and items queries for hosts, accounts, and services | Suite |
| [XEP-0054: vcard-temp](https://xmpp.org/extensions/xep-0054.html) | Account vCard storage and authorized retrieval | Suite |
| [XEP-0280: Message Carbons](https://xmpp.org/extensions/xep-0280.html) | Per-resource enablement and eligible sent/received copies | Suite |
| [XEP-0199: XMPP Ping](https://xmpp.org/extensions/xep-0199.html) | Server replies and routing of entity pings | Product |
| [XEP-0297: Stanza Forwarding](https://xmpp.org/extensions/xep-0297.html) | Forwarded-message envelopes used by Carbons | Supporting |

Milestone completion criteria:

- Two independent desktop clients discover the enabled features and use vCards.
- Multiple resources synchronize eligible messages without recursive copies or
  exposing copies to another account.
- Disabled features are absent from discovery; unsupported requests return the
  appropriate errors.

## S2S federation

Implement authenticated server-to-server federation for messages, IQs,
subscriptions, presence, and service domains, including their certificate
identities and error behavior.

Milestone completion criteria:

- A different server implementation exchanges messages, subscription changes,
  presence, and IQs with Lonewolf; unauthorized sender domains are rejected.
- Federation failures and connection shutdown have bounded, verified outcomes.
  Required deployment services are documented.

Federation can ship with its required dependencies in a release whose only new
capability is S2S support. Discovery, vCards, Carbons, components, rooms, and
uploads follow their own dependencies and completion criteria. Federation alone
does not establish Basic Core + IM compliance.

## Basic desktop IM

Build on federation with components, then built-in MUC and upload services.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0114: Jabber Component Protocol](https://xmpp.org/extensions/xep-0114.html) | Component authentication, domain authorization, routing, and disconnect cleanup | Suite |
| [XEP-0045: Multi-User Chat](https://xmpp.org/extensions/xep-0045.html) | Room discovery, creation, membership, roles, affiliations, administration, and messaging | Suite |
| [XEP-0249: Direct MUC Invitations](https://xmpp.org/extensions/xep-0249.html) | Preserve and route invitation payloads locally and over federation | Suite |
| [XEP-0363: HTTP File Upload](https://xmpp.org/extensions/xep-0363.html) | Slot allocation, authenticated upload authorization, HTTP upload/download, and limits | Suite |
| [XEP-0004: Data Forms](https://xmpp.org/extensions/xep-0004.html) | Forms used by room configuration and later protocol profiles | Supporting |
| [XEP-0128: Service Discovery Extensions](https://xmpp.org/extensions/xep-0128.html) | Extended room and upload discovery information | Supporting |

Milestone completion criteria:

- Basic Core + IM requirements pass for the selected suite.
- Desktop clients create, join, administer, and leave rooms and share files.
- Component loss and interrupted uploads have bounded, verified outcomes.
  Required deployment services are documented.

## Resumption, archives, and blocking

Implement Stream Management in the logical session and MAM through the archive
and query boundaries. Keep the offline queue and message archive as distinct
stores with explicit retention and release rules.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0198: Stream Management](https://xmpp.org/extensions/xep-0198.html) | Stanza acknowledgements, bounded unacknowledged output, and same-node resumption | Suite |
| [XEP-0313: Message Archive Management](https://xmpp.org/extensions/xep-0313.html) | Authorized account archives, filters, paging, and synchronization | Suite |
| [XEP-0191: Blocking Command](https://xmpp.org/extensions/xep-0191.html) | Durable blocklists and policy enforcement for applicable stanzas | Suite |
| [XEP-0359: Unique and Stable Stanza IDs](https://xmpp.org/extensions/xep-0359.html) | Trusted archive identifiers and preservation of client origin identifiers | Supporting |
| [XEP-0059: Result Set Management](https://xmpp.org/extensions/xep-0059.html) | Bounded, stable archive pages | Supporting |

Milestone completion criteria:

- Specify the acceptance event for each stanza class and its crash semantics;
  transport flush, client acknowledgement, and durable commit remain distinct.
- Reconnect tests cover resumption, expiry, counter validation, bounded queues,
  replay, and unsuccessful resumption followed by archive synchronization.
- Blocked traffic cannot bypass policy through federation, services, Carbons,
  archives, or offline delivery.
- Archive retention and account deletion preserve privacy and ordering. Measure
  storage admission and replay costs before changing capacity policy.

## Advanced desktop IM

Implement capabilities and PEP before avatars and bookmarks. Extend MAM to room
archives with room-specific access rules.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0368: SRV records for XMPP over TLS](https://xmpp.org/extensions/xep-0368.html) | Direct TLS listeners and deployment discovery records | Suite |
| [XEP-0115: Entity Capabilities](https://xmpp.org/extensions/xep-0115.html) | Verified capability discovery and bounded caching | Suite |
| [XEP-0163: Personal Eventing Protocol](https://xmpp.org/extensions/xep-0163.html) | Account event nodes and authorized notifications to interested resources | Suite |
| [XEP-0060: Publish-Subscribe](https://xmpp.org/extensions/xep-0060.html) | Operations and node features required by PEP and the selected data profiles | Supporting |
| [XEP-0084: User Avatar](https://xmpp.org/extensions/xep-0084.html) | Avatar data and metadata served through PEP | Supporting |
| [XEP-0153: vCard-Based Avatars](https://xmpp.org/extensions/xep-0153.html) | Server-side avatar compatibility and presence decoration | Suite |
| [XEP-0398: User Avatar to vCard-Based Avatars Conversion](https://xmpp.org/extensions/xep-0398.html) | Consistent PEP-to-vCard avatar conversion | Suite |
| [XEP-0048: Bookmarks](https://xmpp.org/extensions/xep-0048.html) | Legacy bookmark representation and storage compatibility | Suite |
| [XEP-0402: PEP Native Bookmarks](https://xmpp.org/extensions/xep-0402.html) | Native bookmark nodes and specified compatibility conversion | Suite |
| [XEP-0223: Persistent Storage of Private Data via PubSub](https://xmpp.org/extensions/xep-0223.html) | Persistent account-private data with the required access model | Suite |
| [XEP-0049: Private XML Storage](https://xmpp.org/extensions/xep-0049.html) | Legacy private data and bookmark compatibility | Product |
| [XEP-0410: MUC Self-Ping](https://xmpp.org/extensions/xep-0410.html) | Occupant self-ping responses that reflect room membership | Suite |

Milestone completion criteria:

- Advanced Core + IM requirements pass, including account and room MAM.
- Avatars and bookmarks remain consistent across different desktop clients and
  multiple resources, with authorization checked for every access path.
- PEP discovery advertises only supported node features. The required PubSub
  subset does not imply a complete standalone PubSub service.

Private XML Storage is a Lonewolf compatibility choice; the suite recommends it
for legacy bookmarks. Direct TLS deployment records complement listener support.

## PostgreSQL storage and two-node cluster

No new XEP is introduced. Every feature included in a cluster release must work
across node boundaries.

Implement PostgreSQL (PgSQL) as a supported storage backend and verify it on one
node before starting cross-node routing. Keep redb available for embedded,
single-node deployments. Complete the PostgreSQL backend tracker before the
cluster tracker.

Storage requirements:

- Remove concrete redb dependencies from core storage selection and extension
  wiring so operators can select either backend through configuration.
- Cover every persistent feature in this roadmap, including accounts,
  rosters, offline messages, vCards, blocklists, archives, rooms, PEP, and bookmarks.
- Preserve consistent snapshots, stable transactional reads, atomic writes,
  commit/effect ordering, and account deletion/recreation fences. Specify locking
  or isolation and bounded transaction retries; PostgreSQL's default
  [Read Committed isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
  alone does not meet the existing storage contract.
- Use an external PostgreSQL service with a Rust client and TLS dependencies that
  satisfy the project's no-C/C++ application-library rule.
- Bound connection pools and database waits. Verify cancellation, connection
  loss, unknown commit outcomes, and error mapping without duplicate effects.
- Document database connection, TLS, credentials, and pool settings in
  `examples/lonewolf.toml` when the backend is implemented.

Storage completion criteria: the same client workflows pass against redb and
PostgreSQL on one node, with separate transaction and database-failure checks
against a real PostgreSQL instance. Once PostgreSQL is supported, every released
persistent feature must support both backends.

Select the cluster storage topology and ownership model separately. PostgreSQL
provides a shared-storage option; cross-node ordering, ownership, and recovery
still require explicit coordination.

Cluster requirements:

- Keep sockets on the accepting node; assign one fenced owner to each account,
  room, and PEP state domain.
- Authenticate node connections and route through bounded queues with defined
  retry, duplicate, timeout, and overload behavior.
- Use ownership generations so stale owners cannot mutate state after transfer.
- Route federation and component traffic through the same authorized delivery
  rules as local ingress.
- Make sessions, resource conflicts, presence, Carbons, offline replay, archives,
  rooms, and administrative operations consistent across both nodes.

Cluster completion criteria: clients can connect to either node and complete the
desktop workflows. Tests cover ownership transfer, stale-owner rejection,
partitions, node loss, and cleanup. A load balancer alone does not satisfy this
milestone.

## Mobile efficiency and push

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0352: Client State Indication](https://xmpp.org/extensions/xep-0352.html) | Active/inactive state and bounded delivery scheduling | Suite |
| [XEP-0357: Push Notifications](https://xmpp.org/extensions/xep-0357.html) | Authorized registrations, push-service publication, disablement, and cleanup | Suite |

Milestone completion criteria: Advanced Mobile requirements pass. Verify inactive
clients, resumption, archive catch-up, federated push services, registration
expiry or revocation, and provider failure. Notifications must respect blocking,
privacy, and account deletion across nodes.

## Web transports and calling infrastructure

Implement WebSocket first, then BOSH. The server target includes both transports.
Apply [RFC 7395](https://www.rfc-editor.org/rfc/rfc7395.html) to WebSocket framing
and stream behavior.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0124: BOSH](https://xmpp.org/extensions/xep-0124.html) | HTTP binding sessions and bounded request handling | Supporting |
| [XEP-0206: XMPP Over BOSH](https://xmpp.org/extensions/xep-0206.html) | XMPP negotiation and operation over BOSH | Suite |
| [XEP-0156: Discovering Alternative XMPP Connection Methods](https://xmpp.org/extensions/xep-0156.html) | Publish the supported connection endpoints | Product |
| [XEP-0215: External Service Discovery](https://xmpp.org/extensions/xep-0215.html) | STUN/TURN service discovery and authorized temporary credentials | Suite |

Milestone completion criteria:

- Advanced Web + A/V Calling server requirements pass.
- Browser clients authenticate, exchange messages, reconnect, and close over
  WebSocket and BOSH without weakening the existing protocol limits.
- Two compatible clients complete a call using the advertised STUN/TURN
  deployment, including a path that needs a relay.
- Call signaling is routed correctly; media encryption and client Jingle
  behavior remain client responsibilities. The media service is a deployment
  dependency, with no mandatory in-process media implementation.

## Cluster recovery and release qualification

No new XEP is introduced. Qualify the full feature set under failure and load.

Milestone completion criteria:

- Durable acceptance survives loss of one server node within the documented
  storage failure model. Unknown commit outcomes and retries have tested rules.
- Membership and ownership changes prevent conflicting writers during partitions
  and recover without stale presence, subscriptions, or deletion state.
- Resumption requests arriving on another healthy node can reach a live session
  owner. If that owner fails, a fresh login and MAM synchronization provide
  recovery; transparent resumption after owner loss is not a 1.0 requirement.
- Persistent room configuration and affiliations survive owner loss; clients can
  rejoin, and stale occupant state is removed.
- Draining, restart, rebalancing, backup/restore, and the supported rolling-upgrade
  path preserve the published guarantees.
- Mixed-workload tests establish supported capacity and bounded memory, queues,
  archive queries, storage admission, and recovery time. Privacy-safe metrics
  expose saturation and failure.

Define explicit durability, availability, and recovery limits from this evidence.
The roadmap does not promise exactly-once delivery or uninterrupted sessions
during every failure.

## 1.0.0: First stable release

All roadmap milestone requirements are mandatory for 1.0, regardless of the
number or order of development releases. No new XEP is added solely for the
version number.

Release gate:

- Publish a complete compliance matrix for Advanced Core, IM, Mobile, Web, and
  A/V Calling, with pinned specifications and verification evidence.
- Every feature has automated protocol coverage and interoperability evidence
  from independent implementations, including failure and shutdown paths.
- Cluster guarantees are verified for account, room, service, and storage state;
  required external services and supported topologies are documented.
- Configuration, storage compatibility, backup/restore, supported upgrades, and
  operational limits have stable contracts.
- Formatting, strict workspace Clippy, workspace tests, dependency/license checks,
  and required CI pass on the release revision.

## Delivery and scope

Create a tracker for each feature or architectural milestone, with ordered
sub-issues, dependencies, routing labels, and acceptance criteria. A release may
span several trackers or ship completed features from a tracker whose broader
milestone remains open. Discovery is the next planned implementation milestone;
the order may change when feature dependencies permit it.

Define each release's scope and verification checks for the features and
dependencies it includes. Verify their interaction with existing supported
features, including failure and shutdown paths. Apply checks for deferred
features when those features are introduced. Release notes must identify the
shipped capabilities and the compliance level established by the evidence.

Retain the single-node deployment throughout this roadmap. Preserve the project's
allocation, logging, dependency, configuration-reference, and test-organization
rules. PostgreSQL backend support is planned; select its client, cluster storage
topology, coordination service, and replication protocol in implementation
trackers.

The target covers the server compliance categories and their supporting profiles.
Additional XEPs can follow 1.0 without delaying these milestones. Client-only
features require interoperability where they cross server routing, archive,
offline, or PEP boundaries; they do not become separate server implementations.
