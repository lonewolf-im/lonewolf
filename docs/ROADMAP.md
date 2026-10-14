# Roadmap to 1.0

Lonewolf's first priority is desktop instant messaging: Basic IM, then Advanced
IM. The final target is a cluster-aware server that satisfies every server
category in the selected XMPP compliance suite.

This is a release plan. Versions identify cumulative milestones, with no fixed
release dates. Each release retains the requirements of earlier releases. A
milestone is complete only after its protocol and operational checks pass.

## Compliance baseline

The baseline is [XEP-0479: XMPP Compliance Suites 2023, version
0.1.0](https://xmpp.org/extensions/xep-0479.html). It is Experimental. Desktop
corresponds to Core + IM; the final scope also includes Mobile, Web, and A/V
Calling. The target for every category is Advanced Server.

The XEP tables distinguish three reasons for inclusion:

- **Suite:** a server requirement in the selected compliance suite.
- **Supporting:** a dependency or protocol profile needed by a planned feature.
- **Product:** an additional Lonewolf interoperability requirement.

Every listed requirement is part of the release scope. Support means implementing
the applicable server role and the dependencies required by that role. A client
payload needs correct forwarding and storage where applicable; it does not imply
that the server implements a client interface or decrypts message content.

Implementation trackers must pin specification revisions, namespaces, applicable
requirements, and verification evidence. Reassess this baseline before 1.0 and
record any adopted specification changes explicitly.

## Release sequence

| Version | Milestone | Compliance target |
| --- | --- | --- |
| 0.1.0 | Current development foundation | Receiving C2S RFC scope |
| 0.2.0 | Desktop discovery, profiles, and synchronization | Partial Core + IM |
| 0.3.0 | Federation, components, rooms, and uploads | Basic Core + IM |
| 0.4.0 | Resumption, archives, and blocking | Partial Advanced IM |
| 0.5.0 | Capabilities, PEP, avatars, and bookmarks | Advanced Core + IM |
| 0.6.0 | Two-node cluster | Preserve desktop compliance across nodes |
| 0.7.0 | Mobile efficiency and push | Advanced Mobile |
| 0.8.0 | Web transports and calling infrastructure | Advanced Web + A/V Calling |
| 0.9.0 | Cluster recovery and release qualification | All categories under failure and load |
| 1.0.0 | First stable release | All Advanced Server categories + cluster operation |

## 0.1.0: Current development foundation

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

## 0.2.0: Desktop discovery, profiles, and synchronization

Implement discovery first, then vCards and Carbons. Use the existing per-host
extension slots and discovery data.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0030: Service Discovery](https://xmpp.org/extensions/xep-0030.html) | Information and items queries for hosts, accounts, and services | Suite |
| [XEP-0054: vcard-temp](https://xmpp.org/extensions/xep-0054.html) | Account vCard storage and authorized retrieval | Suite |
| [XEP-0280: Message Carbons](https://xmpp.org/extensions/xep-0280.html) | Per-resource enablement and eligible sent/received copies | Suite |
| [XEP-0199: XMPP Ping](https://xmpp.org/extensions/xep-0199.html) | Server replies and routing of entity pings | Product |
| [XEP-0297: Stanza Forwarding](https://xmpp.org/extensions/xep-0297.html) | Forwarded-message envelopes used by Carbons | Supporting |

Release gate:

- Two independent desktop clients discover the enabled features and use vCards.
- Multiple resources synchronize eligible messages without recursive copies or
  exposing copies to another account.
- Disabled features are absent from discovery; unsupported requests return the
  appropriate errors.

## 0.3.0: Basic desktop IM

Implement authenticated federation and components, then built-in MUC and upload
services. Federation must cover messages, IQs, subscriptions, presence, and
service domains, including their certificate identities and error behavior.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0114: Jabber Component Protocol](https://xmpp.org/extensions/xep-0114.html) | Component authentication, domain authorization, routing, and disconnect cleanup | Suite |
| [XEP-0045: Multi-User Chat](https://xmpp.org/extensions/xep-0045.html) | Room discovery, creation, membership, roles, affiliations, administration, and messaging | Suite |
| [XEP-0249: Direct MUC Invitations](https://xmpp.org/extensions/xep-0249.html) | Preserve and route invitation payloads locally and over federation | Suite |
| [XEP-0363: HTTP File Upload](https://xmpp.org/extensions/xep-0363.html) | Slot allocation, authenticated upload authorization, HTTP upload/download, and limits | Suite |
| [XEP-0004: Data Forms](https://xmpp.org/extensions/xep-0004.html) | Forms used by room configuration and later protocol profiles | Supporting |
| [XEP-0128: Service Discovery Extensions](https://xmpp.org/extensions/xep-0128.html) | Extended room and upload discovery information | Supporting |

Release gate:

- Basic Core + IM requirements pass for the selected suite.
- A different server implementation exchanges messages, subscription changes,
  presence, and IQs with Lonewolf; unauthorized sender domains are rejected.
- Desktop clients create, join, administer, and leave rooms and share files.
- Component loss, federation failures, and interrupted uploads have bounded,
  verified outcomes. Required deployment services are documented.

## 0.4.0: Resumption, archives, and blocking

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

Release gate:

- Specify the acceptance event for each stanza class and its crash semantics;
  transport flush, client acknowledgement, and durable commit remain distinct.
- Reconnect tests cover resumption, expiry, counter validation, bounded queues,
  replay, and unsuccessful resumption followed by archive synchronization.
- Blocked traffic cannot bypass policy through federation, services, Carbons,
  archives, or offline delivery.
- Archive retention and account deletion preserve privacy and ordering. Measure
  storage admission and replay costs before changing capacity policy.

## 0.5.0: Advanced desktop IM

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

Release gate:

- Advanced Core + IM requirements pass, including account and room MAM.
- Avatars and bookmarks remain consistent across different desktop clients and
  multiple resources, with authorization checked for every access path.
- PEP discovery advertises only supported node features. The required PubSub
  subset does not imply a complete standalone PubSub service.

Private XML Storage is a Lonewolf compatibility choice; the suite recommends it
for legacy bookmarks. Direct TLS deployment records complement listener support.

## 0.6.0: Two-node cluster

No new XEP is introduced. All earlier features must work across node boundaries.

Select the durable-storage and ownership model before implementation. Compare a
shared transactional store with owner-local replicated storage. Either choice
must preserve stable transactional reads, commit/effect ordering, cross-account
subscription changes, and account deletion/recreation fences.

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

Release gate: clients can connect to either node and complete the desktop
workflows. Tests cover ownership transfer, stale-owner rejection, partitions,
node loss, and cleanup. A load balancer alone does not satisfy this milestone.

## 0.7.0: Mobile efficiency and push

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0352: Client State Indication](https://xmpp.org/extensions/xep-0352.html) | Active/inactive state and bounded delivery scheduling | Suite |
| [XEP-0357: Push Notifications](https://xmpp.org/extensions/xep-0357.html) | Authorized registrations, push-service publication, disablement, and cleanup | Suite |

Release gate: Advanced Mobile requirements pass. Verify inactive clients,
resumption, archive catch-up, federated push services, registration expiry or
revocation, and provider failure. Notifications must respect blocking, privacy,
and account deletion across nodes.

## 0.8.0: Web transports and calling infrastructure

Implement WebSocket first, then BOSH. The server target includes both transports.
Apply [RFC 7395](https://www.rfc-editor.org/rfc/rfc7395.html) to WebSocket framing
and stream behavior.

| XEP | Required scope | Basis |
| --- | --- | --- |
| [XEP-0124: BOSH](https://xmpp.org/extensions/xep-0124.html) | HTTP binding sessions and bounded request handling | Supporting |
| [XEP-0206: XMPP Over BOSH](https://xmpp.org/extensions/xep-0206.html) | XMPP negotiation and operation over BOSH | Suite |
| [XEP-0156: Discovering Alternative XMPP Connection Methods](https://xmpp.org/extensions/xep-0156.html) | Publish the supported connection endpoints | Product |
| [XEP-0215: External Service Discovery](https://xmpp.org/extensions/xep-0215.html) | STUN/TURN service discovery and authorized temporary credentials | Suite |

Release gate:

- Advanced Web + A/V Calling server requirements pass.
- Browser clients authenticate, exchange messages, reconnect, and close over
  WebSocket and BOSH without weakening the existing protocol limits.
- Two compatible clients complete a call using the advertised STUN/TURN
  deployment, including a path that needs a relay.
- Call signaling is routed correctly; media encryption and client Jingle
  behavior remain client responsibilities. The media service is a deployment
  dependency, with no mandatory in-process media implementation.

## 0.9.0: Cluster recovery and release qualification

No new XEP is introduced. Qualify the full feature set under failure and load.

Release gate:

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

All earlier milestone requirements are mandatory. No new XEP is added solely for
the version number.

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
span several trackers. Discovery is the next implementation milestone.

Retain the single-node deployment throughout this roadmap. Preserve the project's
allocation, logging, dependency, configuration-reference, and test-organization
rules. Resolve storage and ownership decisions in their trackers; this roadmap
does not select a database, coordination service, or replication protocol.

The target covers the server compliance categories and their supporting profiles.
Additional XEPs can follow 1.0 without delaying these milestones. Client-only
features require interoperability where they cross server routing, archive,
offline, or PEP boundaries; they do not become separate server implementations.
