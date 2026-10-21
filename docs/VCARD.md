# Account vCards

Lonewolf stores one persistent `vcard-temp` XML document per canonical account. This is the authenticated local C2S storage role in [XEP-0054 1.3.0 (2024-06-27)](https://xmpp.org/extensions/attic/xep-0054-1.3.0.html). It does not implement a remote requesting client or federation.

## Protocol and policy

| Source | Implemented contract | Evidence below |
| --- | --- | --- |
| XEP-0054 §3.1 | Own bare GET returns one stored vCard; an existing owner's absent row returns `item-not-found`. | P1, P2, I3 |
| XEP-0054 §3.2 | SET wholly replaces the document and returns an empty result after commit. Only an omitted destination or the canonical sender bare JID is permitted. | P1, P3, P4, P15, I1, I2 |
| XEP-0054 §3.3 | Bare-account GET is server handled. Other unpublished and nonexistent accounts return the same `service-unavailable` shape. Selector content is ignored. | P1, P2, P16 |
| XEP-0054 §4 | Enabled hosts advertise `vcard-temp` through discovery and must also enable `disco`. | D1, D2, C1, C2 |
| XEP-0054 §5 | An authenticated unrelated local user can retrieve a published bare-account card without subscription, including when its owner is offline. | P1, D3 |
| XEP-0054 §§8–9 | Generated fixtures use uppercase fields, `TEL/NUMBER` including empty `NUMBER`, `EMAIL/USERID`, `CTRY`, and `version='3.0'`. Storage retains arbitrary compatibility data without schema validation. | P6, X1, X4 |
| [RFC 6120 §§8.1–8.4, 10–11](https://www.rfc-editor.org/rfc/rfc6120.html) | Preserve authenticated sender identity, request IDs, legal reply addressing, phase/envelope checks, response silence and per-stream order. Restricted XML and listener limits apply before the handler. | P1, P4, P8–P11, P19, E1–E3 |
| [RFC 6121 §§8.1, 8.5](https://www.rfc-editor.org/rfc/rfc6121.html) | Uniform local SET authorization runs after admission, before any destination delivery; full GET retains ordinary resource routing and visibility. | P3, P14–P16, G1–G3 |
| [RFC 7622 §§3–4](https://www.rfc-editor.org/rfc/rfc7622.html), [RFC 9844 §§3,6](https://www.rfc-editor.org/rfc/rfc9844.html) | Existing typed JID preparation governs identity; resources preserve case and leading space. IPv6 zone identifiers remain rejected. | P14, P18, P20, E4 |
| [XML 1.0 §§2.10–2.12, 3.3.3](https://www.w3.org/TR/xml/), [Namespaces 1.0 §§6–8](https://www.w3.org/TR/REC-xml-names/) | Preserve expanded names, QName-value context, effective language/space and XML-normalized values through detachment. | P6, P7, X1–X3 |

RFC 7622 Verified errata 4534 and 4560 apply to the existing JID layer. Reported or Held proposals do not silently amend the protocol. In particular, an empty IQ ID is valid and is echoed; a missing ID follows the existing recoverable rejection. Held RFC 6120 erratum 4741 does not change that distinction.

An empty publication, including a root with whitespace or attributes, is a stored document and returns a result on GET. It removes all old fields. There is no merge, deduplication by IQ ID, history, subscription-controlled profile ACL or unsolicited update. `JABBERID`, foreign owner-like fields and `CLASS/PRIVATE/CONFIDENTIAL` do not select ownership or restrict public reads. Client-provided `from` cannot replace the authenticated sender.

### Destinations and errors

| Request | Outcome |
| --- | --- |
| SET omitted or canonical own bare destination, enabled owner host | Replace the sender's card; empty result after commit. |
| Exact `{vcard-temp}vCard` SET to any other bare account, any full JID, domain, domain/resource, remote or service destination | `forbidden` / `auth` when the sender host or exact served target host enables vCard. Existence, visibility and subscription do not change this result. |
| SET with both relevant hosts disabled, or another payload QName | Existing generic dispatch/routing. A service suffix does not inherit a parent host's selection. |
| GET published local bare account | One complete vCard, using the target host's selection. |
| GET existing own account without a row | `item-not-found` / `cancel`. |
| GET other unpublished or nonexistent bare account | `service-unavailable` / `cancel`, with equivalent payload-free shape after accounting for the addressed JID. |
| GET full JID | Deliver to the exact resource when ordinary visibility permits. The resource chooses the reply. Availability and priority do not choose a substitute. Hidden, disconnected or missing resources return ordinary `service-unavailable`; no bare-card fallback. |
| GET domain or domain/resource | Existing unsupported `service-unavailable`. |
| GET remote destination | Existing `remote-server-not-found`. |
| SET invalid vCard XML context or direct non-whitespace root text | Recoverable `bad-request` / `modify`, old card unchanged. |
| SET above the final encoded write quota or fixed decoding bounds, after handler admission | `resource-constraint` / `wait`, old card unchanged. |
| GET corrupt retained data or handler backend failure | Sanitized `internal-server-error` / `cancel`; no raw replay. |
| IQ result/error, including vCard payloads | No guard, persistence or automatic response. Existing delivery/drop/policy behavior remains in force. |

Every vCard handler and destination-guard error omits the request child. Its payload contains only the final legal `error` element, one standard condition and the condition's error type. IDs and legal addressing are retained. Handler results target the authenticated bound sender; absent request destinations produce no `from`. Generic core errors may omit `to` on that user's own stream under RFC 6120 §8.1.1.1. Generic envelope, admission and unsupported-dispatch errors keep their existing payload rules.

Admission precedence is unchanged: parser/authentication/stanza/recipient gates run first. An uncertain submitted commit keeps the existing core close outcome; there is no retry or promise of rollback after submission.

## XML storage and limits

The operator reference is [examples/lonewolf.toml](../examples/lonewolf.toml). The built-in extension is `vcard`; its mandatory dependency is `disco`. Explicit `vcard` without `disco` fails startup. Defaults enable both. Options are host scoped.

`hosts.<domain>.vcard.max_bytes` limits the final standalone UTF-8 document, including markup, escaping, namespace declarations and materialized context. Its default is 262144 bytes and its maximum is 1048576 bytes. The fixed storage/read ceiling is 1048576 bytes, with the default 8 MiB decoder arena and 256 attributes per element. Listener stanza/tree/attribute/arena limits are independent and can reject a request before the handler. Lowering the write quota does not make an old bounded card unreadable; a smaller replacement remains possible.

SET uses bounded counting before allocating detached context and bounded serialization appends. The exact final serialization must pass the same fixed decoder used by GET before replacement. A small wire document can still exhaust an arena through namespace expansion. P11 preserves the actual ingress `policy-violation` stream close for the 10 KiB namespace/1000-child fixture; X5 separately supplies a 64 MiB input arena to reach the handler and verifies rejection by the fixed 8 MiB read decoder. P22 and X6 cover detached inherited declarations exceeding the 256-root-attribute bound. These are separate boundaries; ingress rejection is not reported as a recoverable handler error.

The codec preserves child order, expanded element/attribute names, unknown fields, repeated fields, normalized text/attributes and namespaces used in QName-valued attributes or text. It does not preserve quote style, CDATA spelling, prefix spelling or pre-parse source line endings. Profile text, including combining sequences, does not undergo JID normalization. Mixed field content survives; the implementation codec tests assert ordered text/element nodes because the integration assertion fixture aggregates direct text.

The stored root materializes effective `xml:lang`, including an empty reset when no language was supplied. It also materializes valid effective `xml:space`, with `default` when absent. Stream context, IQ overrides, root overrides/resets and nested overrides follow XML inheritance. A later differently languaged or `preserve` retrieval stream cannot change the stored meaning. SET rejects invalid or empty root/nested space, or invalid inherited space without a valid root override. A valid root override can supersede invalid ancestor context. GET selectors ignore these values and all selector content. Retained records missing explicit root language/space metadata are corrupt, rather than inheriting the retrieval stream.

Literal CR/CRLF in text normalizes to LF. Character-referenced CR remains CR. Literal attribute TAB/LF/CR normalizes to spaces; referenced whitespace retains its values. Serialize/reparse is semantically idempotent. Non-whitespace text directly under the SET root is a local storage-profile rejection, distinct from ignored GET selector text.

Explicit payload `xml:base` remains inert data. Inherited base resolution and URL fetching are outside this contract. Outer IQ attributes other than the defined effective XML context are not stored. `PHOTO`, `BINVAL`, URI fields, `KEY/CRED`, `SOUND`, `LOGO`, `AGENT` and foreign data cause no fetch, conversion, presence update or avatar hash. Storage does not enforce `FN/N`, insert a `VERSION` child or claim arbitrary documents satisfy the historical DTD.

Account deletion clears the raw card unconditionally, even with vCard disabled or corrupt/oversized retained bytes. Cleanup does not parse the value or apply the write quota. Existing account transaction, snapshot, administrative serialization and retirement mechanisms remain authoritative; re-enablement cannot resurrect a deleted profile. There is no migration or account rewrite at initialization.

## Automated evidence

These are named executable assertions, not a conformance certificate for deferred roles. `P` tests are in `crates/lonewolf-core/tests/protocol/vcard.rs`; `I` tests sit beside the bound-session implementation. Negative protocol workflows check old state or absent state, expected replies and stream usability through ordinary IQ sentinels or a fresh GET. Resource/service non-delivery uses sentinels and the held-writer/order/probe implementation fixtures, not arbitrary no-reply sleeps.

| ID | Exact protocol test | Acceptance categories |
| --- | --- | --- |
| P1 | `vcard_owner_two_resources_public_offline_whole_replacement_and_empty_publication` | Omitted/canonical own destination, empty/escaped/reused IDs, forged sender, two resource writes/reads, unrelated online/offline reads, inert owner/CLASS/PHOTO/URI/KEY/SOUND/LOGO fields, whole replacement, whitespace/attributed empty publication, no pushes. |
| P2 | `vcard_missing_owner_public_absence_and_ignored_selectors_keep_storage_and_stream_usable` | Omitted/explicit owner absence, other unpublished/nonexistent equivalence, foreign/text/invalid-space selectors, bad root/nested context and direct text, preserved old row. |
| P3 | `vcard_wrong_set_destinations_never_deliver_or_replace_cards` | Other/missing bare accounts, current/sibling/missing/case-distinct own resources, other/missing resources, domains and remote destinations; payload-free forbidden, sender/victim integrity, no resource delivery, marker privacy. |
| P4 | `vcard_pipelined_set_get_and_truncated_stanza_preserve_commit_order` | SET then GET without waiting for SET reply; committed state, incomplete disconnected SET never writes. |
| P5 | `vcard_restart_retains_database_tls_accounts_and_reads_above_reduced_write_quota` | Same directory/database/config/certificate/permit and subprocess entry point, fresh readiness after graceful stop, durable semantics, reduced quota reads and smaller replacement. |
| P6 | `vcard_semantics_namespace_qnames_and_xml_normalization_survive_repeated_storage` | Unicode/combining/escaping, repeated fields, mixed text/elements, nested AGENT/card, foreign attrs/elements, stream/IQ QName values, namespace reset/rebinding, literal/referenced text/attribute normalization, inert explicit base and omitted outer attrs. |
| P7 | `vcard_language_space_context_is_detached_from_later_retrieval_stream` | Stream/IQ/root/nested language and space, reset/default/preserve, valid root override of invalid ancestor, invalid inherited context, ignored GET selectors, differently languaged preserve read stream. |
| P8 | `vcard_envelopes_and_invalid_responses_preserve_storage_and_no_reply_loops` | Missing ID/type, invalid type, zero/two request children, malformed result/error drops at host/owner/missing/full/remote destinations, old card and usable stream. |
| P9 | `vcard_tls_authentication_sasl_and_prebind_gates_never_publish` | Ping/vCard before TLS, before and during SASL, and after authentication before binding; unchanged phase errors/closure, later owner row absent. |
| P10 | `vcard_exact_encoded_quota_counts_context_namespaces_unicode_escaping_and_attributes` | Exact 256 final bytes accepted/readable, +1 omitted resource-constraint, namespace/context/multibyte/escaped/attribute bytes and old-row retention. |
| P11 | `vcard_whole_stanza_and_namespace_amplification_keep_ingress_stream_outcomes` | Whole-stanza wire limit and small-wire arena amplification close at ingress; old card remains after fresh authentication. |
| P12 | `vcard_corrupt_retained_records_produce_sanitized_payload_free_internal_errors` | Malformed XML, invalid UTF-8, oversized raw record, missing root language/space, bad root/nested space and direct text; exactly one sanitized diagnostic, no payload marker, recoverable sentinel and byte-identical raw row after shutdown. |
| P13 | `vcard_deletion_while_enabled_or_disabled_clears_corrupt_oversized_and_valid_rows` | Seeded valid/corrupt/oversized rows, admin deletion/recreation enabled or disabled, later enabled restart, missing-card result and final raw storage absence. |
| P14 | `vcard_full_get_uses_exact_case_sensitive_resources_without_account_fallback` | Resource chooses result, stamped sender, roster authorization, pre-availability/unavailable/negative priority, case/leading-space resource distinction, extension enabled/disabled, no bare fallback or account mutation. |
| P15 | `vcard_exact_qname_host_enablement_guard_and_generic_routes_are_independent` | Source enabled/target disabled and reverse, account/resource/domain/domain-resource targets, both disabled generic bare/full/service/remote paths, wrong case/namespace guard bypass, domain/full and remote GET. |
| P16 | `vcard_full_get_hidden_disconnected_and_directed_visibility_never_fall_back_to_bare` | Hidden/disconnected exact resource failures despite stored card, directed authorization delivers, client chooses result, account unchanged. |
| P17 | `vcard_concurrent_resource_writers_expose_only_complete_documents` | Barrier-started writers and independent reader see whole old/A/B field pairs; final state is a complete committed replacement. |
| P18 | `vcard_canonical_owner_case_and_composed_localparts_do_not_normalize_profile_fields` | Valid case mapping, composed/decomposed localpart ownership, IDN key equivalence, unchanged profile field combining sequences. |
| P19 | `vcard_result_error_policy_and_recipient_budget_variants_never_persist_or_reflect` | Valid result/error silence across host/owner/other/missing/full/remote, active policy and consumed recipient budget; exact bound resource delivery, no persistence or reflection. |
| P20 | `vcard_idn_domain_and_composed_owner_aliases_use_one_canonical_card` | Actual IDN TLS/C2S session with Unicode domain destinations, an A-label TLS server identity and case/decomposed localpart aliases; P18 separately proves A-label/Unicode account-key equality. Profile text stays unchanged. |
| P21 | `vcard_same_username_on_two_hosts_keeps_distinct_cards_and_disabled_host_retains_no_handler` | Distinct persisted cards at same username/two hosts, public target-host selection, disabling one host removes its handler without affecting the other. |
| P22 | `vcard_detached_root_attribute_growth_rejects_before_replacement` | Input individually within structural bounds; inherited declarations push detached root above fixed bound; omitted error, old row and log marker privacy. |

| ID | Exact implementation/shared test | Scope |
| --- | --- | --- |
| I1 | `vcard_staged_cancellation_rolls_back_but_submitted_commit_outlives_requester` | Actual vCard handler stages behind oneshot gate; forced blocked output; cancellation before handoff rolls back, cancellation after submission retains committed replacement; fixed old read snapshot throughout. |
| I2 | `vcard_waiting_writer_is_cancelled_by_retirement_before_deleted_account_recreation` | Actual handler waits behind owned writer; retirement cancels it before handler completion; deletion holds writer, recreation cannot acquire it until deletion commits, no stale card or reply. |
| I5 | `vcard_uncertain_commit_closes_without_success_or_payload_and_recovers_whole_state` | Actual vCard SET under test-only failing-sync storage closes with InternalError, emits no success/payload, logs one sanitized CommitUnknown and recovers only a whole old/new card. |
| I4 | `vcard_submitted_commit_finishes_after_the_pending_request_is_dropped` | Actual handler stages a replacement; submit its transaction to detached commit, drop the pending requester before draining work, then observe the committed card and unchanged old snapshot. |
| I3 | `vcard_get_keeps_account_and_card_snapshot_during_deletion_and_recreation` | Actual GetWork reads old account and card together after deletion; a snapshot fixed while absent still returns public service-unavailable after recreation; fresh snapshot reads the new card. |
| G1 | `iq_destination_rejections_precede_target_work_and_never_deliver` | Generic typed constraint engine, synthetic registered QName and fake service; held writer and order tickets prove synchronous rejection, zero handler/policy/service work and resource mailboxes. Complements actual vCard wire tests P3/P15. |
| G2 | `iq_destination_host_matrix_uses_only_exact_normalized_domains` | All source/target enablement combinations and exact-domain/no-suffix matching in the shared constraint engine. |
| G3 | `iq_destination_recipient_limit_precedes_constraints_and_keeps_exemptions` | Frozen-refill recipient allowance, admission precedence and response exemptions. |
| E1 | `omitted_iq_error_preserves_parsed_envelope_and_authenticated_recipient` | Shared fresh-arena error path, vCard-shaped payload, legal parsed-ID/address/language combinations. |
| E2 | `omitted_get_set_and_missing_account_errors_report_once_and_set_rolls_back` | Shared typed storage failure categories, sanitized once-only diagnostics, vCard-shaped input and SET transaction rollback. |
| E3 | `malformed_responses_are_dropped_without_error_loops`; `full_jid_iq_responses_ignore_presence_and_do_not_generate_error_loops`; `rejected_stanzas_return_errors_and_leave_roster_requests_usable`; `pre_bind_requests_to_permitted_destinations_return_service_unavailable`; `pre_bind_iqs_to_other_entities_close_before_request_or_response_handling` | Shared malformed-response/envelope/namespace and pre-bind admission assertions, supplemented by actual vCard P8/P9. |
| E4 | `ipv6_zone_destinations_return_recoverable_jid_malformed_errors` | Existing zone-identifier rejection and recoverable routing. |
| D1 | `default_hosts_answer_discovery` | Default server and authorized account advertise vCard exactly once. |
| D2 | `discovery_and_vcard_quotas_follow_each_hosts_selection` | Both extension orderings, target-host quota and discovery selection. |
| D3 | `public_vcards_do_not_make_default_account_discovery_public` | Published card public read does not relax account discovery privacy. |
| C1 | `vcard_dependency_cannot_use_another_hosts_discovery` | Cross-host discovery cannot satisfy the vCard dependency. |
| C2 | `invalid_vcard_options_fail_during_extension_preparation`; `builtin_dependency_and_exact_route_constraint_and_discovery_inventory` | Invalid explicit options, required dependency and exact registered route/feature inventory. |
| X1 | `normative_repeated_nested_opaque_fields_and_ordered_mixed_content_round_trip` | Codec ordered-node and inert normative/foreign field assertions. |
| X2 | `inherited_namespaces_qname_values_rebindings_and_default_resets_survive_detachment` | Codec expanded names and QName values in text/attrs, rebinding/reset semantics. |
| X3 | `xml_whitespace_character_references_and_semantic_reparse_stability`; `root_language_space_inheritance_overrides_resets_and_nested_validity` | Codec exact XML-normalized values, serialize/reparse idempotence and exhaustive root/context validity combinations. |
| X4 | `arbitrary_uploaded_versions_and_names_remain_opaque_compatibility_data` | Nonvalidating arbitrary version/unknown-field compatibility fixture. |
| X5 | `namespace_amplification_exhausts_the_fixed_decoder_before_storage_mutation` | Large input arena reaches actual handler; fixed GET decoder rejects namespace amplification before replacement; old card committed unchanged and normal GET succeeds. |
| X7 | `decoder_rejects_missing_metadata_wrong_roots_and_excessive_structure_as_corruption` | Fixed decoder rejects missing metadata, wrong roots and excessive retained structure without raw replay. |
| X6 | `detached_root_attribute_growth_is_rejected_before_mutation`; `response_arena_exhaustion_is_resource_constraint_and_not_persisted_corruption` | Codec structural/read limits and response allocation distinction. |
| L1 | `disabled_extension_cleanup_is_atomic_and_recreation_has_no_previous_card`; `missing_account_cleanup_removes_orphaned_invalid_and_oversized_raw_cards` | Administrative transaction cleanup, unrelated rows intact, snapshot isolation, orphan/raw oversized deletion. |
| L2 | `precommit_vcard_cleanup_failure_rolls_back_account_and_offline_cleanup`; `submitted_deletion_commit_failure_remains_typed_and_recovery_keeps_state_atomic` | Precommit rollback and uncertain administrative commit preserve existing typed atomic outcomes. |
| L3 | `detached_commit_failures_keep_categories_and_log_after_requester_cancellation` | Shared submitted IQ commit path: every storage category, no effects after failure, sanitized diagnostic after requester cancellation; no false rollback promise. |

### Command results

Checks passed locally on 2026-10-21:

| Command | Result |
| --- | --- |
| `cargo fmt --all` | Passed. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed, zero warnings. |
| `cargo test -p lonewolf-core --test protocol vcard` | 24 passed: 22 new vCard workflows and two existing discovery scenarios. |
| `cargo test -p lonewolf-core --test protocol` | 690 passed, one ignored subprocess entry point; includes authentication, stream, binding, routing and policy suites. |
| `cargo test -p lonewolf-core --lib c2s::stream::bound` | 90 passed, three existing ignored tests. |
| `cargo test -p lonewolf-core --lib delivery` | 13 passed. |
| `cargo test -p lonewolf-core --lib vcard` | 10 passed, including all five new deterministic vCard implementation scenarios. |
| `cargo test -p lonewolf-extension vcard` | 23 passed. |
| `cargo test --workspace` | 2209 passed, zero failed, 8 existing ignored tests across 35 result summaries. |

The delivery evidence contains bounded command logs, an exact-name audit and the redacted desktop/deployment manifests. PR CI and post-merge CI are separate delivery gates; these local results do not assert either has passed.

## Desktop interoperability

Both independent desktop clients completed the required gate on 2026-10-21. The server was a native release build of merged revision `bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43` on `lonewolf-im.com`, installed at 17:39:55 UTC. The running executable matched SHA-256 `ba822797d5abfef7fa5025b5b41bba564d3a03c248717f2926249bea22701d1b`. Configuration remained unchanged, using built-in roster/offline/disco/ping/vcard and `max_bytes=262144`; its SHA-256 was `f14d2121235414fcde1b8d5b0d52563f4a7d0fc0b6e3d54e34b5407244dcd866`.

The clients used an owned disposable local account with different bound resources, required STARTTLS, normal certificate verification, isolated temporary profiles and memory-only credentials. No real user's profile was published or replaced. Post-run inspection of 38 service-journal lines found no synthetic profile marker and confirmed the running executable/configuration hashes were unchanged. This is bounded log evidence for this run, not a claim about all possible logging configurations.

| Client and method | Actual observations |
| --- | --- |
| Psi+ 1.5.1650 (2023-07-21, core 526ed0b8), native Service Discovery and classic User Info editor | Fresh discovery advertised classic vCard at 17:41:10 UTC. Publish A completed with the native success dialog at 17:42:16. Fresh Retrieve A at 17:42:26 replaced unpublished local UI probes with the server's expected full name/nickname. Publish B changed the full name and cleared the old nickname. Fresh Retrieve B at 17:42:27 again replaced probes and showed the changed full name with empty nickname. |
| Gajim 2.6.0 / nbxmpp 7.4.0, API-driven verification through the running desktop application's built-in `VCardTemp` module | A fresh authenticated bound desktop connection became AVAILABLE at 17:44:50 UTC. At 17:45:09, fresh disco, publish A, fresh parsed GET A, publish B, fresh parsed GET B and the final completion callback all succeeded. B changed `FN`, omitted `NICKNAME`, and the parsed GET confirmed that key was absent. |

### Reproduction and evidence boundaries

In Psi+, open Service Discovery for the server, browse again with caching disabled, select the server row and verify the feature-gated vCard action is enabled. Open the account's native User Info dialog. Publish `Full Name = Lonewolf Psi fixture A` and `Nickname = remove-on-replacement`, and require the success dialog. Before each Retrieve, replace both local fields with `unpublished local read probe`; Retrieve must overwrite them with the server result. Publish B with full name `Lonewolf Psi fixture B` and an empty nickname, then repeat the probe/Retrieve check. Classic Psi's pinned Iris serializer at `3c308da7` omits an empty `NICKNAME`. The observed replacement evidence is the native empty nickname UI, not an inference that returned XML omitted that element. The newer vCard4 profile editor is outside this test.

The native automation used these stages in order, with the actual deployed revision argument:

```text
python3 /tmp/lonewolf-psi-vcard-verify.py discovery --server-revision bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43
python3 /tmp/lonewolf-psi-vcard-verify.py publish-A --server-revision bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43
python3 /tmp/lonewolf-psi-vcard-verify.py read-A --server-revision bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43
python3 /tmp/lonewolf-psi-vcard-verify.py publish-B --server-revision bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43
python3 /tmp/lonewolf-psi-vcard-verify.py read-B --server-revision bfc5346e9858e4f3e69940c4bc8a39ed3bde8f43
```

The helper snapshot SHA-256 was `ee7225c4724082ae62b1bd71572006b1c9edf5b528b8c024f2af74daf28aa4a7`. An initial UI-selection attempt failed before the successful fresh discovery; it is not counted as passing evidence.

Gajim's native profile editor was not used or verified for classic vCard publication. The running Gajim application performed its normal construction, parsing and authenticated transport. The driver called these methods in its GLib event loop, waiting for each `task.finish()` before starting the next stage:

```python
from nbxmpp.modules.vcard_temp import VCard

module = client.get_module('VCardTemp')
a = {'FN': 'Lonewolf Gajim fixture A', 'NICKNAME': 'omitted-after-replacement'}
b = {'FN': 'Lonewolf Gajim fixture B'}

client.get_module('Discovery').disco_info('lonewolf-im.com', callback=discovered, timeout=30)
module.set_vcard(VCard(data=a), callback=published_a, timeout=30)
module.request_vcard(callback=read_a, timeout=30)
module.set_vcard(VCard(data=b), callback=published_b, timeout=30)
module.request_vcard(callback=read_b, timeout=30)
```

`discovered` asserts `vcard-temp` in the fresh feature set; `read_a` checks both parsed fields, and `read_b` checks the new `FN` and `'NICKNAME' not in result.data`. The driver retains callbacks strongly until their `finally` cleanup because nbxmpp stores weak callback references. The initial helper omitted this retention and was corrected before a new desktop application run; the stalled attempt is not counted. The final driver snapshot SHA-256 was `1012e881d9c58a342f5cf4a9e3efded6b47184152cac94174c46f0d457be3e4d`. Its command was a new `verify` request containing the deployed revision and unchanged configuration description; only the actual available desktop client could execute it.

Redacted stage records and exact helper snapshots are retained with the delivery evidence as `manual-psi-native.json`, `psi-vcard-verify.py`, `manual-gajim-desktop.json`, and `gajim-desktop-driver.py`. `server-deployment.json` ties the observations to the live release/configuration, and `live-service-privacy.json` records the bounded journal check. These files contain no credentials or raw profile/XML logs.

Cleanup was verified: the disposable account was deleted and read back absent at 17:47:33 UTC. The owned clients/private display stopped, temporary profiles/authentication cookies were removed, and the original accessibility setting was restored at 17:48:40 UTC. The real user account and profiles were unchanged.

## Deferred roles

No result here claims vCard4, XEP-0292, S2S worldwide public access, component storage users, server/domain profiles, requester compatibility handling, vCard search, private cards, XML Base resolution, PEP, avatar notifications/conversion, image processing or schema certification. None of the checks marks unrelated roadmap extensions complete.
