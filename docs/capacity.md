# Capacity diagnostics and local baseline

The composed server collects fixed aggregate counters, gauges and histograms. Its existing private admin Unix socket exposes them. There is no additional listener or configuration setting.

```sh
curl --unix-socket ./run/lonewolf/admin.sock http://localhost/v1/diagnostics
curl --unix-socket ./run/lonewolf/admin.sock http://localhost/v1/readiness
```

Both responses use JSON and `Cache-Control: no-store`. Query parameters return status 400 with `invalid_request`. Socket ownership and permissions remain the access boundary.

## API and accounting

Diagnostics schema version 1 contains `uptime_ms`, `readiness`, `counters`, `gauges`, `histograms` and `pool`. Uptime starts at registry creation. Updates use fixed enum-indexed atomics and stack-owned observations; only snapshots allocate. There are no account, resource, IP, stanza, payload or credential labels. Independent atomic reads make concurrent snapshots approximate.

Readiness returns `{"schema_version":1,"state":"ready","ready":true}` and status 200 only after configured services start and the root serves with authoritative router state `Running`. States `starting`, `stopping`, `failed` and `unknown` return status 503 and `ready:false`. Router failure overrides stopping; a fatal root service failure remains failed. There is no database/network probe. A valid configuration with zero C2S listeners can become ready.

Embedded admin servers can use `Server::bind_with_diagnostics` and a synchronous `DiagnosticsProvider`. The existing `Server::bind` returns `diagnostics_unavailable` with status 503 for diagnostics and unknown readiness with status 503. Reusable storage/router constructors keep observation optional. The composed server collects aggregates even when its admin socket is disabled.

| Series | Unit and scope |
| --- | --- |
| `connections_accepted_total`, `connections_closed_total` | Admitted C2S tasks, counted once on stream start and once on owned observation drop. |
| `connections_active`, `connections_establishing`, `connections_authenticating`, `connections_binding`, `connections_bound` | Current tasks and current phase; establishing covers initial TCP/TLS opening. |
| `mailbox_accepted_total`, `mailbox_full_total`, `mailbox_closed_total` | One outcome per actual resource-mailbox admission attempt. |
| `retirements_evicted_total`, `retirements_account_deleted_total`, `retirements_router_stopped_total` | Removed generations using existing retirement causes; stale cleanup does not count again. |
| `replay_subscriptions_flushed_stored_bytes_total`, `replay_offline_flushed_stored_bytes_total` | Valid stored source XML bytes whose whole output batch flush succeeded. |
| `replay_invalid_records_total` | Invalid records skipped during replay. |
| `log_dropped_lines_total` | The bounded logger's underlying dropped-write statistic; an event can use multiple writes. |

Cumulative counters saturate. Connection transitions and classified terminal outcomes complete a phase sample. Unexpected task drop abandons the active observation and releases gauges.

Histograms use integer microseconds with inclusive upper bounds `[10,50,100,500,1000,5000,10000,50000,100000,500000,1000000,5000000]` and an overflow bucket. Buckets are non-cumulative; zero enters the first bucket. Each exposes `count`, `sum_us`, `abandoned_total` and `in_flight`. The endpoint does not estimate quantiles.

| Histograms | Interval |
| --- | --- |
| `connection_establishment_us`, `connection_authentication_us`, `connection_binding_us`, `connection_bound_us` | Owned connection phase. |
| `order_fix_wait_us` | Acquisition of the view-fixing mutex. |
| `order_ticket_wait_us` | Ticket admission until eligibility at every addressed account's head, observed once by its owner. |
| `storage_writer_admission_wait_us` | Acquisition of the open-writer mutex. |
| `storage_read_queue_wait_us`, `storage_write_queue_wait_us`, `storage_commit_queue_wait_us` | First poll through semaphore admission/scheduling to blocking closure entry. |
| `storage_read_service_us`, `storage_write_service_us`, `storage_commit_service_us` | Blocking closure entry through normal exit; commit has a separate series. |

Normally returned errors complete a sample. Unfinished drop/unwind records abandonment without a completed sample; this does not imply rollback. Never-polled futures record nothing. Submitted closures own observations and permits through completion despite requester cancellation. Cancelling/retrying `turn()` keeps the ticket's single observation.

`pool` contains reserve, allocation requests/requested bytes/failures, successful heap fallback count/requested bytes and eight bucket objects. Each bucket reports chunk bytes, total/available chunks, shard count and cumulative allocations. Reserve excludes bookkeeping. Fallback bytes are cumulative successful requests. Pool activity, live heap, total allocator requests and RSS are distinct; the latter two allocator measures are unavailable here.

## Reproduction

Use Linux, Python 3.12+, Cargo, `getconf` and `ss`. Keep build/test workloads outside timed comparisons. From the repository root:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 crates/lonewolf-core/tests/capacity/measure.py \
  --parent 28403048cc88f5d52c6de94011fa8fab655cacd4 \
  --directory /tmp/lonewolf-capacity \
  --report docs/capacity-baseline.json
```

The script archives the exact parent, builds both servers with the same release toolchain/options and drives them with one release executable test. Every repetition uses a fresh process and temporary storage. Full JSON, build logs and test logs remain in the chosen directory. The compact report keeps per-repetition results, configuration/environment, histogram counts/buckets, binary hashes and hashes of full result files. Current-tree provenance records the base revision and SHA-256 over sorted Cargo manifests/lock, Rust sources and `.cargo` files, identifying measured uncommitted code.

The compact report stores histogram bucket indices and counts as `nonzero_buckets`; omitted histograms and bucket indices are zero. Its shared pool layout and `bucket_activity_columns` describe each `[available_chunks, allocations_total]` row. Memory samples retain count, RSS range/median, individual socket component peaks/medians and separate server/driver CPU deltas across the observed sample interval. Full raw files retain every original snapshot and sample.

A single profile can run through Cargo:

```sh
LONEWOLF_CAPACITY_CASE=live_routing \
LONEWOLF_CAPACITY_REPETITIONS=3 \
LONEWOLF_CAPACITY_OUTPUT=/tmp/live.json \
cargo test --release -p lonewolf --test capacity \
  -- --exact server_capacity_baseline --ignored --nocapture
```

Test-only variables select a server binary (`LONEWOLF_CAPACITY_SERVER_BIN`), record its provenance (`LONEWOLF_CAPACITY_PROVENANCE`), expand live/contention measured counts (`LONEWOLF_CAPACITY_MULTIPLIER=5`) or request diagnostics at one-second cadence (`LONEWOLF_CAPACITY_POLL=1`). Actual poll count is recorded; short runs can allow just one request.

## Fixed workloads

All cases use verified STARTTLS, SCRAM-SHA-256, roster/offline, loopback TCP, two server workers, an 8 MiB pool and 64 synthetic bound resources. The report records the full benchmark TOML, including sufficient quotas/rate limits. A 60-second work deadline closes driver sockets and latches failure, followed by bounded server cleanup. Watchdog-induced EOF cannot pass as recovery.

| Case | Workload |
| --- | --- |
| Cold idle | Zero resources, then 64. Each level settles 5 seconds, then takes 10 samples at 200 ms. Report RSS levels/ranges and delta per resource. |
| Post-large idle | Same idle sampling before/after each of 64 resources sends/receives one paired 32768-byte client XML message. Drain all deliveries; record generated client bytes, received server XML bytes and retained RSS delta. |
| Live routing | 32 pairs, 16 drained warmup messages/pair, then 128 measured 1024-byte messages/pair, at most eight outstanding. Report all 4096 send-to-complete-receive samples, delivered rate and empirical p50/p95/p99. |
| Slow reader | One receiver requests 4096-byte receive buffer and stays unread 5 seconds; one sender attempts at most 512 messages of 32768 bytes, draining errors/barriers. Restore original effective Linux buffer after that interval, then drain/finish ordered barriers. Record all buffer settings, pressure/recovery durations and samples, attempts/deliveries/errors/closure. |
| Storage contention | 32 senders each store 16 messages of 1024 bytes for their own offline recipient. Each message has an own-account roster IQ barrier; at most eight pairs outstanding/sender. Report all 512 barrier latencies and completed pairs/s, including IQ/read cost. |
| Reconnect replay | Disconnect eight of 64 recipients; store 64 messages of 1024 bytes each and verify sender barriers. Reconnect eight through TLS/auth/bind/presence, read 512 records, and verify committed flush acknowledgements through existing terminal logs. Report every reconnect-to-last/presence-to-last time and aggregate rate. |

Slow recovery uses the restored setting; Linux's effective socket value is recorded separately from its request. Rejected traffic contributes to error counts. Retirement is an observed outcome, not required. Eight reconnect samples per repetition do not establish a stable p99.

## Measurement limits

RSS uses `/proc/PID/smaps_rollup`, with an identified `VmRSS` fallback. Active sampling is approximately 100 ms; idle sampling is 200 ms. Server user/system CPU and driver CPU ticks remain separate, with clock tick frequency recorded. Short bursts and scheduling can escape sampling: observed peaks are lower bounds. Fresh process/storage does not imply a cold kernel page cache.

Process-owned TCP socket inodes filter `ss -tnme`. Receive/transmit allocation, queued transmit, forward allocation, option/backlog memory stay separate. Buffer limits and overlapping components are never added into a total. Missing accounting is null with its reason; raw socket addresses are not retained.

Three paired overhead runs use A/B, B/A, A/B order for both live and contention profiles. Diagnostics occur outside timed work; external sampling is identical. One extra instrumented live run polls at 1 Hz. Median throughput loss above 10% or p99 increase above 20% triggers five additional pairs with five times the measured traffic. The script retains results and fails if the extended comparison remains above either investigation threshold. These local results do not establish SLOs, production capacity or parser/replay policy.

## Actual results

[capacity-baseline.json](capacity-baseline.json) contains every measured repetition and source/build provenance. The measured summary below applies only to this fixed local profile.

The final run completed all six cases three times, twelve ordered A/B runs and one additional 1 Hz run: 31 fresh server processes. The host used an Intel Core Ultra 9 275HX, 24 logical CPUs, Linux 7.2.8 and Rust 1.96.0. All 361 raw memory samples used `smaps_rollup`, included separate server/driver CPU readings and obtained process-owned socket accounting. No repetition exceeded its watchdog deadline.

| Case | Range across the three final repetitions |
| --- | --- |
| Cold idle | 10.46–10.66 MiB RSS at zero resources; 21.09–21.11 MiB at 64. The measured increment was 167.25–170.06 KiB/resource. |
| Post-large idle | All 64 messages received; 2097152 generated client XML bytes and 2100032 received server XML bytes. Retained RSS increment: 7.14–7.24 MiB. |
| Live routing | All 4096 messages received; 6111–6983 messages/s; p99 42.175–42.720 ms from 4096 samples per repetition. |
| Slow reader | Each attempted 512 messages: 144 delivered, 368 explicit errors, no receiver retirement. The five-second pressure phase used effective buffer 8192 bytes; recovery restored 131072 bytes and took 1.897–1.900 seconds. |
| Storage contention | All 512 message/barrier pairs completed; 5355–6126 pairs/s; p99 47.178–48.169 ms from 512 samples per repetition. |
| Reconnect replay | All 512 records replayed and acknowledgements committed; 3434–3470 records/s; each reconnect-to-last-record sample was 141.012–147.523 ms. |

The pool reserve stayed 8388608 bytes. Cold/post-large/live/contention/reconnect snapshots recorded no heap fallback or allocation failure. Slow-reader repetition 1 recorded 738 successful fallback requests totalling 24156954 requested bytes; those cumulative bytes are not retained heap or RSS. Reconnect snapshots showed 72 accepted/8 closed/64 active connections and 586752 flushed stored XML bytes. These counts distinguish retained process memory, pool activity, rejected mailbox admissions and completed replay.

| Paired comparison | Parent median | Instrumented median | Difference |
| --- | --- | --- | --- |
| Live throughput | 6557 messages/s | 6992 messages/s | +6.64% |
| Live p99 | 42.258 ms | 42.363 ms | +0.25% |
| Contention throughput | 5380 pairs/s | 5416 pairs/s | +0.66% |
| Contention p99 | 48.571 ms | 48.129 ms | −0.91% |

Neither throughput nor p99 investigation threshold was crossed. Median server CPU was 8 ticks for both live variants and 11/12 ticks for parent/instrumented contention; driver CPU was 7 ticks for live and 2 for contention in both variants. At 100 ticks/s, these short runs have coarse CPU resolution. The separate polling run completed all 4096 deliveries at 7002 messages/s and made one actual diagnostics request. Three pairs and one short polling run characterize this local profile; they do not establish a general performance improvement or sustained polling overhead bound.
