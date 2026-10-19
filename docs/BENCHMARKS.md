# XMPP workload measurements

`lonewolf-bench` measures explicit workloads against an isolated local server or an explicitly configured remote server. It never changes a deployed server's configuration. Run, account creation and comparison are separate commands. No command automatically provisions accounts, transfers files or uses SSH.

Build the server and driver before running measurements:

```sh
cargo build --release -p lonewolf -p lonewolf-bench --locked
target_dir="$(cargo metadata --no-deps --locked --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
server="$target_dir/release/lonewolf"
bench="$target_dir/release/lonewolf-bench"
output_parent="$(mktemp -d "${TMPDIR:-/tmp}/lonewolf-benchmark.XXXXXX")"
bash scripts/benchmark-smoke.sh --server-binary "$server" --bench-binary "$bench" --output "$output_parent/smoke"
```

Python3 parses Cargo's metadata. The smoke script requires absolute executable paths and a new output directory. It runs all three two-second workloads, checks their artifacts and compares the message result with itself. It installs and builds nothing, contacts only loopback and deletes no output. The immediately preceding release build establishes `server_profile="release"` and `server_features=[]` in the smoke configurations. Supplying another build requires a matching declaration in its configuration. The script does not discover a build profile from an executable path.

Cargo metadata also finds a nondefault target directory:

```sh
export CARGO_TARGET_DIR="/absolute/path/build output"
cargo build --release -p lonewolf -p lonewolf-bench --locked
target_dir="$(cargo metadata --no-deps --locked --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
server="$target_dir/release/lonewolf"
bench="$target_dir/release/lonewolf-bench"
```

Keep the selected binaries unchanged throughout a comparison series. Record their hashes, source revisions, feature sets and actual `rustc -Vv` output outside the measured runs. A local `server_revision` is a declaration; the driver also hashes the supplied server binary. A path alone proves no build facts. All local examples declare release and the server's empty named feature set. They omit `server_toolchain`; set it only from the actual server build, as one printable line. Omitting profile or features permits a run, but its unknown build declaration prevents comparison. Unknown or different toolchains add caveats. Known/unknown declarations, test/release profiles and different feature sets refuse comparison.

## Local workloads

Run each example in a new output child, using the absolute server override:

```sh
"$bench" run --config examples/bench/idle.toml --server-binary "$server" --output "$output_parent/idle"
"$bench" run --config examples/bench/messages.toml --server-binary "$server" --output "$output_parent/messages"
"$bench" run --config examples/bench/churn.toml --server-binary "$server" --output "$output_parent/churn"
```

The full examples use ten seconds of warmup and sixty seconds of measurement: 100 idle connections, 50 message pairs at a global 1,000 operations/s, or 64 churn accounts at 20 operations/s with connection concurrency 16. Smoke examples use two idle connections, one pair or two churn accounts, zero warmup and two seconds of measurement. Their applicable offered rate is 2/s.

A local run creates a private temporary directory, private certificate and key, a fresh Redb database and exactly the requested accounts. It releases database handles before launching the supplied server executable. Both XMPP and metrics listeners ask the operating system for port 0. The driver owns and reaps this child and removes its temporary files after graceful shutdown or forced termination. Results retain only sanitized server event names. Driver and server worker counts are independent; local examples select two each and an 8 MiB stanza pool.

The local fixture selects an explicit policy for reproducibility: SCRAM-SHA-256, one bound resource per account, empty rosters, no presence, roster/offline extensions, permissive connection/stanza/recipient/XML limits and info logging. `result.json` records the resolved values. These are fixture settings, not recommended deployment defaults. Remote policy remains the operator's actual policy. Check policy-rejection counters before interpreting load.

An idle run keeps the selected sessions open and sends no application stanzas. Messages use two distinct accounts per pair: even positions send to the next odd position's full bound JID. The receiver validates correlation, actual receiver identity, sender, destination and the exact ASCII `x` body length. Churn primes each account's SCRAM keys, then repeats independent TCP, STARTTLS, authentication, binding and clean-close cycles. It reuses only matching cached SCRAM salt/iteration keys. TLS session resumption and early data are disabled in all modes. Priming cost stays outside the nominal window; this is not cold-password-derivation throughput.

## Rate, deadlines and interpretation

Message/churn rates are global, not per pair or account. A fixed schedule determines offered slots without retries, reconnections or shifting the measurement epoch. `dispatch_quantum_us` groups wakeups; `max_dispatch_batch` bounds each group. `max_schedule_lag_ms` permits a finite dispatch tail for the original cohort. It does not reduce the configured rate or add operations. Slots that miss the schedule, in-flight bound, writer availability or account availability remain explicit skipped populations.

Operation deadlines start at each original scheduled slot. Timed phases keep their fixed nominal end even when the producer finishes later. Message drain ends at nominal end plus operation timeout; churn additionally allows its shutdown budget. A receipt during drain can be on time for its operation while lying outside the nominal measurement window. A later receipt is counted separately after timeout. Warmup has its own ledger and drain; invalid warmup never starts measurement.

The ten phases are preflight, target setup, account priming/connections, warmup, warmup drain, measurement, measurement drain, connection shutdown, local child shutdown and artifact finalization. Unentered phases are absent. Offsets are monotonic nanoseconds. Nominal timed-phase ends and observed producer ends have different meanings: message/churn drain starts at nominal end and can overlap producer completion. Artifact-finalization timing ends before serialization/publication of the final result itself.

Interpret planned, dispatched, written, received, login and clean-close counts together with scheduler loss, failures, deadlines, coverage and window/drain populations. Timeouts and failures do not receive invented latency samples. HDR distributions contain successful samples only; a low p99 with poor receipt coverage is not a successful result. Do not average percentiles or combine per-run histograms. Quantiles use microseconds and three significant figures; the artifacts retain counts, sums and bucket populations. Comparisons report candidate minus baseline and percent change when the baseline permits it. They provide no statistical significance test or capacity verdict.

The generator preallocates and touches a fixed 64 MiB telemetry buffer before setup, in addition to workload state and payloads. One sampler collects generator and server metrics sequentially, initially, periodically and at phase boundaries. Missed ticks are skipped. Control notifications are bounded and never block workload producers. HTTP bodies are bounded to 1 MiB; raw telemetry stops at its fixed cap while summary collection continues. Failed/missing/slow scrapes degrade telemetry without inventing resource observations or failing an otherwise valid workload. Process/build identity changes invalidate the run. Missing resource values remain null with reasons and sample coverage. CPU, RSS and descriptor summaries cover only supported sampled intervals; incremental idle RSS uses the initial preconnection baseline when available.

Check `ulimit -n` and recorded soft/hard descriptor limits before increasing clients. Two endpoints per message pair, sockets, database files and driver overhead all consume descriptors. Local server and generator contend for the same CPU, memory and scheduler. Generator lag can limit offered load before the server does. A laptop-to-VPS test includes Internet latency. A nearby separate generator can reduce network variation; shared VPS resources and steal time need separate observation.

## Remote accounts and environment

The remote example and descriptor are illustrative, not observations of a user's VPS. Replace the DNS names, paths, host facts, build declarations and every resolved policy field with verified deployment facts. Keep the descriptor environment ID equal to the run configuration's ID. The example describes release, features `[]` and unknown toolchain; verify these against the actual server build. The strict schema requires every server/provenance field, using null only for permitted unavailable host facts.

Generate credentials in a private directory on the server host, then explicitly provision through that server's Unix admin socket:

```sh
umask 077
mkdir -m 700 /absolute/private/benchmark-accounts
"$bench" accounts generate --domain example.test --prefix bench --count 2 --output /absolute/private/benchmark-accounts/credentials.json
"$bench" accounts provision --socket /absolute/server/run/lonewolf/admin.sock --credentials /absolute/private/benchmark-accounts/credentials.json
```

Generation uses exclusive file creation with private permissions. Provisioning preserves manifest order, refuses an existing account without replacement, stops on the first failure and reports `confirmed_created` and `uncertain_last_create`. An acknowledged create remains confirmed even if its response body later fails. An uncertain final create requires operator inspection before any retry. These commands never delete accounts.

Transfer the credentials privately to the generator using an operator-controlled secure method. The benchmark tool does not transfer them. Keep the receiving directory private and the credential file owner-only readable/writable. Set `credentials_file` to that file, `environment_file` to the completed descriptor and optionally `ca_pem` to the required private CA chain. The system trust roots remain enabled. There is no TLS bypass: `connect_host` chooses the endpoint while `xmpp_domain` controls stream addressing, SNI and DNS certificate verification, including when connecting through an IP or tunnel. Optional `metrics_url` must be an explicit HTTP `/metrics` URL without credentials or query parameters.

```sh
"$bench" run --config /absolute/private/remote.toml --output /absolute/results/remote-001
```

Paths inside a run configuration are relative to that configuration's directory. `--server-binary` and `--output` are relative to the current working directory unless absolute. Credential/account command paths and compare inputs/output are current-directory relative. A remote run never accesses the admin socket or provisions accounts. Use a dedicated controlled account dataset, and manage any deployment changes yourself.

## Artifacts and status

Each run exclusively acquires a new private output directory. Schema version 1 and measurement version 1 apply to `result.json`; `summary.md` explains the result. `telemetry.ndjson` contains bounded sampled OpenMetrics records with schedule/observation offsets, phase, scope, scrape status and duration. Local runs also produce `server.log` containing only bounded sanitized lifecycle tokens. Run metadata includes requested workload/settings, ordered selected-account hash, build declarations and observed TLS/authentication facts. It excludes passwords, keys, auth exchanges and message bodies. Avoid putting secrets in operator-supplied labels and descriptors. Metrics endpoint identity is not retained.

An `.incomplete` marker means publication did not commit. Files are flushed, synchronized and closed before atomic, non-overwriting per-file publication; result JSON is published last and marker removal commits completion. This is not an atomic directory snapshot or a power-loss durability guarantee. Filesystems must support same-directory hard links. A failed publication preserves diagnostic files and the marker. A fully persisted failed or interrupted workload clears the marker and remains unsuccessful. Never manually clear it to make an incomplete run eligible.

| Exit | Meaning |
| --- | --- |
| 0 | Passed run, successful account command or eligible comparison |
| 1 | Failed workload or operational setup/cleanup |
| 2 | Invalid configuration/path/account operation, invalid workload/artifact, or refused comparison |
| 130 | Interrupted run with available finalized evidence |

Integrity failures take precedence over interruption, then workload failure. Ctrl-C stops new work, joins admitted CPU/network/sampler tasks, retires readers/writers, stops the owned local child and finalizes available evidence. Force-killing the driver can leave an incomplete marker and owned temporary resources; retain that evidence and inspect processes before cleaning it.

Compare complete artifact directories into another new directory:

```sh
"$bench" compare /absolute/results/baseline /absolute/results/candidate --output /absolute/results/comparison
```

`comparison.json` and `comparison.md` describe eligibility, stable field mismatch paths, refusals, per-metric values/deltas and caveats. Directory loading verifies declared artifact sizes and SHA-256 hashes with bounded reads and refuses changed files. The pure Rust `compare_runs` API compares in-memory reports without filesystem verification. This checks byte consistency, not authenticity or summary semantics, and requires stable input directories. It does not provide an atomic snapshot, hostile ancestor-path confinement or filesystem I/O deadlines. Incomplete, corrupt, unsuccessful, irreconcilable, old instrumentation metadata and incompatible workload/environment/settings inputs refuse. Matching unknown required metadata does not prove compatibility. Changed server source/binary builds are allowed when the other required facts agree; the same fixed driver is required. Resource values may be unavailable while client metrics remain eligible. Every remote comparison warns that matching declarations cannot prove endpoint or physical-machine equivalence; endpoint identities are excluded from compatibility checks.

## Repeated comparisons and sweeps

First run at least five A/A pairs with the identical selected release server, fixed driver and settings. Use a new equivalent local fixture or a controlled dedicated remote dataset for every run. Keep warmup, metrics collection and policy identical. Save every run and paired comparison; inspect per-run values and their spread without a significance claim. A small valid workload checks usability without establishing server capacity.

For a build comparison, select or build A and B outside the measured runs. Copy/record their exact binaries and facts, then use the same unchanged driver for A1, B1, A2, B2, A3, B3. Point otherwise identical local configurations at the selected servers with matching build declarations. Compare A1/B1, A2/B2 and A3/B3 and inspect consistency alongside the A/A spread. Remote runs require equivalent dedicated data and controlled deployment changes between runs. Do not label two copies of one build as distinct source builds.

For idle sweeps, change only connection count. For message/churn sweeps, change only global offered rate while preserving topology and all other controls. Check schedule lag, skipped populations, policy rejections, connection failures and generator contention before interpreting a limit. Record an unsuccessful offered rate honestly. This milestone supplies a reproducible measurement procedure, not a universal maximum-capacity or optimization claim.
