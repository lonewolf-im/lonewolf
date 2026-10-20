# lonewolf-bench

`lonewolf-bench` runs repeatable XMPP workloads against a Lonewolf server and
records what happened. Use it to answer two kinds of questions:

- How does this server build behave under this load? For example: delivery
  latency, CPU, memory per connection, login cost.
- Did my change make the server slower, heavier or less reliable than the
  baseline build?

It has three commands:

| Command | Purpose |
| --- | --- |
| `run` | Run one workload and write a result directory. |
| `compare` | Compare two result directories and report the differences. |
| `accounts` | Generate and provision test accounts on a remote server. |

The tool requires Unix. Process CPU, memory and file descriptor figures are
only available on Linux.

## Workloads

| Kind | What it does | What to look at |
| --- | --- | --- |
| `idle` | Opens `connections` sessions and keeps them open without sending anything. | Server memory per connection, unexpected disconnects. |
| `messages` | Opens `pairs` sender and receiver sessions. Senders send chat messages with a `body_bytes` body to their receiver at a fixed total `rate_per_second`. | Delivery latency, on-time deliveries, server CPU. |
| `churn` | Repeats full connect, STARTTLS, authenticate, bind and close cycles over `accounts` at a fixed total `rate_per_second`. | Per-stage login latency, clean cycles per second. |

All sessions use STARTTLS and SCRAM-SHA-256. TLS session resumption is
disabled. Churn derives each account's SCRAM keys once before the measurement
and reuses them, so it measures the server's login cost, not the client's.

The load is open loop. Operations follow a fixed schedule, and the tool never
waits for the server before sending the next one. Latency starts at the
scheduled time, so a slow server shows up as higher latency instead of a
quietly lower rate.

Every run has a warmup period followed by a measurement window. Only the
measurement window counts toward the reported results.

## Quick start

Build the server and the tool, then run the two-second message workload:

```sh
cargo build --release -p lonewolf -p lonewolf-bench --locked
./target/release/lonewolf-bench run \
  --config examples/bench/smoke-messages.toml \
  --output /tmp/bench-messages
cat /tmp/bench-messages/summary.md
```

The example configurations find the server at `target/release/lonewolf`. If
you build into another target directory, pass `--server-binary <path>`.

To check the whole pipeline, run the smoke script. It runs all three
two-second workloads and compares the message result with itself. CI runs it
on every change. It verifies that the tool works, not that the server is
fast.

```sh
bash scripts/benchmark-smoke.sh \
  --server-binary "$PWD/target/release/lonewolf" \
  --bench-binary "$PWD/target/release/lonewolf-bench" \
  --output /tmp/bench-smoke
```

## Running a workload

```sh
lonewolf-bench run --config <file> --output <new-dir> [--server-binary <path>]
```

The output directory must not exist yet. Its parent directory must exist.

### Local mode

With `mode = "local"`, the tool starts its own server. It creates a private
temporary directory with a self-signed certificate, a fresh Redb database and
exactly the accounts the workload needs. It then starts the server on loopback
with ephemeral ports, samples the server's metrics endpoint during the run,
stops the server at the end and deletes the temporary directory.

The local server uses a fixed benchmark policy: SCRAM-SHA-256 only, one
resource per account, the roster and offline extensions, and rate limits high
enough not to interfere. It is not a recommended production configuration.

The server and the tool share the same machine and compete for CPU and memory.
`server_workers` and `driver_workers` set the thread count of each side.

### Example configurations

| File | Workload |
| --- | --- |
| `examples/bench/idle.toml` | 100 idle connections, 10 s warmup, 60 s measurement. |
| `examples/bench/messages.toml` | 50 pairs, 1,000 messages/s, 256-byte bodies. |
| `examples/bench/churn.toml` | 64 accounts, 20 login cycles/s. |
| `examples/bench/smoke-*.toml` | Two-second versions of the above, used by CI. |
| `examples/bench/remote.toml` | Template for a remote server. |

Press Ctrl-C to stop a run early. The tool stops sending, closes its sessions,
stops the local server, writes what it has and exits with code 130.

## Configuration

The configuration is a TOML file. Relative paths inside it are resolved from
the file's directory. Unknown keys are rejected.

### `[target]` for a local server

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | required | `"local"`. |
| `server_binary` | required | Server executable. `--server-binary` overrides it. |
| `server_workers` | `2` | Server worker threads. |
| `stanza_pool_size_mib` | `256` | Server stanza pool size. Must be a power of two and at least 8. |

### `[target]` for a remote server

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | required | `"remote"`. |
| `connect_host` | required | Host name or IP address to connect to. |
| `port` | required | Client-to-server port. |
| `xmpp_domain` | required | XMPP domain. It also sets the TLS server name and the certificate check. |
| `credentials_file` | required | Account file from `accounts generate`. |
| `ca_pem` | unset | Extra CA certificates to trust, in PEM format. |
| `metrics_url` | unset | Server metrics endpoint, as `http://<host>:<port>/metrics`. Without it, the result has no server resource figures. |

### `[scenario]`

| Kind | Keys and defaults |
| --- | --- |
| `idle` | `connections = 100` |
| `messages` | `pairs = 50`, `rate_per_second = 1000`, `body_bytes = 256` |
| `churn` | `accounts = 64`, `rate_per_second = 20` |

Rates are totals across all pairs or accounts. A message workload uses two
accounts per pair: account 0 sends to account 1, account 2 sends to account 3,
and so on. A run can use up to 100,000 accounts.

### `[measurement]`

The examples override several of these defaults.

| Key | Default | Meaning |
| --- | --- | --- |
| `warmup_ms` | `10000` | Load applied before the measurement window. Not reported. |
| `duration_ms` | `60000` | Length of the measurement window. |
| `operation_timeout_ms` | `10000` | Time an operation has, counted from its scheduled slot, before it times out. |
| `setup_timeout_ms` | `900000` | Time allowed for everything before warmup: starting the server, creating accounts and connecting. |
| `shutdown_timeout_ms` | `10000` | Time allowed for closing sessions and stopping the server. |
| `ramp_rate_per_second` | `10` | Highest rate of new sessions while connecting before warmup. |
| `connect_concurrency` | `16` | Connection attempts in flight while connecting. |
| `driver_workers` | `2` | Threads that drive the workload. |
| `max_in_flight` | `4096` | Operations allowed to wait for completion at once. |
| `max_schedule_lag_ms` | `100` | How late the driver may send a scheduled operation. Later operations are skipped and reported. Must be less than `operation_timeout_ms`. |

### `[metrics]`

| Key | Default | Meaning |
| --- | --- | --- |
| `interval_ms` | `1000` | How often the tool samples server and driver metrics, from 1000 to 60000. |
| `timeout_ms` | `2000` | Time allowed for one metrics request. |

## Results

Each run writes these files:

| File | Contents |
| --- | --- |
| `result.json` | The complete result: configuration, counters, rates, latency histograms, resource summaries, phase timings, and build and host facts. |
| `summary.md` | A readable digest of `result.json`. |
| `telemetry.ndjson` | Raw metrics samples from the server and the driver, one JSON object per line. |
| `server.log` | Local mode only. The server's log output, capped at 1 MiB. |

A run never records passwords, keys or message bodies.

The command prints the run status and exits with a matching code:

| Exit | Status | Meaning |
| --- | --- | --- |
| 0 | `passed` | Every scheduled operation succeeded on time. |
| 3 | `degraded` | The measurement completed, but some operations were skipped, timed out, failed or lost their connection. The results are complete and comparable. |
| 1 | `failed` | The setup failed or the measurement could not complete. |
| 2 | `invalid` | The configuration is invalid, or the tool cannot trust its own accounting. |
| 130 | `interrupted` | The run was stopped early. |

`summary.md` starts with the reason for any status other than `passed`. A
degraded run says whether the driver or the server fell behind:

- **Skipped by the driver** means the driver could not apply the offered load:
  a sender was still busy with its previous message, a churn account was
  still busy with its previous cycle, `max_in_flight` was reached, or the
  driver started operations too late. The driver may be the bottleneck, not
  the server.
- **Did not succeed on time** lists operations that timed out, failed, were
  misrouted or lost their connection. These point at the server or the
  network.

A run fails instead of degrading when nothing succeeds during the measurement,
or when a local server exits on its own.

A degraded warmup does not stop the run. For messages and churn it does not
affect the status either. For idle, a connection lost during warmup still
degrades the run, because the measurement then holds fewer connections.

The most useful fields in `result.json`:

| Workload | Fields |
| --- | --- |
| all | `status`, `reasons`, `telemetry.server.cpu_average_cores`, `telemetry.server.rss_peak_bytes` |
| `idle` | `counters.connections_at_measurement_end`, `telemetry.server.incremental_rss_per_connection_bytes` |
| `messages` | `counters.dispatched`, `counters.received_on_time`, `latencies.message_schedule_to_receive` |
| `churn` | `rates.closed_cycles_per_second`, `latencies.login_connect_to_bound`, plus `tcp_connect`, `starttls`, `authenticate`, `bind` and `close` |

Each resource field is an object. Read its `value` together with its
`sample_count`. A missing sample leaves `value` as `null`.

Latency histograms include successful operations only. Always read them
together with the success counts. A low p99 with half of the messages missing
is not a good result.

## Comparing runs

```sh
lonewolf-bench compare <baseline-dir> <candidate-dir> --output <new-dir>
```

The command writes `comparison.json` and `comparison.md`. For each metric of
the workload, it reports the baseline value, the candidate value, the
difference (candidate minus baseline) and the percent change. It exits with 0
when the runs are comparable and 2 when it refuses.

The comparison refuses when either run is `failed`, `invalid` or
`interrupted`, or when the runs differ in their `[scenario]` or
`[measurement]` settings. Degraded runs are compared, so you can compare two
builds near their limit.

Everything else produces a warning instead: a degraded run, a different
`lonewolf-bench` build or host, a debug driver build, different metrics
settings, a remote server, or the same server binary on both sides.

A typical A/B comparison of a branch against `main`:

```sh
mkdir -p /tmp/ab
git switch main
cargo build --release -p lonewolf -p lonewolf-bench --locked
cp target/release/lonewolf /tmp/ab/lonewolf-a
cp target/release/lonewolf-bench /tmp/ab/lonewolf-bench

git switch my-branch
cargo build --release -p lonewolf --locked
cp target/release/lonewolf /tmp/ab/lonewolf-b

bench=/tmp/ab/lonewolf-bench
config=examples/bench/messages.toml
$bench run --config $config --server-binary /tmp/ab/lonewolf-a --output /tmp/ab/a1
$bench run --config $config --server-binary /tmp/ab/lonewolf-b --output /tmp/ab/b1
$bench compare /tmp/ab/a1 /tmp/ab/b1 --output /tmp/ab/a1-b1
```

Keeping a copy of the driver means a rebuild of `lonewolf-bench`, including the
one `cargo test --release` performs, cannot change the driver halfway through
a series.

One pair of runs is not enough to trust a small difference. The tool does no
statistics. First compare a few A/A pairs with the same server binary to see
the normal spread. Then alternate A and B runs (A1, B1, A2, B2, A3, B3) and
compare each pair. Never average percentiles across runs.

To find a limit, repeat a workload while raising only `rate_per_second` or
`connections`, and watch where the run turns degraded and why.

## Remote servers

A remote run measures a server you deployed yourself. The tool never changes
the server's configuration, and a remote run never creates accounts.

1. On the server host, generate the accounts. The output file is created with
   owner-only permissions and must not exist yet. Generate at least as many
   accounts as the workload needs: `connections` for idle, two per pair for
   messages, and `accounts` for churn.

   ```sh
   lonewolf-bench accounts generate --domain example.test --prefix bench \
     --count 2 --output /private/bench/credentials.json
   ```

2. Create the accounts through the server's admin socket. This requires
   `[admin]` to be enabled in the server configuration.

   ```sh
   lonewolf-bench accounts provision --socket /path/to/admin.sock \
     --credentials /private/bench/credentials.json
   ```

   Provisioning creates the accounts in file order and stops at the first
   failure, including an account that already exists. It prints
   `confirmed_created=<n>; uncertain_last_create=<bool>`. If the last create
   is uncertain, check that account on the server before you retry. The tool
   never deletes accounts.

3. Copy the credentials file to the driver machine yourself, for example with
   `scp`. It must stay owned by you and readable only by you.

4. Write the run configuration. Start from `examples/bench/remote.toml`.

5. Run the workload:

   ```sh
   lonewolf-bench run --config /private/bench/remote.toml \
     --output results/remote-001
   ```

The tool always verifies the server certificate against the bundled Mozilla
root store plus `ca_pem`. There is no option to skip verification. Use
`connect_host` to reach the server through an IP address or a tunnel.
`xmpp_domain` still decides which certificate name is accepted.

## Limits

- **SCRAM key derivation.** Each idle or messages session, and each churn
  account once, derives SCRAM keys with 100,000 PBKDF2 iterations. Local mode
  also derives each account's server credentials before starting the server. The tool runs this work on all CPU
  cores. On a 24-core desktop, creating 1,000 local accounts takes about 2 s,
  and connecting them at a ramp of 200 sessions per second takes 5 s.
- **Per-sender rate.** Each sender queues one message behind the one it is
  writing. If it is still busy when its next slot comes, the slot is skipped
  and the run is degraded. For example, 50 pairs at 20,000 messages/s (400/s
  per sender) skipped between 0% and 4% of the slots from one run to the next,
  while 500 pairs at the same rate skipped none. Spread a high rate over more
  pairs.
- **File descriptors.** The tool needs one descriptor per account plus 128.
  In local mode, the server needs the same plus 8 per worker. The tool checks
  `ulimit -n` before it starts.
- **Shared hardware.** In local mode, the tool and the server compete for the
  same CPU, memory and scheduler. The tool can become the bottleneck before
  the server does.
