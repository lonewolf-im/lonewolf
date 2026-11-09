# Direct TLS metrics

Transport labels distinguish `starttls` from `direct` without adding hostnames,
addresses, SNI, certificate identities, or error strings to metrics.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `lonewolf_c2s_listener_info` | `listener`, `tls_mode` | Gauge `1` for a bound client listener. |
| `lonewolf_s2s_listener_info` | `listener`, `tls_mode` | Gauge `1` for a bound federation listener. |
| `lonewolf_s2s_transport_attempts_total` | `direction`, `tls_mode`, `outcome` | Terminal results of individual admitted negotiations or outgoing endpoint attempts. |
| `lonewolf_s2s_transport_connections` | `direction`, `tls_mode` | Admitted TCP connections that remain open. |

`tls_mode` is `starttls` or `direct`. `direction` is `inbound` or `outbound`.
Listener numbers follow configuration and readiness order. Workers share one
listener sample. Listener information disappears after its last bound worker
closes, including startup rollback. Disabled federation exposes no S2S metrics.
Existing C2S authentication and connection counters keep their listener labels;
join them with `lonewolf_c2s_listener_info` to identify the transport.

## Attempt results

An inbound attempt starts after admission and before ClientHello or XML. An
admitted future that is dropped before its first poll still counts as an attempt.
Admission rejections remain in the existing rejection counters and create no
transport attempt.

An outbound attempt starts immediately before connecting to one endpoint. TCP
refusal and connection timeout count. DNS results with no candidate and failures
before a connector starts create no transport attempt.

Each attempt records one result. `success` means authenticated negotiation has
completed, including EXTERNAL, protected restart, and stream limits. TLS success
alone is insufficient. A terminal result is recorded before failure cleanup;
cleanup does not create another attempt or replace that result.

The outcome values are:

- `success`, `host_unknown`, `missing_from`, `invalid_from`, `no_certificate`
- `certificate_untrusted`, `certificate_name`, `certificate_purpose`, `certificate_expired`, `certificate_revoked`
- `revocation_unknown`, `revocation_stale`, `revocation_unavailable`
- `tls_failure`, `no_tls`, `tls_refused`, `external_not_offered`
- `invalid_authzid`, `invalid_mechanism`, `sasl_failure`
- `unreachable`, `timeout`, `protocol`, `cancelled`

`cancelled` means an attempt ended without selecting a terminal negotiation
result. It includes shutdown, cancellation of a pending connect or handshake,
and an admitted future dropped before it runs. Cancellation during cleanup does
not replace an already recorded failure. Zero-valued attempt series are omitted.

## Comparing attempts with existing metrics

`lonewolf_s2s_authentications_total` retains its existing scope. Inbound values
summarize polled negotiations. An outgoing value summarizes the whole
establishment across candidate endpoints. For example, a failed direct endpoint
followed by successful STARTTLS records two transport attempts and one aggregate
successful authentication. DNS still records one logical resolution when it
queries both SRV services.

The aggregate authentication result can remain `unreachable` after every TCP
connect attempt times out. Each individual transport attempt records `timeout`.
An unfinished aggregate negotiation retains its existing `protocol` outcome;
its unfinished transport attempt records `cancelled`.

## Connection lifetimes

Transport connection gauges use the same guards as
`lonewolf_s2s_connections{direction}`. Inbound connections enter after admission;
outbound connections enter after TCP connect succeeds. A refusal or cancelled
connect has no open connection. TLS failure, timeout, cancellation, bidi handoff,
replacement, graceful close, and forced shutdown release both views together.
Bidi traffic does not change the direction of its underlying connection.

At a stable observation point, the mode sum equals the existing direction total:

```promql
sum by (direction) (lonewolf_s2s_transport_connections)
```

Compare that result with `lonewolf_s2s_connections`. Collectors read separate
atomic counters, so a scrape during a connection transition can briefly observe
different values. After all connections close, all four transport gauges and
both direction gauges are zero.

There are four transport connection series and at most 96 transport attempt
series: two directions, two modes, and 24 outcomes. No peer identity increases
this cardinality.
