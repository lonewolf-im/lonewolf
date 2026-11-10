# Stream byte metrics

`lonewolf_c2s_received_bytes_total`, `lonewolf_c2s_sent_bytes_total`,
`lonewolf_s2s_received_bytes_total` and `lonewolf_s2s_sent_bytes_total`
count successful TLS socket I/O completions returned by Compio. Observation
occurs below the stream adapter's buffers. Buffered write acceptance does not
add bytes; successful partial operations add their returned count.

The counters include reported handshake traffic, TLS record overhead, alerts
and closure traffic. They exclude plaintext exchanged before STARTTLS, TCP/IP
headers and retransmissions. Direct TLS counting starts before ClientHello
processing; STARTTLS counting starts after the plaintext upgrade exchange.

A later handshake failure does not remove reported bytes. Cancellation or
runtime teardown can discard operation results before the observer receives
them, so the counters can undercount completed kernel I/O during those paths.
They are not lossless network accounting. Pending and failed results add no
bytes.

C2S retains its `listener` label. S2S retains its physical connection
`direction` label (`inbound` or `outbound`), including bidirectional stanza
traffic. S2S idle activity and cooperative reads remain at the decrypted XML
layer and do not define the byte-counter boundary.
