# Account administration

The server accepts HTTP/1.1 and JSON on `./run/lonewolf/admin.sock` by default.
Set `admin.socket_path` to change the path or `admin.enabled = false` to disable
the listener. The configuration reference is in `examples/lonewolf.toml`.

Access is controlled by the filesystem: the parent directory must be private
and owned by the server user, and the socket uses mode `0600`. Run clients as
that user. The service does not listen on TCP.

Existing socket paths are never replaced. After an unclean exit, confirm that
the server has stopped before removing its stale socket. Graceful shutdown
stops accepting connections, drains accepted requests within their deadlines,
and removes the socket if its identity is unchanged.

## Requests

| Method | Path | JSON body | Success |
| --- | --- | --- | --- |
| POST | `/v1/accounts` | `{"jid":"alice@example.org","password":"…"}` | 201, account |
| GET | `/v1/accounts/{jid}` | None | 200, account |
| GET | `/v1/accounts?limit=50&after={jid}` | None | 200, page |
| PUT | `/v1/accounts/{jid}/password` | `{"password":"…"}` | 204 |
| DELETE | `/v1/accounts/{jid}` | None | 204 |

Send `Content-Type: application/json` for requests with JSON bodies. Unknown
JSON fields and query parameters are rejected. JIDs must include a username
and domain without a resource. They are normalized before use. Percent-encode
JIDs in paths and query parameters, including `+`, `%`, and other reserved
characters. Credentials are never returned.

An account response has the form `{"jid":"alice@example.org"}`. Passwords are
converted to salted SCRAM-SHA-1 and SCRAM-SHA-256 credentials with 100,000
iterations on bounded blocking workers. Owned password buffers are cleared
when released.

```sh
curl --unix-socket ./run/lonewolf/admin.sock \
  'http://localhost/v1/accounts?limit=50'
```

## Listing

```json
{
  "accounts": [{"jid": "alice@example.org"}],
  "next_cursor": "alice@example.org"
}
```

`limit` defaults to 50 and accepts 1 through 100. `after` is an exclusive
canonical-key cursor; the referenced account need not exist. Omit it for the
first page. Pass `next_cursor` as `after` for the next request. A null cursor
marks the last page.

Each request reads one storage snapshot. Separate pages can observe concurrent
changes. The service reads at most `limit + 1` accounts and retains only the
bounded encoded response and cursor. It releases the snapshot before sending
the response. A storage error discards the page and returns an error.

## Limits and errors

The service handles at most 32 connections concurrently, with one request per
connection and a 30-second connection deadline. JSON bodies are limited to
16 KiB; HTTP headers are limited to 32 fields within a 16 KiB parsing buffer.
Password derivation admits at most two blocking jobs at a time.

Application errors use `{"error":{"code":"invalid_request"}}`.

| Status | Codes |
| --- | --- |
| 400 | `invalid_request`, `invalid_jid`, `invalid_password` |
| 404 | `not_found` |
| 405 | `method_not_allowed` (with an `Allow` header) |
| 409 | `account_exists` |
| 413 | `body_too_large` |
| 415 | `unsupported_media_type` |
| 500 | `internal_error`, `commit_unknown` |
| 503 | `storage_unavailable` |

Malformed HTTP can be rejected before JSON handling. A connection deadline or
disconnect does not roll back a storage operation that has already started.
After `commit_unknown` or a lost response to a mutation, check the resulting
state before retrying. Account metadata does not confirm a password change;
the replacement can be submitted again if its outcome is unknown.
