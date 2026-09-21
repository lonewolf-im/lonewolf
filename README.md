# Lonewolf

An XMPP messaging server

## Startup logging

On startup, Lonewolf writes an INFO event to stderr before loading configuration:

```text
INFO lonewolf: lonewolf is starting... version="0.1.0" branch="main" commit="abc1234"
```

Each event includes a timestamp. The version comes from the package manifest;
the branch and short commit hash are embedded by `build.rs`. A detached checkout
reports `branch="detached"`. Builds without Git metadata use `"unknown"` for the
branch and commit. Git is not needed at runtime. `--help` and `--version` do not
initialize logging.

Logging uses a bounded queue of 1,024 lines and a background writer. If the queue
fills, new lines are dropped to keep the calling thread from blocking. Queued
logs are flushed on normal exit.

## Configuration

The [configuration reference](examples/lonewolf.toml) documents every supported
setting and its default. All sections and values are commented out. Copy it to
`lonewolf.toml` and uncomment the sections and values you want to change:

```sh
cp examples/lonewolf.toml lonewolf.toml
cargo run -p lonewolf -- --config lonewolf.toml
```

`-c` is the short form of `--config`. With no argument, Lonewolf looks for
`lonewolf.toml` in the current directory and uses built-in defaults if that file
is absent. An explicit path must exist. Read errors and invalid configuration
produce a diagnostic on stderr and a nonzero exit status.

The default settings are:

```toml
[admin]
enabled = true
listen_addr = "127.0.0.1:8080"
```

Omitted settings use their defaults. An empty file also uses defaults. Set
`admin.enabled` to `false` to disable the admin server. The listen address must
contain an IPv4 or bracketed IPv6 address and a port, such as `[::1]:8080`.
Unknown keys, duplicate keys, and invalid values are rejected.

The executable currently loads and validates configuration, then exits. The admin
service and listener startup will be added separately.
