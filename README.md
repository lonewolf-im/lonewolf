# Lonewolf

XMPP server written in Rust

## Configuration

Run with a YAML configuration file:

```sh
cargo run -p lonewolf -- --config lonewolf.example.yaml
```

`-c` is the short form of `--config`. With no argument, Lonewolf looks for
`lonewolf.yaml` in the current directory and uses built-in defaults if that file
is absent. An explicit path must exist. Read errors and invalid configuration
produce a diagnostic on stderr and a nonzero exit status.

The default settings are:

```yaml
admin:
  enabled: true
  listen_addr: "127.0.0.1:8080"
```

Omitted settings use their defaults. An empty file also uses defaults. Set
`admin.enabled` to `false` to disable the admin server. The listen address must
contain an IPv4 or bracketed IPv6 address and a port, such as `[::1]:8080`.
Unknown keys, duplicate keys, and invalid values are rejected.

The executable currently loads and validates configuration, then exits. The admin
service and listener startup will be added separately.
