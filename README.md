# Lonewolf

Lonewolf is a Rust XMPP server focused on performance and a low memory footprint.

The Rust 2024 workspace contains two crates:

- `lonewolf`: the server binary, which depends on `lonewolf-xmpp`.
- `lonewolf-xmpp`: the protocol library, with `jid` and `stanza` modules.

This is a skeleton. The server entry point and protocol modules are empty; no
networking or XMPP behavior is implemented. There are no third-party dependencies.

```text
crates/
├── lonewolf/
│   ├── Cargo.toml
│   └── src/main.rs
└── lonewolf-xmpp/
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── jid.rs
        └── stanza.rs
```

Build and run the server entry point:

```sh
cargo build --workspace
cargo run -p lonewolf
```

Validate changes:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```
