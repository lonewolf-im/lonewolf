# Lonewolf

Lonewolf is a Rust XMPP server focused on performance and a low memory footprint.
It targets Unix systems, with Linux and macOS covered by CI.

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

Validate changes with the stable Rust toolchain:

```sh
export RUSTFLAGS="-D warnings"
export RUSTDOCFLAGS="-D warnings"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo build --workspace --all-features --release --locked
cargo doc --workspace --all-features --no-deps --locked
bash scripts/check-license-headers.sh
```

GitHub Actions runs these checks for pull requests, merge queues, pushes to `main`,
manual runs, and every Monday. Clippy, tests, and release builds run on Linux and
macOS. Compiler and documentation warnings fail CI. The `CI` job
requires every validation job to pass and can be used as a required status check
in branch protection.

Dependency checks use [cargo-deny](https://embarkstudios.github.io/cargo-deny/)
with the policy in [deny.toml](deny.toml). Install it and run the same check locally:

```sh
cargo install cargo-deny --version 0.20.2 --locked
cargo deny --workspace --all-features --locked check
```

The policy checks security advisories, licenses, dependency sources, and common
C/C++ backends across target-specific, build, and development dependencies for
the Linux and macOS targets listed in `deny.toml`.
Duplicate versions produce warnings. Only the licenses listed in `deny.toml` and
the default crates.io registry are allowed. The native backend denylist is not
exhaustive: dependency and feature changes still require review of the resolved
feature graph, build scripts, and native linkage under [AGENTS.md](AGENTS.md).

CI also runs [actionlint](https://github.com/rhysd/actionlint) and ShellCheck:

```sh
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
actionlint
shellcheck scripts/*.sh
```

Install ShellCheck with your system package manager and ensure Go's binary
directory is on `PATH`. Dependabot checks Cargo dependencies and pinned GitHub
Actions weekly. The actionlint version is pinned in the workflow and updated
manually.
