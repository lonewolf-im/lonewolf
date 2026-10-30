<div align="center"><strong>Lonewolf: XMPP with teeth.</strong></div>
<div align="center">
  <img src="./.github/images/lonewolf.png"
       alt="lonewolf"
       width="25%">

[![CI](https://img.shields.io/github/actions/workflow/status/lonewolf-im/lonewolf/ci.yml?branch=main)](https://github.com/lonewolf-im/lonewolf/actions)
[![Releases](https://img.shields.io/github/v/release/lonewolf-im/lonewolf?include_prereleases)](https://github.com/lonewolf-im/lonewolf/releases)
[![LICENSE](https://img.shields.io/github/license/lonewolf-im/lonewolf)](https://github.com/lonewolf-im/lonewolf/blob/main/LICENSE)

</div>

Lonewolf is a self-hosted [XMPP](https://xmpp.org/) server written in Rust. It's
meant to be easy to set up, cheap to run, and able to grow into a cluster when you
need one.

> [!NOTE]
> Lonewolf is early, pre-1.0 software. Today it hosts chat between accounts on
> the domains you run. Federation with other XMPP servers is in progress, and
> clustering comes later.
>
> Most of Lonewolf's code, tests and docs are written with AI coding agents. The
> maintainer sets the design and scope and reviews the changes.

## Why Lonewolf?

- **Easy to run.** One binary with embedded storage. There's no database server
  to install, and a local test server needs two lines of config.
- **Light on resources.** It's native Rust and frugal with memory and CPU.
- **Standards first.** It follows the core XMPP RFCs closely, so standard
  clients behave the way you'd expect.
- **Limits you can see.** Connections, stanzas, rates and resources all have
  configurable limits, so one misbehaving client can't take your server down.

## What works today

- Chat between accounts on any domain you host, with several devices per account
- Contact lists, presence subscriptions, and offline messages that keep their
  original timestamps
- Message copies across your devices (Carbons), service discovery, vCard
  profiles and ping
- STARTTLS, SCRAM login with channel binding, and optional client-certificate
  login
- TLS certificates from your own files or from Let's Encrypt
- Account management with `lonewolfctl`, Prometheus metrics, structured logs and
  graceful shutdown

Lonewolf runs on Unix-like systems, and CI tests it on Linux and macOS. The
[standards reference](docs/STANDARDS.md) lists every supported XEP and RFC, and
its limits.

## What's next

Federation with other XMPP servers is being built on `main` but isn't in a
release yet. After that, the [roadmap to 1.0](docs/ROADMAP.md) covers, in order:

1. Group chats, file upload and the rest of basic desktop IM
2. Message archives, Stream Management, blocking, avatars and bookmarks
3. PostgreSQL storage and clustering
4. Mobile and web support

## Quick start

Let's get a server running on your machine and send a message between two
accounts. It only takes a few minutes, plus however long your first Rust build
takes.

You'll need Linux or macOS, Git, a [stable Rust toolchain](https://rust-lang.org/tools/install/),
a system linker, and an [XMPP client](https://xmpp.org/software/) to chat with.

### 1. Build it

```sh
git clone https://github.com/lonewolf-im/lonewolf.git
cd lonewolf
cargo build --release --locked -p lonewolf -p lonewolfctl
```

You'll end up with two binaries in `target/release/`: `lonewolf`, the server, and
`lonewolfctl`, a small tool for managing accounts.

### 2. Start the server

Create a `lonewolf.toml` in the repo root with a single listener:

```toml
[[c2s.listeners]]
address = "127.0.0.1:5222"
```

Then start it:

```sh
./target/release/lonewolf --config ./lonewolf.toml
```

That's all the config you need. Lonewolf listens on your loopback address only,
serves the built-in `localhost` domain with its default features, and keeps
everything in an embedded [redb](https://github.com/cberner/redb) database. Leave
it running.

### 3. Create two accounts

In a second terminal, from the same directory:

```sh
./target/release/lonewolfctl account create alice@localhost
./target/release/lonewolfctl account create bob@localhost
./target/release/lonewolfctl account list
```

You'll be asked to choose a password for each account. Addresses like
`alice@localhost` are called JIDs, short for Jabber IDs.

### 4. Say hello

Sign in as both users, using two clients or two accounts in one client, with
these settings:

| Setting | Value |
| --- | --- |
| Account | `alice@localhost` or `bob@localhost` |
| Password | The one you just chose |
| Server address override | `127.0.0.1` |
| Port | `5222` |
| Connection security | STARTTLS, required |

The server creates a self-signed certificate for `localhost` when it starts, so
your client will ask whether to trust it. Say yes for this test. You'll get a new
certificate each time the server restarts, unless you give Lonewolf your own.

Now add `bob@localhost` as a contact from Alice's account, and accept the request
on Bob's side. You should see each other come online and be able to chat.

Want to see offline delivery? Sign Bob out and send him a message. He'll get it,
with its original timestamp, the next time he signs in.

When you're done, press `Ctrl+C` to stop the server. Your accounts and any
undelivered messages are saved in `./data/lonewolf.dat`.

## Configuration

Lonewolf reads `./lonewolf.toml` if it exists and uses built-in defaults
otherwise. If you pass `--config`, that file has to exist.

[`examples/lonewolf.toml`](examples/lonewolf.toml) documents every setting and its
default. Everything in it is commented out, so you only uncomment what you want
to change.

### Hosting your own domain

To serve a real domain, give Lonewolf a certificate for it:

```toml
[hosts."example.com".tls]
certificate_chain_path = "./certs/example.com.crt"
private_key_path = "./certs/example.com.key"

[[c2s.listeners]]
address = "0.0.0.0:5222"
```

This replaces the default `localhost` host with `example.com` and listens on all
IPv4 interfaces. Relative paths are resolved from the directory you start the
server in.

### Let's Encrypt

To have Lonewolf get and renew the certificate for you, replace the file paths
with one line. You can choose this per host.

```toml
[hosts."example.com".tls]
provider = "letsencrypt"
```

This accepts Let's Encrypt's subscriber terms. Let's Encrypt checks that you
control the domain by connecting to port 80 on each of its public addresses, so
that port has to reach Lonewolf. If a proxy already owns port 80, have it forward
to a local port, keeping the original Host header and path:

```toml
[letsencrypt]
listen = ["127.0.0.1:8080"]
```

The certificates and ACME account live in `./data/lonewolf/acme.redb`, so keep it
on durable storage. To test against Let's Encrypt's staging server first, see
`directory_url` in the config reference.

## Managing accounts

`lonewolfctl` talks to the running server over a local Unix socket, which is
`./run/lonewolf/admin.sock` by default. Anyone who can open that socket can
manage accounts, so restrict its file permissions.

```sh
./target/release/lonewolfctl account list
./target/release/lonewolfctl account get alice@localhost
./target/release/lonewolfctl account password alice@localhost
./target/release/lonewolfctl account delete bob@localhost
```

Changing a password prompts for the new one twice, and deleting an account asks
you to confirm first. A few handy flags:

- `--socket PATH` for when the server uses a different socket, or you're running
  the tool from another directory
- `--json` for machine-readable output
- `--password-stdin` to read the password from standard input, for scripting
  `create` and `password`

## Contributing

Found a bug or have an idea? [Open an issue](https://github.com/lonewolf-im/lonewolf/issues).
For bug reports, it helps to include the commit you built, your platform, the
relevant config, and steps to reproduce. Please strip out passwords and private
messages first.

Found a security problem? Please report it privately instead; see
[SECURITY.md](SECURITY.md).

Thinking about a new feature? Check the [roadmap](docs/ROADMAP.md) first. It may
already be planned, and it helps us figure out where the feature fits.

## License

Lonewolf is licensed under [Apache-2.0](LICENSE).
