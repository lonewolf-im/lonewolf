<div align="center"><strong>Lonewolf: XMPP with teeth.</strong></div>
<div align="center">
  <img src="./.github/images/lonewolf.png"
       alt="lonewolf"
       width="25%">

[![CI](https://img.shields.io/github/actions/workflow/status/lonewolf-im/lonewolf/ci.yml?branch=main)](https://github.com/lonewolf-im/lonewolf/actions)
[![Releases](https://img.shields.io/github/v/release/lonewolf-im/lonewolf?include_prereleases)](https://github.com/lonewolf-im/lonewolf/releases)
[![LICENSE](https://img.shields.io/github/license/lonewolf-im/lonewolf)](https://github.com/lonewolf-im/lonewolf/blob/main/LICENSE)

</div>

Lonewolf is a self-hosted [XMPP](https://xmpp.org/) server with a simple goal:
combine easy setup and operation with high performance and a path to clustering.
Start small, grow when you need to, and keep your server easy to run.

> [!NOTE]
> Lonewolf is early, pre-1.0 software. Today it can host chat between accounts on
> domains you run. Federation with other XMPP servers is next on the
> [roadmap](docs/ROADMAP.md); clustering comes later.
>
> Most of Lonewolf's code, tests and docs are written with AI coding agents. The
> maintainer sets the design and scope and reviews the changes.

## Why Lonewolf?

- **Easy to run.** One server binary with embedded storage, no database server
  or runtime to install, and just two lines of config for local testing.
- **Room to grow.** The goal is to keep operation simple as your deployment grows,
  from a standalone server to a cluster. PostgreSQL storage and multi-node
  operation are on the [roadmap](docs/ROADMAP.md).
- **Light on resources.** It's a native Rust binary built to be frugal with
  memory and CPU.
- **Standards first.** Lonewolf follows the core XMPP RFCs
  ([RFC 6120](https://www.rfc-editor.org/rfc/rfc6120.html) and friends) closely,
  aiming for standards-compliant clients to behave the way you'd expect.
- **Limits you can see.** Connections, stanzas, rates, and resources all have
  explicit, configurable limits, so one misbehaving client can't quietly take
  down your server.

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

That's all the config you need. With this configuration, Lonewolf listens on your
loopback address only. It serves the built-in `localhost` domain, turns on contact
lists and offline messages, and keeps everything in an embedded [redb](https://github.com/cberner/redb)
database. Leave it running.

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
your client will ask whether to trust it. Say yes for this test. The certificate
changes every time the server restarts, unless you point Lonewolf at your own
certificate files.

Now add `bob@localhost` as a contact from Alice's account, and accept the request
on Bob's side. You should see each other come online and be able to chat.

Want to see offline delivery? Sign Bob out and send him a message. He'll get it,
with its original timestamp, the next time he signs in.

When you're done, press `Ctrl+C` to stop the server. Your accounts and any
undelivered messages are saved in `./data/lonewolf.dat`.

## What works today

**Connections and security**

- TCP connections secured with STARTTLS
- SCRAM authentication, plus optional client-certificate login
- Automatic TLS certificates from Let's Encrypt, or your own certificate files

**Messaging and presence**

- Direct messaging between accounts on any domain you host, with multiple
  devices (resources) per account
- Contact lists (rosters), subscriptions, presence, and roster versioning
- Offline messages that are stored, timestamped, and delivered when the
  recipient comes back

**Running it**

- Host several domains, each with its own roster and offline settings
- Embedded redb storage for accounts, credentials, rosters, and offline messages
- Account management with `lonewolfctl`
- Configurable limits for connections, stanzas, rates, and resources
- Structured logs and graceful shutdown

## What's next

For now, Lonewolf only talks to clients. It can't exchange messages with other XMPP
servers yet. It runs on Unix-like systems, and CI tests it on Linux and macOS.

The [roadmap to 1.0](docs/ROADMAP.md) lays out each milestone, the XEPs it needs,
and what "done" means for it. In order:

1. **Desktop Basic IM**, including federation with other servers and group chats (MUC)
2. **Advanced IM**: message archives and Stream Management
3. **PostgreSQL storage and clustering**
4. **Mobile and web support**

## Configuration

Lonewolf uses a TOML config file. By default it looks for `./lonewolf.toml` and
falls back to built-in defaults if there isn't one. If you pass `--config`, that
file has to exist.

### Hosting your own domain

To serve a real domain instead of `localhost`, Lonewolf needs a certificate for
it. You can hand it your own PEM files, or let it get one from Let's Encrypt.
With files, it looks like this:

```toml
[hosts."example.com"]
extensions = ["roster", "offline"]

[hosts."example.com".tls]
certificate_chain_path = "./certs/example.com.crt"
private_key_path = "./certs/example.com.key"

[[c2s.listeners]]
address = "0.0.0.0:5222"
```

This replaces the default `localhost` host with `example.com` and listens on all
IPv4 interfaces. The certificate files need to be in place before you start the
server.

> [!TIP]
> Relative paths, including the certificate, database, and admin socket paths,
> are resolved from the directory you launch the server in.

### Let's Encrypt certificates

Don't want to manage certificates yourself? Replace the file paths with a single
line, and Lonewolf gets a certificate from Let's Encrypt and renews it before it
expires:

```toml
[hosts."example.com".tls]
provider = "letsencrypt"
```

The choice is per host. You can switch a domain that already uses certificate
files over to Let's Encrypt by changing just its `tls` table, and keep files for
the rest.

Choosing `letsencrypt` registers an ACME account and accepts Let's Encrypt's
subscriber terms. To prove you control the domain, Let's Encrypt connects to
public port 80 on every A and AAAA address the domain publishes, so that port has
to reach Lonewolf. If something else already serves port 80, or you'd rather not
let Lonewolf bind it, have your proxy forward it to a local port instead. The
proxy must keep the original Host header and path:

```toml
[letsencrypt]
listen = ["127.0.0.1:8080"]
```

Lonewolf keeps the ACME account and certificates in `./data/lonewolf/acme.redb`
by default, so put that on durable storage. To try it out first, point
`directory_url` at Let's Encrypt's staging server; the config reference shows
how.

Every setting, its default, and the certificate requirements are documented in
[`examples/lonewolf.toml`](examples/lonewolf.toml). Everything there is commented
out, so you only need to uncomment what you want to change.

## Managing accounts

`lonewolfctl` talks to the running server over a local Unix socket, which is
`./run/lonewolf/admin.sock` by default. Access is controlled by filesystem
permissions, so anyone who can open the socket can manage accounts. Lock it down
accordingly.

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
