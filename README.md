<div align="center"><strong>Lonewolf: XMPP with teeth.</strong></div>
<div align="center">
  <img src="./.github/images/lonewolf.png"
       alt="lonewolf"
       width="25%">

[![CI](https://img.shields.io/github/actions/workflow/status/lonewolf-im/lonewolf/ci.yml?branch=main)](https://github.com/lonewolf-im/lonewolf/actions)
[![Releases](https://img.shields.io/github/v/release/lonewolf-im/lonewolf?include_prereleases)](https://github.com/lonewolf-im/lonewolf/releases)
[![LICENSE](https://img.shields.io/github/license/lonewolf-im/lonewolf)](https://github.com/lonewolf-im/lonewolf/blob/main/LICENSE)

</div>

Lonewolf is an [XMPP](https://xmpp.org/) server you run yourself. It handles the
core of instant messaging (accounts, contacts, presence, and message delivery),
and it's built to be strict about the protocol, frugal with resources, and upfront
about its limits.

> [!NOTE]
> Lonewolf is early, pre-1.0 software. Today it can host chat between accounts on
> domains you run. Federation with other XMPP servers is next on the
> [roadmap](docs/ROADMAP.md). There are no releases yet, so you'll build from source.

## Why Lonewolf?

- **Correct by design.** Lonewolf follows the core XMPP RFCs
  ([RFC 6120](https://www.rfc-editor.org/rfc/rfc6120.html) and friends) closely,
  so standards-compliant clients behave the way you'd expect.
- **Light on resources.** It's a native Rust binary with embedded storage. There's
  no database server to set up and no runtime to install.
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

To serve a real domain instead of `localhost`, give Lonewolf a PEM certificate
chain and private key for it:

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

Thinking about a new feature? Check the [roadmap](docs/ROADMAP.md) first. It may
already be planned, and it helps us figure out where the feature fits.

## License

Lonewolf is licensed under [Apache-2.0](LICENSE).
