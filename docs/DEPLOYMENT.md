# Deploying Lonewolf

This guide covers running Lonewolf on a public domain with Let's Encrypt certificates, behind an existing web proxy or inside a container. The [configuration reference](../examples/lonewolf.toml) describes every setting.

## Minimal configuration

Serving `xmpp.example.com` with an automatic certificate takes one table:

```toml
[hosts."xmpp.example.com".tls]
provider = "letsencrypt"
```

Everything else comes from the defaults:

- Clients connect on `0.0.0.0:5222` and other servers on `0.0.0.0:5269`.
- Federation and the default extensions are on.
- Let's Encrypt validation requests arrive on `0.0.0.0:80`.
- Accounts and messages live in `./data/lonewolf.dat`, and the certificate state in `./data/lonewolf/acme.redb`.
- `lonewolfctl` reaches the server through `./run/lonewolf/admin.sock`.

Defining a host replaces the built-in `localhost` host. Relative paths start from the directory where Lonewolf was launched.

Choosing this provider accepts Let's Encrypt's subscriber terms. While you test your setup, point `letsencrypt.directory_url` at the staging server so failed attempts do not count against production rate limits.

## Ports and DNS

Lonewolf requests a certificate for the XMPP domain itself, so that domain's A and AAAA records must point to this machine.

| Port | Used by | Notes |
| --- | --- | --- |
| 5222/tcp | XMPP clients | Forward it to Lonewolf. |
| 5269/tcp | Other XMPP servers | Needed only for federation. Forward it to Lonewolf. |
| 80/tcp | Let's Encrypt validation | Let's Encrypt connects to port 80 on every A and AAAA address of the domain. A web proxy may own this port and forward validation requests. |

XMPP connections are not HTTP. Forward ports 5222 and 5269 directly or through a TCP-level proxy, not through an HTTP proxy.

## Behind a web proxy

When a proxy already serves port 80, move the validation listener to a local port:

```toml
[letsencrypt]
listen = ["127.0.0.1:8080"]
```

Then forward the domain's plain HTTP traffic to it. The proxy must keep the original `Host` header and request path. Lonewolf answers only under `/.well-known/acme-challenge/`.

With Caddy, use an `http://` site address so Caddy does not request its own certificate for the domain or redirect it to HTTPS:

```Caddyfile
http://xmpp.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

With nginx, set the `Host` header explicitly, because nginx replaces it by default:

```nginx
server {
    listen 80;
    server_name xmpp.example.com;

    location /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

## In a container

Lonewolf writes to `./data` and `./run` below its working directory, so both must be writable by the user the container runs as. Only `./data` needs to survive restarts.

Give `./data` the right owner before the first start. Docker creates a missing bind-mount directory as root, and Lonewolf then cannot create its files. Either create the directory yourself:

```sh
mkdir -p data
sudo chown 1000:1000 data
```

or use a named volume and create the data directory in the image, owned by the runtime user. Docker copies that ownership into a new, empty named volume.

Keep `./data` on a local filesystem. Lonewolf locks and syncs its database files, and network shares or synced folders may not support that.

Inside a container, a high validation port avoids privileged-port rules. Publish it on the port your proxy forwards to, or on the host's port 80 when no proxy is involved:

```toml
[letsencrypt]
listen = ["0.0.0.0:8080"]
```

```yaml
services:
  lonewolf:
    ports:
      - "5222:5222"
      - "5269:5269"
      - "127.0.0.1:8080:8080"
    volumes:
      - ./lonewolf.toml:/app/lonewolf.toml:ro
      - ./data:/app/data
```

This example assumes the image runs Lonewolf from `/app`. Run `lonewolfctl` inside the same container, from the same working directory, so it finds the admin socket:

```sh
docker compose exec lonewolf /app/lonewolfctl account create alice@xmpp.example.com
```

## Troubleshooting

Lonewolf stops when it cannot use its certificate state, and prints the state path with the cause:

| Message | What to check |
| --- | --- |
| `ACME state unavailable: Permission denied (os error 13)` | The user running Lonewolf must own the data directory. |
| `ACME state unavailable:` followed by another system error | The error names the cause, such as a full disk or a read-only filesystem. |
| `ACME state is in use by another open instance` | Another Lonewolf process or container uses the same data directory. |
| `ACME state path is not private regular storage` | The state file must be a regular file that only its owner can read and write. |
| `corrupt ACME state` | The file at the state path is not Lonewolf certificate state. |

When validation fails, Lonewolf keeps running and logs `ACME certificate will retry` with an `outcome` field. `outcome=Authorization` usually means Let's Encrypt could not fetch the validation response: check that port 80 reaches Lonewolf from the internet on every published address, and that your proxy keeps the `Host` header.
