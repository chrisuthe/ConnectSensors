# cs-mailbox

The reference mailbox server for ConnectSensors federation
([spec 09](../spec/09-federation-relay.md)). It routes frames that one home's
proxies heard to the home that owns the sensor, and passes RX2 downlink requests
and their results between them. It holds no device keys, reads no payloads, and
keeps everything except its own key in memory.

The protocol rules (message schemas, deterministic CBOR, strict Ed25519,
registration proofs, the one-request-per-transmission rule) come from the
`connectsensors` package's public API, whose code is the spec's reference module,
[`spec/tools/csframe.py`](../spec/tools/csframe.py). `cs_mailbox.py` is the server
around them. Run from the checkout or the container, it takes the package from
`python/` in place.

## Run

From the checkout (Python 3.12 or later, with `cryptography` and `websockets`;
installed as a package it needs 3.13, as `connectsensors` does):

```sh
python3 mailbox/cs_mailbox.py --host mailbox.example \
    --tls-cert fullchain.pem --tls-key privkey.pem --key-file server.key
```

With uv, which also installs the `connectsensors` package from this checkout:

```sh
uv run --project mailbox cs-mailbox --host mailbox.example --tls-cert ... --tls-key ...
```

As a container, `ghcr.io/chrisuthe/cs-mailbox`: see [Container image](#container-image).

Homes connect with `devtools/cs_testserver.py --mailbox wss://mailbox.example:8443/`,
or as described in [Pointing a home at the server](#pointing-a-home-at-the-server).

## Configure

| Option | Default | Meaning |
|---|---|---|
| `--host NAME` | required | A host name clients use in the server's URL. Repeatable. The greeting signs it (09 section 12.3); a client that connected under any other name rejects the server. Use lowercase, with the A-label (`xn--`) form for internationalized names. |
| `--listen`, `--port` | `0.0.0.0`, `8443` | Where to listen. |
| `--trusted-proxy CIDR` | none | Serve plain `ws://` to a TLS-terminating reverse proxy in this range, and refuse every other peer. Repeatable. Not with `--tls-cert` or `--insecure-dev`. See [Behind a reverse proxy](#behind-a-reverse-proxy). |
| `--key-file FILE` | none | The server key's seed, in hex. Created on first start if missing. Without it the server makes a new key on every start, and every client treats it as a new server. |
| `--members FILE` | none | Admit only these client public keys, one hex key per line (`#` starts a comment). This gives a private (mode 2) or account-based (mode 3) server. |
| `--admit-per-hour N` | 20 | Without `--members`: new client keys admitted per source address per hour (mode 4, 09 section 5.4). Behind a proxy, the address the proxy reports. |
| `--reg-burst`, `--reg-per-hour` | 2048, 512 | Registration entries per owner key: an initial burst, then a steady rate. |
| `--reg-max-live` | 4096 | Live registrations per owner key. |
| `--publish-rate`, `--publish-burst` | 5, 20 | Publishes per second per client key. |
| `--request-rate`, `--request-burst` | 10, the rate | Requests per second per client key. |
| `--message-rate` | 50 | Signed messages of any kind per second per client key, burst twice that. |

The limit defaults are mode 4's (09 section 11). An entry or message over a limit
gets `RATE_LIMITED` and is not acted on.

## TLS

09 section 12.1 requires TLS 1.3, and clients validate the certificate against
the URL's host. Give the certificate chain and key with `--tls-cert` and
`--tls-key`, or let a reverse proxy terminate TLS (next section). The server
refuses to start without one of the two, unless you pass `--insecure-dev`, which
serves plain `ws://` to anyone. That mode exists for tests on one machine
(`tests/federation/`). Never use it anywhere else.

A client that pins a certificate instead of using the public PKI passes it with
`cs_testserver.py --mailbox-ca cert.pem`.

## Behind a reverse proxy

A reverse proxy you control, such as Nginx Proxy Manager or Caddy, can hold the
certificate and terminate TLS, and pass the WebSocket to `cs-mailbox` over plain
`ws://` (09 section 12.1). Clients still connect to `wss://mailbox.example/` and
see nothing different.

```sh
cs-mailbox --host mailbox.example --trusted-proxy 172.30.0.2/32 --key-file server.key
```

With `--trusted-proxy`:

- Only peers in the given ranges may connect. Anyone else gets HTTP 403 before
  the WebSocket handshake, logged at most once a minute per address (per /64 for IPv6).
- Admission counts each client by the address the proxy reports: the last
  `X-Forwarded-For` entry, which the proxy appended, else `X-Real-IP`. A
  malformed value, or none, counts against the proxy's own address. These
  headers are never read from anyone else.
- The `Host` header still picks which `--host` name the greeting signs, so give
  `--host` the public name, and the proxy must pass `Host` through (both below do).
- The startup line reads `Listening on ws://... behind trusted proxies ...`.

The hop from the proxy to `cs-mailbox` carries plain WebSocket, so keep it
private: loopback, a container network that holds only the two, or a LAN
segment no one else uses. Do not publish the mailbox's port, and make the trusted
range as narrow as you can: everything in it may connect without TLS.

Idle connections stay open through the proxy: the server pings every client
every 30 seconds, well inside nginx's 60-second default read timeout and Nginx
Proxy Manager's 90 seconds.

### Nginx Proxy Manager

Run `cs-mailbox` on a Docker network shared with NPM and nothing else, without
publishing its port:

```sh
docker network create --subnet 172.30.0.0/24 mailbox
docker network connect --ip 172.30.0.2 mailbox nginx-proxy-manager   # your NPM container's name
docker run -d --name cs-mailbox --network mailbox -v cs-mailbox:/data ghcr.io/chrisuthe/cs-mailbox \
    --host mailbox.example --trusted-proxy 172.30.0.2/32
```

Trust NPM's fixed address, not the whole network: the network's gateway
(172.30.0.1) is the Docker host itself, and connections from the host, or
through a published port with some port drivers, arrive from it. A compose
file that does the same is under [Container image](#with-nginx-proxy-manager).

Then in NPM, under Hosts, Proxy Hosts, Add Proxy Host:

1. **Details:** Domain Names `mailbox.example`; Scheme `http`; Forward
   Hostname / IP `cs-mailbox`; Forward Port `8443`; turn on **Websockets
   Support**.
2. **SSL:** request a Let's Encrypt certificate for the name (or pick one you
   have), and turn on **Force SSL**.

Homes then use `--mailbox wss://mailbox.example/`.

If NPM runs on another machine on your LAN, forward to the mailbox host's address
instead, and trust only NPM's address: `--trusted-proxy 192.168.1.20/32`.

NPM passes the public name through as `Host`, and sets `X-Forwarded-For` and
`X-Real-IP`. But NPM itself trusts an incoming `X-Real-IP` from private
addresses (10/8, 172.16/12, 192.168/16) and, by default, from the Cloudflare and
CloudFront ranges it downloads at startup. So a client on your LAN, or anyone
who routes through their own CloudFront distribution or Cloudflare zone pointed
at your name, can choose the address it is counted by. That only weakens open
admission's per-address limit (no authentication depends on it). For a public
mailbox that admits anyone:

- set `IP_RANGES_FETCH_ENABLED=false` on the NPM container unless you really
  front it with Cloudflare or CloudFront, and
- check NPM's access log shows real client addresses (some Docker port setups
  make every client look private).

Where the address must not be choosable at all, use `--members`.

### Caddy

With Caddy on the same machine, which obtains the certificate itself and passes
WebSockets, `Host` and `X-Forwarded-For` through by default:

```caddyfile
mailbox.example {
	reverse_proxy 127.0.0.1:8443
}
```

```sh
cs-mailbox --host mailbox.example --listen 127.0.0.1 --trusted-proxy 127.0.0.1/32 --key-file server.key
```

## Container image

`ghcr.io/chrisuthe/cs-mailbox`, for linux/amd64 and linux/arm64. Tags: the exact
version (`0.2.0`), the minor line (`0.2`, which follows patch releases) and
`latest`. Pin `0.2` or an exact version rather than `latest` in anything that
updates itself.

The container runs as uid 10001 and keeps the server key in `/data/server.key`.
Give `/data` a volume: the key is the server's identity, so losing it changes
`server_id` and every home treats the mailbox as a new server.

Configure it with arguments, as [Configure](#configure) lists, or with these
variables, which keep a compose file readable. Arguments win: a variable is
ignored when the arguments give its option, and the TLS and proxy variables all
are when the arguments pick a mode (`--tls-cert`, `--trusted-proxy`,
`--insecure-dev`). An empty variable is unset.

| Variable | Option |
|---|---|
| `CS_MAILBOX_HOST` | `--host`; several names comma-separated |
| `CS_MAILBOX_PORT` | `--port` (default 8443) |
| `CS_MAILBOX_TLS_CERT`, `CS_MAILBOX_TLS_KEY` | `--tls-cert`, `--tls-key` |
| `CS_MAILBOX_TRUSTED_PROXY` | `--trusted-proxy`; several ranges comma-separated |
| `CS_MAILBOX_MEMBERS` | `--members` |

The image's healthcheck connects to `CS_MAILBOX_PORT` on 127.0.0.1, which works
in both modes. To move the port inside the container (with `--network host`, say),
set `CS_MAILBOX_PORT` rather than passing `--port`, so the healthcheck follows.

To build it yourself, from the repository root:
`docker build -f mailbox/Dockerfile -t cs-mailbox .`

### With built-in TLS

```sh
docker run -d --name cs-mailbox --restart unless-stopped -p 8443:8443 \
    -v cs-mailbox:/data -v "$PWD/tls:/tls:ro" \
    -e CS_MAILBOX_HOST=mailbox.example \
    -e CS_MAILBOX_TLS_CERT=/tls/fullchain.pem -e CS_MAILBOX_TLS_KEY=/tls/privkey.pem \
    ghcr.io/chrisuthe/cs-mailbox:0.2
```

or with compose:

```yaml
services:
  cs-mailbox:
    image: ghcr.io/chrisuthe/cs-mailbox:0.2
    restart: unless-stopped
    ports: ["8443:8443"]
    environment:
      CS_MAILBOX_HOST: mailbox.example
      CS_MAILBOX_TLS_CERT: /tls/fullchain.pem
      CS_MAILBOX_TLS_KEY: /tls/privkey.pem
    volumes:
      - cs-mailbox:/data
      - ./tls:/tls:ro
volumes:
  cs-mailbox:
```

The server reads the certificate at start, so restart it after a renewal. The
key must be readable by uid 10001 in the container: `sudo chown 10001
tls/privkey.pem` with Docker, `podman unshare chown 10001 tls/privkey.pem` with
rootless Podman. (Mounting `/etc/letsencrypt` directly needs the same for its
`privkey.pem`.)

For a mailbox on your LAN without a public name, a self-signed certificate does:

```sh
mkdir tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj /CN=mailbox.lan -addext subjectAltName=DNS:mailbox.lan \
    -keyout tls/privkey.pem -out tls/fullchain.pem
```

Each home then trusts `tls/fullchain.pem` explicitly; see
[Pointing a home at the server](#pointing-a-home-at-the-server).

### With Nginx Proxy Manager

NPM holds the certificate and passes the WebSocket on over plain `ws://`; see
[Behind a reverse proxy](#behind-a-reverse-proxy) for what `--trusted-proxy`
does and why the trusted range is NPM's own address. In one compose file, with
the mailbox on a network only NPM shares and its port unpublished:

```yaml
services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    restart: unless-stopped
    ports: ["80:80", "443:443", "81:81"]
    environment:
      IP_RANGES_FETCH_ENABLED: "false"   # unless you front it with Cloudflare or CloudFront
    volumes:
      - ./npm/data:/data
      - ./npm/letsencrypt:/etc/letsencrypt
    networks:
      default:
      mailbox:
        ipv4_address: 172.30.0.2
  cs-mailbox:
    image: ghcr.io/chrisuthe/cs-mailbox:0.2
    restart: unless-stopped
    environment:
      CS_MAILBOX_HOST: mailbox.example
      CS_MAILBOX_TRUSTED_PROXY: 172.30.0.2/32
    volumes:
      - cs-mailbox:/data
    networks: [mailbox]
networks:
  mailbox:
    internal: true   # the mailbox needs no way out; NPM reaches it, nothing else does
    ipam:
      config: [{subnet: 172.30.0.0/24}]
volumes:
  cs-mailbox:
```

Then add the proxy host in NPM as in [Nginx Proxy Manager](#nginx-proxy-manager),
forwarding to `cs-mailbox` port `8443`, and homes use `wss://mailbox.example/`.

### Pointing a home at the server

In Home Assistant, open the Connect Sensors integration's options (Federation)
and add the server's URL under *Mailbox servers*:

- `wss://mailbox.example:8443/` with built-in TLS on the published port, or
  `wss://mailbox.example/` behind NPM.
- The URL's host must be one of the `--host` (`CS_MAILBOX_HOST`) names: the
  greeting signs it, and a home that connected under any other name rejects the
  server.
- With a self-signed certificate, paste it (the whole `fullchain.pem`) into
  *Trusted certificate*. A certificate from a public CA needs nothing there.

`devtools/cs_testserver.py` takes the same as `--mailbox URL` and `--mailbox-ca PEM`.

### Backing up and upgrading

Back up `/data/server.key`, and keep the copy as private as any key:

```sh
docker cp cs-mailbox:/data/server.key ./cs-mailbox-server.key
```

To restore it into a new volume before the first start, as the container's own user:

```sh
docker run --rm -i -v cs-mailbox:/data --entrypoint sh ghcr.io/chrisuthe/cs-mailbox:0.2 \
    -c 'umask 077 && cat > /data/server.key' < ./cs-mailbox-server.key
```

To upgrade, pull the new tag and recreate the container on the same volume
(`docker compose pull && docker compose up -d`). The `server_id` stays; the
registrations, which live in memory, do not, so the server starts a new
`generation` and every home registers its devices again when it reconnects.

## Limits

| Item | Limit | Enforced as |
|---|---|---|
| Message size | 4 096 bytes | close code 1009 |
| Entries per `register` | 32 | `MALFORMED` |
| Tags per `withdraw` | 256 | `MALFORMED` |
| Receptions per `publish` | 1 to 8 | `MALFORMED` |
| Frame | 23 to 86 bytes | `MALFORMED` |
| `expires` | after now, at most 7 days ahead | `BAD_EXPIRES` for that entry |
| `rx_ref` lifetime | 5 seconds | `UNKNOWN_RX_REF` |
| Transmission memory | 60 seconds | |
| Forward timeout | 3 seconds | a later result is ignored |

A fatal error (09 section 12.6) is sent as `error` before the server closes the
connection with code 4000 plus the error code. Registrations survive the
connection. Nothing survives a restart: the server then picks a new
`generation`, and owners register again.

## Behaviour where 09 leaves a choice

- A key may connect more than once. Frames for it are delivered on every
  connection, and a forwarded request goes to the connection that published the
  `rx_ref`. Its limits are shared by all its connections.
- Besides 09's limits, each key may send `--message-rate` signed messages a
  second (default 50, burst 100); beyond that a message gets `RATE_LIMITED`
  before its signature is checked. A client that leaves 256 server messages
  unread is closed with code 1008.
- New keys are counted per source address, and per /64 for IPv6. Behind a
  trusted proxy, that is the address the proxy reports.
- A request is checked against the request rate whether or not it passes the
  earlier checks, so failed requests count. `RATE_LIMITED` is still reported only
  for a request that passed checks 1 to 4 (09 section 7.3).
- A publisher's second `publish` of one transmission is dropped without an
  `error`.

## Tests

```sh
make -C tests/federation   # conformance against 09, trusted-proxy mode, then two homes through one mailbox
CONTAINER_ENGINE=podman make -C tests/mailbox-image   # the image in both modes (default engine: docker)
```

## Releasing the image

The image's version is `version` in `mailbox/pyproject.toml`, released
independently of the `connectsensors` package's `v*` tags.

1. Bump `version` in `mailbox/pyproject.toml` and merge it to `main`.
2. Tag that commit `mailbox-v<version>` and push the tag:
   `git tag mailbox-v0.2.0 && git push origin mailbox-v0.2.0`.

`.github/workflows/mailbox-release.yml` checks the tag matches the version, smoke
tests the image natively on amd64 and arm64, then pushes both platforms to
`ghcr.io/chrisuthe/cs-mailbox` as `<version>`, `<major>.<minor>` and `latest`,
with provenance and SBOM attestations. The first publish creates the package as
private: make it public once in its package settings on GitHub.
