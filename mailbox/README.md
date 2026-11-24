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

As a container, built from the repository root:

```sh
docker build -f mailbox/Dockerfile -t cs-mailbox .
docker run -p 8443:8443 -v cs-mailbox:/data -v /etc/letsencrypt/live/mailbox.example:/tls:ro \
    cs-mailbox --host mailbox.example --tls-cert /tls/fullchain.pem --tls-key /tls/privkey.pem
```

The container keeps the server key in `/data/server.key`.

Homes connect with `devtools/cs_testserver.py --mailbox wss://mailbox.example:8443/`.

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
docker run -d --name cs-mailbox --network mailbox -v cs-mailbox:/data cs-mailbox \
    --host mailbox.example --trusted-proxy 172.30.0.2/32
```

Trust NPM's fixed address, not the whole network: the network's gateway
(172.30.0.1) is the Docker host itself, and connections from the host, or
through a published port with some port drivers, arrive from it.

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
```
