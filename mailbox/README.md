# cs-mailbox

The reference mailbox server for ConnectSensors federation
([spec 09](../spec/09-federation-relay.md)). It routes frames that one home's
proxies heard to the home that owns the sensor, and passes RX2 downlink requests
and their results between them. It holds no device keys, reads no payloads, and
keeps everything except its own key in memory.

The protocol rules (message schemas, deterministic CBOR, strict Ed25519,
registration proofs, the one-request-per-transmission rule) come from the spec's
reference module, [`spec/tools/csframe.py`](../spec/tools/csframe.py).
`cs_mailbox.py` is the server around them.

## Run

From the checkout (Python 3.12 or later, with `cryptography` and `websockets`):

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
| `--key-file FILE` | none | The server key's seed, in hex. Created on first start if missing. Without it the server makes a new key on every start, and every client treats it as a new server. |
| `--members FILE` | none | Admit only these client public keys, one hex key per line (`#` starts a comment). This gives a private (mode 2) or account-based (mode 3) server. |
| `--admit-per-hour N` | 20 | Without `--members`: new client keys admitted per source address per hour (mode 4, 09 section 5.4). |
| `--reg-burst`, `--reg-per-hour` | 2048, 512 | Registration entries per owner key: an initial burst, then a steady rate. |
| `--reg-max-live` | 4096 | Live registrations per owner key. |
| `--publish-rate`, `--publish-burst` | 5, 20 | Publishes per second per connection. |
| `--request-rate` | 10 | Requests per second per connection. |

The limit defaults are mode 4's (09 section 11). An entry or message over a limit
gets `RATE_LIMITED` and is not acted on.

## TLS

09 section 12.1 requires TLS 1.3, and clients validate the certificate against
the URL's host. Give the certificate chain and key with `--tls-cert` and
`--tls-key`. The server refuses to start without them, unless you pass
`--insecure-dev`, which serves plain `ws://`. That mode exists for tests on one
machine (`tests/federation/`). Never use it anywhere else.

A client that pins a certificate instead of using the public PKI passes it with
`cs_testserver.py --mailbox-ca cert.pem`.

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
  `rx_ref`.
- A request is checked against the request rate whether or not it passes the
  earlier checks, so failed requests count. `RATE_LIMITED` is still reported only
  for a request that passed checks 1 to 4 (09 section 7.3).
- A publisher's second `publish` of one transmission is dropped without an
  `error`.

## Tests

```sh
make -C tests/federation   # conformance against 09, then two homes through one mailbox
```
