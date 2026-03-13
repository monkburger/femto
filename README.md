# femto

Static file server. TLS 1.3, HTTP/3, single binary, no external dependencies.

It exists for the case where you just need files served over HTTPS and pulling
in nginx is more than the job calls for. No reverse proxying, no scripts, no
plugins. Small and boring on purpose.

---

## Contents

- [When to use it](#when-to-use-it)
- [Features](#features)
- [Install](#install)
- [Run](#run)
- [Configuration](#configuration)
  - [server](#server)
  - [server.security](#serversecurity)
  - [server.redirect](#serverredirect)
  - [server.unix](#serverunix)
  - [trusted\_proxies](#trusted_proxies)
  - [vhost](#vhost)
  - [Pre-compressed files](#pre-compressed-files)
- [TLS certificates](#tls-certificates)
- [Deployment](#deployment)
  - [Systemd](#systemd)
  - [Let's Encrypt](#lets-encrypt)
  - [Behind a reverse proxy](#behind-a-reverse-proxy)
- [Build targets](#build-targets)
- [Roadmap](#roadmap)
- [License](#license)

---

## When to use it

femto is the right fit when:

- You're serving static files — HTML, CSS, JS, images, fonts, downloads
- You want proper TLS and HTTP/3 without configuring a full web server
- You're on constrained hardware: a Raspberry Pi, a cheap VPS, an embedded
  device where every megabyte of RAM counts
- You want a single binary you can drop anywhere and run, with one config file
  you can read in a few minutes
- You need virtual hosting across multiple domains from one process

femto is **not** the right fit when you need:

- Dynamic content, CGI, FastCGI, or server-side scripting
- URL rewriting or complex routing rules
- Reverse proxying to upstream services
- Load balancing
- Any plugin or module system

If you need those things, reach for nginx, Caddy, or a purpose-built
application server. femto does not plan to grow in that direction.

---

## Features

**Protocol**
- TLS 1.3 minimum — older versions are not negotiated
- HTTP/3 (QUIC) + HTTP/2 + HTTP/1.1 served from the same port; clients
  negotiate the best protocol they support automatically
- `Alt-Svc` header sent on every TCP response to advertise HTTP/3

**Hosting**
- Virtual hosting with per-vhost document roots, TLS certificates, and
  cache settings
- Exact domain names and single-level wildcards (`*.example.com`)
- Directory listing on/off per vhost
- Configurable index file list, tried in order

**Performance**
- Pre-compressed file serving: drop `.br` or `.gz` sidecars next to your
  files and femto serves them automatically to clients that support them —
  no runtime compression, no CPU overhead at request time
- Per-vhost `Cache-Control` — sends `public, max-age=N` on 2xx and 304
  responses; error responses are never cached

**Operations**
- Zero-downtime TLS certificate reload on `SIGHUP` — no dropped connections,
  works with Let's Encrypt renewal hooks
- Graceful shutdown on `SIGTERM` / `SIGINT` — in-flight requests complete
  before the process exits
- HTTP → HTTPS redirect listener — bind a plain HTTP port and femto issues
  301 redirects; Host header is validated to prevent open redirects
- Unix domain socket listener for local reverse proxy setups
- Structured access log: one line per request with remote IP, protocol,
  method, URI, status, bytes, duration, and user-agent

**Security**
- Security headers on every response: HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`,
  `Permissions-Policy` — configurable per header, sensible defaults
- Trusted proxy support: reads real client IPs from `Forwarded` (RFC 7239)
  or `X-Forwarded-For` only from configured CIDRs

**Miscellaneous**
- Hard connection cap (`max_connections`) and five independent timeouts
- Custom MIME types via an optional `mime.types` file layered on top of
  built-in defaults
- Single static binary, ~10 MB stripped — no shared libraries, no runtime,
  no install step

---

## Install

Requires Go 1.24 or later.

```
git clone https://github.com/monkburger/femto
cd femto
make static
```

`make static` produces a fully stripped, statically linked binary with no
CGO. Copy it to any Linux/macOS/\*BSD machine and run it.

On Linux, to bind ports 80 and 443 without running as root:

```
make setcap
```

This calls `setcap cap_net_bind_service=+ep` on the binary. You only need to
redo this after recompiling.

---

## Run

```
./femto -config /etc/femto/femto.toml
```

`-config` defaults to `femto.toml` in the current directory. That is the only
flag.

Signals:

| Signal | Effect |
|--------|--------|
| `SIGTERM` | Graceful shutdown — waits for in-flight requests to finish |
| `SIGINT` | Same as SIGTERM |
| `SIGHUP` | Reload TLS certificates from disk — no connections dropped |

To test locally, an example config and self-signed certificate for localhost
are in `example/`. Start with:

```
./femto -config example/example.toml
curl --insecure https://localhost:8443/
```

---

## Configuration

femto uses [TOML](https://toml.io) — a minimal config format designed to be
easy to read. If you haven't used it before, it's roughly INI with types. The
full spec is at [toml.io](https://toml.io) and takes about ten minutes to read.

A fully annotated example config is in [`example/example.toml`](example/example.toml).

---

### `[server]`

```toml
[server]

# Addresses to listen on for TLS (TCP + QUIC/UDP). One listener pair per entry.
# Formats: bare port "443", "host:port", or "[::]:443" for all IPv6 interfaces.
# Default: ["0.0.0.0:443"]
listen = ["443"]

# Path to an additional mime.types file. Empty = built-in types only.
# mime_types = "/etc/femto/mime.types"

# Log destinations.
# "" or "stderr" — write to standard error (default)
# "off"          — discard entirely
# "/path/to/file" — append to that file; created if missing (mode 0640)
access_log = "/var/log/femto/access.log"
error_log  = "/var/log/femto/error.log"

# How long to wait for the client to send request headers. Tighten this on
# exposed servers to blunt slow-loris style attacks.
read_header_timeout = "5s"

# Time to read the full request (headers + body).
read_timeout = "30s"

# Time allowed to send the full response.
write_timeout = "60s"

# How long an idle keep-alive connection is kept open.
idle_timeout = "120s"

# Grace period on SIGTERM/SIGINT before connections are forcibly closed.
shutdown_timeout = "10s"

# Maximum request header size in bytes. Requests larger than this get a 431.
max_header_bytes = 65536  # 64 KB

# Hard cap on concurrent TCP connections per listen address.
# 0 = unlimited. Set a value on constrained hardware to protect memory.
max_connections = 0
```

---

### `[server.security]`

These headers go out on every response regardless of vhost. Setting any field
to `""` suppresses that header entirely.

```toml
[server.security]

# HTTP Strict Transport Security. The two-year value below is the minimum for
# HSTS preloading (hstspreload.org).
hsts = "max-age=63072000; includeSubDomains; preload"

# Prevents MIME-type sniffing in browsers.
content_type_options = "nosniff"

# Clickjacking protection. SAMEORIGIN allows framing from the same origin.
frame_options = "DENY"

# Content Security Policy. Tighten this per your application's needs.
content_security_policy = "default-src 'self'"

# Controls how much referrer information is sent with outbound requests.
referrer_policy = "strict-origin-when-cross-origin"

# Feature/permissions policy. Empty = header not sent.
permissions_policy = ""
```

---

### `[server.redirect]`

When enabled, femto binds plain HTTP listeners that issue 301 redirects to the
HTTPS equivalent. The Host header is validated against configured vhosts — a
crafted Host cannot redirect to an external domain.

```toml
[server.redirect]
enabled = true
listen  = ["80"]   # defaults to ["80"] when omitted
```

---

### `[server.unix]`

Starts a plain HTTP/1.1 listener on a Unix domain socket in addition to the
TLS/QUIC listeners. Useful when a local reverse proxy (nginx, haproxy, Caddy)
terminates TLS and forwards to femto over the socket, avoiding TLS overhead and
an open network port.

```toml
[server.unix]
enabled = true
path    = "/run/femto/femto.sock"

# Permission bits applied to the socket file after creation.
# 0660 = owner + group can connect. 0600 = owner only.
mode = 0660
```

---

### `trusted_proxies`

Tells femto which upstream addresses are allowed to set `Forwarded` or
`X-Forwarded-For` headers that it will trust for real IP extraction. Everything
else uses `RemoteAddr` directly.

```toml
[server]
trusted_proxies = [
    "127.0.0.1/32",    # local loopback
    "::1/128",         # IPv6 loopback
    "10.0.0.0/8",      # private range
]
```

`Forwarded` (RFC 7239) takes precedence over `X-Forwarded-For` when both
are present.

---

### `[[vhost]]`

At least one `[[vhost]]` block is required. Each one defines a set of domain
names, a document root, and a TLS certificate to use for those names.

```toml
[[vhost]]

# One or more hostnames this vhost answers to. Required.
# Supports exact names and single-level wildcards (*.example.com).
server_names = ["example.com", "www.example.com"]

# Directory to serve. Must exist and be a directory at startup. Required.
document_root = "/var/www/example"

# Whether to serve directory listings. Default: false.
# When false and no index file is found, returns 403.
dir_listing = false

# Files to look for when a directory is requested, tried in order.
# Default: ["index.html"]
index_files = ["index.html", "index.htm"]

# Cache-Control max-age for 2xx and 304 responses from this vhost.
# Uses Go duration syntax: "24h", "7d", "30m", etc.
# 0 or omitted = no Cache-Control header sent.
# Error responses (4xx, 5xx) are never cached regardless of this setting.
cache_max_age = "24h"

  [vhost.tls]
  # PEM certificate file. Can be a full-chain bundle (leaf + intermediates
  # concatenated), such as Let's Encrypt's fullchain.pem.
  cert = "/etc/ssl/example.com/fullchain.pem"

  # PEM private key file.
  key = "/etc/ssl/example.com/privkey.pem"

  # Optional: path to a separate PEM file of intermediate CA certificates,
  # in order from issuing intermediate to root. Leave empty when cert is
  # already a full-chain bundle. Do not include the root CA — browsers
  # already have it and including it wastes handshake bytes.
  chain = ""
```

Multiple vhosts in one file:

```toml
[[vhost]]
server_names  = ["example.com", "www.example.com"]
document_root = "/var/www/example"
  [vhost.tls]
  cert = "/etc/ssl/example.com/fullchain.pem"
  key  = "/etc/ssl/example.com/privkey.pem"

[[vhost]]
server_names  = ["*.apps.internal"]
document_root = "/var/www/apps"
  [vhost.tls]
  cert = "/etc/ssl/apps.internal/fullchain.pem"
  key  = "/etc/ssl/apps.internal/privkey.pem"
```

---

### Pre-compressed files

femto can serve pre-compressed versions of static files without any runtime
compression. For any requested path — say `/app.js` — it checks for sidecars in
the same directory in this order:

1. `app.js.br` — served as `Content-Encoding: br` if the client sends
   `Accept-Encoding: br`
2. `app.js.gz` — served as `Content-Encoding: gzip` if the client sends
   `Accept-Encoding: gzip`
3. `app.js` — served uncompressed as a fallback

`Vary: Accept-Encoding` is added automatically. No configuration required.

Generate sidecars at deploy time (keep originals with `-k`):

```
brotli -k /var/www/example/app.js
gzip   -k /var/www/example/app.js
```

---

## TLS certificates

femto expects a PEM certificate and a PEM private key per vhost. Any CA works.
For production, [Let's Encrypt](https://letsencrypt.org) via
[certbot](https://certbot.eff.org) or [acme.sh](https://acme.sh) is the
standard low-cost option.

Quick certbot example (standalone, run before starting femto):

```
certbot certonly --standalone -d example.com -d www.example.com
```

This writes `fullchain.pem` and `privkey.pem` to
`/etc/letsencrypt/live/example.com/`. Point `cert` and `key` there.

Renewal hook to reload without restarting:

```
/etc/letsencrypt/renewal-hooks/deploy/femto-reload.sh
---
#!/bin/sh
systemctl kill --signal=HUP femto
```

femto picks up the new certificates on `SIGHUP` with no downtime.

For development, the `example/` directory includes a self-signed certificate
for `localhost` / `127.0.0.1` / `::1`. Never use that in production.

---

## Deployment

### Systemd

```ini
[Unit]
Description=femto static file server
After=network.target

[Service]
ExecStart=/usr/local/bin/femto -config /etc/femto/femto.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
User=www-data
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Reload config (certificates) without restarting:

```
systemctl reload femto
```

### Let's Encrypt

See the [TLS certificates](#tls-certificates) section above.

### Behind a reverse proxy

If nginx, Caddy, or haproxy sits in front of femto, the recommended setup is
to have femto listen on a Unix domain socket:

```toml
[server.unix]
enabled = true
path    = "/run/femto/femto.sock"
mode    = 0660

[server]
trusted_proxies = ["127.0.0.1/32"]
```

Then configure the proxy to forward to `unix:/run/femto/femto.sock` and pass
`X-Forwarded-For` or `Forwarded`. femto will log the real client IP.

Direct TLS and the Unix socket can both be active at the same time — useful
during a migration.

---

## Build targets

```
make build    # development build (dynamically linked, fast)
make static   # production build (static, stripped, version-stamped)
make release  # like static but names the output with version + arch
make setcap   # grant the binary cap_net_bind_service (run after each build)
make check    # vet + full test suite (CI gate)
make test     # test suite only
make cover    # test suite + HTML coverage report
make fmt      # gofmt all source files
make tidy     # go mod tidy + verify
make clean    # remove build artifacts
```

---

## Roadmap

femto is deliberately small and the core feature set is considered stable.
There are a few things worth doing in future that stay within the original
scope:

- **Access control lists.** Simple IP allowlists per vhost, without touching
  the proxy/routing space.
- **ETag hardening.** The current ETag comes from `http.FileServer`'s
  default (inode + mtime + size). A content-hash ETag would be stronger and
  portable across instances.
- **Structured JSON access log.** The current log format is human-readable.
  A JSON mode would make it easier to pipe into log aggregators.
- **Plugin or hook interface (tentative).** There's been thought about a
  narrow request/response hook interface — something that would let small
  Go binaries or scripts participate in request handling without femto
  growing a full scripting engine. Nothing is designed or committed yet.
  If that ever ships, it would stay optional and the no-plugin path would
  remain zero-overhead.

What is not on the roadmap: reverse proxying, CGI, server-side scripting,
template rendering, or a control API. Those belong in a different tool.

---

## A note on the docs

This documentation follows plain language conventions — short sentences, active
verbs, concrete examples. That approach comes out of cognitive linguistics and
readability research: readers make fewer errors and reach the answer faster
when documentation is written at the level of the task, not above it.
Grice's maxims of quantity and manner are a useful frame: say what's needed,
no more, and say it clearly.

---

## License

BSD 2-Clause. See [LICENSE](LICENSE).
