# femto

Static file server. TLS 1.3, HTTP/3, single binary, no external dependencies.

It exists for the case where you just need files served over HTTPS and pulling
in nginx is more than the job calls for. No reverse proxying, no scripts, no
plugins. Small and boring on purpose.

---

## When to use it

- Personal sites, project pages, documentation hosts
- Internal dashboards served over HTTPS
- Raspberry Pi, embedded hardware, or any constrained box
- Anywhere the server config should fit in one file you can read in two minutes

## When not to use it

If you need PHP, CGI, URL rewrites, proxying, or anything dynamic — use a full
web server. femto does not plan to grow those features.

---

## Install

Requires Go 1.24.

```
git clone https://github.com/monkburger/femto
cd femto
make static
```

That gives you a stripped static binary. Copy it anywhere and run it.

To bind ports below 1024 without running as root on Linux:

```
make setcap
```

---

## Run

```
./femto -config femto.toml
```

`-config` defaults to `femto.toml` in the current directory. No other flags.

- `SIGTERM` / `SIGINT` — graceful shutdown
- `SIGHUP` — reload TLS certificates from disk without dropping connections

---

## Features

- **TLS 1.3 minimum.** Older versions are not negotiated.
- **HTTP/3 (QUIC) + HTTP/2 + HTTP/1.1.** Clients get the best protocol they
  support. `Alt-Svc` is advertised automatically on every TCP response.
- **Virtual hosting.** Exact names and `*.wildcard` both work, each with its
  own document root and certificate.
- **Pre-compressed serving.** Drop a `.br` or `.gz` sidecar next to any file
  and femto serves it to clients that ask for it. No runtime compression.
- **Zero-downtime cert reload** via `SIGHUP`. Works with Let's Encrypt renewal
  hooks.
- **HTTP → HTTPS redirect listener.** Bind a plain HTTP port and femto issues
  301s. Host header is validated — no open redirect.
- **Unix domain socket.** Plain HTTP/1.1 for a local reverse proxy setup.
- **Trusted proxy support.** Reads real client IPs from `Forwarded` (RFC 7239)
  or `X-Forwarded-For` when the request arrives from a trusted CIDR.
- **Security headers.** HSTS, CSP, `X-Frame-Options`, referrer policy, and
  permissions policy — all configurable, sensible defaults included.
- **Per-vhost `Cache-Control`.** Set a max-age and femto sends
  `Cache-Control: public, max-age=N` on successful responses only. Error
  responses are never cached.
- **Connection cap and five independent timeouts.**
- **Structured access log.** One line per request: remote IP, protocol,
  method, URI, status, bytes, duration, user-agent.
- **Custom MIME types.** Point to a `mime.types` file to extend the built-ins.

---

## Config

TOML. A working example with every option is in `example/example.toml`.

### `[server]`

```toml
[server]
listen = ["443"]          # bare port, "host:port", or "[::]:port" for IPv6
access_log = ""           # "" or "stderr" = stderr | "off" = discard | file path
error_log  = ""

read_header_timeout = "5s"
read_timeout        = "30s"
write_timeout       = "60s"
idle_timeout        = "120s"
shutdown_timeout    = "10s"

max_header_bytes = 65536
max_connections  = 0      # 0 = unlimited
```

### `[server.security]`

All have sensible defaults. Set a field to `""` to suppress that header.

```toml
[server.security]
hsts                    = "max-age=63072000; includeSubDomains; preload"
content_type_options    = "nosniff"
frame_options           = "DENY"
content_security_policy = "default-src 'self'"
referrer_policy         = "strict-origin-when-cross-origin"
permissions_policy      = ""   # not sent unless set
```

### `[server.redirect]`

```toml
[server.redirect]
enabled = true
listen  = ["80"]   # defaults to ["80"] if omitted
```

### `[server.unix]`

```toml
[server.unix]
enabled = true
path    = "/run/femto/femto.sock"
mode    = 0660
```

### `trusted_proxies`

```toml
[server]
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]
```

### `[[vhost]]`

At least one required.

```toml
[[vhost]]
server_names  = ["example.com", "www.example.com"]
document_root = "/var/www/example"
dir_listing   = false
index_files   = ["index.html"]   # tried in order; default is ["index.html"]
cache_max_age = "24h"            # omit or 0 to send no Cache-Control

  [vhost.tls]
  cert  = "/etc/ssl/example.com/fullchain.pem"
  key   = "/etc/ssl/example.com/privkey.pem"
  chain = ""   # separate intermediate chain; leave empty for full-chain bundles
```

`server_names` accepts exact names and single-level wildcards (`*.example.com`).
Deeper wildcards are not supported.

### Pre-compressed files

No config needed. For any requested file `foo.html`, femto checks for
`foo.html.br` and `foo.html.gz` in the same directory. If the client's
`Accept-Encoding` matches and the sidecar is there, it gets served with the
right `Content-Encoding` header.

Generate sidecars at deploy time:

```
brotli -k foo.html
gzip   -k foo.html
```

---

## Systemd

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

---

## A note on the docs

This documentation follows plain language conventions — short sentences, active
verbs, concrete examples. That approach comes out of cognitive linguistics and
readability research: readers make fewer mistakes and get to the answer faster
when instructions are written at the level of the task, not above it. Grice's
maxims of quantity and manner are a useful frame here — say what's needed, no
more, and say it clearly.

---

## License

BSD 2-Clause. See [LICENSE](LICENSE).
