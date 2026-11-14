# Architecture

nrzDNS is one Rust program made of three crates. The **engine** (`engine/`, `nrzdns-engine`) is the DNS server itself: it listens on UDP and TCP, answers from its own memory and knows nothing about HTTP or databases. The **server** (`src/`, `nrzdns`) is a Rocket application: it keeps everything in a single SQLite database, serves the JSON API, the DNS-over-HTTPS endpoint and the embedded web interface, pushes settings, zones and lists into the engine and writes the engine's query log back to the database. The **types** (`types/`, `nrzdns-types`) are shared by server, engine and the web interface (`ui/`, Dioxus/WebAssembly).

```
  Browser                         Devices in the network
  Dioxus app (WASM)               phones, laptops, TVs, router
      │ /api/v1                       │ DoH /dns-query      │ DNS 53/udp, 53/tcp
      ▼                               ▼                     │
┌──────────────────────────────────────────────┐            │
│ Rocket 0.5 (src/)                            │            │
│  JSON API      /api/v1, session cookie       │            │
│  DoH           /dns-query → Engine::handle   │            │
│  web UI        embedded app, locales, icons  │            │
│  auth          sessions, guards, throttle    │            │
│  services      settings, zones, lists, log,  │            │
│                dashboard statistics          │            │
│  background    list updates, log writer,     │            │
│                log retention                 │            │
└───────┬───────────────────────┬──────────────┘            │
        │ sqlx                  │ settings, zones, lists    │
        │                       │ ▲ QueryLogEntry (channel) │
        ▼                       ▼ │                         ▼
┌─────────────────┐   ┌──────────────────────────────────────────────┐
│ nrzdns.db       │   │ nrzdns-engine (engine/)                      │
│ SQLite, WAL     │   │  UDP/TCP listeners · rate limit · zones      │
│ one file        │   │  blocking · local answers · cache · forward  │
└─────────────────┘   └──────────────────────┬───────────────────────┘
                                             │ UDP, TCP, DoT, DoH
                                             │ blocklist downloads
                                             ▼
                               upstream resolvers, blocklist URLs
```

## Decisions

| Area | Choice | Why |
|---|---|---|
| Split | DNS in its own crate (`nrzdns-engine`) without Rocket or SQLite; the server hands it the complete state (`apply_settings`, `set_zones`, `set_block_list`, `set_custom_blocked`, `set_allowed`) after every change | The hot path never waits for the database or a lock held by a web request; the engine can be tested on its own with plain DNS messages |
| Server | Rocket 0.5.1 | Typed request guards for sessions, admins and the origin check; fairings for security headers and background work; graceful shutdown on `SIGTERM` |
| Storage | One SQLite file through **sqlx 0.9** (bundled SQLite, WAL, migrations embedded with `sqlx::migrate!`) | Backup = one file; no database server to run |
| Settings | `DnsSettings` stored as one JSON document; fields missing in older documents get their defaults (`#[serde(default)]`); applied immediately | No restart after a change; settings can grow without migrations |
| Query log | The engine sends one `QueryLogEntry` per answered query into a bounded channel (50 000 entries); the server writes them in batches. When the channel is full, new entries are dropped instead of slowing down DNS | Answering comes first; a slow disk can't make name resolution slow |
| Forwarding | UDP with TCP fallback on truncation, TCP, DNS over TLS (RFC 7858), DNS over HTTPS (RFC 8484); strategies sequential, random, parallel; per-upstream timeout and health | Encrypted upstreams without a separate proxy; parallel trades bandwidth for latency |
| Certificates | Bundled webpki root certificates | Runs in minimal images without a CA store (the Umbrel app uses plain `debian:trixie-slim`) |
| Cache | In memory, bounded (oldest out first), TTL clamped between minimum and maximum, negative answers cached, **serve-stale** (RFC 8767) and **prefetch** | Fast repeat answers; the network keeps working for a while when the internet is gone |
| Blocking | Lists in hosts, domain and Adblock format, parsed into normalized, deduplicated domain sets; a rule matches the name and all subdomains (walk up the parent chain); allowed domains beat every block; on a failed update the previous version stays active | One fast lookup per label; a broken list URL never empties the blocklist |
| Zones | Primary zones answer authoritatively (AA) with wildcards, in-zone CNAME chasing and NXDOMAIN with SOA; forwarder zones send their domain to their own servers; BIND zone files (RFC 1035) for import and export | Covers home networks (`home.arpa`, `fritz.box`) and small own domains; zone files make moving from or to other servers easy |
| MCP server | `POST /mcp`, Model Context Protocol over Streamable HTTP, stateless JSON-RPC (no sessions, no SSE); Bearer token stored only as SHA-256 (or `NRZDNS_MCP_TOKEN`); tools that change something only when the admin allows it, otherwise not even listed; browsers from foreign origins are rejected | nrzDashboard and other clients get the overview figures in one call and can switch filters without a user session |
| Reverse proxy | hyper 0.14 (the same version Rocket uses) on `proxy_listen` (default `0.0.0.0:80`), HTTP/1.1, route by `Host` header; entries in `proxy_hosts`; the server hands each enabled entry to the engine as a tiny primary zone with one A/AAAA record on `@` (merged into an existing zone of the same name) | Names instead of IP:port for apps on the LAN without owning the domain; no extra container; DNS and proxy can't disagree because both come from the same table |
| DoH server | `GET`/`POST /dns-query` on the web port, no login, can be switched off; same pipeline as UDP/TCP | Encrypted DNS for browsers and phones behind an HTTPS reverse proxy |
| Interface | **Dioxus 0.7** (Rust → WebAssembly) with components adapted from **rust-ui**, Tailwind via `dx`; built with `dx bundle` and embedded by `build.rs` (gzip) | One binary, no CDN, works offline; the UI talks only to `/api/v1` |
| Shared types | `types/` (`nrzdns-types`): every request and response struct and the query log entry, used by server, engine and UI | The three parts can't drift apart; the endpoint table lives in its doc comment |
| i18n | German source strings as keys, catalogs in `locales/<lang>.json` embedded by `build.rs`; server messages are German and translated on the client | Readable code; one place for all texts |
| Packaging | One binary; Docker runtime stage without any `RUN`; the Umbrel app ships gzipped binaries in the store instead of an image | Multi-arch images without emulation; installable on Umbrel although the source repository is private |

## Data model

The authoritative schema is in `migrations/`. Logically the database holds:

- **users** (username, display name, Argon2id hash, role `admin`/`member`, disabled, preferences as JSON) and **sessions** (SHA-256 of the token, user, expiry)
- **settings** (instance settings such as open registration, and `DnsSettings` as JSON)
- **zones** (name, kind `primary`/`forwarder`, disabled, SOA, forwarders, comment) and their **records** (name relative to the zone, TTL, typed data as JSON such as `{"type":"MX","preference":10,"exchange":"mail.example.com"}`, disabled, comment)
- **block lists** (name, URL, enabled, number of domains, last update, last error), **own blocked domains** and **allowed domains** (domain, comment)
- **query log** (time in milliseconds, client, protocol, name, type, response code, source of the answer, answer summary, duration, upstream), indexed for the filters and the dashboard, deleted after the retention period

Times are Unix seconds (UTC), query log times Unix milliseconds. Domains are stored lower-case without the trailing dot. The engine never reads the database: on start and after every change the server loads zones, lists and rules and hands them over.

## Query pipeline

`Engine::handle` answers every query the same way, whether it came over UDP, TCP or DoH:

1. **Rate limit** per client (`rateLimitQps`, 0 = off) → over the limit the query is dropped (`dropped`).
2. **Own zones**: the most specific zone that contains the name. Primary zones answer authoritatively with the AA bit, wildcards and CNAMEs inside the zone, NXDOMAIN or an empty answer with the SOA → `authoritative`.
3. **Allowed / blocked**: the name and all its parent domains are looked up in the allowed domains, own blocks and every active list → `blocked`, answered according to the block mode (`0.0.0.0`/`::`, NXDOMAIN, own address, REFUSED). Skipped while blocking is paused or off.
4. **Local answers**: `localhost`, reverse lookups for private networks without a zone, AAAA when IPv6 answers are switched off → `local`.
5. **Cache** → `cached`. Expired entries are only used when no upstream answers (serve-stale); popular entries are refreshed in the background shortly before they expire (prefetch).
6. **Forwarding**: to the servers of a matching forwarder zone (conditional forwarding), otherwise to the forwarders from the settings, with the chosen strategy → `forwarded`; when none answers, SERVFAIL → `failed`.

Each answer becomes a `QueryLogEntry` (when the query log is on); the DNS client of the web interface uses the same pipeline without writing to the log.

## Security

- Passwords with **Argon2id**; at least 8 characters
- Sessions: a random token in the `nrzdns_session` cookie, `HttpOnly`, `SameSite=Lax`, optional `Secure` (`NRZDNS_COOKIE_SECURE`); the database only stores its SHA-256
- Changing requests whose `Origin` doesn't match the host are rejected (CSRF)
- Login throttling per user name and client address; behind a reverse proxy the address comes from `NRZDNS_IP_HEADER`
- Roles: **admins** change everything, **members** read everything and only change their own account; the first account is admin, and the last admin can't be removed or delete themselves
- Security headers on every response (CSP without inline scripts, `frame-ancestors 'none'`)
- DNS and DoH need no login, like every DNS server. **Don't publish port 53 to the internet**: an open resolver gets abused for amplification attacks. The per-client rate limit softens floods from inside the network
- Upstream TLS (DoT, DoH) verifies certificates against the bundled roots; the name for DoT comes from `tlsName` or the address
- Blocklist downloads: `http`/`https` only, size and time limits
- Container: user `1000`, all capabilities dropped, `no-new-privileges`; port 53 is allowed through `net.ipv4.ip_unprivileged_port_start=0` instead of `CAP_NET_BIND_SERVICE`

## Build

`Dockerfile` stages:

1. `ui`: installs `dioxus-cli` and builds the WebAssembly interface (`dx bundle --web --release`) once on the build machine
2. `build`: Rust release build of the workspace, cross-compiled for amd64/arm64 (C dependencies with the target's compiler); embeds the interface, `locales/` and `static/`
3. `binaries`: only the program (`/nrzdns`), exported for the release assets and the Umbrel app
4. `runtime`: pinned `debian:trixie-slim`, only `COPY` steps, user `1000`, `/data` volume, ports `8380`, `53/udp`, `53/tcp`, health check (`nrzdns healthcheck`)

`.github/workflows/release.yml` builds `binaries` and `runtime` for `linux/amd64` and `linux/arm64` when a release is published, attaches `nrzdns-<version>-linux-{amd64,arm64}` and `SHA256SUMS` to the release and pushes `ghcr.io/<owner>/nrz-dns:<version>` and `:latest`. `.github/workflows/ci.yml` runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test` for the workspace and checks the UI for `wasm32-unknown-unknown` on pushes to `main` and pull requests. `scripts/store-binaries.sh <folder>` builds both programs and stores them gzipped as `nrzdns-amd64.gz` and `nrzdns-arm64.gz` for the Umbrel app.

## Tests

`cargo test --workspace` runs the unit tests of the crates (types, zone files, blocklist parsing, the engine's pipeline) and the integration tests in `tests/`. Those start the server with Rocket's local client on an empty, temporary data folder with background work switched off, create accounts, log in and call `/api/v1` exactly like the UI does.
