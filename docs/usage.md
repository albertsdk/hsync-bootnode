# Usage reference — hsync-bootnode

Reference for the CLI, the environment variables, the group-keys contract and
the OS service units. Installation and the open-mode quick start are on the
[welcome page](README.md).

## Command

The commands are `run`, `identity show`, and `identity rotate` (plus the
top-level `--version` flag):

```text
hsync-bootnode run [OPTIONS]
hsync-bootnode identity show [--identity PATH] [--pem]
hsync-bootnode identity rotate [--identity PATH] [--public-host NAME]...
hsync-bootnode --version
```

### `run` options

| Option | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Address to bind the QUIC/UDP listener to. Accepts an optional port (`HOST[:PORT]`, e.g. `0.0.0.0:443` or `[::1]:443`). |
| `--port` | `443` | UDP port (1–65535). 443 is the QUIC/HTTP3 default; ports below 1024 need root or `CAP_NET_BIND_SERVICE` (the systemd unit grants it). Mutually exclusive with a port in `--host HOST:PORT`. |
| `--identity` | XDG state path | Path of the persistent TLS identity (key+cert). Created on first run and reused afterwards, so the certificate fingerprint is stable across restarts and can be pinned by clients. Default: `$HSYNC_BOOTNODE_IDENTITY` or `$XDG_STATE_HOME/hsync/bootnode/identity.pem` (`~/.local/state/…`). |
| `--ephemeral` | *(disabled flag)* | Keep the TLS identity in memory and write no identity file (read-only filesystems, throwaway nodes); the fingerprint changes on every restart, so clients cannot pin it. Mutually exclusive with `--identity`. Environment variable form: `HSYNC_BOOTNODE_EPHEMERAL=1`. |
| `--public-host` | *(none)* | Public hostname or IP to add to the certificate SAN (repeatable). |
| `--protected-bucket` | *(none)* | Bucket that requires a valid `bucket_token`. Repeatable. Declaring a protected bucket without provisioning its key fails fast at startup (exit code 2). |
| `--keys-fd` | *(none)* | File descriptor carrying the group keys (see below). Environment variable form: `HSYNC_BOOTNODE_KEYS_FD`. |
| `--private` | *(disabled flag)* | Private node: every frame must carry a valid `bucket_token`, for **every** bucket (not only `--protected-bucket`). Starting it with no group key fails fast (exit code 2). Environment variable form: `HSYNC_BOOTNODE_PRIVATE=1`. |
| `--no-upnp` | *(disabled flag)* | Disable the zero-touch UPnP UDP mapping. |
| `--ttl` | `60` | Record TTL in seconds (1–3600). Peers refresh every 30 s, so the default 60 s matches the spec. Lower it for faster convergence in tests. |
| `--debug` | *(disabled flag)* | Emit the full operation log to stderr (opt-in): connections, frames, decisions, record changes and TTL sweeps, **including the peer identity** (CID, bucket, IP, port). Every line is timestamped and self-identifying (`2026-09-30T10:30:45.123Z - hsync-bootnode[1234] debug: …`). Stderr only — never written to disk; without it no peer data leaves memory. Environment variable form: `HSYNC_BOOTNODE_DEBUG=1`. |
| `--ready-file` | *(none)* | Write the process PID to this path once the listener is bound (readiness seam, contains no peer data). Environment variable form: `HSYNC_BOOTNODE_READY_FILE`. An unwritable path fails fast with exit code 4. |
| `--no-rate-limit` | *(disabled flag)* | Disable rate limiting entirely (benchmark/test seam). Environment variable form: `HSYNC_BOOTNODE_NO_RATE_LIMIT=1`. Never enable in production — it removes the anti-abuse limits the spec requires. |

### `identity show`

Prints the persisted identity fingerprint (or, with `--pem`, the public
certificate). `--identity PATH` is optional and defaults to the standard state
path; the private key is never printed.

```bash
hsync-bootnode identity show
# sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### `identity rotate`

Regenerates the persisted key+cert and prints the new fingerprint, which the
operator distributes to clients. `--identity PATH` is optional and defaults to
the standard state path; the old fingerprint stays accepted by clients during the
rotation window (two-pin window).

```bash
hsync-bootnode identity rotate --public-host boot.example.com
```

### `--version`

Prints the version and the protocol, e.g.
`hsync-bootnode 1.0.0 (boot/1, Python v1)`, then exits.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Normal termination (Ctrl+C / SIGTERM). |
| 2 | Configuration error: missing/duplicate group key, `--private` without a key, out-of-range `--ttl`, etc. The node refuses to start. |
| 3 | Listener bind failure: the port is privileged, already in use, or `--host` is not a local address. The stderr message explains how to fix it. |
| 4 | Readiness-file failure: `--ready-file` points at a path the node cannot create (missing parent directory, no permission, or a stale file the `O_EXCL` seam refuses to overwrite). |

## Environment variables

| Variable | Meaning |
|---|---|
| `HSYNC_BOOTNODE_KEYS_FD` | Same as `--keys-fd`; the env-var form is what service wrappers set. |
| `HSYNC_BOOTNODE_IDENTITY` | Same as `--identity`; overrides the default state path of the persistent TLS identity. |
| `HSYNC_BOOTNODE_EPHEMERAL` | Same as `--ephemeral`; set to `1` to keep the identity in memory (no identity file). |
| `HSYNC_BOOTNODE_PRIVATE` | Same as `--private`; set to `1` to require a valid `bucket_token` on every frame. |
| `HSYNC_BOOTNODE_DEBUG` | Same as `--debug`; set to `1` for the full opt-in operation log (peer identity included; stderr only). |
| `HSYNC_BOOTNODE_READY_FILE` | Same as `--ready-file`; the readiness PID path used by tests/orchestrators. |
| `HSYNC_BOOTNODE_NO_RATE_LIMIT` | Same as `--no-rate-limit`; benchmark/test seam, never in production. |

## Group keys (`--keys-fd` / `HSYNC_BOOTNODE_KEYS_FD`)

Group keys provision **protected buckets**. The process reads them ONCE
at startup from the given file descriptor — the key payload never touches a
path inside the node's sandbox and is never written to disk. `stdout`/`stderr`
(descriptors 1 and 2) are refused and the payload is capped (1 MiB): a
misrouted or stuck-open descriptor fails fast with a configuration error
instead of stalling startup.

Line format (comments and blank lines are ignored):

```
# bucket=<hex-group-key>
shared=9f1c...
home=44ab...
```

Example with a systemd credential (fd 5):

```bash
hsync-bootnode run --protected-bucket shared --keys-fd 5 \
    5< /etc/hsync-bootnode/group-keys
```

Notes:

- Clients derive the same `bucket_token` from the group key with
  `HMAC-SHA256(key, "boot/1" || bucket)[:32]` and send only the derived token
  (64 lowercase hex chars) on `register`/`refresh`/`query`.
- Wrong or missing tokens are answered uniformly with `token_required` and
  rate-limited (5/min per IP → `rate_limited` with `retry_after`); the node
  never reveals whether a bucket exists.

## Private node (authenticated bootstrap)

An **open** node serves every bucket, gating only the ones declared with
`--protected-bucket`. A **private** node gates *all* of them: that is the mode
for a bootstrap node that acts as the rendezvous point of one community instead
of a public service.

```bash
# every bucket needs a key; without any key the node refuses to start (exit 2)
hsync-bootnode run --host 0.0.0.0 --port 443 --private \
    --keys-fd 5 5< /etc/hsync-bootnode/group-keys
```

What `--private` changes:

| Aspect | Open node (default) | Private node |
|---|---|---|
| `register` / `refresh` / `query` | token required only for `--protected-bucket`; records are owned by their source network | token required for **every** bucket |
| `leave` | honoured only from the source network the peer registered from (a `leave` from any other IP is silently ignored); on a protected bucket a valid token removes from any source | token required (an anonymous `leave` is silently dropped) |
| Bucket with no key loaded | served (public) | refused exactly like a wrong token |
| Startup with no group key | allowed | fails fast, exit code 2 |
| Rate limits | unchanged | unchanged (private mode never removes them) |

Notes:

- The wire format does not change: `bucket_token` is the same optional field the
  protected buckets already use, so a client only needs the group key — no
  new protocol version and no client-side mode switch.
- Refusals stay uniform (`token_required`, then `rate_limited` with
  `retry_after`): a client cannot tell which buckets exist or are provisioned.
- Deployment: uncomment the `HSYNC_BOOTNODE_PRIVATE=1` example in the unit
  shipped with your OS (see "Deploying as a service"); the env-var form is
  exactly equivalent to the flag.

### Provisioning and key rotation

1. Mint one 64-hex group key per bucket (for example `openssl rand -hex 32`).
2. Write one `bucket=<key>` line per bucket to
   `/etc/hsync-bootnode/group-keys` (0640, root-owned) and start the node with
   `--private --keys-fd 5`. An **empty** file means no protected buckets (open
   mode); a standard service install ships it empty, so the node starts open
   until you provision keys.
3. Distribute the same key to the clients allowed in that bucket: they derive
   `HMAC-SHA256(key, "boot/1" || bucket)[:32]` and send only the derived token.

**Revocation is key rotation** — there is no per-peer account to disable.
Replace the key in the group-keys file, restart the node and redistribute the new
key; the previous tokens stop matching immediately. Treat a leaked group key as
a leaked node capability.

Trade-offs (by design, not defects):

- The token proves a *capability*, not an identity: on a protected/private
  bucket whoever holds the key can register under any `cid` (or remove a known
  pair), so peers verify the TLS fingerprint of the peers they contact and a
  spoofed entry does not survive contact. On an **open** bucket, `register`,
  `refresh` and `leave` are honoured only from the record's own source network.
- Rate limits still apply to legitimate key holders; private mode is not a
  substitute for the anti-abuse limits.
- No account system and no persistence: routing table, keys and limits live in
  RAM only (see "Privacy and anonymity model").

## Endpoint candidates (`endpoints`)

`register` carries the peer's data-plane endpoint candidates. The node stores
them and relays the **full list, verbatim and in order**, on every peer of a
`query` response (a peer that advertised none is relayed as a single-element
list with its observed source endpoint).

The list is **advisory only** and the node never interprets or orders by it. A
requester tries the candidates, preferring one reachable from its own network
(a host/LAN address) over the NATed public one, so two peers behind the same NAT
— where the public endpoint has no hairpin route on most home routers — still
connect over the local path. The candidates are unauthenticated hints: the data
plane authenticates the peer by certificate pinning before any file is
exchanged.

## Peer capacity hint (`capacity`)

`register` may carry an advisory `capacity` hint (integer `0..32`, default `0`;
`0` means "not a peer-download seeder"). The node stores it and echoes it in every
peer of a `query` response, so a client can pre-size its download concurrency.

The hint is **advisory only**: it is not authenticated and not authoritative. The
authoritative limit is the `serve_slots` value a peer advertises on the
authenticated data-plane handshake (ADR 0030), so a client must never treat
`capacity` as a guarantee nor use it to exclude a peer. The node never orders its
random sample by `capacity`, so a self-declared value buys no priority; `refresh`
neither carries nor changes it.

## Election advertisement (`server_ready`, `force_master`, `never_master`)

A `register` may also carry the master-election advertisement: the three flags
`server_ready`, `force_master`, `never_master` plus `startup_time` and
`sync_direction` (defaults: `false`, `false`, `false`, `0.0` and
`bidirectional`). The node stores them and echoes them on every peer of a
`query` response, so devices that find each other through the node run the same
master election they would run on a local network:

- `server_ready` marks the device that is currently serving the bucket: it wins
  the election over a newcomer, even one pinned with `force_master`, so a peer
  that joins later does not trigger a takeover.
- `never_master` excludes a device from candidacy (`hsync p2p --never-master`).
- `startup_time` and `sync_direction` break remaining ties deterministically.

Like `capacity`, the advertisement is **advisory only**: it is not
authenticated, the node never interprets it, and the data plane still
authenticates every peer by TLS certificate pinning. A changed value (a device
becoming master, or giving the role up) is published with a new `register`;
`refresh` never alters it.

## Privacy and anonymity model

A bootnode is what turns a group of devices into a **private P2P network over the
Internet**: they find each other through the node, while the file data keeps
flowing only between peers. These are the properties an operator or a community
can rely on.

- **No accounts, no registration** — there is no user database and no per-peer
  credential to issue or revoke. The only credential is the group key of a
  protected bucket (or of a private node): a *capability*, not an identity.
- **Pseudonymous, not anonymous** — the node invents no identity of its own. The
  `cid` a client presents in p2p mode is its **persistent device identifier** (the
  same `device_id` that anchors TOFU pins), so treat it as a stable pseudonym, not
  as an ephemeral anonymous token.
- **Nothing survives the process** — peer data (IPs, CIDs, timestamps) lives only in
  RAM with the configured `--ttl` (default 60 s, max 3600 s); the routing table,
  the group keys and the rate-limit windows are all in memory. Stop the process and
  every trace of the network is gone.
- **No peer data on disk, ever** — the routing table, the group keys and the
  rate-limit windows live only in memory. The single on-disk artifact is the
  node's own self-signed key+cert (ECDSA P-256, `0600` inside a `0700`
  directory), kept by default so the fingerprint is stable and clients can pin
  it; `--ephemeral` drops even that and writes nothing to disk.
- **Uniform refusals (no enumeration oracle)** — a wrong/missing token and a bucket
  with no key loaded are answered with the same `token_required` (then
  `rate_limited` with `retry_after`), compared in constant time in both cases, so
  a client cannot tell which buckets exist, which are provisioned, or that a
  private node gates everything.
- **Records are owned by their source** — creating, replacing or renewing a
  discovery record is honoured only from the source address it was registered
  from (or with a valid token on a protected bucket). A peer that learns another
  peer's `(cid, bucket, group)` cannot redirect its record, keep a hijacked one
  alive, or evict it.
- **Silent about peers by default** — output goes to the console only and the
  shipped service units route stderr to the system log (`journalctl -u
  hsync-bootnode`, a launchd file, the WinSW log). That always-on channel carries
  the node's **own** operational state (a UPnP mapping that could not be created,
  an unwritable readiness file, an unexpected session failure) and is **peer-free
  by construction**: it accepts only non-identifying fields, so no CID, bucket or
  IP can reach it. `--debug` is the only channel that can emit peer identity, and
  it is opt-in, stderr-only and never written to disk (see "Diagnostics").

### Transport security

- QUIC/UDP (default port 443) carrying **TLS 1.3**: the exchanged peer list is not
  readable by an ISP or a passive observer on the path.
- The node presents a **self-signed** certificate and clients authenticate it by
  SHA-256 fingerprint: on a terminal the first contact is confirmed at a prompt
  (the default `ask` policy, like `ssh`), while an unattended client pins the
  fingerprint or trusts the first sighting — the exact steps are in "TLS identity
  & pinning".
- QUIC `RETRY` + address validation before any connection state is allocated
  (anti-amplification) and a node-side **transport guard**: about 30 new QUIC
  connections/handshakes per second (burst 100) per source address, plus a per-IP
  and a process-wide cap on simultaneously-open connections, all enforced before
  any handshake work runs and sized from the host's RAM and CPU. QUIC receive
  windows are bounded too, so a connection cannot buffer unbounded input. A
  connection or handshake flood is throttled without external help (works with a
  bare listener, no firewall/nginx needed).
- **Layered in-memory rate limits**, every window keyed by source address so one
  peer cannot exhaust another's budget: the valid-frame admission (~10 req/s,
  burst 50), per-`(IP, bucket)` windows for `register`/`refresh` (10/min) and
  `query` (5/min), an aggregate per-IP `query` cap (20/min, anti-enumeration), the
  failed-token budget (~5/min per IP) **and a pre-parse budget for
  malformed/unknown frames** (~30/min per IP, burst 60) so a flood of garbage
  frames cannot turn frame validation into a CPU-exhaustion channel. Rate-limit
  refusals are always answered (`rate_limited` + `retry_after`); the silent
  malformed-frame budget answers nothing (there is no oracle to hand out). The
  routing table and the limiter tables have host-derived ceilings, globally and
  per bucket/group, so a registration flood is answered with backpressure
  instead of exhausting RAM or saturating a single bucket's sample. Every
  `boot/1` frame rejects unknown fields, and the deployed units are
  sandboxed (systemd `DynamicUser`, syscall filter).
- **UPnP is hardened by default**: SSDP replies must originate from a private
  LAN address and their `LOCATION` must be `http(s)://<private-IP-literal>/…`
  (no hostnames, no external hosts, no redirects) — the device discovery cannot
  be steered into fetching arbitrary internal/external URLs. On a node with no
  LAN (a public VPS) SSDP simply finds nothing and the node runs stateless, as
  always; nothing about the mapping workflow changes on a LAN.

### What it is not

- **Not an anonymity network** — it is a rendezvous point, so it observes the
  `ip:port` a peer registers with (and echoes it back in the `ack`), and a `query`
  response hands each peer the `ip:port`/`cert_fp` of the peers it returns. Hiding
  your IP from the node or from your peers is out of scope; nothing here is
  Tor-like.
- **Not a relay, a storage node or a control plane** — file data always flows
  directly between peers and the node never sees its content.
- **A private node is authentication, not a VPN** — it gates who may use the node as
  a rendezvous point; the sync traffic is encrypted by the peers' own HTTPS/WSS
  session.

## TLS identity & pinning

The node keeps a persistent, self-signed TLS identity (ECDSA P-256), created on
first run and reused afterwards, so its fingerprint is stable across restarts and
clients can pin it. Its key+cert is the node's **only** on-disk artifact (never
peer data). By default it lives at
`$XDG_STATE_HOME/hsync/bootnode/identity.pem` (`~/.local/state/…`); set an
explicit path (e.g. a service directory) with `--identity`:

```bash
# create (first run) and reuse (subsequent runs) the identity:
hsync-bootnode run --identity /var/lib/hsync-bootnode/identity.pem \
    --public-host boot.example.com
```

Each name/IP clients dial should be added with `--public-host` (repeatable) so a
TLS client that validates the hostname — not only the fingerprint — accepts the
handshake. The file is written with `0600` permissions in a `0700` directory.
Read the fingerprint and distribute it to clients out of band:

```bash
hsync-bootnode identity show
```

`--ephemeral` writes no identity file: the fingerprint then changes on every
restart and clients cannot pin it — use it on a read-only filesystem or for a
throwaway node. Clients authenticate the node by fingerprint: a terminal confirms
the first contact at the prompt, an unattended client pins it with
`--bootnode-fingerprint` (or trusts the first sighting with `--bootnode-tofu`);
see the client `p2p-bootnode` documentation. To rotate the key
(e.g. after a suspected compromise), regenerate it and move clients to the new
fingerprint in a two-pin window:

```bash
hsync-bootnode identity rotate --public-host boot.example.com
```

## Diagnostics

The node emits two kinds of line on stderr, in the same format — a UTC ISO 8601
timestamp, the emitting process, the level and the message:

```text
2026-09-30T10:30:45.123Z - hsync-bootnode[1234] warn: upnp no igd on lan port=443
2026-09-30T10:30:45.130Z - hsync-bootnode[1234] debug: register ack cid=A1b2C3d4E5f6G7h8I9j0K bucket=shared
```

**Always on — node health (`warn` / `error`).** Operational events the operator
must see without any flag: a UPnP mapping that could not be created, an
unwritable `--ready-file`, an unexpected failure inside one QUIC session (which
the listener isolates and keeps serving). This channel is **peer-free by
construction**: it accepts only non-identifying fields, and passing a peer field
is a programming error that raises rather than logging. Repeated identical errors
are throttled and reported as `suppressed=<n>`, so a failing path cannot flood
the log.

**Opt-in — the full operation log (`debug`).** `--debug` (or
`HSYNC_BOOTNODE_DEBUG=1`) adds the whole request life cycle on stderr —
connections opened/closed, frames received, the decision taken, records
created/refreshed/removed, TTL sweeps and refusals — **including the peer
identity** (CID, bucket, IP, port) that makes the log usable for analysis. When
it is enabled the node says so once on the always-on channel
(`warn: peer data logging enabled`).

Neither channel ever writes to disk from the process: without `--debug` no peer
data leaves memory, and `--debug` is for a specific troubleshooting session, not
a permanent setting. The shipped units store stderr in the operating system's log
— bound its retention there (`/etc/systemd/journald.conf`: `SystemMaxUse=`,
`MaxRetentionSec=`, then `journalctl -u hsync-bootnode`; a launchd file rotated
by `newsyslog`; the WinSW log).

The `--ready-file`/`HSYNC_BOOTNODE_READY_FILE` seam writes the process PID to
the given path once the QUIC listener is bound (and removes it on graceful
shutdown). It carries no peer data and exists so tests and orchestrators can
await readiness deterministically. A path the node cannot write (missing
directory, no permission, an existing stale file) fails fast with exit code 4 and
an actionable message instead of a traceback. The Docker entrypoint removes a
stale readiness file before `exec`, so a container killed ungracefully
(`docker kill` timeout → SIGKILL) never leaves the next start wedged.

## Deploying as a service

The [Debian package](getting-started-deb.md) installs and manages the systemd
unit automatically; the [Docker](getting-started-docker.md) and
[installer-script](getting-started-script.md) methods run the node in a
container. The ready-made units below are for a manual [source install](getting-started-source.md):

Ready-made units are in `packaging/`:

| OS | Unit | Install |
|---|---|---|
| Linux | `packaging/systemd/hsync-bootnode.service` | `sudo cp … /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now hsync-bootnode` — hardened (DynamicUser, syscall filter); group keys are read from a systemd credential. |
| macOS | `packaging/launchd/it.hsync.bootnode.plist` | `sudo cp … /Library/LaunchDaemons/ && sudo launchctl bootstrap system …` — group keys are exposed as fd 3 by the embedded shell wrapper. |
| Windows | `packaging/windows/hsync-bootnode-service.xml` | WinSW v2: rename `WinSW-x64.exe` to `hsync-bootnode-service.exe` next to the XML, adjust the venv path, then `.\hsync-bootnode-service.exe install` + `start`. |

Edit the executable paths inside each unit to the location of your venv.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: protected bucket(s) without a group key …` | You declared `--protected-bucket` without provisioning its key: pass `--keys-fd`/`HSYNC_BOOTNODE_KEYS_FD` with a matching `bucket=<key>` line. |
| `configuration error: private node without any group key …` | You started a private node (`--private` / `HSYNC_BOOTNODE_PRIVATE=1`) without provisioning a key: pass `--keys-fd` with at least one `bucket=<key>` line. |
| `error: cannot bind the QUIC/UDP listener … — permission denied` | You bound a privileged port (< 1024, e.g. the 443 default) without root: use `--port 8443` (any port ≥ 1024), run as root, or grant the capability (`sudo setcap cap_net_bind_service=+ep <hsync-bootnode>`). The systemd unit already grants it. |
| `error: cannot bind the QUIC/UDP listener … — address already in use` | Another process (or another node instance) is using that UDP port: stop it, or pick a free port with `--port`. |
| `error: cannot bind the QUIC/UDP listener … — the address is not available` | `--host` is not a local interface address: use a local IP, or `0.0.0.0` to listen on all of them. |
| Client gets `token_required` | The bucket is gated (declared `--protected-bucket`, or every bucket on a private node) and the client's derived token is missing/wrong — check the group key on the client side. |
| Client gets `rate_limited` | A limit was exceeded (per-IP ~10 req/s admission, 5/min failed tokens, 5/min queries per (IP, bucket), 20/min aggregate queries per IP, 10/min registers per (IP, bucket), or the node's host-derived table ceiling); wait for `retry_after` seconds. |
| No UPnP mapping | Router without IGD, or mapping refused: the node keeps running stateless and reports it once on the always-on channel (`warn: upnp no igd on lan port=…` or `warn: upnp mapping unavailable reason=…`); publish a public UDP endpoint in another way or use `--no-upnp` to skip discovery entirely. |
| `error: readiness file not writable` (exit code 4) | `--ready-file` points at a path the node cannot create (missing parent directory, no permission, or a stale file that `O_EXCL` refuses to overwrite): create/remove the path or point the flag elsewhere. |
| `warn: upnp mapping unavailable` / `error: session failed` in the logs | Always-on diagnostics, not peer data: the node degraded (no UPnP mapping) or one session failed unexpectedly and was isolated. Both are emitted without `--debug` and never contain a peer identity. |
| Need to see what the node is doing | Operational warnings and errors are already on stderr (and in the service log). Start with `--debug` (or `HSYNC_BOOTNODE_DEBUG=1`) to add the full operation log, peer identity included. |
