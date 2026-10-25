# Operating a bootnode

How-to for a node installed from the Debian/Ubuntu package and supervised by the
packaged systemd unit (installation: [getting started](getting-started-deb.md);
CLI, environment variables and units: [usage.md](usage.md)).

A bootnode is a long-running network daemon. Four things keep it useful, and
only the first is about the process itself:

1. a supervisor that owns its lifecycle — never a foreground shell;
2. a bounded log, with the peer-aware debug channel kept out of it;
3. a probe from **outside** the host: a running process is not a reachable
   service;
4. the aggregate counters, to see the population and its peak
   ([Measure the node](#measure-the-node)).

## Start it and keep it running

The package installs the unit but never enables it: starting at boot is your
decision.

```bash
sudo systemctl enable --now hsync-bootnode.service
sudo systemctl status hsync-bootnode.service
```

Never start the node with `sudo hsync-bootnode run` in an SSH session. The unit is
what gives it a restart policy, a filesystem sandbox, the group keys as a
credential and a log that outlives the session; a manual run has none of them.

## Read the state of the unit

```bash
systemctl is-enabled hsync-bootnode.service
systemctl is-active hsync-bootnode.service
systemctl show -p NRestarts hsync-bootnode.service
sudo journalctl -u hsync-bootnode.service -n 50
```

The unit is `Type=notify`: `active` means the QUIC/UDP listeners were bound and
the node announced readiness, not that a process exists. `NRestarts` climbing
above zero is the signal that something is failing at runtime — read the journal
for the always-on `warn`/`error` lines instead of waiting for clients to report
it.

## Probe it from outside

Supervision answers "is the process alive?". Only a request from another host
answers "does discovery work right now?": a cloud security group, a changed
firewall rule, a lost NAT mapping or a filtered UDP port all leave a perfectly
healthy process that no client can reach.

The probe is a `boot/1` handshake read from a host that is **not** the node
(`hsync` from the [client](https://github.com/albertsdk/hsync-client) must be
installed there):

```bash
hsync trust bootnode fingerprint BOOTNODE_HOST
```

It exits non-zero when no QUIC handshake completes, and prints the fingerprint it
received — the same value you distribute to clients, so a run also detects an
identity change. To run it on a schedule, add a timer on the monitoring host:

```bash
sudo tee /usr/local/bin/hsync-bootnode-probe >/dev/null <<'EOF'
#!/bin/sh
exec hsync trust bootnode fingerprint "$1"
EOF
sudo chmod 755 /usr/local/bin/hsync-bootnode-probe
```

```bash
sudo tee /etc/systemd/system/hsync-bootnode-probe.service >/dev/null <<'EOF'
[Unit]
Description=Reachability probe for the HSYNC bootnode

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hsync-bootnode-probe BOOTNODE_HOST
EOF
```

```bash
sudo tee /etc/systemd/system/hsync-bootnode-probe.timer >/dev/null <<'EOF'
[Unit]
Description=Probe the HSYNC bootnode every five minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now hsync-bootnode-probe.timer
```

A failed probe is a failed unit: point `OnFailure=` at your alerting unit, or let
the monitoring system run the same command directly.

## Measure the node

Three sinks report the same aggregates — the metric reference is in
[usage.md](usage.md#metrics): the systemd `STATUS=` line (always on), a
Prometheus text file and a loopback `/metrics` endpoint. Enable the last two
once, in a drop-in.

Mint the endpoint's bearer token (its only authorization, at least 32
characters):

```bash
sudo sh -c 'openssl rand -hex 32 > /etc/hsync-bootnode/metrics-token'
sudo chmod 0600 /etc/hsync-bootnode/metrics-token
```

```bash
sudo systemctl edit hsync-bootnode.service
```

```ini
[Service]
Environment=HSYNC_BOOTNODE_STATS_FILE=/var/lib/hsync-bootnode/stats.prom
ExecStart=
ExecStart=/bin/sh -c 'exec /usr/bin/hsync-bootnode run --host 0.0.0.0 --port 443 --identity /var/lib/hsync-bootnode/identity.pem --keys-fd 5 5<"${CREDENTIALS_DIRECTORY}/group-keys" --metrics-port 9101 --metrics-token-fd 6 6<"${CREDENTIALS_DIRECTORY}/metrics-token"'
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart hsync-bootnode.service
systemctl show -p StatusText hsync-bootnode.service
```

`StatusText` carries the live summary (`conn=3/57 peers=1203/1240`), so the
simplest monitoring needs no extra component.

To scrape the endpoint from Prometheus on another host, keep the token in a
file there and let the scrape read it:

```yaml
scrape_configs:
  - job_name: hsync-bootnode
    static_configs:
      - targets: ["NODE_HOST:9101"]
    authorization:
      credentials_file: /etc/prometheus/hsync-bootnode-token
```

Reach it through an SSH tunnel or a proxy when the node is remote, and never
publish the port: the endpoint speaks plain HTTP and the token travels in
clear on the wire.

If you collect with node_exporter instead, skip the `/metrics` flags and point
its textfile collector at the directory you enabled above
(`--collector.textfile.directory=/var/lib/hsync-bootnode`).

Useful queries:

```text
hsync_bootnode_peers_current                     # clients online now
hsync_bootnode_peers_peak                        # since the last restart
max_over_time(hsync_bootnode_peers_current[7d])   # a week-long peak
rate(hsync_bootnode_quic_connections_total[5m])   # handshakes per second
rate(hsync_bootnode_peers_expired_total[5m])      # churn
```

## Bound the log

The node writes only peer-free `warn`/`error` lines without `--debug`, and the
unit sends them to the journal. Bound the journal on the node's host:

```bash
sudo systemctl edit systemd-journald
```

```ini
[Journal]
SystemMaxUse=200M
MaxRetentionSec=2week
```

```bash
sudo systemctl restart systemd-journald
```

Never add `--debug` to the unit: those lines carry peer identity (CID, bucket,
IP, port) and the journal is on disk, which turns the no-log node into a
node that records its peers. Use `--debug` interactively, for the session you
are diagnosing (see [Diagnostics](usage.md#diagnostics)).

## Back up the identity

The TLS identity is the node's only persistent state, and clients pin its
fingerprint: lose it and every pinned client refuses the node.

```bash
sudo install -d -m 0700 /var/backups/hsync-bootnode
sudo cp --preserve=mode,timestamps \
    /var/lib/hsync-bootnode/identity.pem \
    /var/backups/hsync-bootnode/identity.pem
```

Restoring it before a start keeps the fingerprint:

```bash
sudo cp /var/backups/hsync-bootnode/identity.pem \
    /var/lib/hsync-bootnode/identity.pem
sudo chown --reference=/var/lib/hsync-bootnode \
    /var/lib/hsync-bootnode/identity.pem
sudo chmod 0600 /var/lib/hsync-bootnode/identity.pem
sudo systemctl start hsync-bootnode.service
```

## Rotate the identity

Rotation is explicit, because a running node has no reload path:

```bash
sudo hsync-bootnode identity rotate \
    --identity /var/lib/hsync-bootnode/identity.pem
sudo systemctl restart hsync-bootnode.service
hsync trust bootnode fingerprint BOOTNODE_HOST
```

During the rotation window give clients **both** fingerprints: `--bootnode-fingerprint` is
repeatable for exactly that window. The last command proves the certificate the
clients actually receive is the new one.

## Upgrade

```bash
curl -fLO "https://github.com/albertsdk/hsync-bootnode/releases/latest/download/hsync-bootnode-amd64.deb"
sudo dpkg -i hsync-bootnode-amd64.deb
systemctl is-enabled hsync-bootnode.service
systemctl is-active hsync-bootnode.service
```

An upgrade stops the node so its executable can be replaced, then starts it again
if it was enabled — the enablement state is yours and is never changed by an
install or an upgrade. The identity lives in the unit's `StateDirectory`, so it
survives the upgrade and the fingerprint does not change; confirm with the probe
above.

## What the unit protects

| Directive | Effect |
|---|---|
| `Type=notify` + `WatchdogSec=` | The unit is up only once the listeners are bound; a wedged event loop is restarted, which a PID check would never see. |
| `Restart=on-failure`, `RestartSec=`, `StartLimit*` | A crash restarts the node; a crash loop stops at the start limit and stays `failed` for the alert instead of spinning forever. |
| `TimeoutStopSec=` | Bounds the transport teardown before SIGKILL is escalated. |
| `MemoryMax=`, `TasksMax=`, `LimitNOFILE=` | Keeps a runaway node inside its cgroup instead of taking the host down with it. `MemoryMax=` is also the capacity knob: the node sizes its peer/connection ceilings from the memory its cgroup allows, so raising it admits more peers and lowering it admits fewer (watch the `limits` line in the startup banner). |
| `DynamicUser=`, `CapabilityBoundingSet=` | An unprivileged, transient user that holds only `CAP_NET_BIND_SERVICE`. |
| `LoadCredential=` | The group keys are a descriptor read once at startup, never a path inside the sandbox. |
