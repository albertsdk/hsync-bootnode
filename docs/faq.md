# FAQ — hsync-bootnode

Operational questions about running the node and about the clients that connect
to it. For the CLI itself see [usage.md](usage.md).

## Why does my client abort with "Bootnode '…' trust failed: the certificate fingerprint does not match the accepted pin"?

**Symptom.** A client that connected to the node before now stops with:

```text
ERROR: Bootnode '<host>:<port>' trust failed: the certificate fingerprint
does not match the accepted pin (possible man-in-the-middle).
The bootnode presented this SHA256 fingerprint:
  sha256:<new-fingerprint>
```

The client also prints the known-hosts file that holds the accepted pin and the
exact `hsync trust bootnode add`/`hsync trust bootnode remove` commands that
unblock the situation.

**Why.** The client authenticates the node's **self-signed** certificate by
fingerprint: at the prompt (the default `ask` policy) or, with
`--bootnode-tofu`, it remembers the first fingerprint it sees for `<host>:<port>`
and refuses any later change as a possible man-in-the-middle. By default the node
generates a **fresh identity at every start** (the no-log invariant: the key
lives only in RAM), so **restarting the node changes its fingerprint** and every
client that pinned it then refuses it.

**Fix — operator (recommended).** Give the node a stable identity so the
fingerprint survives restarts, then distribute that fingerprint to clients:

```bash
# create on first run, reuse afterwards (0600 file, only the operator's key+cert)
hsync-bootnode run --identity /var/lib/hsync-bootnode/identity.pem
hsync-bootnode identity show --identity /var/lib/hsync-bootnode/identity.pem
```

Clients then pin it with `--bootnode-fingerprint <fingerprint>` (or confirm it
once at the prompt on a terminal).

**Fix — clients after an expected change.** If the new fingerprint is legitimate
(e.g. the operator just provisioned `--identity`, or rotated it), accept it
explicitly:

```bash
hsync p2p <host> -b <bucket> --bootnode-fingerprint <new-fingerprint>
```

Or, if a client already pinned it, forget the stale pin with
`hsync trust bootnode remove` (the client prints this exact command, with the host
and port, when it refuses) so the next connection is trusted again; the entry
lives in the client's trust store (`bootnode_known_hosts.json` under
`$XDG_STATE_HOME/hsync/`, or the path in
`HSYNC_BOOTNODE_TRUST_FILE`).

**Never** accept a fingerprint you cannot explain: a mismatch is precisely what
the pin protects against.

## What is `--public-host` for?

`hsync p2p` authenticates the node by **certificate fingerprint** (prompt, TOFU
or pin), not by hostname: the QUIC/TLS handshake does not validate the
certificate chain or its SAN, so a client reaches the node with or without this
flag.

It matters when the node is dialled by a TLS client that *does* verify the
hostname — a generic QUIC/TLS tool, or any implementation that does not pin the
fingerprint. Without it, and when the node binds `0.0.0.0`/`::`, the certificate
SAN falls back to the placeholder DNS name `hsync-bootnode`, which never matches
the address dialled, so such a client rejects the handshake (`Error: 298`). Add
every name/IP that clients dial:

```bash
hsync-bootnode run --identity /var/lib/hsync-bootnode/identity.pem \
    --public-host boot.example.net
```

`--public-host` is repeatable. Changing the SAN requires regenerating the
certificate, so the fingerprint changes too — see the rotation window above.

## The fingerprint changed after a restart — how do I avoid that?

Run the node with `--identity PATH` (see above). Without it the identity is
ephemeral and *any* restart or redeploy changes the fingerprint. With it, the
same fingerprint is reused until you deliberately rotate it.

```bash
hsync-bootnode identity rotate --identity /var/lib/hsync-bootnode/identity.pem
```

Rotation prints the new fingerprint; during the change window clients can be
given both fingerprints (the client accepts up to two pins), then moved to the
new one.

## I ran a *public* node — do clients need a fingerprint?

Not necessarily: on a terminal the client confirms the fingerprint once at the
prompt (the default `ask` policy) and remembers it, while an unattended client
uses `--bootnode-tofu` instead. Pin it explicitly with
`--bootnode-fingerprint` when the identity must be *stable* and verified out of
band.

## A client keeps logging "Waiting for peers to join" instead of exiting

If the trigger was the trust failure above, the client now **exits** with a fatal
exit code instead of waiting forever (the discovery lease loop stops on a pin
mismatch). If the client still waits, it means the node is reachable but no peer
is registered in the bucket yet — nothing is wrong: see the client's
[FAQ — p2p Mode](https://github.com/albertsdk/hsync-client/blob/main/docs/faq-p2p.md).

## Where can I read the pin the client stored?

On the client host, in `bootnode_known_hosts.json` under `$XDG_STATE_HOME/hsync/`
(or `~/.local/state/hsync/`), overridable with `HSYNC_BOOTNODE_TRUST_FILE`; the
client prints this path whenever it pins a fingerprint. It maps `<host>:<port>`
to the current fingerprint and its `updated_at` timestamp.
