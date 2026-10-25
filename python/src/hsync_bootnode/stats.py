"""Peer-free operational counters for the bootstrap node (RAM only, O(1)).

The node is no-log: nothing peer-related may reach disk. These aggregates carry no
CID, bucket, IP or port, so they are the only operational numbers the node
exposes \u2014 the service manager's ``STATUS=``, the Prometheus text file and the
loopback ``/metrics`` endpoint (``hsync_bootnode.metrics``).

A level is observed where the event happens (a connection admitted or released, a
record upserted or removed) instead of being sampled: ``boot/1`` clients open one
connection per exchange and let it idle out after 30 s, so a concurrency spike is
shorter than any sane sampling interval and a sampled peak would systematically
under-report it. A peak never decreases and nothing is persisted, so it covers
the lifetime of the process; long-term history is the monitoring system's job.

Consumers: ``hsync_bootnode.server`` (connection guard), ``hsync_bootnode.handler``
(registered peers), ``hsync_bootnode.metrics`` (exposition) and
``hsync_bootnode.cli`` (the periodic sink and the banner).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from hsync_bootnode import __version__
from hsync_bootnode.protocol import PROTOCOL_VERSION_BOOT

__all__ = ["METRICS_OUTCOMES", "NodeStats"]

# Outcomes the metrics endpoint can answer, in exposition order. The set is
# closed: an unknown outcome is not recorded, so the series cannot grow with
# caller input.
METRICS_OUTCOMES = (
    "ok",
    "unauthorized",
    "not_found",
    "method_not_allowed",
    "rate_limited",
    "unavailable",
)


def _prom_escape(value: str) -> str:
    """Escape a Prometheus label value (backslash, double quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass(slots=True)
class NodeStats:
    """Levels, peaks and lifetime counters of one node process.

    Levels and peaks are integers maintained in O(1) on the event path; the
    ``*_peak_at`` stamps are wall-clock (epoch seconds) so they can be compared
    with a monitoring time series, never ``monotonic()``.
    """

    started_at: float = field(default_factory=time.time)
    connections_current: int = 0
    connections_peak: int = 0
    connections_peak_at: float = 0.0
    connections_total: int = 0
    peers_current: int = 0
    peers_peak: int = 0
    peers_peak_at: float = 0.0
    peers_updates_total: int = 0
    peers_expired_total: int = 0
    metrics_requests: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(METRICS_OUTCOMES, 0)
    )
    stats_write_errors: int = 0

    def connections_changed(self, current: int, *, opened: bool = False) -> None:
        """Record the open-connection level, ``opened`` on one admitted connection."""
        self.connections_current = current
        if opened:
            self.connections_total += 1
        if current > self.connections_peak:
            self.connections_peak = current
            self.connections_peak_at = time.time()

    def peers_changed(self, current: int, *, written: bool = False, expired: int = 0) -> None:
        """Record the registered-peer level; ``written`` counts a register/refresh write."""
        self.peers_current = current
        if written:
            self.peers_updates_total += 1
        if expired:
            self.peers_expired_total += expired
        if current > self.peers_peak:
            self.peers_peak = current
            self.peers_peak_at = time.time()

    def metrics_request(self, outcome: str) -> None:
        """Count one ``/metrics`` request outcome (unknown outcomes are ignored)."""
        if outcome in self.metrics_requests:
            self.metrics_requests[outcome] += 1

    def stats_write_failed(self) -> None:
        """Count one failed periodic write of the Prometheus text file."""
        self.stats_write_errors += 1

    def status_text(self) -> str:
        """One-line summary for the service manager's ``STATUS=`` assignment."""
        return (
            f"conn={self.connections_current}/{self.connections_peak} "
            f"peers={self.peers_current}/{self.peers_peak}"
        )

    def render_prometheus(self) -> str:
        """Prometheus text exposition: fixed cardinality, never peer-identifying."""
        version = _prom_escape(__version__)
        protocol = _prom_escape(PROTOCOL_VERSION_BOOT)
        lines = [
            "# HELP hsync_bootnode_build_info Identity of the running node.",
            "# TYPE hsync_bootnode_build_info gauge",
            f'hsync_bootnode_build_info{{version="{version}",protocol="{protocol}"}} 1',
            "# HELP hsync_bootnode_start_time_seconds Unix time the process started.",
            "# TYPE hsync_bootnode_start_time_seconds gauge",
            f"hsync_bootnode_start_time_seconds {self.started_at:.3f}",
            "# HELP hsync_bootnode_quic_connections_current Open QUIC connections.",
            "# TYPE hsync_bootnode_quic_connections_current gauge",
            f"hsync_bootnode_quic_connections_current {self.connections_current}",
            "# HELP hsync_bootnode_quic_connections_peak Highest open-connection level.",
            "# TYPE hsync_bootnode_quic_connections_peak gauge",
            f"hsync_bootnode_quic_connections_peak {self.connections_peak}",
            "# HELP hsync_bootnode_quic_connections_peak_timestamp_seconds When the peak was reached.",
            "# TYPE hsync_bootnode_quic_connections_peak_timestamp_seconds gauge",
            "hsync_bootnode_quic_connections_peak_timestamp_seconds "
            f"{self.connections_peak_at:.3f}",
            "# HELP hsync_bootnode_quic_connections_total Admitted QUIC connections.",
            "# TYPE hsync_bootnode_quic_connections_total counter",
            f"hsync_bootnode_quic_connections_total {self.connections_total}",
            "# HELP hsync_bootnode_peers_current Peers registered right now (TTL-bounded).",
            "# TYPE hsync_bootnode_peers_current gauge",
            f"hsync_bootnode_peers_current {self.peers_current}",
            "# HELP hsync_bootnode_peers_peak Highest registered-peer level.",
            "# TYPE hsync_bootnode_peers_peak gauge",
            f"hsync_bootnode_peers_peak {self.peers_peak}",
            "# HELP hsync_bootnode_peers_peak_timestamp_seconds When the peak was reached.",
            "# TYPE hsync_bootnode_peers_peak_timestamp_seconds gauge",
            f"hsync_bootnode_peers_peak_timestamp_seconds {self.peers_peak_at:.3f}",
            "# HELP hsync_bootnode_peers_updates_total Accepted register/refresh writes.",
            "# TYPE hsync_bootnode_peers_updates_total counter",
            f"hsync_bootnode_peers_updates_total {self.peers_updates_total}",
            "# HELP hsync_bootnode_peers_expired_total Records dropped by the TTL sweep.",
            "# TYPE hsync_bootnode_peers_expired_total counter",
            f"hsync_bootnode_peers_expired_total {self.peers_expired_total}",
            "# HELP hsync_bootnode_metrics_requests_total Requests answered by /metrics.",
            "# TYPE hsync_bootnode_metrics_requests_total counter",
        ]
        lines.extend(
            f'hsync_bootnode_metrics_requests_total{{outcome="{outcome}"}} '
            f"{self.metrics_requests[outcome]}"
            for outcome in METRICS_OUTCOMES
        )
        lines.extend(
            (
                "# HELP hsync_bootnode_stats_write_errors_total Failed stats-file writes.",
                "# TYPE hsync_bootnode_stats_write_errors_total counter",
                f"hsync_bootnode_stats_write_errors_total {self.stats_write_errors}",
            )
        )
        return "\n".join(lines) + "\n"
