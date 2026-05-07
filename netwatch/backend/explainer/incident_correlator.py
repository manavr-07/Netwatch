"""
incident_correlator.py
Anomaly Correlation Engine — groups individual flow anomalies into
higher-level "incidents" based on temporal and source proximity.

Novel Contribution:
    Flow-level anomaly detection produces one alert per flow. In a real
    attack scenario (port scan, DDoS, data exfiltration) dozens of flows
    are flagged within seconds. This module correlates those individual
    alerts into a single named incident with a composite severity and
    a unified explanation — dramatically reducing alert fatigue.

    Example: 5 anomalous flows from 172.16.0.171 within 2 minutes
    → Single incident: "Sustained port scanning activity detected"

    This elevates NetWatch from flow-level detection to incident-level
    detection — a significant conceptual advancement over the base paper.

Paper Reference:
    Addresses Limitation 4 (limited operational interpretability) —
    analysts see incidents, not raw flow alerts.

Correlation Rules:
    - Same source IP
    - Within CORRELATION_WINDOW seconds
    - Minimum INCIDENT_THRESHOLD anomalies to form an incident
"""

import time
import threading
import logging
from collections import defaultdict
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Time window in seconds to group anomalies into an incident
CORRELATION_WINDOW = 120   # 2 minutes

# Minimum anomalies from same source to declare an incident
INCIDENT_THRESHOLD = 3

# How long to keep resolved incidents in memory (seconds)
INCIDENT_TTL = 3600  # 1 hour


class Incident:
    """Represents a correlated group of anomalies from a single source."""

    def __init__(self, src_ip: str, first_anomaly: dict):
        self.src_ip         = src_ip
        self.first_ts       = first_anomaly['ts']
        self.last_ts        = first_anomaly['ts']
        self.anomalies      = [first_anomaly]
        self.is_active      = True
        self.incident_id    = f"INC-{int(self.first_ts)}-{src_ip.replace('.', '')}"

    def add_anomaly(self, anomaly: dict):
        self.anomalies.append(anomaly)
        self.last_ts = anomaly['ts']

    @property
    def count(self) -> int:
        return len(self.anomalies)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def composite_severity(self) -> str:
        """Escalate severity based on count and individual severities."""
        sev_rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        max_sev = max(
            (sev_rank.get(a.get('severity', 'INFO'), 0) for a in self.anomalies),
            default=0
        )
        # Escalate one level if 5+ anomalies
        if self.count >= 5 and max_sev < 4:
            max_sev += 1
        rank_sev = {v: k for k, v in sev_rank.items()}
        return rank_sev.get(max_sev, 'MEDIUM')

    @property
    def avg_score(self) -> float:
        scores = [a.get('anomaly_score', 0) for a in self.anomalies]
        return round(sum(scores) / len(scores), 4) if scores else 0.0

    @property
    def top_score(self) -> float:
        return round(max((a.get('anomaly_score', 0) for a in self.anomalies), default=0), 4)

    def get_pattern_summary(self) -> str:
        """Describe the dominant pattern across all correlated anomalies."""
        # Collect all deviating feature names across anomalies
        feat_counts = defaultdict(int)
        for a in self.anomalies:
            for dev in (a.get('deviating_features') or []):
                feat_counts[dev.get('feature', '')] += 1

        if not feat_counts:
            return f"{self.count} anomalous flows detected from {self.src_ip}."

        top_feat = max(feat_counts, key=feat_counts.get)
        top_count = feat_counts[top_feat]

        # Pattern recognition
        if 'syn_count' in feat_counts and 'rst_count' in feat_counts:
            return (
                f"Sustained port scanning or connection probing detected from "
                f"{self.src_ip} — {self.count} anomalous flows over "
                f"{self.duration:.0f}s. SYN/RST pattern present in "
                f"{feat_counts['syn_count']} flows."
            )
        if 'byte_count' in feat_counts:
            return (
                f"Repeated large data transfers detected from {self.src_ip} — "
                f"{self.count} flows over {self.duration:.0f}s suggest "
                f"potential data exfiltration or bulk transfer activity."
            )
        if 'duration' in feat_counts:
            return (
                f"Multiple persistent connections detected from {self.src_ip} — "
                f"{self.count} long-lived flows over {self.duration:.0f}s "
                f"may indicate command-and-control beaconing."
            )
        if 'mean_iat' in feat_counts:
            return (
                f"High-rate traffic bursts detected from {self.src_ip} — "
                f"{self.count} flows with abnormal packet timing over "
                f"{self.duration:.0f}s. Potential flood activity."
            )

        return (
            f"{self.count} anomalous flows from {self.src_ip} over "
            f"{self.duration:.0f}s. Dominant deviation: {top_feat} "
            f"(flagged in {top_count} flows)."
        )

    def get_correlation_reason(self) -> str:
        """
        Explain WHY these anomalies were correlated into one incident.
        """
        return (
            f"{self.count} anomalous flows from the same source IP ({self.src_ip}) "
            f"were detected within {self.duration:.0f}s of each other — "
            f"below the {CORRELATION_WINDOW}s correlation window. "
            f"Grouping repeated anomalies from a single source reduces alert fatigue "
            f"and surfaces sustained behavioral patterns invisible at the per-flow level."
        )

    def get_flow_breakdown(self) -> list:
        """
        Return a concise breakdown of each anomaly in this incident.
        """
        breakdown = []
        for i, a in enumerate(self.anomalies):
            devs = a.get('deviating_features') or []
            top_dev = devs[0] if devs else None
            breakdown.append({
                'index':       i + 1,
                'ts':          a.get('ts'),
                'src_ip':      a.get('src_ip'),
                'dst_ip':      a.get('dst_ip'),
                'dst_port':    a.get('dst_port'),
                'protocol':    a.get('protocol'),
                'score':       a.get('anomaly_score'),
                'severity':    a.get('severity'),
                'explanation': a.get('explanation', '')[:120] + '...' if len(a.get('explanation', '')) > 120 else a.get('explanation', ''),
                'top_feature': top_dev.get('label') if top_dev else None,
                'top_z':       top_dev.get('z_score') if top_dev else None,
            })
        return breakdown

    def get_dst_summary(self) -> list:
        """
        Return destination IPs with hit counts and port info.
        """
        dst_counts = defaultdict(lambda: {'count': 0, 'ports': set()})
        for a in self.anomalies:
            dst = a.get('dst_ip')
            port = a.get('dst_port')
            if dst:
                dst_counts[dst]['count'] += 1
                if port:
                    dst_counts[dst]['ports'].add(port)
        return [
            {
                'dst_ip': ip,
                'count':  v['count'],
                'ports':  sorted(list(v['ports']))[:5],
            }
            for ip, v in sorted(dst_counts.items(), key=lambda x: -x[1]['count'])
        ]

    def to_dict(self) -> dict:
        return {
            'incident_id':         self.incident_id,
            'src_ip':              self.src_ip,
            'first_ts':            self.first_ts,
            'last_ts':             self.last_ts,
            'duration_seconds':    round(self.duration, 1),
            'anomaly_count':       self.count,
            'composite_severity':  self.composite_severity,
            'avg_score':           self.avg_score,
            'top_score':           self.top_score,
            'pattern_summary':     self.get_pattern_summary(),
            'correlation_reason':  self.get_correlation_reason(),
            'flow_breakdown':      self.get_flow_breakdown(),
            'dst_summary':         self.get_dst_summary(),
            'is_active':           self.is_active,
            'dst_ips':             list({a.get('dst_ip') for a in self.anomalies if a.get('dst_ip')}),
        }


class IncidentCorrelator:
    """
    Stateful engine that receives individual anomaly records and groups
    them into incidents by source IP within a time window.
    """

    def __init__(self):
        # {src_ip: Incident}  — active incidents
        self._active: Dict[str, Incident] = {}
        # Completed incidents (past TTL or closed)
        self._resolved: List[Incident] = []
        self._lock = threading.Lock()

        # New incident broadcast callback
        self._on_incident = None

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="incident-cleanup")
        self._cleanup_thread.start()

    def set_incident_callback(self, fn):
        """Register a callback called when a new incident is confirmed."""
        self._on_incident = fn

    def ingest(self, anomaly: dict) -> Optional[dict]:
        """
        Feed a single anomaly into the correlator.
        Returns an incident dict if this anomaly triggered or updated an incident,
        otherwise returns None.
        """
        src_ip = anomaly.get('src_ip')
        if not src_ip:
            return None

        ts = anomaly.get('ts', time.time())

        with self._lock:
            existing = self._active.get(src_ip)

            if existing and (ts - existing.last_ts) <= CORRELATION_WINDOW:
                # Add to existing active incident
                existing.add_anomaly(anomaly)
                if existing.count >= INCIDENT_THRESHOLD:
                    incident_dict = existing.to_dict()
                    if self._on_incident and existing.count == INCIDENT_THRESHOLD:
                        # Fire callback only when threshold is first crossed
                        self._on_incident(incident_dict)
                    return incident_dict
            else:
                # Start a new incident window for this source
                self._active[src_ip] = Incident(src_ip=src_ip, first_anomaly=anomaly)

        return None

    def get_active_incidents(self) -> list:
        with self._lock:
            return [
                inc.to_dict()
                for inc in self._active.values()
                if inc.count >= INCIDENT_THRESHOLD
            ]

    def get_all_incidents(self) -> list:
        with self._lock:
            active = [i.to_dict() for i in self._active.values() if i.count >= INCIDENT_THRESHOLD]
            resolved = [i.to_dict() for i in self._resolved[-20:]]  # last 20 resolved
        return sorted(active + resolved, key=lambda x: x['last_ts'], reverse=True)

    def _cleanup_loop(self):
        """Periodically move expired incidents from active to resolved."""
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [
                    ip for ip, inc in self._active.items()
                    if (now - inc.last_ts) > CORRELATION_WINDOW
                ]
                for ip in expired:
                    inc = self._active.pop(ip)
                    inc.is_active = False
                    if inc.count >= INCIDENT_THRESHOLD:
                        self._resolved.append(inc)
                        logger.info(
                            "Incident closed: %s | %d anomalies | severity: %s",
                            inc.incident_id, inc.count, inc.composite_severity
                        )
                # Trim resolved list
                if len(self._resolved) > 100:
                    self._resolved = self._resolved[-100:]
