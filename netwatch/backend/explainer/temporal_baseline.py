"""
temporal_baseline.py
Temporal Baseline Segmentation — maintains separate statistical baselines
for different time-of-day windows.

Novel Contribution:
    Standard anomaly detection trains a single global baseline, causing
    false positives when legitimate traffic naturally varies by time of day
    (e.g. backup jobs at night, video calls during work hours, streaming
    in evenings). This module partitions the day into segments and maintains
    an independent baseline per segment.

    Result: Telegram streaming at 11pm is compared against the 11pm baseline,
    not the 9am baseline — dramatically reducing false positives from
    legitimate diurnal traffic variation.

Paper Reference:
    Directly addresses Limitation 3 (no explicit behavioral baseline) by
    making the baseline temporally-aware rather than globally static.

Segments:
    NIGHT     00:00 - 06:00
    MORNING   06:00 - 12:00
    AFTERNOON 12:00 - 18:00
    EVENING   18:00 - 24:00
"""

import time
import threading
import numpy as np
import logging
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Minimum samples per segment before its baseline is considered valid
MIN_SEGMENT_SAMPLES = 30

SEGMENTS = {
    'NIGHT':     (0,  6),
    'MORNING':   (6,  12),
    'AFTERNOON': (12, 18),
    'EVENING':   (18, 24),
}

FEATURES = [
    'duration', 'pkt_count', 'byte_count',
    'mean_pkt_size', 'std_pkt_size',
    'mean_iat', 'std_iat',
    'syn_count', 'fin_count', 'rst_count',
    'payload_ratio',
]


def _get_segment(ts: float = None) -> str:
    """Return the time segment name for a given Unix timestamp."""
    if ts is None:
        ts = time.time()
    hour = int(time.strftime('%H', time.localtime(ts)))
    for name, (start, end) in SEGMENTS.items():
        if start <= hour < end:
            return name
    return 'NIGHT'


class TemporalBaseline:
    """
    Maintains per-segment statistical baselines.
    Falls back to global baseline if a segment has insufficient samples.
    """

    def __init__(self):
        # {segment_name: [feature_vectors]}
        self._buffers: Dict[str, list] = defaultdict(list)
        # {segment_name: {feature: {mean, std, ...}}}
        self._baselines: Dict[str, Dict] = {}
        self._global_baseline: Dict = {}
        self._lock = threading.Lock()

    def add_flow(self, flow_dict: dict, ts: float = None):
        """Add a flow to the appropriate temporal segment buffer."""
        segment = _get_segment(ts or flow_dict.get('ts'))
        vec = [float(flow_dict.get(f, 0.0)) for f in FEATURES]
        with self._lock:
            self._buffers[segment].append(vec)
            # Recompute segment baseline if enough samples
            if len(self._buffers[segment]) >= MIN_SEGMENT_SAMPLES:
                self._compute_segment_baseline(segment)

    def _compute_segment_baseline(self, segment: str):
        """Compute statistics for a single segment from its buffer."""
        arr = np.array(self._buffers[segment], dtype=np.float64)
        baseline = {}
        for i, feat in enumerate(FEATURES):
            col = arr[:, i]
            baseline[feat] = {
                'mean': float(np.mean(col)),
                'std':  float(np.std(col)) + 1e-9,
                'p25':  float(np.percentile(col, 25)),
                'p50':  float(np.percentile(col, 50)),
                'p75':  float(np.percentile(col, 75)),
                'p95':  float(np.percentile(col, 95)),
                'n':    len(arr),
            }
        self._baselines[segment] = baseline
        logger.debug("Temporal baseline updated for segment %s (n=%d)", segment, len(arr))

    def set_global_baseline(self, baseline: dict):
        """Set the global fallback baseline from the main detector."""
        self._global_baseline = baseline

    def get_baseline_for_flow(self, flow_dict: dict) -> Dict:
        """
        Return the most appropriate baseline for a given flow.
        Uses segment baseline if available, otherwise falls back to global.
        """
        segment = _get_segment(flow_dict.get('ts'))
        with self._lock:
            if segment in self._baselines:
                return self._baselines[segment]
        return self._global_baseline

    def get_current_segment(self) -> str:
        return _get_segment()

    def get_segment_stats(self) -> Dict:
        """Return summary of how many samples each segment has."""
        with self._lock:
            return {
                seg: {
                    'samples': len(self._buffers[seg]),
                    'has_baseline': seg in self._baselines,
                    'hours': f"{SEGMENTS[seg][0]:02d}:00 - {SEGMENTS[seg][1]:02d}:00",
                }
                for seg in SEGMENTS
            }

    def get_deviations_for_flow(self, flow_dict: dict) -> list:
        """
        Compute z-score deviations using the temporally-appropriate baseline.
        Returns same format as AnomalyDetector._find_deviating_features().
        """
        from backend.ml.detector import FEATURE_LABELS, Z_SCORE_THRESHOLD
        baseline = self.get_baseline_for_flow(flow_dict)
        if not baseline:
            return []

        deviating = []
        for feat in FEATURES:
            val = float(flow_dict.get(feat, 0.0))
            b = baseline.get(feat)
            if not b:
                continue
            z = (val - b['mean']) / b['std']
            if abs(z) >= Z_SCORE_THRESHOLD:
                deviating.append({
                    'feature':        feat,
                    'label':          FEATURE_LABELS[feat],
                    'value':          round(val, 4),
                    'baseline_mean':  round(b['mean'], 4),
                    'baseline_std':   round(b['std'], 4),
                    'z_score':        round(z, 2),
                    'ratio':          round(val / max(b['mean'], 1e-9), 2),
                    'percentile_95':  round(b['p95'], 4),
                    'segment':        _get_segment(flow_dict.get('ts')),
                })

        deviating.sort(key=lambda x: abs(x['z_score']), reverse=True)
        return deviating
