"""
detector.py
Unsupervised anomaly detection using Isolation Forest + Adaptive Baseline.

Novel contribution over base paper:
  - Adaptive baseline that detects its own quality (low/high traffic regime)
    and adjusts z-score thresholds accordingly
  - Rolling window retraining — baseline continuously evolves with traffic
  - Baseline quality scoring — system knows when its own baseline is weak
    and communicates this through confidence-adjusted explanations
  - Traffic regime detection — distinguishes low/normal/high traffic periods
    and calibrates sensitivity per regime

Architecture overcomes paper limitations:
  - Limitation 1: Explanations derived from explicit baseline, NOT model internals
  - Limitation 3: Living adaptive baseline with quality metrics
  - Limitation 4: Scoring includes baseline confidence indicator
  - Limitation 5: Explanations fully decoupled from model
"""

import numpy as np
import logging
import threading
import time
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Feature definitions                                                 #
# ------------------------------------------------------------------ #

FEATURES = [
    'duration',
    'pkt_count',
    'byte_count',
    'mean_pkt_size',
    'std_pkt_size',
    'mean_iat',
    'std_iat',
    'syn_count',
    'fin_count',
    'rst_count',
    'payload_ratio',
]

FEATURE_LABELS = {
    'duration':       'flow duration',
    'pkt_count':      'packet count',
    'byte_count':     'total bytes transferred',
    'mean_pkt_size':  'average packet size',
    'std_pkt_size':   'packet size variability',
    'mean_iat':       'average inter-arrival time',
    'std_iat':        'inter-arrival time variability',
    'syn_count':      'SYN packet count',
    'fin_count':      'FIN packet count',
    'rst_count':      'RST packet count',
    'payload_ratio':  'payload-to-header ratio',
}

# ------------------------------------------------------------------ #
# Adaptive thresholds                                                 #
# ------------------------------------------------------------------ #

# Base z-score threshold — features must exceed this to be flagged
Z_SCORE_THRESHOLD = 2.5

# Minimum flows before initial training
MIN_TRAINING_SAMPLES = 300

# Rolling buffer size — how many recent benign flows to keep
ROLLING_BUFFER_SIZE = 1000

# Retrain every N new benign flows after initial training
RETRAIN_INTERVAL = 200

# Traffic regime thresholds (bytes/flow)
# Used to detect if baseline was trained on low-traffic period
REGIME_LOW_BYTES_THRESHOLD    = 5_000    # <5KB avg = low traffic baseline
REGIME_NORMAL_BYTES_THRESHOLD = 50_000   # <50KB avg = normal
# >50KB avg = high traffic baseline

# Minimum absolute thresholds — below these, features are never flagged
# regardless of z-score (prevents false positives on tiny flows)
ABSOLUTE_MINIMUMS = {
    'byte_count':    100_000,   # must be >100KB to flag for volume
    'pkt_count':     10,        # must be >10 packets
    'syn_count':     5,         # must have >5 SYNs
    'rst_count':     5,         # must have >5 RSTs
    'fin_count':     3,
}

# Minimum packet count for variability features to be meaningful
MIN_PKTS_FOR_VARIANCE_FEATURES = 3


class BaselineQuality:
    """
    Assesses the quality of the current baseline and returns
    adaptive parameters to compensate for low-quality baselines.
    """

    LOW    = 'LOW'      # trained on very little / low traffic
    MEDIUM = 'MEDIUM'   # reasonable baseline
    HIGH   = 'HIGH'     # rich, diverse baseline

    @staticmethod
    def assess(baseline: dict, n_samples: int) -> dict:
        """
        Analyze baseline statistics to determine quality and regime.

        Returns:
            quality         : LOW / MEDIUM / HIGH
            regime          : low_traffic / normal / high_traffic
            z_multiplier    : multiplier applied to Z_SCORE_THRESHOLD
                              (higher = less sensitive = fewer false positives)
            byte_minimum    : adaptive minimum byte threshold
            confidence      : 0.0 to 1.0
            description     : human-readable quality summary
        """
        if not baseline or n_samples < MIN_TRAINING_SAMPLES:
            return {
                'quality':      BaselineQuality.LOW,
                'regime':       'unknown',
                'z_multiplier': 1.5,
                'byte_minimum': 100_000,
                'confidence':   0.1,
                'description':  'Insufficient training data',
            }

        byte_mean = baseline.get('byte_count', {}).get('mean', 0)
        byte_std  = baseline.get('byte_count', {}).get('std',  1)
        pkt_mean  = baseline.get('pkt_count',  {}).get('mean', 0)

        # Coefficient of variation — how diverse is the baseline?
        cv = byte_std / max(byte_mean, 1e-9)

        # Determine traffic regime from average bytes/flow
        if byte_mean < REGIME_LOW_BYTES_THRESHOLD:
            regime       = 'low_traffic'
            # Low traffic baseline — be much less sensitive to byte_count
            # because even tiny transfers look massive relative to baseline
            z_multiplier = 2.0    # require 2x the z-score to flag
            byte_minimum = 500_000  # 500KB minimum for low-traffic baseline
            quality      = BaselineQuality.LOW
            confidence   = min(0.4, n_samples / MIN_TRAINING_SAMPLES)
            description  = (
                f"Baseline trained on low-traffic period "
                f"(avg {byte_mean/1024:.1f} KB/flow, {n_samples} flows). "
                f"Volume thresholds auto-adjusted to reduce false positives."
            )

        elif byte_mean < REGIME_NORMAL_BYTES_THRESHOLD:
            regime       = 'normal'
            z_multiplier = 1.0    # standard sensitivity
            byte_minimum = 100_000
            quality      = BaselineQuality.MEDIUM
            confidence   = min(0.8, n_samples / (MIN_TRAINING_SAMPLES * 2))
            description  = (
                f"Normal traffic baseline "
                f"(avg {byte_mean/1024:.1f} KB/flow, {n_samples} flows). "
                f"Standard detection sensitivity."
            )

        else:
            regime       = 'high_traffic'
            z_multiplier = 0.85   # slightly more sensitive during high traffic
            byte_minimum = 100_000
            quality      = BaselineQuality.HIGH
            confidence   = min(1.0, n_samples / (MIN_TRAINING_SAMPLES * 3))
            description  = (
                f"High-traffic baseline "
                f"(avg {byte_mean/1024:.1f} KB/flow, {n_samples} flows). "
                f"Sensitivity calibrated for high-volume environment."
            )

        return {
            'quality':      quality,
            'regime':       regime,
            'z_multiplier': z_multiplier,
            'byte_minimum': byte_minimum,
            'confidence':   round(confidence, 2),
            'description':  description,
            'byte_mean_kb': round(byte_mean / 1024, 2),
            'pkt_mean':     round(pkt_mean, 1),
            'n_samples':    n_samples,
            'diversity_cv': round(cv, 2),
        }


class AnomalyDetector:
    """
    Isolation Forest with adaptive statistical baseline.

    Key behaviors:
    - Detects traffic regime during warmup (low/normal/high)
    - Auto-adjusts detection thresholds based on baseline quality
    - Rolling window retraining — adapts to traffic changes over time
    - Never silently produces misleading results — quality is always surfaced
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators  = n_estimators

        self._model:  IsolationForest = None
        self._scaler: StandardScaler  = StandardScaler()

        # Rolling buffer — deque automatically drops oldest when full
        self._buffer: deque = deque(maxlen=ROLLING_BUFFER_SIZE)
        self._buffer_lock   = threading.Lock()
        self._model_lock    = threading.RLock()  # protects scaler+model during retrain

        # Baseline statistics
        self.baseline: dict = {}

        # Baseline quality assessment
        self.quality: dict  = {}

        self.is_trained          = False
        self._n_training_samples = 0
        self._flows_since_retrain = 0
        self._retraining          = False   # lock to prevent concurrent retrains

    # ------------------------------------------------------------------ #
    # Training                                                             #
    # ------------------------------------------------------------------ #

    def add_to_buffer(self, flow_dict: dict):
        """
        Add a confirmed-benign flow to the rolling training buffer.
        The deque automatically evicts the oldest entry when full,
        implementing the rolling window.
        """
        vec = self._extract_vector(flow_dict)
        with self._buffer_lock:
            self._buffer.append(vec)

    def train(self) -> bool:
        """
        Train Isolation Forest and compute adaptive baseline.
        Safe to call repeatedly — implements rolling retraining.
        """
        with self._buffer_lock:
            n = len(self._buffer)
            if n < MIN_TRAINING_SAMPLES:
                logger.info("Buffer has %d/%d flows — skipping train", n, MIN_TRAINING_SAMPLES)
                return False
            data = list(self._buffer)

        arr = np.array(data, dtype=np.float64)
        self._n_training_samples = len(arr)

        # Compute explicit baseline statistics
        self.baseline = {}
        for i, feat in enumerate(FEATURES):
            col = arr[:, i]
            self.baseline[feat] = {
                'mean': float(np.mean(col)),
                'std':  float(np.std(col)) + 1e-9,
                'p25':  float(np.percentile(col, 25)),
                'p50':  float(np.percentile(col, 50)),
                'p75':  float(np.percentile(col, 75)),
                'p95':  float(np.percentile(col, 95)),
                'min':  float(np.min(col)),
                'max':  float(np.max(col)),
                'n':    len(col),
            }

        # Assess baseline quality — THIS is the adaptive part
        self.quality = BaselineQuality.assess(self.baseline, self._n_training_samples)
        logger.info(
            "Baseline assessed: regime=%s quality=%s confidence=%.2f z_mult=%.2f byte_min=%dKB",
            self.quality['regime'], self.quality['quality'],
            self.quality['confidence'], self.quality['z_multiplier'],
            self.quality['byte_minimum'] // 1024
        )

        # Fit scaler and model — lock prevents score() using half-fitted scaler
        new_scaler = StandardScaler()
        new_scaler.fit(arr)
        arr_scaled = new_scaler.transform(arr)

        new_model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        new_model.fit(arr_scaled)

        # Atomic swap — score() is never caught with half-fitted objects
        with self._model_lock:
            self._scaler          = new_scaler
            self._model           = new_model
            self.is_trained       = True
            self._flows_since_retrain = 0
            self._retraining      = False

        logger.info(
            "Model trained on %d flows | regime=%s | buffer utilization=%.0f%%",
            len(data), self.quality['regime'],
            (len(data) / ROLLING_BUFFER_SIZE) * 100
        )
        return True

    # ------------------------------------------------------------------ #
    # Scoring                                                              #
    # ------------------------------------------------------------------ #

    def score(self, flow_dict: dict) -> dict:
        """
        Score a single flow against the current adaptive baseline.

        Returns:
            is_anomaly          : bool
            anomaly_score       : float [0, 1] — higher = more anomalous
            deviating_features  : list of deviating feature dicts
            baseline_quality    : quality dict for this scoring decision
        """
        if not self.is_trained:
            return None

        with self._model_lock:
            vec        = np.array([self._extract_vector(flow_dict)], dtype=np.float64)
            vec_scaled = self._scaler.transform(vec)

            # Isolation Forest score — flip so higher = more anomalous
            raw_score     = self._model.decision_function(vec_scaled)[0]
            anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
            is_anomaly    = self._model.predict(vec_scaled)[0] == -1

        # Adaptive deviating feature detection
        deviating = self._find_deviating_features(flow_dict)

        # Schedule rolling retrain if due
        self._flows_since_retrain += 1
        if self._flows_since_retrain >= RETRAIN_INTERVAL and not self._retraining:
            self._retraining = True
            t = threading.Thread(target=self.train, daemon=True, name="retrain")
            t.start()

        return {
            'is_anomaly':         is_anomaly,
            'anomaly_score':      round(anomaly_score, 4),
            'deviating_features': deviating,
            'baseline_quality':   self.quality,
        }

    # ------------------------------------------------------------------ #
    # Adaptive feature deviation detection                                 #
    # ------------------------------------------------------------------ #

    def _find_deviating_features(self, flow_dict: dict) -> list:
        """
        Compute z-score deviations with adaptive thresholds.

        Adaptive behaviors:
        1. Z-score threshold is multiplied by quality.z_multiplier
           (low-traffic baseline → higher threshold → less sensitive)
        2. Absolute minimums prevent flagging tiny values
        3. Variance features suppressed for very short flows
        4. Byte count minimum scales with baseline regime
        """
        if not self.baseline or not self.quality:
            return []

        # Adaptive z-score threshold
        effective_z_threshold = Z_SCORE_THRESHOLD * self.quality.get('z_multiplier', 1.0)

        # Adaptive byte minimum — from quality assessment
        adaptive_byte_min = self.quality.get('byte_minimum', ABSOLUTE_MINIMUMS['byte_count'])

        pkt_count = float(flow_dict.get('pkt_count', 0))
        deviating = []

        for feat in FEATURES:
            val = float(flow_dict.get(feat, 0.0))
            b   = self.baseline.get(feat)
            if not b:
                continue

            # ── Absolute minimum guards ──────────────────────────────
            if feat == 'byte_count' and val < adaptive_byte_min:
                continue   # never flag tiny transfers regardless of z-score

            if feat in ('pkt_count',) and val < ABSOLUTE_MINIMUMS.get(feat, 0):
                continue

            if feat in ('syn_count', 'rst_count', 'fin_count'):
                if val < ABSOLUTE_MINIMUMS.get(feat, 0):
                    continue

            # ── Variance features need enough packets ────────────────
            if feat in ('std_pkt_size', 'std_iat') and pkt_count < MIN_PKTS_FOR_VARIANCE_FEATURES:
                continue

            # ── Z-score computation ──────────────────────────────────
            z = (val - b['mean']) / b['std']

            if abs(z) >= effective_z_threshold:
                deviating.append({
                    'feature':       feat,
                    'label':         FEATURE_LABELS[feat],
                    'value':         round(val, 4),
                    'baseline_mean': round(b['mean'], 4),
                    'baseline_std':  round(b['std'], 4),
                    'z_score':       round(z, 2),
                    'ratio':         round(val / max(b['mean'], 1e-9), 2),
                    'percentile_95': round(b['p95'], 4),
                    'effective_threshold': round(effective_z_threshold, 2),
                })

        deviating.sort(key=lambda x: abs(x['z_score']), reverse=True)
        return deviating

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _extract_vector(self, flow_dict: dict) -> list:
        return [float(flow_dict.get(f, 0.0)) for f in FEATURES]

    def get_baseline_summary(self) -> dict:
        return {
            'features': {feat: stats for feat, stats in self.baseline.items()},
            'quality':  self.quality,
            'n_samples': self._n_training_samples,
            'buffer_size': len(self._buffer),
            'buffer_capacity': ROLLING_BUFFER_SIZE,
        }

    def get_quality(self) -> dict:
        return self.quality
