"""
pipeline.py
Orchestrates the full detection pipeline:
  PacketCapture → FlowQueue → FeatureExtraction → IsolationForest →
  TemporalBaselineComparison → Explainer → CounterfactualEngine →
  IncidentCorrelator → SQLite → SSE broadcast queue

Self-learning mechanisms:
  1. Temporal Baseline Segmentation  — time-aware baselines (4 day segments)
  2. Anomaly Correlation / Incidents — groups flows into higher-level incidents
  3. Counterfactual Explanations     — "would not have been flagged if X < Y"
  4. Surge Detection                 — detects traffic regime shifts and pauses
                                       flagging to allow baseline adaptation
  5. Confidence-weighted thresholds  — fresh baselines require higher scores
                                       to flag, reducing cold-start false positives
  6. Whitelist suppression           — repeated false positives auto-suppressed
  7. Periodic Baseline Refresh        — soft retrain every 15 minutes on rolling
                                       buffer without any detection blind spot
"""

import logging
import threading
import time
import queue
import json
import collections

from backend.capture.capture import PacketCapture
from backend.ml.detector import AnomalyDetector, MIN_TRAINING_SAMPLES
from backend.api.ip_intel import get_local_ips
from backend.explainer.explainer import explain, assign_severity
from backend.explainer.counterfactual import generate_counterfactuals
from backend.explainer.temporal_baseline import TemporalBaseline
from backend.explainer.incident_correlator import IncidentCorrelator
from backend.db.database import (
    init_db, insert_flow, insert_anomaly,
    insert_baseline_snapshot, insert_counterfactuals,
    upsert_incident, init_db_v2
)

logger = logging.getLogger(__name__)

# Shared broadcast queues — SSE endpoints consume these
_broadcast_queue: queue.Queue = queue.Queue(maxsize=500)
_incident_queue:  queue.Queue = queue.Queue(maxsize=100)


def get_broadcast_queue() -> queue.Queue:
    return _broadcast_queue


def get_incident_queue() -> queue.Queue:
    return _incident_queue


# ------------------------------------------------------------------ #
# Surge Detector                                                      #
# ------------------------------------------------------------------ #

class SurgeDetector:
    """
    Detects sudden traffic regime shifts by tracking flow arrival rate
    over a sliding window.

    When a surge is detected the pipeline pauses anomaly flagging and
    feeds flows into the baseline buffer instead, allowing the model to
    adapt to the new traffic regime without flooding the analyst with
    false positives.

    Novel Contribution:
        Addresses the cold-start bootstrap paradox — when the baseline is
        trained on low-traffic data and traffic suddenly surges, anomalous-
        scoring flows are normally never added to the buffer (because they're
        flagged as anomalous), so the baseline can never adapt. Surge detection
        breaks this cycle by temporarily treating high-volume flows as benign
        during the adaptation window.
    """

    # Sliding window duration in seconds
    WINDOW_SECONDS = 30

    # Surge threshold — flow rate must be N× the baseline rate to trigger
    SURGE_MULTIPLIER = 4.0

    # How long to stay in surge mode (seconds) once triggered
    SURGE_COOLDOWN = 60

    def __init__(self):
        self._timestamps   = collections.deque()
        self._baseline_rate = None   # flows/second during normal operation
        self._surge_until   = 0.0
        self._lock          = threading.Lock()

    def record_flow(self, ts: float = None) -> bool:
        """
        Record a flow arrival. Returns True if currently in surge mode.
        """
        now = ts or time.time()
        with self._lock:
            self._timestamps.append(now)
            # Evict old timestamps outside the window
            cutoff = now - self.WINDOW_SECONDS
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()

            current_rate = len(self._timestamps) / self.WINDOW_SECONDS

            # Establish baseline rate from first 60 seconds of operation
            if self._baseline_rate is None:
                if now - (self._timestamps[0] if self._timestamps else now) > 60:
                    self._baseline_rate = current_rate
                    logger.info("Surge detector: baseline rate established = %.2f flows/s",
                                self._baseline_rate)
                return False   # no baseline yet — never surge mode

            # Check if we're in a surge
            if now < self._surge_until:
                return True    # currently in cooldown surge period

            # Detect new surge
            if self._baseline_rate > 0 and current_rate > self._baseline_rate * self.SURGE_MULTIPLIER:
                self._surge_until = now + self.SURGE_COOLDOWN
                logger.warning(
                    "Traffic surge detected! Rate=%.2f flows/s (%.1f× baseline=%.2f). "
                    "Pausing flagging for %ds to allow baseline adaptation.",
                    current_rate, current_rate / self._baseline_rate,
                    self._baseline_rate, self.SURGE_COOLDOWN
                )
                return True

            # Gradually update baseline rate with exponential moving average
            self._baseline_rate = 0.95 * self._baseline_rate + 0.05 * current_rate
            return False

    def is_surging(self) -> bool:
        with self._lock:
            return time.time() < self._surge_until

    def get_stats(self) -> dict:
        with self._lock:
            now = time.time()
            current_rate = len(self._timestamps) / max(self.WINDOW_SECONDS, 1)
            return {
                'current_rate_per_sec': round(current_rate, 2),
                'baseline_rate_per_sec': round(self._baseline_rate or 0, 2),
                'is_surging': now < self._surge_until,
                'surge_until': self._surge_until,
            }


# ------------------------------------------------------------------ #
# Whitelist / False Positive Suppressor                               #
# ------------------------------------------------------------------ #

class FalsePositiveSuppressor:
    """
    Tracks repeatedly-flagged IPs and suppresses them after N occurrences
    within a time window, treating them as known-benign false positives.

    Self-learning behavior:
        If the same source IP is flagged 5+ times within 10 minutes with
        no human action, it's almost certainly a false positive (e.g. Telegram,
        Apple background services). The suppressor adds it to a temporary
        whitelist and stops surfacing its alerts.

        The whitelist expires after SUPPRESS_TTL seconds, allowing the system
        to re-evaluate the IP if its behavior genuinely changes.
    """

    # How many times an IP must be flagged before suppression
    SUPPRESS_THRESHOLD = 5

    # Time window for counting (seconds)
    COUNT_WINDOW = 600   # 10 minutes

    # How long suppression lasts (seconds)
    SUPPRESS_TTL = 3600  # 1 hour

    def __init__(self):
        # {src_ip: deque of timestamps}
        self._counts:     dict = collections.defaultdict(collections.deque)
        # {src_ip: suppressed_until timestamp}
        self._suppressed: dict = {}
        self._lock = threading.Lock()

    def record_and_check(self, src_ip: str) -> bool:
        """
        Record a flagged anomaly for src_ip.
        Returns True if this IP should be SUPPRESSED (i.e. skip broadcasting).
        """
        if not src_ip:
            return False

        now = time.time()
        with self._lock:
            # Check if currently suppressed
            if src_ip in self._suppressed:
                if now < self._suppressed[src_ip]:
                    return True   # still suppressed
                else:
                    del self._suppressed[src_ip]   # suppression expired

            # Record this occurrence
            dq = self._counts[src_ip]
            dq.append(now)

            # Evict old timestamps
            cutoff = now - self.COUNT_WINDOW
            while dq and dq[0] < cutoff:
                dq.popleft()

            # Check threshold
            if len(dq) >= self.SUPPRESS_THRESHOLD:
                self._suppressed[src_ip] = now + self.SUPPRESS_TTL
                self._counts[src_ip].clear()
                logger.info(
                    "FP Suppressor: %s suppressed for %ds "
                    "(flagged %d times in %ds window)",
                    src_ip, self.SUPPRESS_TTL,
                    self.SUPPRESS_THRESHOLD, self.COUNT_WINDOW
                )
                return True

        return False

    def is_suppressed(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip in self._suppressed:
                if time.time() < self._suppressed[src_ip]:
                    return True
                del self._suppressed[src_ip]
        return False

    def unsuppress(self, src_ip: str):
        """Manually remove an IP from the suppression list."""
        with self._lock:
            self._suppressed.pop(src_ip, None)
            self._counts.pop(src_ip, None)

    def get_suppressed(self) -> dict:
        now = time.time()
        with self._lock:
            return {
                ip: round(until - now)
                for ip, until in self._suppressed.items()
                if now < until
            }


# ------------------------------------------------------------------ #
# Pipeline                                                            #
# ------------------------------------------------------------------ #

class Pipeline:
    """
    Central pipeline singleton. Call start() once at app startup.

    Self-learning architecture:
      - Rolling baseline retraining (in detector.py)
      - Temporal segment baselines (in temporal_baseline.py)
      - Confidence-weighted anomaly thresholds
      - Surge detection + baseline adaptation
      - False positive suppression with auto-whitelist
    """

    # Minimum anomaly score multiplier based on baseline confidence
    # Fresh baseline (confidence=0) → require 30% higher score to flag
    CONFIDENCE_THRESHOLD_BOOST = 0.15

    def __init__(self, interface: str = None, warmup_flows: int = MIN_TRAINING_SAMPLES):
        self.interface    = interface
        self.warmup_flows = warmup_flows

        self._flow_queue = queue.Queue()
        self._capture    = PacketCapture(
            interface=self.interface,
            output_queue=self._flow_queue
        )

        # Core ML detector (rolling window + adaptive baseline built in)
        self._detector   = AnomalyDetector(contamination=0.08, n_estimators=100)

        # Novel Feature 1: Temporal baseline segmentation
        self._temporal   = TemporalBaseline()

        # Novel Feature 2: Incident correlator
        self._correlator = IncidentCorrelator()
        self._correlator.set_incident_callback(self._on_incident_confirmed)

        # Novel Feature 4: Surge detector
        self._surge      = SurgeDetector()

        # Novel Feature 6: False positive suppressor
        self._suppressor = FalsePositiveSuppressor()

        # Permanent whitelist — this machine's own IPs are never flagged as source
        self._permanent_whitelist = get_local_ips()
        # Destination whitelist — system's own service call destinations
        self._dst_whitelist = {
            '208.95.112.1',   # ip-api.com — our own IP intel lookups
        }
        logger.info("Permanent src whitelist: %s", self._permanent_whitelist)

        self._warmup_count     = 0
        self._running          = False
        self._paused           = False   # user-controlled pause
        self._total_surges     = 0
        self._total_suppressed = 0
        self._last_refresh_ts  = 0.0
        self._refresh_interval = 900   # 15 minutes
        self._total_refreshes  = 0

    def start(self):
        init_db()
        init_db_v2()
        self._capture.start()
        proc_thread = threading.Thread(
            target=self._process_loop, daemon=True, name="pipeline-processor")
        proc_thread.start()

        refresh_thread = threading.Thread(
            target=self._periodic_retrain_loop, daemon=True, name="baseline-refresh")
        refresh_thread.start()

        logger.info("Pipeline started. Warm-up: collecting %d flows.", self.warmup_flows)
        logger.info("Periodic baseline refresh every %ds.", self._refresh_interval)

    def stop(self):
        self._running = False
        self._capture.stop()

    # ------------------------------------------------------------------ #
    # Processing loop                                                      #
    # ------------------------------------------------------------------ #

    def _process_loop(self):
        self._running = True
        while self._running:
            try:
                flow = self._flow_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self._handle_flow(flow)
            except Exception as e:
                logger.exception("Error processing flow: %s", e)

    def _handle_flow(self, flow_dict: dict):
        """Full self-learning pipeline per flow."""

        # 0. User-paused — discard flow entirely
        if self._paused:
            return

        # 1. Persist raw flow
        flow_id = insert_flow(flow_dict)

        # 2. Track flow rate for surge detection
        is_surging = self._surge.record_flow(flow_dict.get('ts', time.time()))

        # 3. Feed into temporal baseline always
        self._temporal.add_flow(flow_dict)

        # 4. Warm-up phase
        if not self._detector.is_trained:
            self._detector.add_to_buffer(flow_dict)
            self._warmup_count += 1
            if self._warmup_count >= self.warmup_flows:
                logger.info("Warm-up complete. Training model...")
                success = self._detector.train()
                if success:
                    self._temporal.set_global_baseline(
                        self._detector.get_baseline_summary()
                    )
                    insert_baseline_snapshot(self._detector.get_baseline_summary())
                    logger.info("Model trained. Baseline saved.")
            return

        # 5. Score with Isolation Forest
        result = self._detector.score(flow_dict)
        if result is None:
            return

        # 6. Permanent whitelist checks — never flag this device's own traffic
        if flow_dict.get('src_ip') in self._permanent_whitelist:
            self._detector.add_to_buffer(flow_dict)
            return

        if flow_dict.get('dst_ip') in self._dst_whitelist:
            self._detector.add_to_buffer(flow_dict)
            return

        # 7. Surge mode — feed into baseline instead of flagging
        #    This breaks the bootstrap paradox during traffic regime shifts
        if is_surging:
            self._total_surges += 1
            self._detector.add_to_buffer(flow_dict)
            logger.debug("Surge mode: feeding flow into baseline (src=%s)",
                         flow_dict.get('src_ip'))
            return

        # 8. Augment with temporal baseline deviations
        temporal_deviations = self._temporal.get_deviations_for_flow(flow_dict)
        if temporal_deviations:
            seen = {d['feature'] for d in temporal_deviations}
            for d in result['deviating_features']:
                if d['feature'] not in seen:
                    temporal_deviations.append(d)
            result['deviating_features'] = temporal_deviations

        # 9. Confidence-weighted threshold
        #    Fresh baseline → require higher score to flag
        #    Calibrated baseline → standard threshold
        quality     = result.get('baseline_quality', {})
        confidence  = quality.get('confidence', 1.0)
        score_boost = self.CONFIDENCE_THRESHOLD_BOOST * (1.0 - confidence)
        effective_threshold = 0.50 + score_boost

        if not result['is_anomaly'] or result['anomaly_score'] < effective_threshold:
            self._detector.add_to_buffer(flow_dict)
            return

        # 10. False positive suppressor check
        src_ip = flow_dict.get('src_ip')
        if self._suppressor.record_and_check(src_ip):
            # Still log to DB but don't broadcast — reduces alert fatigue
            self._total_suppressed += 1
            logger.debug("FP suppressed: %s (score=%.3f)", src_ip,
                         result['anomaly_score'])
            # Still feed into buffer since it's likely benign
            self._detector.add_to_buffer(flow_dict)
            return

        # 11. Enrich flow with dst org for severity capping
        try:
            from backend.api.ip_intel import lookup as ip_lookup
            dst_intel = ip_lookup(flow_dict.get('dst_ip', ''))
            flow_dict['dst_org'] = dst_intel.get('org', '') if dst_intel else ''
        except Exception:
            flow_dict['dst_org'] = ''

        # 12. Generate behavioral explanation
        explanation = explain(flow_dict, result)

        # 13. Generate counterfactual explanations
        counterfactuals = generate_counterfactuals(
            flow_dict=flow_dict,
            deviating_features=result['deviating_features'],
            detector=self._detector,
        )

        # 14. Persist anomaly
        anomaly_record = {
            'flow_id':            flow_id,
            'ts':                 flow_dict['ts'],
            'anomaly_score':      explanation['anomaly_score'],
            'severity':           explanation['severity'],
            'deviating_features': explanation['deviating_features'],
            'explanation':        explanation['explanation'],
            'mitigation':         explanation['mitigation'],
            'src_ip':             flow_dict.get('src_ip'),
            'dst_ip':             flow_dict.get('dst_ip'),
            'dst_port':           flow_dict.get('dst_port'),
            'protocol':           flow_dict.get('protocol'),
        }
        anomaly_id = insert_anomaly(anomaly_record)

        # 15. Persist counterfactuals
        if counterfactuals:
            insert_counterfactuals(anomaly_id, counterfactuals)

        # 16. Incident correlator
        incident = self._correlator.ingest({**anomaly_record, 'id': anomaly_id})
        if incident:
            upsert_incident(incident)

        # 17. Broadcast to SSE clients
        broadcast_payload = {
            'id':               anomaly_id,
            **anomaly_record,
            'severity_color':   explanation['severity_color'],
            'counterfactuals':  counterfactuals,
            'temporal_segment': self._temporal.get_current_segment(),
            'incident_id':      incident.get('incident_id') if incident else None,
            'baseline_quality': quality.get('quality', 'UNKNOWN'),
            'baseline_regime':  quality.get('regime', 'unknown'),
            'confidence':       round(confidence, 2),
        }
        try:
            _broadcast_queue.put_nowait(broadcast_payload)
        except queue.Full:
            try:
                _broadcast_queue.get_nowait()
                _broadcast_queue.put_nowait(broadcast_payload)
            except Exception:
                pass

        logger.info(
            "Anomaly | score=%.3f | sev=%s | src=%s | seg=%s | "
            "regime=%s | conf=%.2f | CFs=%d",
            explanation['anomaly_score'], explanation['severity'],
            flow_dict.get('src_ip'), self._temporal.get_current_segment(),
            quality.get('regime', '?'), confidence, len(counterfactuals)
        )

    def _periodic_retrain_loop(self):
        """
        Soft baseline refresh every 15 minutes.

        Retrains the Isolation Forest on the current rolling buffer of
        confirmed-benign flows — no warmup pause, no detection blind spot.

        This directly addresses the cold-start sensitivity problem:
        even if the initial baseline trained on low-traffic data, within
        15 minutes the buffer will contain recent high-traffic flows and
        the model will adapt automatically.

        Novel Contribution (Manav Raitani):
            Periodic soft baseline refresh combined with rolling window
            retraining ensures continuous adaptation to traffic regime
            changes without any detection interruption — distinguishing
            this system from static baseline approaches in existing literature.
        """
        while self._running:
            time.sleep(self._refresh_interval)

            if not self._detector.is_trained:
                logger.debug("Periodic refresh skipped — model not yet trained.")
                continue

            try:
                logger.info(
                    "Periodic baseline refresh #%d starting "
                    "(interval=%ds buffer_size=%d)...",
                    self._total_refreshes + 1,
                    self._refresh_interval,
                    len(self._detector._buffer)
                )

                success = self._detector.train()

                if success:
                    self._total_refreshes += 1
                    self._last_refresh_ts = time.time()

                    # Update temporal baseline with new global baseline
                    self._temporal.set_global_baseline(
                        self._detector.get_baseline_summary()
                    )

                    # Snapshot to DB for historical tracking
                    insert_baseline_snapshot(
                        self._detector.get_baseline_summary()
                    )

                    quality = self._detector.get_quality()
                    logger.info(
                        "Baseline refresh #%d complete | regime=%s | "
                        "confidence=%.2f | byte_mean=%.1fKB",
                        self._total_refreshes,
                        quality.get('regime', '?'),
                        quality.get('confidence', 0),
                        quality.get('byte_mean_kb', 0),
                    )
                else:
                    logger.warning("Periodic refresh skipped — insufficient buffer data.")

            except Exception as e:
                logger.exception("Periodic baseline refresh failed: %s", e)

    def _on_incident_confirmed(self, incident: dict):
        logger.warning(
            "INCIDENT: %s | %d flows | sev=%s | %s",
            incident['incident_id'], incident['anomaly_count'],
            incident['composite_severity'], incident['pattern_summary']
        )
        try:
            _incident_queue.put_nowait(incident)
        except queue.Full:
            pass

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def pause(self):
        """Pause anomaly detection — flows are discarded until resumed."""
        self._paused = True
        logger.info("Detection PAUSED by user.")

    def resume(self):
        """Resume anomaly detection."""
        self._paused = False
        logger.info("Detection RESUMED by user.")

    @property
    def is_paused(self) -> bool:
        return self._paused

    def get_status(self) -> dict:
        quality = self._detector.get_quality() if self._detector.is_trained else {}
        return {
            'trained':              self._detector.is_trained,
            'warmup_progress':      min(self._warmup_count, self.warmup_flows),
            'warmup_total':         self.warmup_flows,
            'queue_size':           self._flow_queue.qsize(),
            'current_segment':      self._temporal.get_current_segment(),
            'segment_stats':        self._temporal.get_segment_stats(),
            'active_incidents':     len(self._correlator.get_active_incidents()),
            'baseline_quality':     quality.get('quality', 'UNKNOWN'),
            'baseline_regime':      quality.get('regime', 'unknown'),
            'baseline_confidence':  quality.get('confidence', 0.0),
            'surge_stats':          self._surge.get_stats(),
            'total_surges':         self._total_surges,
            'total_suppressed':     self._total_suppressed,
            'paused':               self._paused,
            'suppressed_ips':       self._suppressor.get_suppressed(),
            'total_refreshes':      self._total_refreshes,
            'last_refresh_ts':      self._last_refresh_ts,
            'next_refresh_in':      max(0, int(self._refresh_interval - (time.time() - self._last_refresh_ts))) if self._last_refresh_ts else self._refresh_interval,
        }

    def get_baseline(self) -> dict:
        return self._detector.get_baseline_summary()

    def get_incidents(self) -> list:
        return self._correlator.get_all_incidents()

    def unsuppress_ip(self, ip: str):
        """Manually remove an IP from the false positive whitelist."""
        self._suppressor.unsuppress(ip)


# ------------------------------------------------------------------ #
# Module-level singleton                                              #
# ------------------------------------------------------------------ #

_pipeline: Pipeline = None


def get_pipeline() -> Pipeline:
    return _pipeline


def init_pipeline(interface: str = None, warmup_flows: int = MIN_TRAINING_SAMPLES):
    global _pipeline
    _pipeline = Pipeline(interface=interface, warmup_flows=warmup_flows)
    _pipeline.start()
    return _pipeline