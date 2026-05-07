"""
explainer.py
Generates human-readable behavioral explanations and mitigation suggestions.

This module is FULLY DECOUPLED from the ML model — it operates purely on
explicit baseline statistics and z-score deviations. This directly overcomes
the base paper's Limitation 5 (explanations tightly coupled to model internals)
and Limitation 2 (heavy deep learning dependence for explanation).

No LLMs, no SHAP, no gradient methods — only transparent statistical reasoning
expressed in operational language.
"""

from typing import List, Dict, Any

# Severity thresholds on Isolation Forest anomaly score
# Severity thresholds — calibrated for real-world home/office traffic
# CRITICAL: genuine extreme events (port scans, exfiltration, floods)
# HIGH:     significant behavioral deviation worth immediate review
# MEDIUM:   statistically unusual, may be benign background service
# LOW:      mild deviation, log and monitor only
SEVERITY_THRESHOLDS = {
    'CRITICAL': 0.72,   # lowered from 0.80 — real attacks score here
    'HIGH':     0.60,   # lowered from 0.65
    'MEDIUM':   0.50,   # unchanged
    'LOW':      0.40,   # raised from 0.35 — avoids near-threshold noise
}

# CSS/UI color hints per severity (used by frontend)
SEVERITY_COLORS = {
    'CRITICAL': '#c0392b',
    'HIGH':     '#e67e22',
    'MEDIUM':   '#d4ac0d',
    'LOW':      '#27ae60',
}

# Known benign organizations — severity capped at MEDIUM regardless of score
KNOWN_BENIGN_ORGS = {
    'google', 'microsoft', 'apple', 'amazon', 'aws',
    'cloudflare', 'akamai', 'fastly', 'github',
    'telegram', 'spotify', 'netflix', 'icloud',
    'baidu', 'zoom', 'slack', 'digitalocean',
}

# ------------------------------------------------------------------ #
# Pattern-based behavioral templates                                  #
# ------------------------------------------------------------------ #

# Each pattern is (condition_fn, explanation_template, mitigation)
# condition_fn receives the deviating_features list and flow_dict
# and returns (bool, format_kwargs)

def _feat_map(deviating: List[Dict]) -> Dict[str, Dict]:
    """Build a quick lookup: feature name -> deviation record."""
    return {d['feature']: d for d in deviating}


def _build_explanation(deviating: List[Dict], flow_dict: Dict, score: float) -> str:
    """
    Construct a plain-English behavioral explanation by inspecting the
    top deviating features. Multiple patterns can contribute sentences.
    """
    if not deviating:
        return (
            f"Flow exhibits overall statistical deviation from learned baseline "
            f"(anomaly score {score:.2f}) but no single feature stands out dramatically. "
            f"Composite behavior warrants inspection."
        )

    fm = _feat_map(deviating)
    sentences = []

    # --- Port scan / SYN flood heuristic ---
    if 'syn_count' in fm and 'rst_count' in fm:
        syn = fm['syn_count']
        rst = fm['rst_count']
        sentences.append(
            f"The flow contains {int(flow_dict.get('syn_count', 0))} SYN packets "
            f"({abs(syn['z_score']):.1f}× baseline standard deviation) "
            f"and {int(flow_dict.get('rst_count', 0))} RST packets, "
            f"a pattern consistent with port scanning or connection probing."
        )

    elif 'syn_count' in fm:
        syn = fm['syn_count']
        sentences.append(
            f"SYN packet count is {syn['ratio']:.1f}× the baseline average, "
            f"suggesting abnormal connection initiation behavior."
        )

    # --- Large data transfer ---
    if 'byte_count' in fm:
        bc = fm['byte_count']
        mb = flow_dict.get('byte_count', 0) / 1_048_576
        baseline_mb = bc['baseline_mean'] / 1_048_576

        if mb > 5.0:
            label = "an unusually large data transfer"
        elif mb > 1.0:
            label = "above-average data volume for this baseline window"
        elif mb > 0.1:
            label = "mildly elevated data volume relative to baseline"
        else:
            label = (
                f"statistically elevated relative to the baseline "
                f"(baseline mean: {baseline_mb:.4f} MB) — "
                f"absolute volume is low but deviates significantly from learned norms"
            )

        sentences.append(
            f"Total data transferred ({mb:.4f} MB) is {bc['ratio']:.1f}× "
            f"the baseline mean, {label}."
        )

    # --- Short, rapid flows (possible scan or DoS) ---
    if 'duration' in fm and fm['duration']['z_score'] < 0:
        dur = fm['duration']
        sentences.append(
            f"Flow duration ({flow_dict.get('duration', 0):.4f}s) is "
            f"{abs(dur['ratio'] - 1) * 100:.0f}% shorter than baseline, "
            f"suggesting rapid or aborted connections."
        )

    # --- Unusually long flow ---
    if 'duration' in fm and fm['duration']['z_score'] > 0:
        dur = fm['duration']
        sentences.append(
            f"Flow duration is {dur['ratio']:.1f}× the baseline average "
            f"({flow_dict.get('duration', 0):.2f}s vs {dur['baseline_mean']:.2f}s), "
            f"which may indicate a persistent or stealthy connection."
        )

    # --- Very high packet rate (low IAT) ---
    if 'mean_iat' in fm and fm['mean_iat']['z_score'] < 0:
        iat = fm['mean_iat']
        sentences.append(
            f"Inter-arrival time is {abs(iat['z_score']):.1f} standard deviations "
            f"below baseline, indicating packets are arriving at an unusually high rate."
        )

    # --- Tiny packets (possible header-only scan) ---
    if 'mean_pkt_size' in fm and fm['mean_pkt_size']['z_score'] < 0:
        ps = fm['mean_pkt_size']
        sentences.append(
            f"Average packet size ({flow_dict.get('mean_pkt_size', 0):.0f} bytes) "
            f"is {ps['ratio']:.2f}× the baseline mean, suggesting minimal-payload "
            f"or header-only traffic."
        )

    # --- Low payload ratio (overhead-heavy) ---
    if 'payload_ratio' in fm and fm['payload_ratio']['z_score'] < 0:
        pr = fm['payload_ratio']
        sentences.append(
            f"Payload-to-header ratio ({flow_dict.get('payload_ratio', 0):.2%}) "
            f"is significantly below baseline ({pr['baseline_mean']:.2%}), "
            f"indicating traffic dominated by headers with little application data."
        )

    # --- Fallback: describe top deviating feature ---
    if not sentences:
        top = deviating[0]
        direction = "above" if top['z_score'] > 0 else "below"
        sentences.append(
            f"{top['label'].capitalize()} deviates {abs(top['z_score']):.1f} standard "
            f"deviations {direction} the learned baseline "
            f"(observed: {top['value']}, baseline mean: {top['baseline_mean']})."
        )

    return " ".join(sentences)


def _build_mitigation(deviating: List[Dict], severity: str, flow_dict: Dict) -> str:
    """
    Select operational mitigation suggestion based on deviation pattern
    and severity, without reference to model internals.
    """
    fm = _feat_map(deviating)

    # Port scan / SYN anomaly
    if 'syn_count' in fm and 'rst_count' in fm:
        return (
            "Inspect firewall logs for rapid sequential connection attempts from "
            f"{flow_dict.get('src_ip', 'source IP')}. "
            "Consider rate-limiting SYN packets at the perimeter. "
            "Verify whether the source host is authorized to initiate broad connections."
        )

    # Large exfiltration candidate
    if 'byte_count' in fm and fm['byte_count']['ratio'] > 5:
        return (
            "Review outbound data transfer policies. "
            f"Verify whether {flow_dict.get('dst_ip', 'destination IP')} "
            f"on port {flow_dict.get('dst_port', '?')} is an authorized endpoint. "
            "Check for data loss prevention (DLP) alerts on this host."
        )

    # Long-lived connection
    if 'duration' in fm and fm['duration']['z_score'] > 0:
        return (
            "Investigate persistent connections from "
            f"{flow_dict.get('src_ip', 'source IP')}. "
            "Long-duration flows can indicate command-and-control (C2) beaconing. "
            "Review application logs and verify the destination is legitimate."
        )

    # High packet rate
    if 'mean_iat' in fm and fm['mean_iat']['z_score'] < 0:
        return (
            "Monitor for potential flood or denial-of-service activity. "
            "Apply rate limiting or QoS policy on the affected network segment. "
            "Confirm the source host is not compromised."
        )

    # Generic by severity
    severity_actions = {
        'CRITICAL': (
            "Immediately isolate the source host if possible. "
            "Escalate to the security operations team. "
            "Capture full packet trace for forensic analysis."
        ),
        'HIGH': (
            "Block or throttle the offending flow at the firewall. "
            "Notify the network security team and investigate the source host."
        ),
        'MEDIUM': (
            "Flag the source IP for continued monitoring. "
            "Review recent activity logs for corroborating anomalies."
        ),
        'LOW': (
            "Log and monitor. Verify with the asset owner that this behavior "
            "is expected. No immediate action required."
        ),
    }
    return severity_actions.get(severity, "Review network logs for further context.")


# ------------------------------------------------------------------ #
# Public API                                                          #
# ------------------------------------------------------------------ #

def assign_severity(anomaly_score: float, baseline_quality: str = None,
                    dst_org: str = None) -> str:
    """
    Map anomaly score to a discrete severity level.

    Two caps applied:
    1. LOW baseline quality — CRITICAL capped at HIGH to prevent cold-start
       false positives from appearing more severe than warranted.
    2. Known benign organizations — CRITICAL/HIGH capped at MEDIUM since
       Google, Microsoft, Apple, AWS etc. are legitimate services whose
       behavioral anomalies are almost never genuine threats.
    """
    if anomaly_score >= SEVERITY_THRESHOLDS['CRITICAL']:
        sev = 'CRITICAL'
    elif anomaly_score >= SEVERITY_THRESHOLDS['HIGH']:
        sev = 'HIGH'
    elif anomaly_score >= SEVERITY_THRESHOLDS['MEDIUM']:
        sev = 'MEDIUM'
    elif anomaly_score >= SEVERITY_THRESHOLDS['LOW']:
        sev = 'LOW'
    else:
        return 'INFO'

    # Cap severity during low-quality baseline
    if baseline_quality == 'LOW' and sev == 'CRITICAL':
        sev = 'HIGH'

    # Cap known benign orgs at MEDIUM — they are never CRITICAL or HIGH
    if dst_org and any(org in dst_org.lower() for org in KNOWN_BENIGN_ORGS):
        if sev in ('CRITICAL', 'HIGH'):
            sev = 'MEDIUM'

    return sev


def explain(flow_dict: Dict, scoring_result: Dict) -> Dict[str, Any]:
    """
    Full explanation pipeline. Accepts a flow dict and the output of
    AnomalyDetector.score(). Returns enriched anomaly record ready for storage.

    Parameters
    ----------
    flow_dict       : raw flow feature dict
    scoring_result  : {'is_anomaly', 'anomaly_score', 'deviating_features'}

    Returns
    -------
    dict with: severity, explanation, mitigation, deviating_features,
               anomaly_score, severity_color
    """
    score    = scoring_result['anomaly_score']
    deviating = scoring_result['deviating_features']
    bq        = scoring_result.get('baseline_quality', {})
    bl_quality = bq.get('quality') if isinstance(bq, dict) else None

    # Extract destination org from flow dict for known benign org capping
    dst_org = flow_dict.get('dst_org', '') or ''
    severity = assign_severity(score, baseline_quality=bl_quality, dst_org=dst_org)
    explanation = _build_explanation(deviating, flow_dict, score)
    mitigation = _build_mitigation(deviating, severity, flow_dict)

    return {
        'anomaly_score': score,
        'severity': severity,
        'severity_color': SEVERITY_COLORS.get(severity, '#888'),
        'deviating_features': deviating,
        'explanation': explanation,
        'mitigation': mitigation,
    }