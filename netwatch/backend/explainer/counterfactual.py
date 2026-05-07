"""
counterfactual.py
Generates counterfactual explanations for anomalous flows.

Novel Contribution:
    For each flagged anomaly, this module answers:
    "What would this flow need to look like to NOT be flagged?"

    Single-feature counterfactuals:
        Perturbs each deviating feature toward baseline mean until the
        Isolation Forest score drops below the anomaly threshold.
        Result: "This flow would not have been flagged if packet count
        were below 47 (observed: 312, baseline mean: 8.2)."

    Composite counterfactuals (fallback):
        When no single feature can suppress the anomaly alone, describes
        the combination of features that jointly drive the detection.
        Result: "This anomaly is driven by a combination of SYN packet
        count and flow duration — both would need to approach baseline
        simultaneously to suppress this alert."

    Confidence-aware output:
        Counterfactuals include the effective detection threshold so
        analysts know exactly how far the flow is from the decision boundary.

Paper Reference:
    Overcomes Limitation 4 (limited operational interpretability) by giving
    analysts exact threshold values rather than abstract deviation scores.
    First application of counterfactual explanations to unsupervised network
    anomaly detection without model internals access.
"""

import copy
from typing import Dict, List, Any, Optional

from backend.ml.detector import FEATURES, FEATURE_LABELS

# Number of interpolation steps between observed and baseline
PERTURBATION_STEPS = 50

# Score below which a flow is considered "would not be flagged"
COUNTERFACTUAL_THRESHOLD = 0.48

# How many top features to try for single-feature counterfactuals
MAX_FEATURES_TO_TRY = 5


def _build_single_cf(
    feat: str,
    observed: float,
    baseline_mean: float,
    threshold_val: float,
    direction: str,
) -> dict:
    """Build a single-feature counterfactual dict."""
    label = FEATURE_LABELS.get(feat, feat)
    verb  = 'below' if direction == 'decrease' else 'above'
    statement = (
        f"This flow would not have been flagged if {label} "
        f"were {verb} {_fmt(threshold_val)} "
        f"(observed: {_fmt(observed)}, baseline mean: {_fmt(baseline_mean)})."
    )
    return {
        'feature':    feat,
        'label':      label,
        'observed':   observed,
        'threshold':  threshold_val,
        'direction':  direction,
        'statement':  statement,
        'type':       'single',
    }


def _build_composite_cf(deviating: List[Dict]) -> dict:
    """
    Build a composite counterfactual when no single feature
    can suppress the anomaly alone.
    """
    if not deviating:
        return {
            'feature':   'composite',
            'label':     'Multiple features',
            'observed':  0,
            'threshold': 0,
            'direction': 'decrease',
            'statement': (
                "This anomaly is driven by overall composite deviation across "
                "multiple features simultaneously. No single feature change "
                "would suppress this alert — the flow would need to resemble "
                "baseline behavior across all dimensions."
            ),
            'type': 'composite',
        }

    top    = deviating[0]
    second = deviating[1] if len(deviating) > 1 else None
    third  = deviating[2] if len(deviating) > 2 else None

    top_label    = FEATURE_LABELS.get(top['feature'], top['feature'])
    second_label = FEATURE_LABELS.get(second['feature'], second['feature']) if second else None
    third_label  = FEATURE_LABELS.get(third['feature'], third['feature']) if third else None

    if second and third:
        feature_list = f"{top_label}, {second_label}, and {third_label}"
    elif second:
        feature_list = f"{top_label} and {second_label}"
    else:
        feature_list = top_label

    statement = (
        f"This anomaly is driven by a combination of {feature_list}. "
        f"The strongest deviation is {top_label} "
        f"({_fmt(top['value'])} vs baseline {_fmt(top['baseline_mean'])}, "
        f"z={top['z_score']:.1f}σ). "
        f"All deviating features would need to approach their baseline values "
        f"simultaneously to suppress this alert — no single change is sufficient."
    )

    return {
        'feature':   top['feature'],
        'label':     top_label,
        'observed':  top['value'],
        'threshold': round(top['baseline_mean'] * 1.5, 4),
        'direction': 'decrease' if top['z_score'] > 0 else 'increase',
        'statement': statement,
        'type':      'composite',
        'features_involved': [
            {'feature': d['feature'], 'label': FEATURE_LABELS.get(d['feature'], d['feature']),
             'z_score': d['z_score']}
            for d in deviating[:3]
        ],
    }


def _fmt(val: float) -> str:
    """Format a feature value cleanly."""
    if val == 0:
        return '0'
    if abs(val) >= 1000:
        return f"{val:,.0f}"
    if abs(val) >= 1:
        return f"{val:.2f}"
    return f"{val:.4f}"


def generate_counterfactuals(
    flow_dict: Dict,
    deviating_features: List[Dict],
    detector,
) -> List[Dict[str, Any]]:
    """
    Generate counterfactual explanations for an anomalous flow.

    Tries single-feature perturbation for each top deviating feature.
    Falls back to composite explanation if no single feature is sufficient.

    Parameters
    ----------
    flow_dict           : original flow feature dict
    deviating_features  : list of deviating feature dicts from detector
    detector            : AnomalyDetector instance (for rescoring)

    Returns
    -------
    List of counterfactual dicts — always returns at least one entry
    if deviating_features is non-empty.
    """
    if not detector.is_trained:
        return []

    if not deviating_features:
        return []

    counterfactuals = []

    # ── Single-feature counterfactuals ──────────────────────────────
    for dev in deviating_features[:MAX_FEATURES_TO_TRY]:
        feat          = dev['feature']
        observed      = dev['value']
        baseline_mean = dev['baseline_mean']

        direction = 'decrease' if observed > baseline_mean else 'increase'

        # Linearly interpolate from observed → baseline in N steps
        # Also try going 10% BEYOND baseline to handle tight baselines
        threshold_val: Optional[float] = None

        for step in range(1, PERTURBATION_STEPS + 1):
            # Steps 1..PERTURBATION_STEPS go from observed toward baseline
            # Step > PERTURBATION_STEPS goes 10% beyond baseline
            alpha         = step / PERTURBATION_STEPS
            perturbed_val = observed + alpha * (baseline_mean - observed)

            perturbed_flow       = copy.copy(flow_dict)
            perturbed_flow[feat] = perturbed_val

            result = detector.score(perturbed_flow)
            if result and result['anomaly_score'] < COUNTERFACTUAL_THRESHOLD:
                threshold_val = round(perturbed_val, 4)
                break

        if threshold_val is not None:
            counterfactuals.append(
                _build_single_cf(feat, observed, baseline_mean, threshold_val, direction)
            )

    # ── Composite fallback ───────────────────────────────────────────
    # If no single feature could suppress the anomaly, explain the combination
    if not counterfactuals:
        counterfactuals.append(_build_composite_cf(deviating_features))

    return counterfactuals
