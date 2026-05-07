"""
api.py
Flask REST API and Server-Sent Events endpoint.

Routes:
  GET /api/status                      — pipeline health + segment stats
  GET /api/anomalies                   — recent anomaly records
  GET /api/anomalies/trend             — per-minute counts
  GET /api/anomalies/<id>/counterfactuals — counterfactuals for one anomaly
  GET /api/severity                    — severity distribution
  GET /api/baseline                    — current baseline statistics
  GET /api/incidents                   — correlated incident records
  GET /api/stats                       — aggregate counts
  GET /api/stream                      — SSE live anomaly stream
  GET /api/stream/incidents            — SSE live incident stream
"""

import json
import time
import logging
from flask import Blueprint, jsonify, request, Response, stream_with_context

from backend.db.database import (
    fetch_recent_anomalies,
    fetch_anomaly_trend,
    fetch_severity_distribution,
    fetch_stats,
    fetch_incidents,
    fetch_counterfactuals_for_anomaly,
)
from backend.pipeline import get_pipeline, get_broadcast_queue, get_incident_queue

logger = logging.getLogger(__name__)

api = Blueprint('api', __name__, url_prefix='/api')


def _ok(data):
    return jsonify({'status': 'ok', 'data': data})


def _err(msg, code=400):
    return jsonify({'status': 'error', 'message': msg}), code


# ------------------------------------------------------------------ #
# Existing routes                                                      #
# ------------------------------------------------------------------ #

@api.route('/status')
def status():
    pipeline = get_pipeline()
    if pipeline is None:
        return _err('Pipeline not initialized', 503)
    return _ok(pipeline.get_status())


@api.route('/anomalies')
def anomalies():
    limit = min(int(request.args.get('limit', 50)), 200)
    return _ok(fetch_recent_anomalies(limit=limit))


@api.route('/anomalies/trend')
def anomaly_trend():
    hours = min(float(request.args.get('hours', 1)), 24)
    return _ok(fetch_anomaly_trend(hours=hours))


@api.route('/anomalies/<int:anomaly_id>/counterfactuals')
def counterfactuals(anomaly_id: int):
    """Return counterfactual explanations for a specific anomaly."""
    cfs = fetch_counterfactuals_for_anomaly(anomaly_id)
    return _ok(cfs)


@api.route('/severity')
def severity():
    return _ok(fetch_severity_distribution())


@api.route('/baseline')
def baseline():
    pipeline = get_pipeline()
    if pipeline is None:
        return _err('Pipeline not initialized', 503)
    return _ok(pipeline.get_baseline())


@api.route('/stats')
def stats():
    s = fetch_stats()
    pipeline = get_pipeline()
    if pipeline:
        s.update(pipeline.get_status())
        # Include baseline quality in stats for dashboard display
        baseline = pipeline.get_baseline()
        if baseline and 'quality' in baseline:
            s['baseline_quality'] = baseline['quality']
    return _ok(s)


# ------------------------------------------------------------------ #
# New routes for novel features                                        #
# ------------------------------------------------------------------ #

@api.route('/incidents')
def incidents():
    """Return correlated incident records."""
    limit = min(int(request.args.get('limit', 20)), 100)
    pipeline = get_pipeline()
    if pipeline:
        data = pipeline.get_incidents()[:limit]
    else:
        data = fetch_incidents(limit=limit)
    return _ok(data)


# ------------------------------------------------------------------ #
# SSE streams                                                          #
# ------------------------------------------------------------------ #

@api.route('/stream')
def stream():
    """SSE live anomaly stream — now includes counterfactuals + incident_id."""
    bq = get_broadcast_queue()

    def event_generator():
        last_heartbeat = time.time()
        yield ": connected\n\n"
        while True:
            now = time.time()
            if now - last_heartbeat > 15:
                yield ": heartbeat\n\n"
                last_heartbeat = now
            try:
                payload = bq.get(timeout=1.0)
                data = json.dumps(payload, default=str)
                yield f"data: {data}\n\n"
            except Exception:
                continue

    return Response(
        stream_with_context(event_generator()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@api.route('/stream/incidents')
def stream_incidents():
    """SSE stream for confirmed incidents only."""
    iq = get_incident_queue()

    def event_generator():
        last_heartbeat = time.time()
        yield ": connected\n\n"
        while True:
            now = time.time()
            if now - last_heartbeat > 15:
                yield ": heartbeat\n\n"
                last_heartbeat = now
            try:
                payload = iq.get(timeout=1.0)
                data = json.dumps(payload, default=str)
                yield f"data: {data}\n\n"
            except Exception:
                continue

    return Response(
        stream_with_context(event_generator()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ------------------------------------------------------------------ #
# Detection control — pause / resume                                  #
# ------------------------------------------------------------------ #

@api.route('/detection/pause', methods=['POST'])
def pause_detection():
    """Pause anomaly detection. Flows are discarded until resumed."""
    pipeline = get_pipeline()
    if pipeline is None:
        return _err('Pipeline not initialized', 503)
    pipeline.pause()
    return _ok({'paused': True, 'message': 'Detection paused.'})


@api.route('/detection/resume', methods=['POST'])
def resume_detection():
    """Resume anomaly detection."""
    pipeline = get_pipeline()
    if pipeline is None:
        return _err('Pipeline not initialized', 503)
    pipeline.resume()
    return _ok({'paused': False, 'message': 'Detection resumed.'})


@api.route('/detection/status')
def detection_status():
    """Return whether detection is currently paused or running."""
    pipeline = get_pipeline()
    if pipeline is None:
        return _err('Pipeline not initialized', 503)
    return _ok({'paused': pipeline.is_paused})


# ------------------------------------------------------------------ #
# IP Intelligence routes                                              #
# ------------------------------------------------------------------ #

from backend.api.ip_intel import lookup, get_local_ips, get_cache

@api.route('/ip/<string:ip>')
def ip_intel(ip: str):
    """Return geolocation and org info for a single IP."""
    result = lookup(ip)
    return _ok(result)


@api.route('/ip/batch', methods=['POST'])
def ip_intel_batch():
    """
    Batch IP lookup. POST body: {"ips": ["1.2.3.4", "5.6.7.8"]}
    Returns dict of ip -> intel.
    """
    from flask import request as freq
    body = freq.get_json(silent=True) or {}
    ips  = body.get('ips', [])[:20]  # max 20 per batch
    results = {ip: lookup(ip) for ip in ips}
    return _ok(results)


@api.route('/ip/local')
def local_ips():
    """Return this machine's detected IP addresses."""
    return _ok(list(get_local_ips()))


@api.route('/ip/cache')
def ip_cache():
    """Return all cached IP intel records."""
    return _ok(get_cache())
