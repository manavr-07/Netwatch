"""
database.py
SQLite database initialization and query helpers for NetWatch.
Schema stores flows, anomalies, and baseline snapshots.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'netwatch.db')


def get_connection():
    """Return a thread-safe SQLite connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they do not exist."""
    conn = get_connection()
    c = conn.cursor()

    # --- flows table: every completed flow record ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS flows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              REAL    NOT NULL,        -- Unix timestamp of flow completion
            src_ip          TEXT    NOT NULL,
            dst_ip          TEXT    NOT NULL,
            src_port        INTEGER,
            dst_port        INTEGER,
            protocol        INTEGER,
            duration        REAL,
            pkt_count       INTEGER,
            byte_count      INTEGER,
            mean_pkt_size   REAL,
            std_pkt_size    REAL,
            mean_iat        REAL,   -- inter-arrival time
            std_iat         REAL,
            syn_count       INTEGER,
            fin_count       INTEGER,
            rst_count       INTEGER,
            payload_ratio   REAL    -- payload bytes / total bytes
        )
    ''')

    # --- anomalies table: detected anomalous flows ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id             INTEGER REFERENCES flows(id),
            ts                  REAL    NOT NULL,
            anomaly_score       REAL    NOT NULL,   -- Isolation Forest score (0..1, higher=more anomalous)
            severity            TEXT    NOT NULL,   -- LOW / MEDIUM / HIGH / CRITICAL
            deviating_features  TEXT    NOT NULL,   -- JSON list of {feature, value, baseline_mean, z_score}
            explanation         TEXT    NOT NULL,   -- Human-readable behavioral narrative
            mitigation          TEXT    NOT NULL,   -- Recommended action
            src_ip              TEXT,
            dst_ip              TEXT,
            dst_port            INTEGER,
            protocol            INTEGER
        )
    ''')

    # --- baseline_snapshots: periodic summaries of baseline stats ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS baseline_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL    NOT NULL,
            stats_json  TEXT    NOT NULL    -- JSON of {feature: {mean, std, p25, p50, p75, p95}}
        )
    ''')

    conn.commit()
    conn.close()


# ---------- INSERT helpers ----------

def insert_flow(flow_dict: dict) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO flows
            (ts, src_ip, dst_ip, src_port, dst_port, protocol,
             duration, pkt_count, byte_count, mean_pkt_size, std_pkt_size,
             mean_iat, std_iat, syn_count, fin_count, rst_count, payload_ratio)
        VALUES
            (:ts, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
             :duration, :pkt_count, :byte_count, :mean_pkt_size, :std_pkt_size,
             :mean_iat, :std_iat, :syn_count, :fin_count, :rst_count, :payload_ratio)
    ''', flow_dict)
    flow_id = c.lastrowid
    conn.commit()
    conn.close()
    return flow_id


def insert_anomaly(anomaly_dict: dict) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO anomalies
            (flow_id, ts, anomaly_score, severity, deviating_features,
             explanation, mitigation, src_ip, dst_ip, dst_port, protocol)
        VALUES
            (:flow_id, :ts, :anomaly_score, :severity, :deviating_features,
             :explanation, :mitigation, :src_ip, :dst_ip, :dst_port, :protocol)
    ''', {**anomaly_dict,
          'deviating_features': json.dumps(anomaly_dict['deviating_features'])})
    aid = c.lastrowid
    conn.commit()
    conn.close()
    return aid


def insert_baseline_snapshot(stats: dict):
    conn = get_connection()
    c = conn.cursor()
    c.execute('INSERT INTO baseline_snapshots (ts, stats_json) VALUES (?, ?)',
              (datetime.utcnow().timestamp(), json.dumps(stats)))
    conn.commit()
    conn.close()


# ---------- QUERY helpers ----------

def fetch_recent_anomalies(limit=50) -> list:
    conn = get_connection()
    c = conn.cursor()
    rows = c.execute('''
        SELECT * FROM anomalies ORDER BY ts DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d['deviating_features'] = json.loads(d['deviating_features'])
        result.append(d)
    return result


def fetch_anomaly_trend(hours=1) -> list:
    """Return per-minute anomaly counts for the last N hours."""
    import time
    since = time.time() - hours * 3600
    conn = get_connection()
    c = conn.cursor()
    rows = c.execute('''
        SELECT CAST((ts - ?) / 60 AS INTEGER) AS minute_bucket,
               COUNT(*) as count
        FROM anomalies
        WHERE ts >= ?
        GROUP BY minute_bucket
        ORDER BY minute_bucket
    ''', (since, since)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_severity_distribution() -> dict:
    conn = get_connection()
    c = conn.cursor()
    rows = c.execute('''
        SELECT severity, COUNT(*) as count
        FROM anomalies
        GROUP BY severity
    ''').fetchall()
    conn.close()
    return {r['severity']: r['count'] for r in rows}


def fetch_stats() -> dict:
    conn = get_connection()
    c = conn.cursor()
    total_flows = c.execute('SELECT COUNT(*) FROM flows').fetchone()[0]
    total_anomalies = c.execute('SELECT COUNT(*) FROM anomalies').fetchone()[0]
    conn.close()
    return {'total_flows': total_flows, 'total_anomalies': total_anomalies}


# ================================================================ #
# NEW TABLES — Temporal Baseline + Incidents + Counterfactuals     #
# ================================================================ #

def init_db_v2():
    """Add new tables for the three novel features. Safe to call on existing DB."""
    conn = get_connection()
    c = conn.cursor()

    # Incidents table — correlated anomaly groups
    c.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id         TEXT    NOT NULL UNIQUE,
            src_ip              TEXT    NOT NULL,
            first_ts            REAL    NOT NULL,
            last_ts             REAL    NOT NULL,
            duration_seconds    REAL,
            anomaly_count       INTEGER NOT NULL,
            composite_severity  TEXT    NOT NULL,
            avg_score           REAL,
            top_score           REAL,
            pattern_summary     TEXT,
            dst_ips_json        TEXT,
            is_active           INTEGER DEFAULT 1
        )
    ''')

    # Counterfactuals table — per anomaly
    c.execute('''
        CREATE TABLE IF NOT EXISTS counterfactuals (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id      INTEGER REFERENCES anomalies(id),
            ts              REAL    NOT NULL,
            feature         TEXT    NOT NULL,
            label           TEXT    NOT NULL,
            observed        REAL,
            threshold       REAL,
            direction       TEXT,
            statement       TEXT    NOT NULL
        )
    ''')

    # Temporal segment stats table
    c.execute('''
        CREATE TABLE IF NOT EXISTS temporal_segments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL    NOT NULL,
            segment     TEXT    NOT NULL,
            stats_json  TEXT    NOT NULL
        )
    ''')

    conn.commit()
    conn.close()


def upsert_incident(incident: dict):
    """Insert or update an incident record."""
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO incidents
            (incident_id, src_ip, first_ts, last_ts, duration_seconds,
             anomaly_count, composite_severity, avg_score, top_score,
             pattern_summary, dst_ips_json, is_active)
        VALUES
            (:incident_id, :src_ip, :first_ts, :last_ts, :duration_seconds,
             :anomaly_count, :composite_severity, :avg_score, :top_score,
             :pattern_summary, :dst_ips_json, :is_active)
        ON CONFLICT(incident_id) DO UPDATE SET
            last_ts            = excluded.last_ts,
            duration_seconds   = excluded.duration_seconds,
            anomaly_count      = excluded.anomaly_count,
            composite_severity = excluded.composite_severity,
            avg_score          = excluded.avg_score,
            top_score          = excluded.top_score,
            pattern_summary    = excluded.pattern_summary,
            dst_ips_json       = excluded.dst_ips_json,
            is_active          = excluded.is_active
    ''', {**incident, 'dst_ips_json': json.dumps(incident.get('dst_ips', []))})
    conn.commit()
    conn.close()


def insert_counterfactuals(anomaly_id: int, counterfactuals: list):
    """Store counterfactual records for an anomaly."""
    if not counterfactuals:
        return
    conn = get_connection()
    c = conn.cursor()
    ts = datetime.utcnow().timestamp()
    for cf in counterfactuals:
        c.execute('''
            INSERT INTO counterfactuals
                (anomaly_id, ts, feature, label, observed, threshold, direction, statement)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (anomaly_id, ts, cf['feature'], cf['label'],
              cf['observed'], cf['threshold'], cf['direction'], cf['statement']))
    conn.commit()
    conn.close()


def fetch_incidents(limit=20) -> list:
    conn = get_connection()
    c = conn.cursor()
    rows = c.execute('''
        SELECT * FROM incidents ORDER BY last_ts DESC LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d['dst_ips'] = json.loads(d.get('dst_ips_json', '[]'))
        result.append(d)
    return result


def fetch_counterfactuals_for_anomaly(anomaly_id: int) -> list:
    conn = get_connection()
    c = conn.cursor()
    rows = c.execute('''
        SELECT * FROM counterfactuals WHERE anomaly_id = ? ORDER BY id
    ''', (anomaly_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
