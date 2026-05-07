# NetWatch — Explainable Network Anomaly Detection System

> **IEEE-level project**: "Beyond Black-Box Detection: An Explainable Unsupervised Framework for Network Anomaly Analysis"

---

## Architecture Overview

```
Live Packet Capture (Scapy)
        |
        v
  Flow Aggregation (5-tuple, timeout/FIN/RST)
        |
        v
  Feature Extraction (11 statistical features)
        |
        v
  [Warm-up Buffer: first N flows = benign baseline]
        |
        v
  Isolation Forest Scoring  ←──────────────────────────┐
        |                                               |
        v                                         Online adaptation:
  Baseline Comparison (z-scores vs explicit stats)  benign flows
        |                                         fed back into buffer
        v
  Explainable Reasoning (pattern-based behavioral templates)
        |
        v
  Severity Assignment + Mitigation Suggestion
        |
        v
  SQLite Storage  ──→  Flask REST API  ──→  Frontend Dashboard
                                              (SSE live feed)
```

---

## How This Overcomes the Base Paper's Limitations

| Limitation | Base Paper | NetWatch Solution |
|---|---|---|
| 1. Model-centric explanations | SHAP / Normalizing Flow internals | Pure statistical baseline deviation; model internals never exposed |
| 2. Heavy deep learning | Normalizing Flows | Isolation Forest only — no neural networks |
| 3. No behavioral baseline | Implicit in model weights | Explicit `{mean, std, p25, p50, p75, p95}` per feature, stored and queryable |
| 4. Limited operational interpretability | Probability density outputs | Severity levels + plain-English explanations + specific recommended actions |
| 5. Explanations coupled to model | Model requires retraining to change explanations | Explainer module is fully decoupled — swap models without changing explanations |

---

## Folder Structure

```
netwatch/
├── app.py                          # Flask entry point
├── requirements.txt
├── README.md
├── data/                           # SQLite database (auto-created)
├── backend/
│   ├── pipeline.py                 # Orchestrates full pipeline
│   ├── capture/
│   │   └── capture.py              # Scapy capture + flow aggregation
│   ├── ml/
│   │   └── detector.py             # Isolation Forest + baseline statistics
│   ├── explainer/
│   │   └── explainer.py            # Behavioral explanation engine
│   ├── api/
│   │   └── api.py                  # Flask REST API + SSE
│   └── db/
│       └── database.py             # SQLite schema + helpers
└── frontend/
    ├── templates/
    │   └── index.html              # Dashboard HTML
    └── static/
        ├── css/dashboard.css
        └── js/dashboard.js
```

---

## Setup Instructions

### 1. Prerequisites

- Python 3.10+
- Linux or macOS (raw socket capture requires root on Linux)
- `libpcap` installed (`sudo apt install libpcap-dev` on Debian/Ubuntu)

### 2. Install dependencies

```bash
cd netwatch
pip install flask flask-cors scapy scikit-learn numpy pandas scipy
```

### 3. Run in DEMO mode (no root required)

Demo mode generates synthetic traffic so you can test the full pipeline without a network interface:

```bash
python app.py --demo
```

Open http://localhost:5000 in your browser.

The system will collect 100 synthetic flows as warm-up, train the model, then begin detecting and explaining anomalies in real time.

### 4. Run with live packet capture (root required)

```bash
sudo python app.py --interface eth0
```

Replace `eth0` with your actual network interface (`ip link` to list interfaces).

Additional options:
```bash
sudo python app.py --interface wlan0 --warmup 200 --port 8080
```

| Flag | Default | Description |
|---|---|---|
| `--interface` | system default | Network interface for capture |
| `--warmup` | 100 | Flows to collect before training |
| `--port` | 5000 | Flask port |
| `--demo` | off | Use synthetic traffic generator |

---

## API Reference

| Method | Route | Description |
|---|---|---|
| GET | `/api/status` | Pipeline health, warm-up progress |
| GET | `/api/anomalies?limit=50` | Recent anomaly records |
| GET | `/api/anomalies/trend?hours=1` | Per-minute anomaly counts |
| GET | `/api/severity` | Severity distribution |
| GET | `/api/baseline` | Feature baseline statistics |
| GET | `/api/stats` | Aggregate counts |
| GET | `/api/stream` | SSE live anomaly stream |

---

## Features Extracted per Flow

| Feature | Description |
|---|---|
| `duration` | Flow lifetime in seconds |
| `pkt_count` | Total packets |
| `byte_count` | Total bytes |
| `mean_pkt_size` | Mean packet size |
| `std_pkt_size` | Packet size variance |
| `mean_iat` | Mean inter-arrival time |
| `std_iat` | IAT variance |
| `syn_count` | SYN flag count (TCP) |
| `fin_count` | FIN flag count (TCP) |
| `rst_count` | RST flag count (TCP) |
| `payload_ratio` | Payload bytes / total bytes |

---

## Example Anomaly Output

```json
{
  "anomaly_score": 0.847,
  "severity": "CRITICAL",
  "explanation": "The flow contains 312 SYN packets (8.4× baseline standard deviation) and 287 RST packets, a pattern consistent with port scanning or connection probing. Average packet size (44 bytes) is 0.05× the baseline mean, suggesting minimal-payload or header-only traffic.",
  "mitigation": "Inspect firewall logs for rapid sequential connection attempts from 192.168.1.42. Consider rate-limiting SYN packets at the perimeter. Verify whether the source host is authorized to initiate broad connections.",
  "deviating_features": [
    {
      "feature": "syn_count",
      "label": "SYN packet count",
      "value": 312,
      "baseline_mean": 1.2,
      "z_score": 8.4,
      "ratio": 260.0
    }
  ]
}
```

---

## Design Principles

- **No deep learning** — Isolation Forest is the only model.
- **No LLMs** — Explanations are rule-based behavioral pattern matching.
- **No microservices** — Single Python process, single SQLite file.
- **Explanations are model-agnostic** — The `explainer.py` module reads only z-scores and flow values; it has no dependency on the model.
- **Online adaptation** — Confirmed-benign flows are continuously fed back into the training buffer, enabling the model to adapt to shifting baselines over time.
