"""
capture.py
Live packet capture using Scapy and flow aggregation using 5-tuple logic.

A "flow" is identified by (src_ip, dst_ip, src_port, dst_port, protocol).
Packets are collected into flows; a flow is considered complete when:
  - It receives a FIN or RST flag (TCP), OR
  - No new packets arrive within FLOW_TIMEOUT seconds.

This module runs in a background thread and pushes completed flows
to a queue consumed by the pipeline.
"""

import time
import threading
import queue
import logging
from collections import defaultdict

# Scapy import with graceful fallback for environments without root
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf
    conf.verb = 0  # suppress Scapy output
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Flow timeout in seconds — flows idle longer than this are finalized
FLOW_TIMEOUT = 30

# Maximum packets per flow before forcing finalization (prevents memory bloat)
MAX_FLOW_PACKETS = 500


class PacketCapture:
    """
    Captures live packets on a given interface, aggregates into flows,
    and pushes finalized flow records to an output queue.
    """

    def __init__(self, interface: str = None, output_queue: queue.Queue = None,
                 bpf_filter: str = "ip"):
        self.interface = interface
        self.output_queue = output_queue or queue.Queue()
        self.bpf_filter = bpf_filter

        # Active flows: flow_key -> FlowRecord
        self._flows: dict = {}
        self._lock = threading.Lock()

        self._running = False
        self._capture_thread = None
        self._timeout_thread = None

    # ------------------------------------------------------------------ #
    # Public control methods                                               #
    # ------------------------------------------------------------------ #

    def start(self):
        self._running = True

        # Thread that sweeps for timed-out flows
        self._timeout_thread = threading.Thread(
            target=self._timeout_sweep, daemon=True, name="flow-timeout-sweep")
        self._timeout_thread.start()

        if SCAPY_AVAILABLE:
            self._capture_thread = threading.Thread(
                target=self._capture_loop, daemon=True, name="packet-capture")
            self._capture_thread.start()
            logger.info("Packet capture started on interface: %s", self.interface or "default")
        else:
            # Demo mode: generate synthetic flows so the system is testable
            # without root / Scapy access
            logger.warning("Scapy not available or no root — running in DEMO mode")
            self._capture_thread = threading.Thread(
                target=self._demo_loop, daemon=True, name="demo-flow-gen")
            self._capture_thread.start()

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------ #
    # Internal: Scapy capture                                             #
    # ------------------------------------------------------------------ #

    def _capture_loop(self):
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self._running
        )

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        proto = ip.proto  # 6=TCP, 17=UDP, etc.
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = len(pkt)
        payload_len = len(bytes(ip.payload)) if ip.payload else 0

        src_port, dst_port = 0, 0
        syn, fin, rst = 0, 0, 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = tcp.flags
            syn = 1 if flags & 0x02 else 0
            fin = 1 if flags & 0x01 else 0
            rst = 1 if flags & 0x04 else 0
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        ts = time.time()

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowRecord(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=proto, start_ts=ts)

            flow = self._flows[key]
            flow.add_packet(ts=ts, pkt_len=pkt_len, payload_len=payload_len,
                            syn=syn, fin=fin, rst=rst)

            # Finalize on FIN/RST or packet cap
            if fin or rst or flow.pkt_count >= MAX_FLOW_PACKETS:
                self._finalize(key, flow)

    # ------------------------------------------------------------------ #
    # Internal: timeout sweep                                             #
    # ------------------------------------------------------------------ #

    def _timeout_sweep(self):
        while self._running:
            time.sleep(5)
            now = time.time()
            with self._lock:
                expired = [k for k, f in self._flows.items()
                           if now - f.last_ts > FLOW_TIMEOUT]
                for k in expired:
                    self._finalize(k, self._flows[k])

    def _finalize(self, key, flow: "FlowRecord"):
        """Convert FlowRecord to dict and push to output queue."""
        record = flow.to_dict()
        self.output_queue.put(record)
        del self._flows[key]

    # ------------------------------------------------------------------ #
    # Demo mode: synthetic flows for environments without raw socket      #
    # ------------------------------------------------------------------ #

    def _demo_loop(self):
        """
        Generates realistic-looking benign flows with occasional anomalous spikes
        so developers can run the full pipeline without root/Scapy.
        """
        import random
        import math

        COMMON_PORTS = [80, 443, 53, 22, 8080, 3306, 5432]
        INTERNAL_NETS = ["192.168.1.", "10.0.0.", "172.16.0."]

        flow_id = 0
        while self._running:
            flow_id += 1
            ts = time.time()

            # ~5% chance of anomalous flow
            is_anomaly = random.random() < 0.05

            src_ip = random.choice(INTERNAL_NETS) + str(random.randint(2, 254))
            dst_ip = f"{random.randint(1,223)}.{random.randint(0,255)}." \
                     f"{random.randint(0,255)}.{random.randint(1,254)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(COMMON_PORTS)
            proto = random.choice([6, 17])  # TCP or UDP

            if is_anomaly:
                # Simulate port scan: many packets, tiny size, rapid IAT
                pkt_count = random.randint(200, 500)
                duration = random.uniform(0.01, 0.5)
                byte_count = pkt_count * random.randint(40, 60)
                mean_pkt_size = byte_count / pkt_count
                std_pkt_size = random.uniform(0, 5)
                mean_iat = duration / max(pkt_count - 1, 1)
                std_iat = random.uniform(0, 0.001)
                syn_count = pkt_count
                fin_count = 0
                rst_count = random.randint(50, pkt_count)
                payload_ratio = random.uniform(0.0, 0.05)
            else:
                pkt_count = random.randint(3, 60)
                duration = random.uniform(0.1, 15.0)
                mean_pkt_size = random.gauss(800, 200)
                mean_pkt_size = max(40, mean_pkt_size)
                byte_count = int(pkt_count * mean_pkt_size)
                std_pkt_size = random.uniform(50, 300)
                mean_iat = duration / max(pkt_count - 1, 1)
                std_iat = mean_iat * random.uniform(0.1, 0.5)
                syn_count = 1 if proto == 6 else 0
                fin_count = 1 if proto == 6 else 0
                rst_count = 0
                payload_ratio = random.uniform(0.6, 0.95)

            record = {
                'ts': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': proto,
                'duration': round(duration, 4),
                'pkt_count': pkt_count,
                'byte_count': byte_count,
                'mean_pkt_size': round(mean_pkt_size, 2),
                'std_pkt_size': round(std_pkt_size, 2),
                'mean_iat': round(mean_iat, 6),
                'std_iat': round(std_iat, 6),
                'syn_count': syn_count,
                'fin_count': fin_count,
                'rst_count': rst_count,
                'payload_ratio': round(payload_ratio, 4),
            }
            self.output_queue.put(record)
            # Simulate ~2 flows/second
            time.sleep(random.uniform(0.3, 0.8))


# ------------------------------------------------------------------ #
# FlowRecord: mutable accumulator for a single 5-tuple flow          #
# ------------------------------------------------------------------ #

class FlowRecord:
    """Accumulates packets for a single 5-tuple flow."""

    __slots__ = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'start_ts', 'last_ts', 'pkt_count', 'byte_count',
        'pkt_sizes', 'iats', 'last_pkt_ts',
        'syn_count', 'fin_count', 'rst_count',
        'payload_bytes'
    ]

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, start_ts):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_ts = start_ts
        self.last_ts = start_ts
        self.last_pkt_ts = start_ts
        self.pkt_count = 0
        self.byte_count = 0
        self.pkt_sizes = []
        self.iats = []
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.payload_bytes = 0

    def add_packet(self, ts, pkt_len, payload_len, syn, fin, rst):
        if self.pkt_count > 0:
            self.iats.append(ts - self.last_pkt_ts)
        self.last_pkt_ts = ts
        self.last_ts = ts
        self.pkt_count += 1
        self.byte_count += pkt_len
        self.pkt_sizes.append(pkt_len)
        self.syn_count += syn
        self.fin_count += fin
        self.rst_count += rst
        self.payload_bytes += payload_len

    def to_dict(self) -> dict:
        import numpy as np
        sizes = self.pkt_sizes or [0]
        iats = self.iats or [0]
        duration = self.last_ts - self.start_ts
        return {
            'ts': self.last_ts,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': round(duration, 4),
            'pkt_count': self.pkt_count,
            'byte_count': self.byte_count,
            'mean_pkt_size': round(float(np.mean(sizes)), 2),
            'std_pkt_size': round(float(np.std(sizes)), 2),
            'mean_iat': round(float(np.mean(iats)), 6),
            'std_iat': round(float(np.std(iats)), 6),
            'syn_count': self.syn_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'payload_ratio': round(self.payload_bytes / max(self.byte_count, 1), 4),
        }
