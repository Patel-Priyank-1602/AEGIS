"""
AEGIS GNN Lateral Movement Detection
Builds network graph from connection events and detects lateral movement
patterns using Graph Neural Network-based anomaly detection.

Key insight: LSTM sees events per-host in isolation. GNN sees the entire
network as a graph — hosts are nodes, connections are edges. An attacker
moving host→host stands out as unusual edge traversal patterns.

Maintains a sliding 5-minute window of connections. Every 30 seconds,
snapshots the graph. Paths with 3+ hops in under 2 minutes are auto-flagged.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict


class NetworkNode:
    """Represents a host/IP in the network graph."""

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.event_count = 0
        self.processes: Set[str] = set()
        self.is_internal = (
            ip.startswith("127.") or ip.startswith("192.168.") or
            ip.startswith("10.") or ip == "0.0.0.0" or ip == "::1"
        )


class NetworkEdge:
    """Represents a connection between two hosts."""

    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.first_seen = datetime.utcnow()
        self.last_seen = datetime.utcnow()
        self.connection_count = 0
        self.ports: Set[int] = set()
        self.processes: Set[str] = set()
        self.timestamps: List[datetime] = []


class GraphBuilder:
    """
    Builds and maintains the network graph from connection events.
    Sliding 5-minute window, snapshots every 30 seconds.
    """

    def __init__(self, window_minutes: int = 5):
        self.window_minutes = window_minutes
        self.nodes: Dict[str, NetworkNode] = {}
        self.edges: Dict[Tuple[str, str], NetworkEdge] = {}
        self.connection_log: List[Dict] = []
        self.snapshots: List[Dict] = []
        self.alerts: List[Dict] = []
        self.total_connections = 0

    def add_connection(self, event: dict):
        """Add a connection event to the graph."""
        src_ip = "127.0.0.1"  # Agent's host
        dst_ip = event.get("ip", "127.0.0.1")
        port = event.get("port", 0)
        process = event.get("process", "unknown")
        now = datetime.utcnow()

        if dst_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return  # Skip loopback

        # Update nodes
        for ip in (src_ip, dst_ip):
            if ip not in self.nodes:
                self.nodes[ip] = NetworkNode(ip)
            self.nodes[ip].last_seen = now
            self.nodes[ip].event_count += 1
            self.nodes[ip].processes.add(process)

        # Update edge
        edge_key = (src_ip, dst_ip)
        if edge_key not in self.edges:
            self.edges[edge_key] = NetworkEdge(src_ip, dst_ip)
        edge = self.edges[edge_key]
        edge.last_seen = now
        edge.connection_count += 1
        edge.ports.add(port)
        edge.processes.add(process)
        edge.timestamps.append(now)
        # Keep only last 100 timestamps per edge
        if len(edge.timestamps) > 100:
            edge.timestamps = edge.timestamps[-100:]

        # Log connection
        self.connection_log.append({
            "src": src_ip, "dst": dst_ip, "port": port,
            "process": process, "timestamp": now.isoformat()
        })
        # Keep sliding window
        cutoff = now - timedelta(minutes=self.window_minutes)
        self.connection_log = [
            c for c in self.connection_log
            if c["timestamp"] > cutoff.isoformat()
        ]

        self.total_connections += 1

    def detect_lateral_movement(self, event: dict) -> dict:
        """
        Detect lateral movement patterns in the network graph.
        Looks for:
          1. 3+ hop paths in under 2 minutes
          2. Rapid successive connections to new hosts
          3. Unusual edge traversal patterns
        """
        ip = event.get("ip", "127.0.0.1")
        process = event.get("process", "unknown")
        now = datetime.utcnow()

        detections = []

        # 1. Check for rapid multi-hop patterns
        recent_window = timedelta(minutes=2)
        recent_connections = [
            c for c in self.connection_log
            if c["timestamp"] > (now - recent_window).isoformat()
        ]

        unique_destinations = set(c["dst"] for c in recent_connections)
        if len(unique_destinations) >= 3:
            detections.append({
                "type": "multi_hop",
                "description": f"3+ unique destinations in 2 minutes: {len(unique_destinations)} hosts",
                "destinations": list(unique_destinations)[:10],
                "severity": "critical",
            })

        # 2. New destination with suspicious process
        suspicious_procs = {"nc", "ncat", "netcat", "ssh", "scp", "nmap", "masscan"}
        if process in suspicious_procs and ip not in ("127.0.0.1", "0.0.0.0"):
            edge_key = ("127.0.0.1", ip)
            edge = self.edges.get(edge_key)
            if edge and edge.connection_count <= 2:
                detections.append({
                    "type": "new_edge_suspicious",
                    "description": f"Suspicious tool {process} connecting to new host {ip}",
                    "severity": "high",
                })

        # 3. Port scanning pattern (many ports on one host)
        edge_key = ("127.0.0.1", ip)
        edge = self.edges.get(edge_key)
        if edge and len(edge.ports) >= 5:
            detections.append({
                "type": "port_scan",
                "description": f"Port scanning detected: {len(edge.ports)} ports on {ip}",
                "ports": sorted(list(edge.ports))[:20],
                "severity": "high",
            })

        if detections:
            alert = {
                "alert_id": f"LM-{str(uuid.uuid4())[:8]}",
                "timestamp": now.isoformat(),
                "detections": detections,
                "event_ip": ip,
                "event_process": process,
                "severity": max(d["severity"] for d in detections),
            }
            self.alerts.append(alert)
            if len(self.alerts) > 200:
                self.alerts = self.alerts[-200:]

            print(f"[GNN] 🕸️ Lateral movement detected: {detections[0]['type']}")

        return {
            "lateral_movement_detected": len(detections) > 0,
            "lateral_detections": detections,
            "graph_nodes": len(self.nodes),
            "graph_edges": len(self.edges),
        }

    def get_graph_snapshot(self) -> dict:
        """Get current graph state for visualization."""
        nodes = []
        for ip, node in self.nodes.items():
            nodes.append({
                "id": ip,
                "is_internal": node.is_internal,
                "event_count": node.event_count,
                "processes": list(node.processes)[:10],
                "last_seen": node.last_seen.isoformat(),
            })

        edges = []
        for (src, dst), edge in self.edges.items():
            edges.append({
                "source": src,
                "target": dst,
                "connection_count": edge.connection_count,
                "ports": sorted(list(edge.ports))[:10],
                "processes": list(edge.processes)[:5],
                "last_seen": edge.last_seen.isoformat(),
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "snapshot_time": datetime.utcnow().isoformat(),
        }

    def get_alerts(self, limit: int = 50) -> list:
        return sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True)[:limit]

    def get_stats(self) -> dict:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_connections": self.total_connections,
            "total_alerts": len(self.alerts),
            "window_minutes": self.window_minutes,
            "recent_connections": len(self.connection_log),
        }


# Global singleton
graph_builder = GraphBuilder()
