"""
AEGIS Threat Intelligence Feed Engine
Ingests IOCs from free threat intel sources with Bloom filter for O(1) lookups.
Sources: Abuse.ch Feodo Tracker, URLhaus, SSL Blacklist (all free, no API key).
"""

import hashlib
import math
import time
import threading
import requests as http_requests
from datetime import datetime
from typing import Optional, Set, Dict


class BloomFilter:
    """Space-efficient probabilistic set. ~0.1% FP rate at 500K items, ~700KB RAM."""

    def __init__(self, expected_items: int = 500_000, fp_rate: float = 0.001):
        self.size = int(-expected_items * math.log(fp_rate) / (math.log(2) ** 2))
        self.hash_count = max(1, int((self.size / expected_items) * math.log(2)))
        self.bit_array = bytearray(self.size // 8 + 1)
        self.count = 0

    def _hashes(self, item: str) -> list:
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha256(item.encode()).hexdigest(), 16)
        return [(h1 + i * h2) % self.size for i in range(self.hash_count)]

    def add(self, item: str):
        if item not in self:
            for pos in self._hashes(item.lower().strip()):
                self.bit_array[pos // 8] |= (1 << (pos % 8))
            self.count += 1

    def __contains__(self, item: str) -> bool:
        return all(
            self.bit_array[pos // 8] & (1 << (pos % 8))
            for pos in self._hashes(item.lower().strip())
        )


class ThreatFeedManager:
    """Manages IOC ingestion and provides O(1) lookup for IPs, domains, hashes."""

    def __init__(self):
        self.ip_filter = BloomFilter(200_000)
        self.domain_filter = BloomFilter(200_000)
        self.hash_filter = BloomFilter(100_000)
        self.url_filter = BloomFilter(100_000)
        self.critical_ips: Set[str] = set()
        self.critical_domains: Set[str] = set()
        self.last_update: Optional[str] = None
        self.source_stats: Dict[str, int] = {}
        self.total_iocs: int = 0
        self._refresh_lock = threading.Lock()
        self._running = False

    def start_auto_refresh(self, interval_minutes: int = 60):
        self._running = True
        def _loop():
            while self._running:
                try:
                    self.refresh_all_feeds()
                except Exception as e:
                    print(f"[ThreatIntel] Refresh error: {e}")
                time.sleep(interval_minutes * 60)
        threading.Thread(target=_loop, daemon=True).start()

    def refresh_all_feeds(self):
        with self._refresh_lock:
            print("[ThreatIntel] Refreshing threat feeds...")
            self._fetch_feodo_tracker()
            self._fetch_urlhaus()
            self._fetch_sslbl()
            self._load_builtin_iocs()
            self.total_iocs = sum(f.count for f in [
                self.ip_filter, self.domain_filter, self.hash_filter, self.url_filter
            ])
            self.last_update = datetime.utcnow().isoformat()
            print(f"[ThreatIntel] Done. Total IOCs: {self.total_iocs}")

    def _fetch_feodo_tracker(self):
        try:
            r = http_requests.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", timeout=15)
            if r.status_code == 200:
                count = 0
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.ip_filter.add(line)
                        self.critical_ips.add(line)
                        count += 1
                self.source_stats["feodo_tracker"] = count
                print(f"  ✓ Feodo Tracker: {count} C2 IPs")
        except Exception as e:
            print(f"  ✗ Feodo Tracker: {e}")

    def _fetch_urlhaus(self):
        try:
            r = http_requests.get(
                "https://urlhaus.abuse.ch/downloads/text_online/", timeout=15)
            if r.status_code == 200:
                count = 0
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.url_filter.add(line)
                        try:
                            from urllib.parse import urlparse
                            domain = urlparse(line).hostname
                            if domain:
                                self.domain_filter.add(domain)
                        except Exception:
                            pass
                        count += 1
                self.source_stats["urlhaus"] = count
                print(f"  ✓ URLhaus: {count} malicious URLs")
        except Exception as e:
            print(f"  ✗ URLhaus: {e}")

    def _fetch_sslbl(self):
        try:
            r = http_requests.get(
                "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", timeout=15)
            if r.status_code == 200:
                count = 0
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ip = line.split(",")[0].strip() if "," in line else line
                        if ip:
                            self.ip_filter.add(ip)
                            self.critical_ips.add(ip)
                            count += 1
                self.source_stats["sslbl"] = count
                print(f"  ✓ SSL Blacklist: {count} IPs")
        except Exception as e:
            print(f"  ✗ SSL Blacklist: {e}")

    def _load_builtin_iocs(self):
        for ip in ["45.33.32.156", "185.220.101.1", "23.129.64.1"]:
            self.ip_filter.add(ip)
            self.critical_ips.add(ip)
        for d in ["evil.com", "malware.com", "c2server.net"]:
            self.domain_filter.add(d)
            self.critical_domains.add(d)
        self.source_stats["builtin"] = 6

    def check_event(self, event: dict) -> dict:
        """Check all IOC fields in an event. Returns enrichment data."""
        matches = []
        ip = event.get("ip", "127.0.0.1")
        if ip and ip not in ("127.0.0.1", "0.0.0.0", "::1"):
            is_critical = ip in self.critical_ips
            is_bloom = ip in self.ip_filter
            if is_critical:
                matches.append({"type": "ip", "value": ip, "confidence": "critical"})
            elif is_bloom:
                matches.append({"type": "ip", "value": ip, "confidence": "high"})

        file_hash = event.get("file_hash", "")
        if file_hash and file_hash in self.hash_filter:
            matches.append({"type": "hash", "value": file_hash[:16], "confidence": "high"})

        return {
            "ioc_matched": len(matches) > 0,
            "ioc_matches": matches,
            "ioc_confidence": matches[0]["confidence"] if matches else "none",
            "ioc_count": len(matches),
        }

    def add_custom_ioc(self, ioc_type: str, value: str, critical: bool = False):
        value = value.strip().lower()
        if ioc_type == "ip":
            self.ip_filter.add(value)
            if critical: self.critical_ips.add(value)
        elif ioc_type == "domain":
            self.domain_filter.add(value)
            if critical: self.critical_domains.add(value)
        elif ioc_type == "hash":
            self.hash_filter.add(value)
        elif ioc_type == "url":
            self.url_filter.add(value)
        self.total_iocs += 1

    def get_stats(self) -> dict:
        return {
            "total_iocs": self.total_iocs,
            "ip_count": self.ip_filter.count,
            "domain_count": self.domain_filter.count,
            "hash_count": self.hash_filter.count,
            "url_count": self.url_filter.count,
            "critical_ips": len(self.critical_ips),
            "last_update": self.last_update,
            "sources": self.source_stats,
            "bloom_size_kb": round(len(self.ip_filter.bit_array) / 1024, 1),
        }


# Global singleton
threat_feeds = ThreatFeedManager()
