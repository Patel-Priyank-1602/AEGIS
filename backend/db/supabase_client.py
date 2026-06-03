"""
AEGIS Supabase Client
Manages the database connection and provides helper methods for common operations.
Falls back to in-memory storage when Supabase is not configured (for local development).
"""

import os
import requests as http_requests
from datetime import datetime, timedelta
from core.config import settings

# ─── Try to connect to Supabase via REST API ────────────────────
_using_memory = False
_supabase_url = ""
_supabase_headers = {}

try:
    if settings.SUPABASE_URL and settings.SUPABASE_KEY:
        # Use the PostgREST API directly — bypasses the gotrue/httpx proxy bug
        _supabase_url = settings.SUPABASE_URL.rstrip("/") + "/rest/v1"
        _supabase_headers = {
            "apikey": settings.SUPABASE_KEY,
            "Authorization": f"Bearer {settings.SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        # Quick connectivity test
        r = http_requests.get(
            _supabase_url + "/users?select=count&limit=0",
            headers=_supabase_headers,
            timeout=5
        )
        if r.status_code in (200, 406):
            # 406 means table might not exist yet but connection works
            print(f"[DB] Connected to Supabase REST API: {settings.SUPABASE_URL[:40]}...")
        elif r.status_code == 404:
            print(f"[DB] Connected to Supabase but tables not created yet. Run schemas.sql first.")
        else:
            raise ConnectionError(f"HTTP {r.status_code}: {r.text[:100]}")
    else:
        _using_memory = True
        print("[DB] No Supabase credentials. Using in-memory storage.")
except Exception as e:
    _using_memory = True
    print(f"[DB] Supabase REST failed: {e}. Using in-memory storage.")


# ─── In-Memory Fallback Store ───────────────────────────────────
class MemoryStore:
    """Simple in-memory database for development/demo purposes."""

    def __init__(self):
        self.users = []
        self.sessions = []
        self.audit_logs = []
        self.recent_events = []
        # Advanced feature tables
        self.action_ledger = []
        self.honeypot_alerts = []
        self.forensics_captures = []
        self.federated_rounds = []

    def insert(self, table: str, data: dict):
        data["id"] = str(len(getattr(self, table, [])) + 1)
        data["created_at"] = data.get("created_at", datetime.utcnow().isoformat())
        getattr(self, table, []).append(data)
        return data

    def select(self, table: str, filters: dict = None, order_by: str = None,
               desc: bool = False, limit: int = None):
        items = list(getattr(self, table, []))

        if filters:
            for key, value in filters.items():
                items = [i for i in items if i.get(key) == value]

        if order_by:
            items.sort(key=lambda x: x.get(order_by, ""), reverse=desc)

        if limit:
            items = items[:limit]

        return items

    def delete(self, table: str, filters: dict):
        store = getattr(self, table, [])
        before = len(store)
        for key, value in filters.items():
            store[:] = [i for i in store if i.get(key) != value]
        return before - len(store)


_memory_store = MemoryStore()


# ─── Unified Database Interface ─────────────────────────────────
class Database:
    """Unified interface that works with both Supabase REST API and in-memory storage."""

    @staticmethod
    def insert(table: str, data: dict) -> dict:
        if _using_memory:
            return _memory_store.insert(table, data)
        try:
            r = http_requests.post(
                f"{_supabase_url}/{table}",
                headers=_supabase_headers,
                json=data,
                timeout=5
            )
            if r.status_code in (200, 201):
                result = r.json()
                return result[0] if isinstance(result, list) and result else data
            else:
                print(f"[DB] Insert error ({table}): {r.status_code} {r.text[:100]}")
                return data
        except Exception as e:
            print(f"[DB] Insert failed: {e}")
            return data

    @staticmethod
    def select(table: str, filters: dict = None, order_by: str = None,
               desc: bool = False, limit: int = None) -> list:
        if _using_memory:
            return _memory_store.select(table, filters, order_by, desc, limit)
        try:
            params = {"select": "*"}
            if filters:
                for key, value in filters.items():
                    params[key] = f"eq.{value}"
            if order_by:
                direction = "desc" if desc else "asc"
                params["order"] = f"{order_by}.{direction}"
            if limit:
                params["limit"] = str(limit)

            r = http_requests.get(
                f"{_supabase_url}/{table}",
                headers=_supabase_headers,
                params=params,
                timeout=5
            )
            if r.status_code == 200:
                return r.json()
            else:
                print(f"[DB] Select error ({table}): {r.status_code} {r.text[:100]}")
                return []
        except Exception as e:
            print(f"[DB] Select failed: {e}")
            return []

    @staticmethod
    def delete(table: str, filters: dict) -> int:
        if _using_memory:
            return _memory_store.delete(table, filters)
        try:
            params = {}
            for key, value in filters.items():
                params[key] = f"eq.{value}"

            r = http_requests.delete(
                f"{_supabase_url}/{table}",
                headers=_supabase_headers,
                params=params,
                timeout=5
            )
            if r.status_code in (200, 204):
                result = r.json() if r.text else []
                return len(result) if isinstance(result, list) else 0
            else:
                print(f"[DB] Delete error ({table}): {r.status_code}")
                return 0
        except Exception as e:
            print(f"[DB] Delete failed: {e}")
            return 0


# Export the unified database interface
db = Database()
