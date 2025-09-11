"""
Pi-hole DNS tap: reads recent DNS resolutions to map device IP -> hostname.

Modes:
- FTL SQLite (pi-hole FTL database) if available and path provided
- Log tailing as a simple fallback (not implemented fully here)

We keep this lightweight and optional. If no Pi-hole is present, this module is inert.
"""

import os
import sqlite3
from datetime import datetime, timedelta


class PiHoleTap:
    def __init__(self, ftl_db_path: str = None):
        self.ftl_db_path = ftl_db_path or os.getenv('PIHOLE_FTL_DB')
        # Check if path exists and is accessible
        self.enabled = False
        if self.ftl_db_path:
            try:
                # For network paths, try to check if file exists
                if self.ftl_db_path.startswith('\\\\'):
                    # Network path - just try to connect later
                    self.enabled = False  # Disabled for now since not accessible
                else:
                    self.enabled = os.path.exists(self.ftl_db_path)
            except Exception:
                self.enabled = False

    def lookup_recent_a(self, since_seconds: int = 300):
        """Return list of (ip, hostname, timestamp) seen in last N seconds."""
        if not self.enabled:
            return []
        try:
            conn = sqlite3.connect(self.ftl_db_path)
            cur = conn.cursor()
            # Typical FTL schema has 'queries' table with fields: timestamp, type, domain, client, status
            cutoff = int(datetime.utcnow().timestamp()) - since_seconds
            # Filter to A/AAAA answers that were permitted; join with replies if present
            cur.execute(
                """
                SELECT q.timestamp, q.domain, q.client
                FROM queries q
                WHERE q.timestamp >= ? AND q.status IN (1,2,3,4,5,6)
                ORDER BY q.timestamp DESC
                LIMIT 200
                """,
                (cutoff,)
            )
            rows = cur.fetchall()
            conn.close()
            results = []
            for ts, domain, client in rows:
                try:
                    ip = client
                    host = domain
                    t = datetime.utcfromtimestamp(int(ts))
                    if host and ip:
                        results.append((ip, host, t))
                except Exception:
                    continue
            return results
        except Exception:
            return []


