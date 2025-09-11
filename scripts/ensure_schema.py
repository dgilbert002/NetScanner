"""
Ensure SQLite schema matches SQLAlchemy models (additive & safe).

Usage (from repo root):
  venv/Scripts/python -m src.scripts.ensure_schema  (Windows)
or
  python3 -m src.scripts.ensure_schema               (Unix)
"""

import os
import sys
from contextlib import suppress

# Ensure project root is on sys.path so `import src.*` works when running as a script
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.main import app, db  # imports app and binds db
from src.models.settings import AppSettings
from src.models.hostnames import HnCategory, HnApp, HnRule, bootstrap_defaults
from src.models.network import Device, TrafficSession, EnrichedData, WebsiteVisit, NetworkStats


def main() -> int:
    print('🔧 Ensuring schema is up-to-date...')
    with app.app_context():
        # Create all missing tables/columns (no-op if present)
        db.create_all()
        # Bootstrap defaults
        AppSettings.get_or_create_defaults()
        with suppress(Exception):
            bootstrap_defaults()
    print('✅ Schema ensured.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


