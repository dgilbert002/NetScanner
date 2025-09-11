"""
Backfill Device.vendor using OUI (manuf) for existing devices.

Usage (from repo root):
  venv/Scripts/python scripts/backfill_vendors.py   (Windows)
  python3 scripts/backfill_vendors.py               (Unix)
"""

import os
import sys
from contextlib import suppress

# Ensure project root on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.main import app
from src.models.network import Device, db

try:
    from manuf import manuf as _manuf_mod
except Exception:
    _manuf_mod = None


def normalize_mac(mac: str) -> str:
    return (mac or '').strip().lower()


def lookup_vendor(parser, mac: str) -> str:
    if not parser or not mac:
        return 'Unknown'
    mac = normalize_mac(mac)
    vendor = None
    with suppress(Exception):
        vendor = parser.get_manuf_long(mac)
    if not vendor:
        with suppress(Exception):
            vendor = parser.get_manuf(mac)
    return vendor or 'Unknown'


def main() -> int:
    if _manuf_mod is None:
        print('manuf library not installed. Install with: pip install manuf')
        return 1

    parser = _manuf_mod.MacParser(update=False)
    updated = 0
    total = 0

    with app.app_context():
        devices = Device.query.all()
        total = len(devices)
        for d in devices:
            current = (getattr(d, 'vendor', '') or '').strip()
            mac = getattr(d, 'mac_address', None)
            if not mac:
                continue
            new_vendor = lookup_vendor(parser, mac)
            # Update if empty, 'Unknown', or placeholder like 'Local Device'
            if not current or current.lower() in ('unknown', 'local device') or current.startswith('device-'):
                if new_vendor and new_vendor != current:
                    d.vendor = new_vendor
                    updated += 1
        if updated:
            db.session.commit()

    print(f'Processed {total} devices, updated {updated} vendor names.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


