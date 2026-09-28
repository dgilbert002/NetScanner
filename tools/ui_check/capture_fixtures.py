"""Capture real API responses for the UI check.

    python tools/ui_check/capture_fixtures.py [base_url] [out.json]

Run it while the dashboard is serving (the preview script does that), then run
verify.mjs against the same fixtures.
"""

import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:5002'
OUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/vt/fixtures.json'

URLS = [
    '/api/intel/assignment', '/api/intel/people', '/api/intel/status', '/api/intel/quality',
    '/api/intel/live', '/api/intel/devices', '/api/intel/identity', '/api/intel/vpn',
    '/api/intel/apps', '/api/intel/sessions', '/api/intel/events', '/api/intel/alerts',
    '/api/intel/alerts/rules', '/api/intel/searches',
    '/api/intel/people/overview', '/api/intel/categories', '/api/intel/timeline',
    '/api/intel/sites', '/api/intel/sites?day=2026-09-28',
    '/api/intel/daylog?range=week', '/api/intel/daylog?range=week&person=1',
    '/api/intel/heatmap?range=week', '/api/intel/heatmap?range=week&person=1',
    '/api/intel/series?range=week&dimension=category&top=7',
    '/api/intel/series?range=week&dimension=category&top=7&person=1',
    '/api/intel/gantt?date=2026-09-28&by=person',
    '/api/intel/usage?range=week&dimension=app', '/api/intel/usage?range=week&dimension=category',
    '/api/intel/usage?range=week&dimension=game', '/api/intel/usage?range=week&dimension=site',
    '/api/intel/usage?range=week&dimension=device',
    '/api/intel/usage?range=day&dimension=app', '/api/intel/usage?range=day&dimension=site',
    '/api/intel/calendar?dimension=app&key=Roblox&range=month',
    '/api/intel/top?range=week&dimension=app&order=seconds&limit=30',
    '/api/intel/top?range=week&dimension=url&order=seconds&limit=15',
    '/api/intel/top?range=week&dimension=category&order=seconds&limit=15',
    '/api/intel/top?range=week&dimension=site&order=seconds&limit=15',
    '/api/intel/device/de%3Aad%3Abe%3Aef%3Aaa%3A01',
    '/api/intel/device/aa%3Abb%3Acc%3Add%3Aee%3A02',
]

fixtures = {}
for url in URLS:
    try:
        with urllib.request.urlopen(BASE + url, timeout=15) as response:
            fixtures[url] = json.loads(response.read().decode())
    except Exception as exc:                                  # noqa: BLE001
        print('MISS', url, type(exc).__name__)

json.dump(fixtures, open(OUT, 'w'))
print('captured', len(fixtures), 'fixtures ->', OUT)
