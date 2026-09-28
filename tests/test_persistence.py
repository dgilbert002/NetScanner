"""Regression tests for the persistence bugs found while wiring the engine.

Flask-SQLAlchemy scopes its session to the app context and rolls it back at
teardown.  The engine writes from worker threads that have no app context, and
the API accepts evidence from a request - both used to lose their rows.
"""

import threading
from datetime import datetime, timedelta

import pytest

from src.intel.flow import Evidence
from src.intel.models import (
    IntelDailyUsage,
    IntelFlow,
    IntelObservation,
    IntelOnlineDay,
    IntelSiteSession,
    IntelUsageBucket,
)
from src.intel.store import engine_session, forced_engine_session


def ev(ts, mac='aa:bb:cc:00:00:42', dst_ip='142.250.0.1', dst_port=443, host='discord.com',
       src_port=40000, bytes_down=1000):
    return Evidence(observed_at=ts, source='live', collector='test', device_mac=mac,
                    src_ip='192.168.1.42', dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                    protocol='TCP', sni=host, bytes_down=bytes_down, packets=10, confidence=0.9)


def _engine():
    from src.intel.engine import get_engine
    return get_engine()


def _flush_engine():
    """Flush exactly the way a worker thread does: forced engine session."""
    engine = _engine()
    with forced_engine_session():
        engine.sessionizer.sweep()
        engine.sessionizer.flush()
        engine_session().commit()
    return engine


def test_worker_thread_can_persist_flows(ctx):
    """The engine loop has no app context; its writes must still land."""
    base = datetime.utcnow() - timedelta(minutes=3)
    results = {}

    def worker():
        try:
            for step in range(6):
                _engine().process_evidence(ev(base + timedelta(seconds=30 * step), src_port=41111))
            _flush_engine()
            results['ok'] = True
        except Exception as exc:                                  # pragma: no cover
            results['error'] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=30)
    assert results.get('ok'), results

    engine_session().expire_all()
    flow = IntelFlow.query.filter_by(src_port=41111).first()
    assert flow is not None, 'flow written from a worker thread was not persisted'
    assert flow.state in ('live', 'idle')
    assert flow.duration_seconds == 150
    sites = IntelSiteSession.query.filter_by(device_mac='aa:bb:cc:00:00:42').all()
    assert sites
    buckets = IntelUsageBucket.query.filter_by(device_mac='aa:bb:cc:00:00:42').all()
    assert sum(b.online_seconds or 0 for b in buckets) == 150


def test_observe_api_persists_and_is_visible_immediately(client, app):
    """/api/intel/observe hands the batch to the engine and commits it."""
    now = datetime.utcnow()
    records = [{
        'source': 'live', 'device_mac': 'aa:bb:cc:00:00:43', 'src_ip': '192.168.1.43',
        'dst_ip': '162.159.130.1', 'dst_port': 443, 'src_port': 42222, 'protocol': 'TCP',
        'sni': 'discord.com', 'observed_at': (now - timedelta(seconds=30 * (5 - i))).isoformat(),
        'bytes_down': 2048, 'packets': 8,
    } for i in range(6)]
    resp = client.post('/api/intel/observe', json=records)
    assert resp.status_code == 200
    assert resp.get_json()['accepted'] == 6

    live = client.get('/api/intel/live').get_json()
    assert live['count'] >= 1
    entry = [s for s in live['sessions'] if s['device_mac'] == 'aa:bb:cc:00:00:43'][0]
    assert entry['app'] == 'Discord'
    assert entry['site'] == 'discord.com'
    assert entry['freshness']['state'] == 'live'
    assert entry['duration_human'] == '2m 30s'

    apps = client.get('/api/intel/apps?hours=1').get_json()
    assert any(i['key'] == 'Discord' for i in apps['items'])

    quality = client.get('/api/intel/quality').get_json()
    assert quality['observations']['1h']['count'] >= 6      # writer flushed, not lost


def test_observations_and_online_day_survive_flush(ctx):
    base = datetime.utcnow() - timedelta(minutes=2)
    engine = _engine()
    for step in range(5):
        engine.process_evidence(ev(base + timedelta(seconds=30 * step), mac='aa:bb:cc:00:00:44',
                                   src_port=43333, host='discord.com'))
    _flush_engine()
    engine_session().expire_all()
    day = IntelOnlineDay.query.filter_by(device_mac='aa:bb:cc:00:00:44').first()
    assert day is not None
    assert day.online_seconds == 120


def test_daily_rollup_counts_sessions(ctx):
    base = datetime.utcnow() - timedelta(minutes=1)
    engine = _engine()
    engine.process_evidence(ev(base, mac='aa:bb:cc:00:00:45', src_port=44444, host='discord.com'))
    engine.process_evidence(ev(base + timedelta(seconds=30), mac='aa:bb:cc:00:00:45',
                               src_port=44444, host='discord.com'))
    _flush_engine()
    engine_session().expire_all()
    rows = IntelDailyUsage.query.filter_by(dimension='app', key='Discord',
                                           device_mac='aa:bb:cc:00:00:45').all()
    assert rows
    assert sum(r.sessions or 0 for r in rows) >= 1
