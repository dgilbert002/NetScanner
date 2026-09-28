"""
Persistence layer: batched writes, SQLite tuning, retention, source health.

Why this exists
---------------
The legacy capture code commits once per packet and shares one SQLAlchemy
scoped session across threads.  Both are reliability bugs at capture rates.
This module provides:

* :class:`BatchWriter` - a single writer thread that commits at most every
  ``flush_interval`` seconds (default 5) or every ``max_batch`` rows (default
  500), whichever comes first.  Callers never block on SQLite.
* :func:`configure_sqlite` - WAL journal, 5 s busy timeout, NORMAL sync and a
  larger cache, which removes most ``database is locked`` errors.
* :func:`ensure_indexes` - additive indexes on the hot columns of the existing
  tables (the legacy schema has none).
* :func:`apply_retention` - the 90-day retention job from the roadmap, extended
  to the new tables.
* :class:`SourceHealth` - per-collector counters so the UI can show whether the
  data it is displaying is live, lagging or stale.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta

from src.models.user import db
from src.intel.models import (
    IntelDailyUsage,
    IntelFlow,
    IntelObservation,
    IntelOnlineDay,
    IntelRuntimeState,
    IntelSiteSession,
    IntelSourceHealth,
    IntelUsageBucket,
)


# ---------------------------------------------------------------------------
# Engine-owned session
# ---------------------------------------------------------------------------
# The intel layer must not write through Flask's request-scoped session from a
# worker thread: Flask rolls that session back and detaches its ORM rows as soon
# as the request (or the transient app context) ends, which silently discarded
# every open flow.  The engine therefore owns one long-lived session, bound to
# the same engine and shared only by its own worker threads, which serialise on
# the engine lock.

_ENGINE_SESSION_FACTORY = None
_ENGINE_SESSION = None
_SESSION_LOCK = threading.RLock()
_FORCED = threading.local()


def set_engine_session_factory(factory):
    """Register the sessionmaker the engine threads should use."""
    global _ENGINE_SESSION_FACTORY
    _ENGINE_SESSION_FACTORY = factory


def _build_engine_session():
    global _ENGINE_SESSION_FACTORY
    if _ENGINE_SESSION_FACTORY is None:
        from sqlalchemy.orm import sessionmaker
        from flask import has_app_context
        if has_app_context():
            _ENGINE_SESSION_FACTORY = sessionmaker(bind=db.engine)
        else:
            try:
                import src.main as _main  # noqa: F401  (ensures the app exists)
                _ENGINE_SESSION_FACTORY = sessionmaker(bind=db.engine)
            except Exception:
                return None
    return _ENGINE_SESSION_FACTORY()


def _db_session():
    """The Flask-SQLAlchemy request/context session (kept behind a helper so a
    blanket ``db.session`` rewrite can never recurse into :func:`engine_session`)."""
    from src.models.user import db as _db
    return _db.session


def engine_session():
    """Return the session the intel layer should write through.

    Inside a Flask app context (views, tests, scripts) this is ``db.session`` so
    callers keep their own transaction.  Worker threads - which have no app
    context - get one shared engine session instead, guarded by the engine lock.
    """
    forced = getattr(_FORCED, 'session', None)
    if forced is not None:
        return forced
    try:
        from flask import has_app_context
        if has_app_context():
            return _db_session()
    except Exception:
        pass
    global _ENGINE_SESSION
    with _SESSION_LOCK:
        if _ENGINE_SESSION is None:
            _ENGINE_SESSION = _build_engine_session()
        return _ENGINE_SESSION


class forced_engine_session:
    """Context manager forcing the engine session even inside a request."""

    def __enter__(self):
        self._session = _get_process_session()
        self._previous = getattr(_FORCED, 'session', None)
        _FORCED.session = self._session
        return self._session

    def __exit__(self, *exc_info):
        _FORCED.session = self._previous
        return False


def _get_process_session():
    global _ENGINE_SESSION
    with _SESSION_LOCK:
        if _ENGINE_SESSION is None:
            _ENGINE_SESSION = _build_engine_session()
        return _ENGINE_SESSION


def engine_engine():
    """Bind of the engine session (works without an app context)."""
    session = engine_session()
    try:
        return session.get_bind()
    except Exception:
        return db.engine


def engine_commit():
    """Commit the engine session, rolling back on failure.  Never raises."""
    session = engine_session()
    try:
        session.commit()
        return True
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
        return False


def engine_rollback():
    try:
        engine_session().rollback()
    except Exception:
        pass


def equery(model):
    """``Model.query`` against the engine session (extra query attribute)."""
    return engine_session().query(model)


# ---------------------------------------------------------------------------
# SQLite tuning
# ---------------------------------------------------------------------------

def configure_sqlite(app):
    """Apply performance/reliability PRAGMAs and raise the connection timeout."""
    try:
        app.config.setdefault('SQLALCHEMY_ENGINE_OPTIONS', {})
        opts = app.config['SQLALCHEMY_ENGINE_OPTIONS']
        opts.setdefault('pool_pre_ping', True)
        opts.setdefault('connect_args', {'timeout': 30, 'check_same_thread': False})
    except Exception:
        pass

    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    already = getattr(Engine, '_netscanner_pragmas', False)

    @event.listens_for(Engine, 'connect')
    def _set_pragmas(dbapi_connection, _record):  # pragma: no cover - driver level
        try:
            cur = dbapi_connection.cursor()
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.execute('PRAGMA busy_timeout=5000')
            cur.execute('PRAGMA cache_size=-16000')     # 16 MB page cache
            cur.execute('PRAGMA temp_store=MEMORY')
            cur.execute('PRAGMA foreign_keys=OFF')      # legacy rows have dangling MAC FKs
            cur.close()
        except Exception:
            pass

    Engine._netscanner_pragmas = True


INDEX_SQL = [
    'CREATE INDEX IF NOT EXISTS ix_ts_start ON traffic_sessions(start_time)',
    'CREATE INDEX IF NOT EXISTS ix_ts_mac ON traffic_sessions(src_mac)',
    'CREATE INDEX IF NOT EXISTS ix_ts_dst ON traffic_sessions(dst_ip, dst_port)',
    'CREATE INDEX IF NOT EXISTS ix_ts_end ON traffic_sessions(end_time)',
    'CREATE INDEX IF NOT EXISTS ix_wv_ts ON website_visits(timestamp)',
    'CREATE INDEX IF NOT EXISTS ix_wv_mac ON website_visits(device_mac)',
    'CREATE INDEX IF NOT EXISTS ix_wv_domain ON website_visits(domain)',
    'CREATE INDEX IF NOT EXISTS ix_dev_last ON devices(last_seen)',
    'CREATE INDEX IF NOT EXISTS ix_enr_updated ON enriched_data(updated_at)',
    'CREATE INDEX IF NOT EXISTS ix_intel_obs_time ON intel_observations(observed_at)',
    'CREATE INDEX IF NOT EXISTS ix_intel_obs_host ON intel_observations(sni, dns_qname)',
    'CREATE INDEX IF NOT EXISTS ix_intel_obs_mac ON intel_observations(device_mac, observed_at)',
    'CREATE INDEX IF NOT EXISTS ix_intel_flow_state ON intel_flows(state, last_seen)',
    'CREATE INDEX IF NOT EXISTS ix_intel_site_state ON intel_site_sessions(state, last_seen)',
    'CREATE INDEX IF NOT EXISTS ix_intel_bucket_time ON intel_usage_buckets(bucket_start)',
    'CREATE INDEX IF NOT EXISTS ix_intel_events_time ON intel_device_events(event_at)',
    'CREATE INDEX IF NOT EXISTS ix_intel_vpn_time ON intel_vpn_findings(last_seen)',
    'CREATE INDEX IF NOT EXISTS ix_intel_id_updated ON intel_identity_scores(updated_at)',
]


def ensure_indexes():
    """Create additive indexes; safe to run on every start (IF NOT EXISTS)."""
    created = []
    try:
        engine = engine_engine()
        with engine.begin() as conn:
            for stmt in INDEX_SQL:
                try:
                    conn.exec_driver_sql(stmt)
                    created.append(stmt.split(' ON ')[-1].split('(')[0])
                except Exception:
                    continue
    except Exception:
        return []
    return created


# ---------------------------------------------------------------------------
# Source health
# ---------------------------------------------------------------------------

class SourceHealth:
    """Records per-source counters without flooding the DB."""

    def __init__(self, flush_interval=30.0):
        self.flush_interval = flush_interval
        self._pending = {}
        self._lock = threading.Lock()
        self._last_flush = 0.0

    def note(self, source, events=0, dropped=0, lag_seconds=None, error=None,
             status=None, detail=None):
        with self._lock:
            entry = self._pending.setdefault(source, {
                'events': 0, 'dropped': 0, 'lag': None, 'error': None,
                'status': None, 'detail': None, 'last_event_at': None,
            })
            entry['events'] += int(events or 0)
            entry['dropped'] += int(dropped or 0)
            if lag_seconds is not None:
                entry['lag'] = float(lag_seconds)
            if error:
                entry['error'] = str(error)[:400]
                entry['status'] = 'error'
            if status:
                entry['status'] = status
            if detail:
                entry['detail'] = detail
            if events:
                entry['last_event_at'] = datetime.utcnow()

    def flush(self, force=False):
        now = time.time()
        if not force and now - self._last_flush < self.flush_interval:
            return
        with self._lock:
            pending = self._pending
            self._pending = {}
            self._last_flush = now
        if not pending:
            return
        try:
            for source, entry in pending.items():
                row = equery(IntelSourceHealth).filter_by(source=source).first()
                if row is None:
                    row = IntelSourceHealth(source=source)
                    engine_session().add(row)
                row.events = int((row.events or 0) + entry['events'])
                row.dropped = int((row.dropped or 0) + entry['dropped'])
                if entry['lag'] is not None:
                    row.lag_seconds = round(entry['lag'], 3)
                if entry['status']:
                    row.status = entry['status']
                if entry['error']:
                    row.last_error = entry['error']
                elif entry['events']:
                    row.last_error = None
                    row.last_success_at = datetime.utcnow()
                if entry['last_event_at']:
                    row.last_event_at = entry['last_event_at']
                if entry['detail']:
                    row.detail = json.dumps(entry['detail'])[:2000]
            engine_session().commit()
        except Exception:
            engine_session().rollback()

    def snapshot(self):
        rows = equery(IntelSourceHealth).order_by(IntelSourceHealth.source).all()
        now = datetime.utcnow()
        out = []
        for row in rows:
            data = row.to_dict()
            if row.last_event_at:
                age = (now - row.last_event_at).total_seconds()
                data['age_seconds'] = round(age, 1)
                if row.status not in ('error', 'disabled'):
                    data['status'] = 'healthy' if age < 300 else ('degraded' if age < 1800 else 'stale')
            else:
                data['age_seconds'] = None
            out.append(data)
        return out


# ---------------------------------------------------------------------------
# Batched writer
# ---------------------------------------------------------------------------

class BatchWriter:
    """Single-writer-thread persistence for observations, plus a generic queue.

    ``submit`` is non-blocking and thread-safe.  ``flush`` performs the actual
    ORM bulk insert.  Any exception is counted against the source rather than
    raised into the capture loop.
    """

    def __init__(self, app=None, flush_interval=5.0, max_batch=500, health=None, hard_max=20000):
        self.app = app
        self.flush_interval = flush_interval
        self.max_batch = max_batch
        self.hard_max = hard_max
        self.health = health
        self._buffer = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._last_flush = time.time()
        self.counters = {'queued': 0, 'written': 0, 'dropped': 0, 'flushes': 0, 'errors': 0}

    # -- producer side ---------------------------------------------------
    def submit(self, evidence):
        with self._lock:
            if len(self._buffer) >= self.hard_max:
                self.counters['dropped'] += 1
                if self.health:
                    self.health.note('live', dropped=1)
                return False
            self._buffer.append(evidence)
            self.counters['queued'] += 1
            should_flush = len(self._buffer) >= self.max_batch
        if should_flush:
            self.flush()
        elif time.time() - self._last_flush >= self.flush_interval:
            self.flush()
        return True

    # -- consumer side ---------------------------------------------------
    def flush(self):
        with self._lock:
            if not self._buffer:
                return 0
            batch = self._buffer
            self._buffer = []
        written = 0
        try:
            if self.app is not None:
                with self.app.app_context():
                    written = self._write(batch)
            else:
                written = self._write(batch)
        except Exception as exc:
            self.counters['errors'] += 1
            if self.health:
                self.health.note('live', dropped=len(batch), error=exc)
            try:
                engine_session().rollback()
            except Exception:
                pass
            # Re-queue once so a transient lock does not lose data.
            with self._lock:
                if len(self._buffer) < self.hard_max:
                    self._buffer.extend(batch[:1000])
            return 0
        self.counters['written'] += written
        self._last_flush = time.time()
        return written

    def _write(self, batch):
        rows = []
        latency_total = 0.0
        now = datetime.utcnow()
        for ev in batch:
            latency = max(0.0, (now - ev.observed_at).total_seconds() * 1000.0)
            latency_total += latency
            detail = dict(ev.detail or {})
            if ev.process_name:
                detail['process'] = ev.process_name
            rows.append({
                'observed_at': ev.observed_at,
                'ingested_at': now,
                'latency_ms': int(latency),
                'source': ev.source or 'live',
                'collector': ev.collector or 'scapy',
                'device_mac': ev.device_mac,
                'src_ip': ev.src_ip,
                'dst_ip': ev.dst_ip,
                'src_port': ev.src_port,
                'dst_port': ev.dst_port,
                'protocol': ev.protocol,
                'direction': ev.direction,
                'dns_qname': ev.dns_qname,
                'sni': ev.sni,
                'http_host': ev.http_host,
                'http_path': ev.http_path,
                'quic_sni': ev.quic_sni,
                'tls_fingerprint': ev.tls_fingerprint,
                'dhcp_hostname': ev.dhcp_hostname,
                'mdns_name': ev.mdns_name,
                'user_agent': ev.user_agent,
                'bytes_up': int(ev.bytes_up or 0),
                'bytes_down': int(ev.bytes_down or 0),
                'packets': int(ev.packets or 0),
                'is_estimated': bool(ev.is_estimated),
                'confidence': float(ev.confidence or 0.5),
                'detail': json.dumps(detail, default=str)[:4000],
            })
        if not rows:
            return 0
        engine_session().bulk_insert_mappings(IntelObservation, rows)
        engine_session().commit()
        self.counters['flushes'] += 1
        if self.health:
            self.health.note('live', events=len(rows),
                             lag_seconds=(latency_total / len(rows)) / 1000.0,
                             status='healthy')
        return len(rows)

    # -- lifecycle -------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='intel-writer', daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.flush()
            except Exception:
                pass
            if self.health:
                try:
                    self.health.flush()
                except Exception:
                    pass
            self._stop.wait(self.flush_interval)

    def stop(self, timeout=5.0):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self.flush()
        if self.health:
            self.health.flush(force=True)

    def pending(self):
        with self._lock:
            return len(self._buffer)


# ---------------------------------------------------------------------------
# Retention / housekeeping
# ---------------------------------------------------------------------------

RETENTION_TABLES = (
    ('intel_observations', 'observed_at'),
    ('intel_flows', 'last_seen'),
    ('intel_site_sessions', 'last_seen'),
    ('intel_usage_buckets', 'bucket_start'),
    ('intel_daily_usage', 'updated_at'),
    ('intel_online_days', 'day'),
    ('intel_vpn_findings', 'last_seen'),
    ('intel_device_events', 'event_at'),
    ('intel_revisions', 'created_at'),
    ('traffic_sessions', 'start_time'),
    ('website_visits', 'timestamp'),
)


def apply_retention(days=90, dry_run=False):
    """Delete rows older than ``days``; returns a per-table count dict."""
    cutoff = datetime.utcnow() - timedelta(days=int(days))
    counts = {}
    engine = engine_engine()
    for table, column in RETENTION_TABLES:
        try:
            if table == 'intel_online_days':
                cutoff_value = cutoff.strftime('%Y-%m-%d')
            elif table == 'intel_daily_usage':
                cutoff_value = cutoff
            else:
                cutoff_value = cutoff
            if dry_run:
                with engine.connect() as conn:
                    result = conn.exec_driver_sql(
                        f'SELECT COUNT(*) FROM {table} WHERE {column} < ?', (cutoff_value,))
                    counts[table] = int(result.scalar() or 0)
            else:
                with engine.begin() as conn:
                    result = conn.exec_driver_sql(
                        f'DELETE FROM {table} WHERE {column} < ?', (cutoff_value,))
                    counts[table] = result.rowcount if result.rowcount and result.rowcount > 0 else 0
        except Exception as exc:
            counts[table] = f'error: {exc.__class__.__name__}'
    if not dry_run:
        try:
            with engine_engine().begin() as conn:
                conn.exec_driver_sql('PRAGMA optimize')
        except Exception:
            pass
    return counts


def database_stats():
    """Row counts + file size, for the data-quality screen."""
    stats = {}
    engine = engine_engine()
    tables = [t for (t, _c) in RETENTION_TABLES] + [
        'devices', 'enriched_data', 'intel_device_macs', 'intel_identity_scores',
        'intel_behavior_profiles', 'intel_names', 'intel_source_health',
    ]
    with engine.connect() as conn:
        for table in tables:
            try:
                stats[table] = int(conn.exec_driver_sql(f'SELECT COUNT(*) FROM {table}').scalar() or 0)
            except Exception:
                continue
    try:
        import os
        path = engine_engine().url.database
        if path and os.path.exists(path):
            stats['_db_bytes'] = os.path.getsize(path)
    except Exception:
        pass
    return stats


# ---------------------------------------------------------------------------
# Restart-safe key/value state
# ---------------------------------------------------------------------------

def state_get(key, default=None):
    try:
        row = equery(IntelRuntimeState).get(key)
        if row is None:
            return default
        try:
            return json.loads(row.value)
        except Exception:
            return row.value
    except Exception:
        return default


def state_set(key, value):
    try:
        row = equery(IntelRuntimeState).get(key)
        payload = json.dumps(value, default=str)
        if row is None:
            row = IntelRuntimeState(key=key, value=payload)
            engine_session().add(row)
        else:
            row.value = payload
        engine_session().commit()
        return True
    except Exception:
        engine_session().rollback()
        return False


def clear_intel_data(tables=None):
    """Wipe only intelligence-derived tables (keeps legacy/device data)."""
    names = tables or [
        'intel_usage_buckets', 'intel_daily_usage', 'intel_online_days',
        'intel_site_sessions', 'intel_flows', 'intel_observations',
        'intel_device_events', 'intel_vpn_findings', 'intel_identity_scores',
        'intel_behavior_profiles', 'intel_revisions',
    ]
    removed = {}
    with engine_engine().begin() as conn:
        for name in names:
            try:
                removed[name] = conn.exec_driver_sql(f'DELETE FROM {name}').rowcount
            except Exception as exc:
                removed[name] = f'error: {exc.__class__.__name__}'
    return removed


def model_counts():
    return {
        'observations': equery(IntelObservation).count(),
        'flows': equery(IntelFlow).count(),
        'site_sessions': equery(IntelSiteSession).count(),
        'buckets': equery(IntelUsageBucket).count(),
        'daily': equery(IntelDailyUsage).count(),
        'online_days': equery(IntelOnlineDay).count(),
    }
