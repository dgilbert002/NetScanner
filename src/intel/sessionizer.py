"""
Idle-aware sessionizer with accurate time accounting.

Three numbers matter and they are all different:

``attributed``   seconds per app / per site.  Computed as the **union** of that
                 app's (or site's) activity intervals, so five parallel YouTube
                 sockets count once, and Netflix + YouTube each get their own
                 (overlapping) time.  This is the number parents want.
``online``       seconds a device was online, computed as the union of *all* of
                 that device's activity intervals, so simultaneous apps never
                 double count.
``session``      duration of one flow / site visit: first to last packet with
                 gaps longer than the idle window removed.

Rules
-----
* A gap longer than ``idle_seconds`` (default 90, configurable in Settings)
  closes the session - state ``closed``, reason ``idle_timeout``.
* ``last_seen`` is always the last-activity marker.  ``end_time`` is never
  overloaded the way the legacy capture code does.
* Buckets are accrued incrementally from *newly covered* interval pieces, so a
  restart, a replayed batch or a late-arriving packet can never double count.
* Device-level intervals are persisted to ``intel_runtime_state`` so the union
  maths survives a restart.
* Every derived row records the evidence source and whether its numbers are
  estimated (connection-table fallback) or observed (packet capture).
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta

from sqlalchemy.orm import object_session

from src.models.user import db
from src.intel.catalog import DEFAULT_CATALOG, root_domain
from src.intel.models import (
    IntelDailyUsage,
    IntelFlow,
    IntelOnlineDay,
    IntelSiteSession,
    IntelUsageBucket,
)
from src.intel import store as intel_store

BUCKET_SECONDS = 300
SERVER_PORTS = {80, 443, 8080, 8443, 53, 123, 25, 110, 143, 465, 587, 993, 995,
                22, 21, 20, 3478, 3479, 5222, 5223, 5353, 1900, 853, 500, 4500,
                1194, 51820, 51821, 1701, 1723, 1935, 554, 3389, 5900, 8000,
                8883, 5060, 5061, 19302, 19305, 19307, 19308}


def server_port(src_port, dst_port):
    """Pick the port that identifies the service (not the ephemeral client port)."""
    if dst_port in SERVER_PORTS:
        return dst_port
    if src_port in SERVER_PORTS:
        return src_port
    if src_port and dst_port:
        return min(src_port, dst_port)
    return dst_port or src_port


def bucket_start_for(ts, bucket_seconds=BUCKET_SECONDS):
    epoch = datetime(1970, 1, 1)
    seconds = int((ts - epoch).total_seconds())
    return epoch + timedelta(seconds=(seconds // bucket_seconds) * bucket_seconds)


def split_interval(start, end, bucket_seconds=BUCKET_SECONDS):
    """Yield ``(bucket_start, seconds)`` pieces for the half-open interval."""
    if end <= start:
        return
    cursor = start
    guard = 0
    while cursor < end and guard < 5000:
        guard += 1
        bstart = bucket_start_for(cursor, bucket_seconds)
        bend = bstart + timedelta(seconds=bucket_seconds)
        chunk_end = min(end, bend)
        yield bstart, (chunk_end - cursor).total_seconds()
        cursor = chunk_end


def merge_interval(intervals, start, end, max_len=4000):
    """Union-add ``[start, end]``. Returns ``(intervals, fresh_pieces)``.

    ``fresh_pieces`` are the parts of ``[start, end]`` not covered before, which
    is exactly what may be accrued without double counting.
    """
    if end <= start:
        return intervals, []
    new_start, new_end = start, end
    covered = []
    remaining = []
    for (a, b) in intervals:
        if b < new_start or a > new_end:
            remaining.append((a, b))
            continue
        if a < new_start:
            new_start = a
        if b > new_end:
            new_end = b
        covered.append((max(a, new_start), min(b, new_end)))
    covered.sort()
    fresh = []
    cursor = start
    for (lo, hi) in covered:
        if lo > cursor:
            fresh.append((cursor, min(lo, end)))
        cursor = max(cursor, hi)
        if cursor >= end:
            break
    if end > cursor:
        fresh.append((cursor, end))
    remaining.append((new_start, new_end))
    remaining.sort()
    if len(remaining) > max_len:
        remaining = remaining[-max_len:]
    return remaining, [(a, b) for (a, b) in fresh if b > a]


def merged_seconds(intervals, since=None):
    total = 0.0
    for (a, b) in intervals:
        if since and b <= since:
            continue
        lo = max(a, since) if since else a
        total += max(0.0, (b - lo).total_seconds())
    return total


class Sessionizer:
    """Builds flows, site visits and usage buckets from evidence rows."""

    def __init__(self, app=None, idle_seconds=90, health=None, mirror_legacy=True,
                 max_intervals=4000, estimated_gap_seconds=900):
        self.app = app
        self.idle_seconds = int(idle_seconds or 90)
        # A connection-table sample every N seconds proves the socket existed in
        # between.  Cap how far that logic may stretch so a stale ESTABLISHED row
        # cannot invent hours of usage.
        self.estimated_gap_seconds = int(estimated_gap_seconds or 900)
        self.health = health
        self.mirror_legacy = mirror_legacy
        self.max_intervals = max_intervals
        self._lock = threading.RLock()

        self.flows = {}            # key -> IntelFlow
        self.sites = {}            # (device, root) -> IntelSiteSession

        # merged activity intervals, keyed by (dimension, device, key)
        self.intervals = {}
        self.device_presence = {}
        # A connection-table sample every N seconds proves the socket existed in
        # between.  Cap how far that logic may stretch (15 min) so a stale
        # ESTABLISHED row cannot invent hours.

        self._bucket_pending = {}
        self._daily_pending = {}
        self._online_pending = {}
        self._interval_state_dirty = set()
        # Rows whose owning session may be torn down before the next flush
        # (Flask-SQLAlchemy rolls the request session back at teardown).
        self._closed_rows = []

        self.counters = {'flows_created': 0, 'flows_extended': 0, 'flows_closed': 0,
                         'sites_created': 0, 'sites_extended': 0, 'sites_closed': 0,
                         'evidence': 0, 'skipped_late': 0, 'estimated_gaps': 0}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def load_open_sessions(self):
        """Restore live flows/sites and per-device intervals after a restart."""
        try:
            open_flows = intel_store.equery(IntelFlow).filter(IntelFlow.state != 'closed').all()
            for flow in open_flows:
                self.flows[self._flow_key_from_row(flow)] = flow
                if not flow.last_accrued:
                    flow.last_accrued = flow.last_seen
            open_sites = intel_store.equery(IntelSiteSession).filter(IntelSiteSession.state != 'closed').all()
            for site in open_sites:
                self.sites[(site.device_mac, site.root_domain)] = site
                if not site.last_accrued:
                    site.last_accrued = site.last_seen
            today = datetime.utcnow().strftime('%Y-%m-%d')
            for device in {f.device_mac for f in open_flows if f.device_mac}:
                raw = intel_store.state_get(f'intervals:{today}:{device}')
                if raw:
                    try:
                        self.intervals[('device', device, device)] = [
                            (datetime.fromisoformat(a), datetime.fromisoformat(b)) for a, b in raw]
                    except Exception:
                        pass
            return {'flows': len(open_flows), 'sites': len(open_sites)}
        except Exception as exc:
            if self.health:
                self.health.note('sessionizer', error=exc)
            return {'flows': 0, 'sites': 0, 'error': str(exc)}

    # ------------------------------------------------------------------
    # keys
    # ------------------------------------------------------------------
    @staticmethod
    def _device_of(ev):
        return (ev.device_mac or ev.src_ip or 'unknown').lower()

    def _flow_key(self, ev):
        return (self._device_of(ev), ev.src_ip, ev.dst_ip,
                server_port(ev.src_port, ev.dst_port),
                (ev.protocol or 'IP').upper(), ev.src_port)

    @staticmethod
    def _flow_key_from_row(flow):
        return (flow.device_mac, flow.src_ip, flow.dst_ip,
                flow.service_port or flow.dst_port,
                (flow.protocol or 'IP').upper(), flow.src_port)

    # ------------------------------------------------------------------
    # ingest
    # ------------------------------------------------------------------
    def ingest(self, ev):
        """Fold one evidence row into flows, site visits and buckets."""
        with self._lock:
            self.counters['evidence'] += 1
            name = ev.hostname()
            info = DEFAULT_CATALOG.lookup_host(name) if name else None
            app = info.get('app') if info else None
            category = (info.get('category') if info else None) or 'Unknown'
            if info and info.get('source') == 'root_domain':
                app = None
            if ev.process_name:
                app = app or ev.process_name
                if app == ev.process_name:
                    category = category if category != 'Unknown' else 'Application'

            result = {'flow': None, 'site': None, 'created': False, 'closed': [],
                      'app': app, 'category': category, 'name': name, 'device': self._device_of(ev)}

            flow = self._upsert_flow(ev, name, app, category, result)
            site = self._upsert_site(ev, name, app, category, flow, result)
            self._accrue(ev, flow, site, app, category)
            return result

    # -- flow -----------------------------------------------------------
    def _upsert_flow(self, ev, name, app, category, result):
        key = self._flow_key(ev)
        flow = self.flows.get(key)
        ts = ev.observed_at
        idle_window = self.estimated_gap_seconds if (flow is not None and flow.is_estimated
                                                     and ev.is_estimated) else self.idle_seconds
        if flow is not None and (ts - (flow.last_seen or ts)).total_seconds() > idle_window:
            self._close_flow(flow, 'idle_timeout', flow.last_seen)
            result['closed'].append({'kind': 'flow', 'id': flow.id, 'mac': flow.device_mac})
            self.flows.pop(key, None)
            flow = None

        estimated = bool(ev.is_estimated)
        if flow is None:
            flow = IntelFlow(
                device_mac=ev.device_mac, src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                src_port=ev.src_port, dst_port=ev.dst_port,
                service_port=server_port(ev.src_port, ev.dst_port),
                protocol=(ev.protocol or 'IP').upper(),
                hostname=name, root_domain=root_domain(name) if name else None,
                app=app, category=category,
                name_source=ev.name_source() or ('process' if ev.process_name else 'port'),
                name_confidence=float(ev.confidence or 0.4),
                first_seen=ts, last_seen=ts, state='live',
                bytes_up=int(ev.bytes_up or 0), bytes_down=int(ev.bytes_down or 0),
                packets=int(ev.packets or 0), obs_count=1,
                source=ev.source or 'live', is_estimated=estimated,
                confidence=float(ev.confidence or 0.5), last_accrued=ts)
            flow.url_sample = self._build_url(ev, name)
            intel_store.engine_session().add(flow)
            intel_store.engine_session().flush()
            self.flows[key] = flow
            self.counters['flows_created'] += 1
            result['created'] = True
            self._count_session(app, category, root_domain(name) if name else None,
                                self._device_of(ev))
        else:
            flow.last_seen = max(flow.last_seen or ts, ts)
            flow.bytes_up = int((flow.bytes_up or 0) + (ev.bytes_up or 0))
            flow.bytes_down = int((flow.bytes_down or 0) + (ev.bytes_down or 0))
            flow.packets = int((flow.packets or 0) + (ev.packets or 0))
            flow.obs_count = int((flow.obs_count or 0) + 1)
            flow.state = 'live'
            if not estimated:
                flow.is_estimated = False
            if name and (ev.confidence or 0) > (flow.name_confidence or 0) + 0.05:
                if flow.hostname != name:
                    self._revise(flow, 'hostname', flow.hostname, name,
                                 source=ev.name_source() or ev.source,
                                 confidence=float(ev.confidence or 0.5))
                    flow.hostname = name
                    flow.root_domain = root_domain(name)
                    flow.name_source = ev.name_source() or flow.name_source
                    flow.name_confidence = float(ev.confidence or 0.5)
            elif name and not flow.hostname:
                flow.hostname = name
                flow.root_domain = root_domain(name)
            if app and not flow.app:
                flow.app = app
            if category and category != 'Unknown' and (not flow.category or flow.category == 'Unknown'):
                flow.category = category
            url = self._build_url(ev, name or flow.hostname)
            if url:
                flow.url_sample = url
            self.counters['flows_extended'] += 1
        result['flow'] = flow
        return flow

    @staticmethod
    def _build_url(ev, name):
        if not name:
            return None
        secure = bool(ev.sni or ev.quic_sni or (ev.dst_port in (443, 8443)))
        scheme = 'https' if secure else 'http'
        path = ev.http_path or '/'
        return f'{scheme}://{name}{path}'[:1000]

    def _count_session(self, app, category, root, device):
        """Count one session against the app/site/category dimensions."""
        now = datetime.utcnow()
        bstart = bucket_start_for(now)
        for dimension, key in (('app', app), ('site', root), ('category', category)):
            if not key:
                continue
            slot = self._bucket_pending.setdefault(
                (bstart, dimension, key, device or ''),
                self._empty_slot('live', False))
            slot['sessions'] += 1
            day = now.strftime('%Y-%m-%d')
            daily = self._daily_pending.setdefault(
                (day, dimension, key, device or ''),
                {'seconds': 0.0, 'bytes': 0, 'sessions': 0,
                 'first': now, 'last': now, 'estimated': False})
            daily['sessions'] += 1

    # -- site -----------------------------------------------------------
    def _upsert_site(self, ev, name, app, category, flow, result):
        if not name:
            return None
        root = root_domain(name)
        if not root:
            return None
        device = self._device_of(ev)
        key = (device, root)
        site = self.sites.get(key)
        ts = ev.observed_at
        site_window = self.estimated_gap_seconds if (site is not None and site.is_estimated
                                                     and ev.is_estimated) else self.idle_seconds
        if site is not None and (ts - (site.last_seen or ts)).total_seconds() > site_window:
            self._close_site(site, 'idle_timeout', site.last_seen)
            result['closed'].append({'kind': 'site', 'id': site.id, 'mac': site.device_mac,
                                     'domain': site.root_domain})
            self.sites.pop(key, None)
            site = None

        if site is None:
            site = IntelSiteSession(
                device_mac=ev.device_mac, root_domain=root, hostname=name,
                app=app, category=category,
                url_last=(flow.url_sample if flow else None),
                first_seen=ts, last_seen=ts, state='live', pageviews=1,
                bytes_total=int((ev.bytes_up or 0) + (ev.bytes_down or 0)),
                packets=int(ev.packets or 0), source=ev.source or 'live',
                is_estimated=bool(ev.is_estimated),
                confidence=float(ev.confidence or 0.5), last_accrued=ts)
            intel_store.engine_session().add(site)
            intel_store.engine_session().flush()
            self.sites[key] = site
            self.counters['sites_created'] += 1
        else:
            if result.get('created'):
                site.pageviews = int((site.pageviews or 0) + 1)
            site.last_seen = max(site.last_seen or ts, ts)
            site.bytes_total = int((site.bytes_total or 0) + (ev.bytes_up or 0) + (ev.bytes_down or 0))
            site.packets = int((site.packets or 0) + (ev.packets or 0))
            site.state = 'live'
            if not ev.is_estimated:
                site.is_estimated = False
            if flow is not None and flow.url_sample:
                site.url_last = flow.url_sample
                site.hostname = flow.hostname or site.hostname
            if app and not site.app:
                site.app = app
            if category and category != 'Unknown' and (not site.category or site.category == 'Unknown'):
                site.category = category
            self.counters['sites_extended'] += 1
        result['site'] = site
        return site

    # ------------------------------------------------------------------
    # accrual
    # ------------------------------------------------------------------
    @staticmethod
    def _empty_slot(source='live', estimated=False):
        return {'seconds': 0.0, 'bytes': 0, 'sessions': 0, 'source': source,
                'is_estimated': estimated, 'online': 0.0}

    def _accrue(self, ev, flow, site, app, category):
        ts = ev.observed_at
        device = self._device_of(ev)
        source = ev.source or 'live'
        estimated = bool(ev.is_estimated)
        byte_total = int((ev.bytes_up or 0) + (ev.bytes_down or 0))

        presence = self.device_presence.setdefault(device, {'first': ts, 'last': ts})
        presence['first'] = min(presence['first'], ts)
        presence['last'] = max(presence['last'], ts)

        # Which marker does the interval start from?  A *flow* marker only
        # exists once that particular socket has been seen twice, but a browser
        # opens a fresh socket for almost every request - so the site session
        # carries the marker that makes a multi-connection visit add up.  The
        # device dimension additionally remembers its own last accrual, so
        # unnamed traffic still counts towards "online".
        flow_start = flow.last_accrued if flow is not None else None
        site_start = site.last_accrued if site is not None else None
        device_start = presence.get('last_accrued')
        def _previous(*candidates):
            # The interval is [last time this thing was seen, now].  A brand-new
            # flow is stamped with *now*, so markers equal to the current
            # timestamp must be ignored or every connection would look empty.
            usable = [c for c in candidates if c is not None and c < ts]
            return max(usable) if usable else None

        named_start = _previous(site_start, flow_start)
        device_start_used = _previous(device_start, site_start, flow_start)
        marker_row = site if (site is not None and site_start is not None
                              and site_start == named_start) else flow
        marker_is_estimated = bool(marker_row is not None and marker_row.is_estimated)

        estimated_gap = False
        start = named_start
        if start is not None and start > ts:     # late/duplicate evidence
            self.counters['skipped_late'] += 1
            start = None
        if (start is not None and estimated and marker_is_estimated
                and self.idle_seconds < (ts - start).total_seconds() <= self.estimated_gap_seconds):
            # Two samples of the same established connection.  The socket
            # existed in between, so the gap is usage - recorded as estimated,
            # and capped so an abandoned sample cannot invent hours.
            estimated_gap = True
            self.counters['estimated_gaps'] = self.counters.get('estimated_gaps', 0) + 1
        if start is None or ts <= start:
            # still record bytes at the current bucket without time
            if byte_total:
                bstart = bucket_start_for(ts)
                slot = self._bucket_pending.setdefault(
                    (bstart, 'device', device, device), self._empty_slot(source, estimated))
                slot['bytes'] += byte_total
            return

        # NOTE: the site dimension is accrued once, from the site session below,
        # so parallel flows to the same domain are counted as a union and never
        # double counted in the daily rollups.
        targets = [('device', device, device)]
        if device_start_used is not None and device_start_used <= ts \
                and (ts - device_start_used).total_seconds() <= self.estimated_gap_seconds:
            self._accrue_union('device', device, device, device_start_used, ts, source,
                               bool(estimated or marker_is_estimated), byte_total)
        if app:
            targets.append(('app', device, app))
        if category and category != 'Unknown':
            targets.append(('category', device, category))
        if site is not None:
            targets.append(('site', device, site.root_domain))

        estimated = bool(estimated or estimated_gap)
        seen = set()
        targets = [t for t in targets if t[0] != 'device']
        for dimension, dev, key in targets:
            if (dimension, dev, key) in seen:
                continue
            seen.add((dimension, dev, key))
            self._accrue_union(dimension, dev, key, start, ts, source, estimated,
                               byte_total if dimension == 'device' else 0)

        if presence.get('last_accrued') is None or ts > presence['last_accrued']:
            presence['last_accrued'] = ts
        if flow is not None:
            flow.last_accrued = ts
            if flow.first_seen:
                flow.duration_seconds = int(max(0, (ts - flow.first_seen).total_seconds()))
                flow.span_seconds = flow.duration_seconds
        if site is not None:
            site.last_accrued = ts
            site.dwell_seconds = int(merged_seconds(
                self.intervals.get(('site', device, site.root_domain), [])))
            if site.first_seen:
                # span = how long the session lasted; dwell = proven active time.
                # Their difference is quiet time, shown as such, never hidden.
                site.span_seconds = int(max(0, (ts - site.first_seen).total_seconds()))
                site.idle_seconds = int(max(0, site.span_seconds - (site.dwell_seconds or 0)))
            site.active_seconds = int(min(self.idle_seconds,
                                          max(0.0, (datetime.utcnow() - (site.last_seen or ts)).total_seconds())))

    def _accrue_union(self, dimension, device, key, start, end, source, estimated, bytes_total=0):
        store_key = (dimension, device, key)
        intervals = self.intervals.setdefault(store_key, [])
        intervals, fresh = merge_interval(intervals, start, end, self.max_intervals)
        self.intervals[store_key] = intervals
        if dimension == 'device':
            self._interval_state_dirty.add(device)
        for (lo, hi) in fresh:
            for bstart, seconds in split_interval(lo, hi):
                slot = self._bucket_pending.setdefault(
                    (bstart, dimension, key, device or ''), self._empty_slot(source, estimated))
                if dimension == 'device':
                    slot['online'] += seconds
                    slot['bytes'] += bytes_total
                else:
                    slot['seconds'] += seconds
                slot['source'] = source
            day = lo.strftime('%Y-%m-%d')
            daily = self._daily_pending.setdefault(
                (day, dimension, key, device or ''),
                {'seconds': 0.0, 'bytes': 0, 'sessions': 0,
                 'first': lo, 'last': hi, 'estimated': estimated})
            daily['seconds'] += (hi - lo).total_seconds()
            if dimension == 'device':
                daily['bytes'] += bytes_total
            daily['first'] = min(daily['first'], lo)
            daily['last'] = max(daily['last'], hi)

    # ------------------------------------------------------------------
    # closing
    # ------------------------------------------------------------------
    def _close_flow(self, flow, reason='idle_timeout', when=None):
        when = when or flow.last_seen or datetime.utcnow()
        flow.state = 'closed'
        flow.close_reason = reason
        flow.closed_at = when + (timedelta(seconds=self.idle_seconds)
                                if reason == 'idle_timeout' else timedelta())
        flow.duration_seconds = int(max(0, (when - (flow.first_seen or when)).total_seconds()))
        flow.span_seconds = flow.duration_seconds
        self.counters['flows_closed'] += 1
        self._closed_rows.append(flow)
        self._mirror_flow_to_legacy(flow)

    def _close_site(self, site, reason='idle_timeout', when=None):
        when = when or site.last_seen or datetime.utcnow()
        site.state = 'closed'
        site.closed_at = when + (timedelta(seconds=self.idle_seconds)
                                 if reason == 'idle_timeout' else timedelta())
        if site.first_seen:
            site.span_seconds = int(max(0, (when - site.first_seen).total_seconds()))
            site.idle_seconds = int(max(0, site.span_seconds - (site.dwell_seconds or 0)))
        self.counters['sites_closed'] += 1
        self._closed_rows.append(site)
        self._mirror_site_to_legacy(site)

    def sweep(self, now=None):
        """Close sessions whose idle window has expired. Call every few seconds."""
        now = now or datetime.utcnow()
        closed = []
        with self._lock:
            for key, flow in list(self.flows.items()):
                age = (now - (flow.last_seen or now)).total_seconds()
                window = self.estimated_gap_seconds if flow.is_estimated else self.idle_seconds
                if age > window:
                    self._close_flow(flow, 'idle_timeout', flow.last_seen)
                    closed.append({'kind': 'flow', 'id': flow.id, 'mac': flow.device_mac})
                    self.flows.pop(key, None)
                elif age > min(60, self.idle_seconds):
                    flow.state = 'idle'
            for key, site in list(self.sites.items()):
                age = (now - (site.last_seen or now)).total_seconds()
                window = self.estimated_gap_seconds if site.is_estimated else self.idle_seconds
                if age > window:
                    self._close_site(site, 'idle_timeout', site.last_seen)
                    closed.append({'kind': 'site', 'id': site.id, 'mac': site.device_mac,
                                   'domain': site.root_domain})
                    self.sites.pop(key, None)
                elif age > min(60, self.idle_seconds):
                    site.state = 'idle'
                    site.active_seconds = int(min(self.idle_seconds,
                                                  (now - (site.last_seen or now)).total_seconds()))
        return closed

    # ------------------------------------------------------------------
    # flush
    # ------------------------------------------------------------------
    def _reattach(self):
        """Re-attach open/closed rows to the current session.

        A flow created while handling an HTTP request belongs to that request's
        session; Flask-SQLAlchemy removes (and rolls back) it at teardown, which
        would silently throw the flow away.  ``merge`` moves the row - state and
        all - into whichever session calls ``flush`` next.
        """
        for key, flow in list(self.flows.items()):
            if object_session(flow) is intel_store.engine_session():
                continue
            try:
                self.flows[key] = intel_store.engine_session().merge(flow)
            except Exception:
                pass
        for key, site in list(self.sites.items()):
            if object_session(site) is intel_store.engine_session():
                continue
            try:
                self.sites[key] = intel_store.engine_session().merge(site)
            except Exception:
                pass
        if self._closed_rows:
            rows, self._closed_rows = self._closed_rows, []
            for row in rows:
                if object_session(row) is intel_store.engine_session():
                    continue
                try:
                    intel_store.engine_session().merge(row)
                except Exception:
                    pass

    def flush(self, commit=True, prune=True):
        with self._lock:
            self._reattach()
            buckets = self._bucket_pending
            daily = self._daily_pending
            online = self._online_pending
            self._bucket_pending = {}
            self._daily_pending = {}
            self._online_pending = {}
            dirty_devices = self._interval_state_dirty
            self._interval_state_dirty = set()
            # Collect the online-day totals *before* pruning old intervals so a
            # device that went offline more than a day ago still gets its day.
            self._collect_online(dirty_devices)
            online = self._online_pending
            self._online_pending = {}
            if prune:
                cutoff = datetime.utcnow() - timedelta(hours=30)
                for key in list(self.intervals.keys()):
                    pruned = [(a, b) for (a, b) in self.intervals[key] if b > cutoff]
                    if pruned:
                        self.intervals[key] = pruned
                    else:
                        self.intervals.pop(key, None)
            stats = {'buckets': len(buckets), 'daily': len(daily), 'online_days': len(online),
                     'flows_open': len(self.flows), 'sites_open': len(self.sites),
                     'intervals': len(self.intervals)}
        try:
            self._write_buckets(buckets)
            self._write_daily(daily)
            self._write_online(online)
            for device in dirty_devices:
                today = datetime.utcnow().strftime('%Y-%m-%d')
                payload = [(a.isoformat(), b.isoformat())
                           for (a, b) in self.intervals.get(('device', device, device), [])]
                intel_store.state_set(f'intervals:{today}:{device}', payload[-self.max_intervals:])
            if commit:
                intel_store.engine_session().commit()
            return stats
        except Exception as exc:
            intel_store.engine_session().rollback()
            if self.health:
                self.health.note('sessionizer', error=exc, dropped=len(buckets))
            return {'error': str(exc)}

    def _collect_online(self, devices):
        """Rebuild per-device online totals from the merged intervals."""
        for device in devices:
            for (a, b) in self.intervals.get(('device', device, device), []):
                day = a.strftime('%Y-%m-%d')
                slot = self._online_pending.setdefault(
                    (day, device), {'seconds': 0.0, 'first': a, 'last': b})
                slot['seconds'] += max(0.0, (b - a).total_seconds())
                slot['first'] = min(slot['first'], a)
                slot['last'] = max(slot['last'], b)

    def _write_buckets(self, pending):
        if not pending:
            return 0
        starts = sorted({k[0] for k in pending})
        existing = {}
        try:
            rows = intel_store.equery(IntelUsageBucket).filter(IntelUsageBucket.bucket_start >= starts[0]).all()
            for row in rows:
                existing[(row.bucket_start, row.dimension, row.key, row.device_mac)] = row
        except Exception:
            existing = {}
        written = 0
        for key, slot in pending.items():
            row = existing.get(key)
            if row is None:
                row = IntelUsageBucket(bucket_start=key[0], dimension=key[1], key=key[2][:255],
                                       device_mac=key[3] or '', seconds=0, online_seconds=0,
                                       bytes_total=0, sessions=0)
                intel_store.engine_session().add(row)
                existing[key] = row
            row.seconds = int((row.seconds or 0) + round(slot['seconds']))
            row.online_seconds = int((row.online_seconds or 0) + round(slot['online']))
            row.bytes_total = int((row.bytes_total or 0) + slot['bytes'])
            row.sessions = int((row.sessions or 0) + slot['sessions'])
            row.source = slot['source']
            row.is_estimated = bool(slot['is_estimated'])
            written += 1
        return written

    def _write_daily(self, pending):
        if not pending:
            return 0
        written = 0
        for (day, dimension, key, device), slot in pending.items():
            row = intel_store.equery(IntelDailyUsage).filter_by(
                day=day, dimension=dimension, key=key[:255], device_mac=device or '').first()
            if row is None:
                row = IntelDailyUsage(day=day, dimension=dimension, key=key[:255],
                                      device_mac=device or '', seconds=0, bytes_total=0, sessions=0)
                intel_store.engine_session().add(row)
            row.seconds = int((row.seconds or 0) + round(slot['seconds']))
            row.bytes_total = int((row.bytes_total or 0) + slot['bytes'])
            row.sessions = int((row.sessions or 0) + slot['sessions'])
            row.first_seen = min(row.first_seen, slot['first']) if row.first_seen else slot['first']
            row.last_seen = max(row.last_seen, slot['last']) if row.last_seen else slot['last']
            row.is_estimated = bool(slot['estimated'])
            written += 1
        return written

    def _write_online(self, pending):
        if not pending:
            return 0
        written = 0
        for (day, device), slot in pending.items():
            row = intel_store.equery(IntelOnlineDay).filter_by(day=day, device_mac=device).first()
            if row is None:
                row = IntelOnlineDay(day=day, device_mac=device, online_seconds=0)
                intel_store.engine_session().add(row)
            row.online_seconds = int((row.online_seconds or 0) + round(slot['seconds']))
            row.first_seen = min(row.first_seen, slot['first']) if row.first_seen else slot['first']
            row.last_seen = max(row.last_seen, slot['last']) if row.last_seen else slot['last']
            written += 1
        return written

    # ------------------------------------------------------------------
    # provenance + legacy mirror
    # ------------------------------------------------------------------
    @staticmethod
    def _revise(row, field, old, new, source='live', confidence=0.5):
        if old == new:
            return
        try:
            from src.intel.models import IntelRevision
            intel_store.engine_session().add(IntelRevision(entity='flow', entity_id=row.id, field=field,
                                         old_value=str(old), new_value=str(new),
                                         source=source, confidence=confidence))
        except Exception:
            pass

    def _savepoint(self):
        """A savepoint around a legacy-mirror write.

        The mirror runs *inside* the engine's transaction, so a constraint
        violation here (a duplicate device row, a strict NOT NULL column) would
        poison the whole transaction and silently discard the evidence that is
        still pending.  A savepoint keeps the damage local.
        """
        from contextlib import contextmanager

        @contextmanager
        def _ctx():
            session = intel_store.engine_session()
            nested = session.begin_nested()
            try:
                yield session
                nested.commit()
            except Exception:
                try:
                    nested.rollback()
                except Exception:
                    pass
                raise
        return _ctx()

    def _ensure_legacy_device(self, flow):
        if not self.mirror_legacy or not flow or not flow.device_mac:
            return
        try:
            from src.intel.maclab import classify_vendor, is_valid_mac, vendor_for
            from src.models.network import Device
            from src.models.hostnames import HnApp, HnCategory, HnRule
            if not is_valid_mac(flow.device_mac):
                return
            vendor = vendor_for(flow.device_mac)
            with self._savepoint():
                # engine-session queries: a row created moments ago by this very
                # transaction is invisible to the request session, which is how
                # the duplicate device insert used to happen.
                device = intel_store.equery(Device).filter_by(
                    mac_address=flow.device_mac).first()
                if device is None:
                    device = Device(mac_address=flow.device_mac, ip_address=flow.src_ip,
                                    hostname=flow.device_mac, vendor=vendor or 'Unknown',
                                    device_type=classify_vendor(vendor),
                                    first_seen=flow.first_seen, last_seen=flow.last_seen,
                                    is_active=True)
                    intel_store.engine_session().add(device)
                else:
                    device.last_seen = flow.last_seen or datetime.utcnow()
                    if flow.src_ip and not device.ip_address:
                        device.ip_address = flow.src_ip
                    if (not device.vendor or device.vendor == 'Unknown') and vendor:
                        device.vendor = vendor
                intel_store.engine_session().flush()

            if flow.hostname and flow.app and flow.root_domain:
                with self._savepoint():
                    app_row = intel_store.equery(HnApp).filter_by(name=flow.app).first()
                    if app_row is None:
                        cat = intel_store.equery(HnCategory).filter_by(
                            name=flow.category or 'Uncategorized').first()
                        if cat is None:
                            cat = HnCategory(name=flow.category or 'Uncategorized',
                                             description='Auto-created by the intelligence layer')
                            intel_store.engine_session().add(cat)
                            intel_store.engine_session().flush()
                        app_row = HnApp(category_id=cat.id, name=flow.app,
                                        slug=flow.app.lower().replace(' ', '-')[:110])
                        intel_store.engine_session().add(app_row)
                        intel_store.engine_session().flush()
                    existing_rule = intel_store.equery(HnRule).filter_by(
                        type='domain', value=flow.root_domain).first()
                    if not existing_rule:
                        intel_store.engine_session().add(HnRule(
                            app_id=app_row.id, type='domain', value=flow.root_domain,
                            source='auto', confidence=0.6))
        except Exception as exc:
            if self.health:
                self.health.note('mirror', error=exc)

    def _mirror_flow_to_legacy(self, flow):
        """Write one summary TrafficSession per closed flow (bounded volume)."""
        if not self.mirror_legacy or not flow:
            return
        try:
            from src.models.network import TrafficSession
            self._ensure_legacy_device(flow)
            if (flow.bytes_up or 0) + (flow.bytes_down or 0) == 0 and (flow.obs_count or 0) < 2:
                return
            with self._savepoint():
                exists = intel_store.equery(TrafficSession).filter_by(
                    src_mac=flow.device_mac, dst_ip=flow.dst_ip, dst_port=flow.dst_port,
                    protocol=flow.protocol, start_time=flow.first_seen).first()
                if exists:
                    return
                intel_store.engine_session().add(TrafficSession(
                    src_mac=flow.device_mac, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                    src_port=flow.src_port, dst_port=flow.dst_port, protocol=flow.protocol,
                    start_time=flow.first_seen, end_time=flow.closed_at or flow.last_seen,
                    bytes_sent=int(flow.bytes_up or 0), bytes_received=int(flow.bytes_down or 0),
                    packet_count=int(flow.packets or 0)))
        except Exception as exc:
            if self.health:
                self.health.note('mirror', error=exc)

    def _mirror_site_to_legacy(self, site):
        if not self.mirror_legacy or not site or not site.device_mac:
            return
        try:
            from src.intel.maclab import is_valid_mac
            from src.models.network import WebsiteVisit
            if not is_valid_mac(site.device_mac):
                return
            with self._savepoint():
                intel_store.engine_session().add(WebsiteVisit(
                    device_mac=site.device_mac, domain=site.root_domain, url=site.url_last,
                    timestamp=site.first_seen, bytes_transferred=int(site.bytes_total or 0),
                    response_code=200, method='GET'))
        except Exception as exc:
            if self.health:
                self.health.note('mirror', error=exc)
