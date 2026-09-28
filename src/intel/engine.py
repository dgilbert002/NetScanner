"""
Intel engine: the single orchestrator for the intelligence layer.

Owns one background worker thread plus the batch writer thread.  Every source
(packet capture, connection table, Pi-hole, API uploads) calls
:meth:`IntelEngine.process_evidence`, which is thread safe and never raises.

Duties
------
* resolve names via the free catalog and remember them,
* keep the IP ↔ MAC ↔ hostname maps that the legacy code never had,
* feed the sessionizer (flows, site visits, buckets, true online time),
* run the VPN/proxy/DNS-bypass detector,
* run the periodic jobs: behaviour fingerprints, identity scores, rotation
  detection, retention, source-health flush,
* expose a status snapshot for the API and the UI.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta

from src.models.user import db
from src.intel import capture as intel_capture
from src.intel import store as intel_store
from src.intel.behavior import BehaviorEngine
from src.intel.catalog import DEFAULT_CATALOG, root_domain
from src.intel.maclab import MacRegistry, is_valid_mac, normalize_mac
from src.intel.models import (
    IntelBehaviorProfile,
    IntelSearch,
    IntelDeviceEvent,
    IntelFlow,
    IntelIdentityScore,
    IntelObservation,
    IntelPerson,
    IntelSiteSession,
    IntelUsageBucket,
    IntelVpnFinding,
)
from src.intel.sessionizer import Sessionizer
from src.intel import alerts as intel_alerts
from src.intel.vpnwatch import VpnWatch

SETTINGS_KEY = 'settings'
DEFAULT_SETTINGS = {
    'enabled': True,
    'capture_enabled': True,
    'interface': None,
    'idle_seconds': 90,
    'retention_days': 90,
    'behavior_days': 30,
    'behavior_interval_seconds': 900,
    'vpn_scan_interval_seconds': 600,
    'retention_interval_seconds': 86400,
    'mirror_legacy_tables': True,
    'feeds_enabled': False,
    'track_private_macs': True,
    'sessionizer_flush_seconds': 10,
    # parental alerting (see src/intel/alerts.py for the rule semantics)
    'alert_alerts_enabled': True,
    'alert_adult_alert': True,
    'alert_gambling_alert': True,
    'alert_bypass_alert': True,
    'alert_bypass_score_threshold': 40,
    'alert_gaming_alert': True,
    'alert_gaming_minutes': 120,
    'alert_late_night_alert': True,
    'alert_bedtime_start': '22:30',
    'alert_bedtime_end': '06:30',
    'alert_late_night_minutes': 20,
    'alert_daily_limit_alert': False,
    'alert_daily_limit_hours': 4,
    'alert_new_app_alert': True,
    'alert_new_device_alert': True,
    'alerts_interval_seconds': 300,
}


@dataclass
class IntelSettings:
    values: dict = field(default_factory=lambda: dict(DEFAULT_SETTINGS))

    @classmethod
    def load(cls):
        raw = intel_store.state_get(SETTINGS_KEY, {}) or {}
        merged = dict(DEFAULT_SETTINGS)
        if isinstance(raw, dict):
            merged.update({k: v for k, v in raw.items() if k in DEFAULT_SETTINGS})
        return cls(values=merged)

    def save(self):
        return intel_store.state_set(SETTINGS_KEY, self.values)

    def get(self, key, default=None):
        return self.values.get(key, DEFAULT_SETTINGS.get(key, default))

    def update(self, patch):
        for key, value in (patch or {}).items():
            if key in DEFAULT_SETTINGS:
                self.values[key] = value
        return self.save()

    def to_dict(self):
        return dict(self.values)


class IntelEngine:
    """The orchestrator.  One instance per process (see :func:`get_engine`)."""

    def __init__(self, app=None):
        self.app = app
        self.settings = IntelSettings.load() if app else IntelSettings()
        self.health = intel_store.SourceHealth()
        self.writer = intel_store.BatchWriter(app=app, health=self.health)
        self.sessionizer = Sessionizer(
            app=app,
            idle_seconds=int(self.settings.get('idle_seconds', 90)),
            health=self.health,
            mirror_legacy=bool(self.settings.get('mirror_legacy_tables', True)))
        self.maclab = MacRegistry()
        self.behavior = BehaviorEngine(idle_seconds=int(self.settings.get('idle_seconds', 90)),
                                       days=int(self.settings.get('behavior_days', 30)))
        self.vpn = VpnWatch(health=self.health)
        self.alerts = intel_alerts.AlertEngine(settings=self.settings, health=self.health, engine=self)
        self.capture = None

        self.local_networks = intel_capture.local_ipv4_networks()
        self.dns_cache = {}
        self.ip_to_mac = {}
        self.mac_to_host = {}
        self.dhcp_fingerprints = {}
        self._seen_search = {}
        self._identity_cache = {}

        self.running = False
        self._thread = None
        self._lock = threading.RLock()
        if app is not None:
            # Bind the engine session to the same engine the request session uses.
            try:
                from sqlalchemy.orm import sessionmaker
                from src.models.user import db as _db
                with app.app_context():
                    intel_store.set_engine_session_factory(sessionmaker(bind=_db.engine))
            except Exception:
                pass
        self._last_jobs = {}
        self.started_at = None
        self.errors = []
        self.counters = {'evidence': 0, 'dropped': 0, 'events': 0, 'vpn_findings': 0,
                         'searches': 0}

    # ------------------------------------------------------------------
    # session plumbing
    # ------------------------------------------------------------------
    # Every intel write goes through one long-lived engine session (see
    # intel_store.engine_session).  Flask's request session is rolled back and
    # detached at teardown, which used to throw away open flows and left the
    # buffers unwritable from worker threads.
    def session(self):
        return intel_store.engine_session()

    def flush_now(self):
        """Persist everything buffered right now (used by the observe API)."""
        with intel_store.forced_engine_session():
            try:
                with self._lock:
                    self.sessionizer.sweep()
                    self.sessionizer.flush()
                    self.writer.flush()
                    self.health.flush(force=True)
            except Exception as exc:
                self._record_error(f'flush_now: {exc}')
                intel_store.engine_rollback()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self, with_capture=True):
        if self.running:
            return False
        self.running = True
        self.started_at = datetime.utcnow()
        self.writer.start()
        restored = self.sessionizer.load_open_sessions()
        self._load_maps()
        if with_capture and self.settings.get('capture_enabled', True):
            try:
                self.capture = intel_capture.CaptureManager(
                    self, interface=self.settings.get('interface'))
                mode = self.capture.start()
                self.health.note('capture', status='healthy', detail={'mode': mode})
            except Exception as exc:
                self._record_error(f'capture start failed: {exc}')
        self._thread = threading.Thread(target=self._loop, name='intel-engine', daemon=True)
        self._thread.start()
        self.health.note('engine', status='healthy', events=1,
                         detail={'restored': restored, 'networks': self.local_networks[:6]})
        self.health.flush(force=True)
        return True

    def stop(self):
        self.running = False
        if self.capture:
            try:
                self.capture.stop()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        try:
            self.sessionizer.flush()
        except Exception:
            pass
        self.writer.stop()
        self.health.flush(force=True)

    def _record_error(self, message):
        self.errors.append({'at': datetime.utcnow().isoformat(), 'message': str(message)[:300]})
        self.errors = self.errors[-20:]

    # ------------------------------------------------------------------
    # maps
    # ------------------------------------------------------------------
    def _load_maps(self):
        """Seed IP→MAC from the ARP table and the MAC registry."""
        try:
            for ip, mac in intel_capture.arp_table().items():
                if is_valid_mac(mac):
                    self.ip_to_mac[ip] = normalize_mac(mac)
        except Exception:
            pass
        try:
            from src.intel.models import IntelDeviceMac
            for row in intel_store.equery(IntelDeviceMac).all():
                if row.hostname:
                    self.mac_to_host[row.normalized or row.mac] = row.hostname
        except Exception:
            pass

    def mac_for_ip(self, ip):
        if not ip:
            return None
        return self.ip_to_mac.get(ip)

    def note_arp(self, ip, mac):
        if ip and mac and is_valid_mac(mac):
            self.ip_to_mac[ip] = normalize_mac(mac)
            self._touch_mac(mac, ip=ip, source='arp')

    def note_dns_answers(self, answers):
        for item in answers or []:
            name = (item.get('name') or '').strip('.').lower()
            ip = item.get('ip')
            if name and ip:
                self.dns_cache[ip] = name

    def note_dhcp(self, mac, ip, hostname, vendor_class=None):
        if not mac:
            return
        norm = normalize_mac(mac) or mac
        if ip:
            self.ip_to_mac[ip] = norm
        if hostname:
            self.mac_to_host[norm] = hostname
        if vendor_class:
            self.dhcp_fingerprints[norm] = vendor_class
        self._touch_mac(mac, ip=ip, hostname=hostname, source='dhcp',
                        dhcp_hostname=hostname, extra={'vendor_class': vendor_class})

    def _touch_mac(self, mac, ip=None, hostname=None, source='live', dhcp_hostname=None,
                   mdns_name=None, bytes_total=0, when=None):
        try:
            row, events = self.maclab.observe(
                mac, ip=ip, hostname=hostname, dhcp_hostname=dhcp_hostname,
                mdns_name=mdns_name, bytes_total=bytes_total, when=when, source=source)
            for event in events or []:
                self.raise_event(event.get('kind'), event.get('severity', 'info'),
                                 device_mac=normalize_mac(mac) or mac,
                                 related_mac=event.get('related_mac'),
                                 title=event.get('title'), detail=event.get('detail'),
                                 confidence=event.get('confidence', 0.5))
            return row
        except Exception as exc:
            self._record_error(f'mac registry: {exc}')
            return None

    def raise_event(self, kind, severity='info', device_mac=None, related_mac=None,
                    person_id=None, title=None, detail=None, confidence=0.5):
        try:
            event = IntelDeviceEvent(
                event_at=datetime.utcnow(), kind=kind, severity=severity,
                device_mac=device_mac, related_mac=related_mac, person_id=person_id,
                title=title or kind.replace('_', ' '), detail=json.dumps(detail or {}, default=str),
                confidence=confidence)
            intel_store.engine_session().add(event)
            self.counters['events'] += 1
            return event
        except Exception:
            return None

    # ------------------------------------------------------------------
    # ingest path (called from capture threads and the API)
    # ------------------------------------------------------------------
    def process_evidence(self, ev, count_time=True):
        """Fold one Evidence into the model.  Thread safe, never raises."""
        if ev is None:
            return None
        with intel_store.forced_engine_session():
            return self._process_evidence(ev, count_time)

    def _process_evidence(self, ev, count_time=True):
        try:
            with self._lock:
                if isinstance(ev.observed_at, datetime) and ev.observed_at.tzinfo is not None:
                    ev.observed_at = ev.observed_at.astimezone(tz=None).replace(tzinfo=None)

                # device resolution: MAC preferred, else the IP's known MAC
                if not ev.device_mac and ev.src_ip:
                    ev.device_mac = self.ip_to_mac.get(ev.src_ip)
                if ev.device_mac and not is_valid_mac(ev.device_mac):
                    ev.device_mac = self.ip_to_mac.get(ev.src_ip)
                if ev.device_mac and ev.src_ip:
                    self.ip_to_mac[ev.src_ip] = ev.device_mac

                # name resolution from the DNS cache when the packet had none
                if not ev.hostname() and ev.dst_ip:
                    cached = self.dns_cache.get(ev.dst_ip)
                    if cached:
                        ev.dns_qname = cached
                        ev.confidence = max(ev.confidence, 0.55)

                if ev.dhcp_hostname or ev.mdns_name:
                    self._touch_mac(ev.device_mac, ip=ev.src_ip,
                                    hostname=ev.hostname() or ev.dhcp_hostname or ev.mdns_name,
                                    dhcp_hostname=ev.dhcp_hostname, mdns_name=ev.mdns_name,
                                    source=ev.source, when=ev.observed_at)
                elif ev.device_mac:
                    self._touch_mac(ev.device_mac, ip=ev.src_ip, source=ev.source,
                                    when=ev.observed_at,
                                    bytes_total=int((ev.bytes_up or 0) + (ev.bytes_down or 0)))
                    if ev.hostname() and ev.device_mac:
                        self.mac_to_host.setdefault(ev.device_mac, ev.hostname())

                self.writer.submit(ev)
                self.counters['evidence'] += 1

                result = self.sessionizer.ingest(ev)

                # VPN / bypass detection
                if self.settings.get('vpn_scan_interval_seconds', 0) is not None:
                    self._evaluate_vpn(ev, result)

                # remember the resolved name so the name cache and revisions learn
                host = ev.hostname()
                if host:
                    try:
                        DEFAULT_CATALOG.lookup_host(host)
                    except Exception:
                        pass

                # observable search queries (plain HTTP only) into their own table
                self._record_search(ev, result)
        except Exception as exc:
            self.counters['dropped'] += 1
            self.health.note('engine', error=exc, dropped=1)
            try:
                intel_store.engine_session().rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # search capture
    # ------------------------------------------------------------------
    def _record_search(self, ev, result):
        """Store a search term that arrived in clear text.

        HTTPS hides the query string, so this only ever fires for plain HTTP
        (or an unencrypted redirect/prefetch).  The person is attached from the
        current best identity so the alert and history views can group by child.
        """
        detail = ev.detail or {}
        term = detail.get('search_term')
        if not term and ev.http_host and ev.http_path:
            # derive it here as well, so evidence arriving through the API or a
            # pcap replay gets the same treatment as live packets
            try:
                from src.intel.flow import search_term_from_url
                engine_name, derived = search_term_from_url(ev.http_host, ev.http_path)
                if derived:
                    term = derived
                    detail = dict(detail)
                    detail['search_engine'] = engine_name
                    detail['search_term'] = derived
            except Exception:
                term = None
        if not term:
            return None
        if self._seen_search.get(term.lower()) == (ev.device_mac, ev.observed_at.date()):
            return None
        self._seen_search[term.lower()] = (ev.device_mac, ev.observed_at.date())
        if len(self._seen_search) > 5000:
            self._seen_search.clear()
        try:
            person_id, person_name = self.identity_for_mac(ev.device_mac)
            row = IntelSearch(
                seen_at=ev.observed_at, device_mac=ev.device_mac,
                person_id=person_id, person_name=person_name,
                engine=detail.get('search_engine'),
                term=term[:300],
                url=f"http://{ev.http_host or ''}{ev.http_path or ''}"[:1000],
                category=(result or {}).get('category'),
                source=ev.source or 'live', collector=ev.collector,
                confidence=float(ev.confidence or 0.8),
                is_estimated=bool(ev.is_estimated))
            intel_store.engine_session().add(row)
            self.counters['searches'] = self.counters.get('searches', 0) + 1
            return row
        except Exception as exc:
            self.health.note('searches', error=exc)
            return None

    def identity_for_mac(self, mac):
        """Best (person_id, person_name) for a MAC; locked bindings win."""
        mac = (mac or '').lower()
        if not mac:
            return None, None
        cached = self._identity_cache.get(mac)
        if cached and (time.time() - cached[0]) < 60:
            return cached[1], cached[2]
        person_id = person_name = None
        try:
            rows = intel_store.equery(IntelIdentityScore).filter_by(device_mac=mac).all()
            rows.sort(key=lambda r: (bool(r.locked or r.is_binding), r.probability or 0), reverse=True)
            for row in rows:
                if row.locked or row.is_binding or (row.probability or 0) >= 0.5:
                    person_id, person_name = row.person_id, row.person_name
                    break
        except Exception:
            pass
        self._identity_cache[mac] = (time.time(), person_id, person_name)
        if len(self._identity_cache) > 2000:
            self._identity_cache.clear()
        return person_id, person_name


    def _evaluate_vpn(self, ev, session_result):
        try:
            host = ev.hostname()
            # cheap pre-filter: only call the detector when something looks relevant
            interesting = bool(
                host and (DEFAULT_CATALOG.vpn_provider_for(host) or DEFAULT_CATALOG.is_doh_domain(host)
                          or any(h in host for h in ('vpn', 'proxy', 'tunnel', 'tor', 'warp'))))
            if not interesting and ev.dst_port not in (53, 853, 1080, 1194, 1701, 1723, 3128, 4500,
                                                       500, 51820, 5555, 8118, 8388, 8888, 9001,
                                                       9030, 9050, 9150):
                return
            finding = self.vpn.evaluate(
                device_mac=ev.device_mac, dst_ip=ev.dst_ip, dst_port=ev.dst_port,
                hostname=host, protocol=ev.protocol, source=ev.source, when=ev.observed_at)
            if not finding:
                return
            row = self.vpn.record(finding)
            self.counters['vpn_findings'] += 1
            if row is not None and (finding.get('label') in ('high', 'critical')):
                existing = intel_store.equery(IntelDeviceEvent).filter_by(
                    device_mac=ev.device_mac, kind='vpn_detected').filter(
                    IntelDeviceEvent.event_at >= datetime.utcnow() - timedelta(hours=6)).first()
                if not existing:
                    self.raise_event(
                        'vpn_detected', 'warning', device_mac=ev.device_mac,
                        title=(f"Possible VPN/proxy bypass: {finding.get('provider') or finding.get('dst_host') or ev.dst_ip} "
                               f"({finding.get('label')})"),
                        detail={'score': finding.get('score'), 'evidence': finding.get('evidence'),
                                'kind': finding.get('kind')},
                        confidence=finding.get('confidence', 0.5))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # background jobs
    # ------------------------------------------------------------------
    def _loop(self):
        # Worker thread: no Flask app context, so this uses the engine session.
        with intel_store.forced_engine_session():
            while self.running:
                try:
                    with self._lock:
                        self.sessionizer.sweep()
                        self.sessionizer.flush()
                        self.health.flush()
                        self._run_due_jobs()
                        intel_store.engine_commit()
                except Exception as exc:
                    self._record_error(f'engine loop: {exc}')
                    intel_store.engine_rollback()
                time.sleep(max(2.0, float(self.settings.get('sessionizer_flush_seconds', 10) or 10)))

    def _due(self, name, seconds):
        last = self._last_jobs.get(name)
        now = time.time()
        if last is None or now - last >= seconds:
            self._last_jobs[name] = now
            return True
        return False

    def _run_due_jobs(self):
        if self._due('behavior', int(self.settings.get('behavior_interval_seconds', 900))):
            try:
                self.behavior.update_profiles(days=int(self.settings.get('behavior_days', 30)))
                summary = self.behavior.score_all(days=int(self.settings.get('behavior_days', 30)))
                self.health.note('behavior', status='healthy', events=summary.get('scored', 0),
                                 detail=summary)
            except Exception as exc:
                self._record_error(f'behavior job: {exc}')
                self.health.note('behavior', error=exc)

        if self._due('vpn', int(self.settings.get('vpn_scan_interval_seconds', 600))):
            try:
                found = self.vpn.scan_flows(hours=24)
                found += self.vpn.scan_dns_bypass(hours=6)
                self.health.note('vpnwatch', status='healthy', events=found)
            except Exception as exc:
                self._record_error(f'vpn job: {exc}')
                self.health.note('vpnwatch', error=exc)

        if self._due('retention', int(self.settings.get('retention_interval_seconds', 86400))):
            try:
                days = int(self.settings.get('retention_days', 90) or 90)
                if days > 0:
                    counts = intel_store.apply_retention(days=days)
                    self.health.note('retention', status='healthy',
                                     detail={'days': days, 'deleted': counts})
            except Exception as exc:
                self._record_error(f'retention job: {exc}')

        if self._due('alerts', int(self.settings.get('alerts_interval_seconds', 300) or 300)):
            try:
                summary = self.alerts.evaluate(hours=26)
                self.health.note('alerts', status='healthy', events=summary.get('raised', 0),
                                 detail={k: v for k, v in summary.items() if isinstance(v, int)})
            except Exception as exc:
                self._record_error(f'alert job: {exc}')
                self.health.note('alerts', error=exc)

        if self._due('discovery', 300):
            self._refresh_presence()

    def _refresh_presence(self):
        """Refresh the IP→MAC map and mark MACs inactive when they go quiet."""
        try:
            from src.intel.models import IntelDeviceMac
            for ip, mac in intel_capture.arp_table().items():
                if is_valid_mac(mac):
                    self.ip_to_mac[ip] = normalize_mac(mac)
            cutoff = datetime.utcnow() - timedelta(hours=12)
            stale = intel_store.equery(IntelDeviceMac).filter(IntelDeviceMac.is_active == True,  # noqa: E712
                                               IntelDeviceMac.last_seen < cutoff).all()
            for row in stale:
                row.is_active = False
            intel_store.engine_session().commit()
        except Exception:
            intel_store.engine_session().rollback()

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    def status(self):
        counts = {}
        try:
            counts = intel_store.model_counts()
        except Exception:
            pass
        writer = dict(self.writer.counters)
        writer['pending'] = self.writer.pending()
        return {
            'running': self.running,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'settings': self.settings.to_dict(),
            'platform': os.name,
            'local_networks': self.local_networks,
            'capture': self.capture.status() if self.capture else None,
            'counts': counts,
            'writer': writer,
            'sessionizer': dict(self.sessionizer.counters),
            'engine_counters': dict(self.counters),
            'sources': self.health.snapshot(),
            'errors': self.errors[-5:],
        }

    def health_summary(self):
        """Group collectors into 'actual' vs 'delayed/estimated' buckets for the UI."""
        sources = self.health.snapshot()
        live_sources = [s for s in sources if s.get('status') == 'healthy']
        lagging = [s for s in sources if s.get('status') in ('degraded', 'stale')]
        errored = [s for s in sources if s.get('status') == 'error']
        try:
            now = datetime.utcnow()
            window = now - timedelta(minutes=15)
            live_flows = intel_store.equery(IntelFlow).filter(IntelFlow.last_seen >= window).count()
            live_sites = intel_store.equery(IntelSiteSession).filter(IntelSiteSession.last_seen >= window).count()
            estimated_flows = intel_store.equery(IntelFlow).filter(IntelFlow.last_seen >= window,
                                                    IntelFlow.is_estimated == True).count()  # noqa: E712
            recent_obs = intel_store.equery(IntelObservation).filter(IntelObservation.observed_at >= window).count()
            lag_rows = intel_store.equery(IntelObservation).filter(IntelObservation.observed_at >= window).all()
            lags = [r.latency_ms or 0 for r in lag_rows]
            avg_lag = round(sum(lags) / len(lags), 1) if lags else 0
        except Exception:
            live_flows = live_sites = estimated_flows = recent_obs = avg_lag = 0
        return {
            'sources': sources,
            'live_sources': len(live_sources),
            'lagging_sources': len(lagging),
            'errored_sources': len(errored),
            'live_flows_15m': live_flows,
            'live_sites_15m': live_sites,
            'estimated_flows_15m': estimated_flows,
            'observations_15m': recent_obs,
            'average_ingest_lag_ms': avg_lag,
            'generated_at': datetime.utcnow().isoformat(),
        }


# ---------------------------------------------------------------------------
# singleton
# ---------------------------------------------------------------------------

_ENGINE = None
_ENGINE_LOCK = threading.Lock()


def get_engine(app=None, create=True):
    global _ENGINE
    if _ENGINE is None and create:
        with _ENGINE_LOCK:
            if _ENGINE is None:
                _ENGINE = IntelEngine(app=app)
    return _ENGINE
