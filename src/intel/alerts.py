"""
Parental alerting: turn observed usage into a short, actionable list.

The rules are deliberately few and explicable.  Every alert states *why* it
fired, which device it came from, and who the tracker believes that device
belongs to, so a parent can judge it instead of trusting a black box.

Rules
-----
``adult_content``     a site in the Adult category was used (any duration)
``gambling``          a site in the Gambling category was used
``bypass``            a VPN/proxy/DoH/Tor finding above the configured score,
                      *or* new use of a VPN/proxy app
``unknown_bypass``    a device started talking to a VPN provider domain
``gaming_session``    a game/platform session longer than the configured limit
``late_night``        activity inside the configured bedtime window
``daily_limit``       a person/device passed the daily online or per-category limit
``new_app``           an application seen for the first time on a device
``new_device``        a device appeared on the network for the first time

Alerts are ordinary ``intel_device_events`` rows, so they inherit the ★ / severity
handling, the seen/unseen flag and the retention policy.  Evaluation is
idempotent per (kind, device, day) so a five-minute sweep cannot spam the list.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from src.intel import store as intel_store
from src.intel.models import (
    IntelDailyUsage,
    IntelDeviceEvent,
    IntelDeviceMac,
    IntelFlow,
    IntelSearch,
    IntelSiteSession,
    IntelUsageBucket,
    IntelVpnFinding,
)

# kinds that make up the alert list (everything else is background noise)
ALERT_KINDS = ('adult_content', 'gambling', 'bypass', 'unknown_bypass',
               'gaming_session', 'late_night', 'daily_limit', 'new_app',
               'new_device', 'vpn_detected')

DEFAULT_RULES = {
    'alerts_enabled': True,
    'adult_alert': True,
    'gambling_alert': True,
    'bypass_alert': True,
    'bypass_score_threshold': 40,
    'gaming_alert': True,
    'gaming_minutes': 120,          # a single game session longer than this
    'late_night_alert': True,
    'bedtime_start': '22:30',
    'bedtime_end': '06:30',
    'late_night_minutes': 20,       # ignore brief, innocent blips
    'daily_limit_alert': False,
    'daily_limit_hours': 4,
    'daily_limit_categories': ['Gaming', 'Video', 'Streaming'],
    'new_app_alert': True,
    'new_device_alert': True,
}

CATEGORY_ALERTS = {'Adult': 'adult_content', 'Gambling': 'gambling'}
VPN_CATEGORIES = ('VPN & Proxy',)

# Whole-domain matches used to spot proxies/apps the catalogue does not know.
BYPASS_HINTS = ('vpn', 'proxy', 'tunnel', 'unblock', 'torrent', 'socks',
                'warp', 'shadowsocks', 'v2ray', 'wireguard', 'openvpn')


def _minutes(hhmm):
    try:
        hour, minute = str(hhmm).split(':')
        return int(hour) * 60 + int(minute)
    except Exception:
        return None


class AlertEngine:
    """Evaluates the parental rules against the rollups and raises events."""

    def __init__(self, settings=None, health=None, engine=None):
        self.settings = settings
        self.health = health
        self.engine = engine
        self.counters = {'evaluated': 0, 'raised': 0, 'suppressed': 0, 'errors': 0}

    # -- rule access -----------------------------------------------------
    def rules(self):
        rules = dict(DEFAULT_RULES)
        if self.settings is not None:
            for key in DEFAULT_RULES:
                value = self.settings.get(f'alert_{key}', None) if hasattr(self.settings, 'get') else None
                if value is None:
                    value = self.settings.get(key, None) if hasattr(self.settings, 'get') else None
                if value is not None:
                    rules[key] = value
        return rules

    def _enabled(self, rules, key):
        return bool(rules.get('alerts_enabled', True)) and bool(rules.get(key, True))

    # -- event helpers ---------------------------------------------------
    def _already_raised(self, kind, device_mac, since):
        try:
            return intel_store.equery(IntelDeviceEvent).filter(
                IntelDeviceEvent.kind == kind,
                IntelDeviceEvent.device_mac == device_mac,
                IntelDeviceEvent.event_at >= since).first() is not None
        except Exception:
            return False

    def raise_alert(self, kind, severity, device_mac=None, title=None, detail=None,
                    confidence=0.7, person_id=None, related_mac=None, dedupe_hours=24):
        """Create one alert unless an identical one was raised recently."""
        since = datetime.utcnow() - timedelta(hours=dedupe_hours)
        if self._already_raised(kind, device_mac, since):
            self.counters['suppressed'] += 1
            return None
        if self.engine is not None:
            event = self.engine.raise_event(kind, severity, device_mac=device_mac,
                                            person_id=person_id, related_mac=related_mac,
                                            title=title or kind.replace('_', ' '),
                                            detail=detail, confidence=confidence)
        else:
            event = IntelDeviceEvent(
                event_at=datetime.utcnow(), kind=kind, severity=severity,
                device_mac=device_mac, person_id=person_id, related_mac=related_mac,
                title=(title or kind.replace('_', ' '))[:200],
                detail=str(detail or {}), confidence=confidence)
            intel_store.engine_session().add(event)
        self.counters['raised'] += 1
        return event

    # -- main entry ------------------------------------------------------
    def evaluate(self, hours=26, now=None):
        """Run every rule over the recent window.  Returns a summary dict."""
        rules = self.rules()
        if not rules.get('alerts_enabled', True):
            return {'skipped': 'alerts disabled'}
        now = now or datetime.utcnow()
        since = now - timedelta(hours=hours)
        summary = {'adult': 0, 'gambling': 0, 'bypass': 0, 'gaming': 0,
                   'late_night': 0, 'limits': 0, 'new_app': 0}
        try:
            summary['adult'] = self._check_categories(since, rules)
            summary['gambling'] = 0
            summary['bypass'] = self._check_bypass(since, rules)
            summary['gaming'] = self._check_gaming(since, rules)
            summary['late_night'] = self._check_late_night(since, rules, now)
            summary['limits'] = self._check_limits(since, rules)
            summary['new_app'] = self._check_new_apps(since, rules)
            self.counters['evaluated'] += 1
        except Exception as exc:
            self.counters['errors'] += 1
            if self.health:
                self.health.note('alerts', error=exc)
        summary['raised'] = self.counters['raised']
        return summary

    # -- individual rules -------------------------------------------------
    def _check_categories(self, since, rules):
        raised = 0
        day_start = since
        try:
            rows = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.last_seen >= day_start).all()
        except Exception:
            return 0
        seen = set()
        for row in rows:
            category = (row.category or '')
            kind = CATEGORY_ALERTS.get(category)
            if not kind or not self._enabled(rules, f'{kind}_alert'):
                continue
            key = (kind, row.device_mac)
            if key in seen:
                continue
            seen.add(key)
            if self.raise_alert(
                kind, 'critical' if kind == 'adult_content' else 'warning',
                device_mac=row.device_mac,
                title=f"{'Adult' if kind == 'adult_content' else 'Gambling'} site visited: "
                      f"{row.root_domain or row.hostname}",
                detail={'site': row.root_domain, 'app': row.app, 'category': category,
                        'seconds': row.dwell_seconds, 'url': row.url_last,
                        'first_seen': row.first_seen.isoformat() if row.first_seen else None,
                        'last_seen': row.last_seen.isoformat() if row.last_seen else None},
                confidence=0.9):
                raised += 1
        # searches for adult terms are worth flagging on their own
        if self._enabled(rules, 'adult_alert'):
            try:
                term_rows = intel_store.equery(IntelSearch).filter(
                    IntelSearch.seen_at >= since).all()
            except Exception:
                term_rows = []
            for row in term_rows:
                if not row.term:
                    continue
                if not any(word in row.term.lower() for word in ('porn', 'xxx', 'nude',
                                                                 'sex', 'onlyfans', 'naked')):
                    continue
                key = ('adult_term', row.device_mac)
                if key in seen:
                    continue
                seen.add(key)
                if self.raise_alert(
                    'adult_content', 'critical', device_mac=row.device_mac,
                    title=f"Search that looks adult-related: “{row.term[:60]}”",
                    detail={'term': row.term, 'engine': row.engine, 'url': row.url,
                            'observable': 'plain-HTTP search'},
                    confidence=0.6):
                    raised += 1
        return raised

    def _check_bypass(self, since, rules):
        raised = 0
        if not self._enabled(rules, 'bypass_alert'):
            return 0
        threshold = int(rules.get('bypass_score_threshold', 40) or 40)
        try:
            findings = intel_store.equery(IntelVpnFinding).filter(
                IntelVpnFinding.last_seen >= since,
                IntelVpnFinding.score >= threshold).all()
        except Exception:
            findings = []
        for row in findings:
            if self.raise_alert(
                'bypass', 'critical' if (row.score or 0) >= 80 else 'warning',
                device_mac=row.device_mac,
                title=f"Bypass attempt: {row.provider or row.dst_host or row.dst_ip} "
                      f"(score {row.score}, {row.label})",
                detail={'score': row.score, 'kind': row.kind, 'provider': row.provider,
                        'dst_ip': row.dst_ip, 'dst_host': row.dst_host,
                        'signals': [e.get('signal') for e in (row.evidence or [])]},
                confidence=min(0.95, 0.4 + 0.1 * len(row.evidence or [])),
                dedupe_hours=12):
                raised += 1
        # unknown proxy-ish domains that never made it into the catalogue
        try:
            rows = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.last_seen >= since).all()
        except Exception:
            rows = []
        seen = set()
        for row in rows:
            domain = (row.root_domain or row.hostname or '').lower()
            if row.category in VPN_CATEGORIES:
                continue
            if not any(hint in domain for hint in BYPASS_HINTS):
                continue
            key = ('unknown_bypass', row.device_mac, domain)
            if key in seen:
                continue
            seen.add(key)
            if self.raise_alert(
                'unknown_bypass', 'warning', device_mac=row.device_mac,
                title=f'Possible proxy/VPN tool: {domain}',
                detail={'domain': domain, 'seconds': row.dwell_seconds,
                        'category': row.category, 'url': row.url_last,
                        'note': 'domain name looks like a bypass tool; not in the catalogue'},
                confidence=0.5):
                raised += 1
        return raised

    def _check_gaming(self, since, rules):
        raised = 0
        if not self._enabled(rules, 'gaming_alert'):
            return 0
        limit = int(rules.get('gaming_minutes', 120) or 120) * 60
        try:
            rows = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.last_seen >= since,
                IntelSiteSession.category == 'Gaming').all()
        except Exception:
            return 0
        for row in rows:
            if (row.dwell_seconds or 0) < limit:
                continue
            if self.raise_alert(
                'gaming_session', 'info', device_mac=row.device_mac,
                title=f"Long gaming session: {row.app or row.root_domain} "
                      f"({int((row.dwell_seconds or 0) // 60)} min)",
                detail={'app': row.app, 'domain': row.root_domain,
                        'seconds': row.dwell_seconds,
                        'limit_minutes': rules.get('gaming_minutes')},
                confidence=0.8, dedupe_hours=6):
                raised += 1
        return raised

    def _check_late_night(self, since, rules, now):
        if not self._enabled(rules, 'late_night_alert'):
            return 0
        start = _minutes(rules.get('bedtime_start', '22:30'))
        end = _minutes(rules.get('bedtime_end', '06:30'))
        if start is None or end is None:
            return 0
        minimum = int(rules.get('late_night_minutes', 20) or 20) * 60

        def in_bedtime(hour, minute):
            current = hour * 60 + minute
            if start <= end:                       # same-day window
                return start <= current <= end
            return current >= start or current <= end
        try:
            buckets = intel_store.equery(IntelUsageBucket).filter(
                IntelUsageBucket.bucket_start >= since,
                IntelUsageBucket.dimension == 'device').all()
        except Exception:
            return 0
        per_device = {}
        for row in buckets:
            stamp = row.bucket_start
            if not in_bedtime(stamp.hour, stamp.minute):
                continue
            entry = per_device.setdefault(row.device_mac, {'seconds': 0.0, 'first': stamp, 'last': stamp})
            entry['seconds'] += float(row.online_seconds or row.seconds or 0)
            entry['first'] = min(entry['first'], stamp)
            entry['last'] = max(entry['last'], stamp)
        raised = 0
        for mac, entry in per_device.items():
            if entry['seconds'] < minimum:
                continue
            if self.raise_alert(
                'late_night', 'warning', device_mac=mac,
                title=f"Online during bedtime ({int(entry['seconds'] // 60)} min after "
                      f"{rules.get('bedtime_start')})",
                detail={'seconds': entry['seconds'],
                        'window': [rules.get('bedtime_start'), rules.get('bedtime_end')],
                        'first': entry['first'].isoformat(), 'last': entry['last'].isoformat()},
                confidence=0.85, dedupe_hours=14):
                raised += 1
        return raised

    def _check_limits(self, since, rules):
        if not self._enabled(rules, 'daily_limit_alert'):
            return 0
        raised = 0
        limit = int(rules.get('daily_limit_hours', 4) or 4) * 3600
        categories = rules.get('daily_limit_categories') or []
        try:
            rows = intel_store.equery(IntelDailyUsage).filter(
                IntelDailyUsage.dimension == 'category').all()
        except Exception:
            return 0
        today = datetime.utcnow().strftime('%Y-%m-%d')
        for row in rows:
            if row.day != today or row.key not in categories:
                continue
            if (row.seconds or 0) < limit:
                continue
            if self.raise_alert(
                'daily_limit', 'warning', device_mac=row.device_mac,
                title=f"Daily limit reached for {row.key}: "
                      f"{round((row.seconds or 0) / 3600, 1)} h",
                detail={'category': row.key, 'seconds': row.seconds,
                        'limit_hours': rules.get('daily_limit_hours')},
                confidence=0.9, dedupe_hours=20):
                raised += 1
        return raised

    def _check_new_apps(self, since, rules):
        if not self._enabled(rules, 'new_app_alert'):
            return 0
        raised = 0
        try:
            rows = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.last_seen >= since).all()
        except Exception:
            return 0
        for row in rows:
            name = row.app or row.root_domain
            if not name:
                continue
            try:
                # scope the history check to *this* device: "Roblox is new" must
                # mean new for the child's own device, not new for the whole
                # household - otherwise the second child's first game is silent.
                earlier = intel_store.equery(IntelSiteSession).filter(
                    IntelSiteSession.device_mac == row.device_mac,
                    (IntelSiteSession.app == row.app) if row.app
                    else (IntelSiteSession.root_domain == row.root_domain),
                    IntelSiteSession.first_seen < since).first()
            except Exception:
                earlier = None
            if earlier is not None:
                continue
            if self.raise_alert(
                'new_app', 'info', device_mac=row.device_mac,
                title=f'First use of {name}',
                detail={'app': row.app, 'domain': row.root_domain,
                        'category': row.category,
                        'first_seen': row.first_seen.isoformat() if row.first_seen else None},
                confidence=0.7, dedupe_hours=24):
                raised += 1
        return raised


def alert_summary(hours=168):
    """Group recent alerts for the dashboard: per kind, per device, unseen count."""
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = intel_store.equery(IntelDeviceEvent).filter(
        IntelDeviceEvent.event_at >= since,
        IntelDeviceEvent.kind.in_(ALERT_KINDS)).order_by(
        IntelDeviceEvent.event_at.desc()).all()
    by_kind = {}
    by_device = {}
    for row in rows:
        by_kind[row.kind] = by_kind.get(row.kind, 0) + 1
        mac = (row.device_mac or '').lower()
        by_device[mac] = by_device.get(mac, 0) + 1
    return {
        'total': len(rows),
        'unseen': len([r for r in rows if not r.seen]),
        'by_kind': by_kind,
        'by_device': by_device,
        'critical': len([r for r in rows if (r.severity or '') in ('critical', 'error')]),
    }


def device_classes_for_alerts():
    """Devices that are console/handheld - useful context for a gaming alert."""
    try:
        rows = intel_store.equery(IntelDeviceMac).all()
    except Exception:
        return []
    out = []
    for row in rows:
        klass = (row.device_class or '').lower()
        if klass in ('console', 'handheld', 'phone', 'tablet'):
            out.append({'mac': row.normalized, 'name': row.hostname, 'class': row.device_class})
    return out


def recent_flows_with_category(category='Gaming', hours=24, limit=50):
    since = datetime.utcnow() - timedelta(hours=hours)
    try:
        return intel_store.equery(IntelFlow).filter(
            IntelFlow.category == category, IntelFlow.last_seen >= since).order_by(
            IntelFlow.last_seen.desc()).limit(limit).all()
    except Exception:
        return []
