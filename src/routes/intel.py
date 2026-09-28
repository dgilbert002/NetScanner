"""
REST API for the intelligence layer (all endpoints under ``/api/intel``).

Design goals
------------
* **Never invent data.**  Every row carries ``freshness`` (live / idle / recent /
  today / historic), ``source`` and ``is_estimated`` so the UI can separate
  observed facts from delayed or inferred data.
* **Answer the questions directly**: what is being used right now, what was used
  today, how long, on which device, by whom (with a probability), and whether
  anything is trying to bypass the home network.
* **Cheap queries.**  Everything reads the 5-minute buckets / daily rollups that
  the sessionizer maintains, not the raw evidence table.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

from src.models.user import db
from src.intel.catalog import DEFAULT_CATALOG, catalog_summary, root_domain
from src.intel.maclab import is_valid_mac, normalize_mac, vendor_for
from src.intel.models import (
    IntelBehaviorProfile,
    IntelDailyUsage,
    IntelDeviceEvent,
    IntelDeviceMac,
    IntelFlow,
    IntelIdentityScore,
    IntelObservation,
    IntelOnlineDay,
    IntelPerson,
    IntelRevision,
    IntelSiteSession,
    IntelUsageBucket,
    IntelVpnFinding,
)
from src.intel import store as intel_store

intel_bp = Blueprint('intel', __name__, url_prefix='/api/intel')


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _engine():
    from src.intel.engine import get_engine
    return get_engine()


def _settings():
    engine = _engine()
    return engine.settings if engine else None


def _idle_seconds():
    settings = _settings()
    return int((settings.get('idle_seconds', 90) if settings else 90) or 90)


def freshness(last_seen, source=None, is_estimated=False, idle=None):
    """Classify a row so the UI can draw the live / delayed distinction."""
    if not last_seen:
        return {'state': 'unknown', 'age_seconds': None, 'is_delayed': True,
                'source': source, 'is_estimated': bool(is_estimated)}
    idle = idle or _idle_seconds()
    age = (datetime.utcnow() - last_seen).total_seconds()
    if age <= 60:
        state = 'live'
    elif age <= idle:
        state = 'idle'
    elif age <= 900:
        state = 'recent'
    elif last_seen.date() == datetime.utcnow().date():
        state = 'today'
    else:
        state = 'historic'
    delayed_sources = {'pihole', 'netstat', 'backfill', 'import', 'scan'}
    return {
        'state': state,
        'age_seconds': int(age),
        'is_delayed': bool(is_estimated or (source in delayed_sources) or age > 900),
        'source': source,
        'is_estimated': bool(is_estimated),
    }


def _device_labels():
    """MAC -> {name, vendor, randomized, device_key, star, person}."""
    labels = {}
    try:
        for row in IntelDeviceMac.query.all():
            mac = (row.normalized or row.mac or '').lower()
            labels[mac] = {
                'mac': mac,
                'name': row.hostname or row.mac,
                'vendor': row.vendor,
                'device_class': row.device_class,
                'is_randomized': bool(row.is_randomized),
                'random_kind': row.random_kind,
                'device_key': row.device_key,
                'mac_rotations': row.mac_rotations or 0,
                'first_seen': row.first_seen.isoformat() if row.first_seen else None,
                'last_seen': row.last_seen.isoformat() if row.last_seen else None,
                'is_active': bool(row.is_active),
            }
    except Exception:
        pass
    return labels


def _identity_map():
    """MAC -> best identity score row."""
    out = {}
    try:
        rows = IntelIdentityScore.query.order_by(IntelIdentityScore.probability.desc()).all()
        for row in rows:
            mac = (row.device_mac or '').lower()
            if mac not in out:
                out[mac] = {
                    'person': row.person_name,
                    'person_id': row.person_id,
                    'probability': round(row.probability or 0, 3),
                    'similarity': round(row.similarity or 0, 3),
                    'prior_reason': (json.loads(row.explanation or '{}') or {}).get('prior_reason'),
                    'locked': bool(row.locked),
                    'is_binding': bool(row.is_binding),
                }
    except Exception:
        pass
    return out


def _star_map(hours=48):
    """MAC -> movement event (drives the star in the UI)."""
    out = {}
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        rows = IntelDeviceEvent.query.filter(
            IntelDeviceEvent.event_at >= since,
            IntelDeviceEvent.kind.in_(('mac_rotation', 'mac_handoff', 'identity_recovered',
                                       'identity_switch'))).order_by(
            IntelDeviceEvent.event_at.desc()).all()
        for row in rows:
            for mac in (row.device_mac, row.related_mac):
                if mac and mac not in out:
                    out[mac] = {
                        'kind': row.kind, 'title': row.title,
                        'at': row.event_at.isoformat() if row.event_at else None,
                        'confidence': row.confidence,
                        'related_mac': row.related_mac if mac == row.device_mac else row.device_mac,
                    }
    except Exception:
        pass
    return out


def _window_hours():
    try:
        return max(1, min(24 * 30, int(request.args.get('hours', 24))))
    except Exception:
        return 24


def _day_param():
    day = request.args.get('day')
    if day:
        try:
            datetime.strptime(day, '%Y-%m-%d')
            return day
        except Exception:
            pass
    return datetime.utcnow().strftime('%Y-%m-%d')


def _limit(default=100, maximum=1000):
    try:
        return max(1, min(maximum, int(request.args.get('limit', default))))
    except Exception:
        return default


def _seconds_to_hms(seconds):
    seconds = int(seconds or 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f'{hours}h {minutes}m'
    if minutes:
        return f'{minutes}m {secs}s'
    return f'{secs}s'


# ---------------------------------------------------------------------------
# status / settings / quality
# ---------------------------------------------------------------------------

@intel_bp.route('/status')
def status():
    engine = _engine()
    if not engine:
        return jsonify({'error': 'intelligence engine not initialised'}), 503
    return jsonify(engine.status())


@intel_bp.route('/settings', methods=['GET'])
def get_settings():
    engine = _engine()
    settings = engine.settings if engine else None
    if not settings:
        return jsonify({'error': 'engine unavailable'}), 503
    return jsonify(settings.to_dict())


@intel_bp.route('/settings', methods=['POST'])
def update_settings():
    engine = _engine()
    if not engine:
        return jsonify({'error': 'engine unavailable'}), 503
    patch = request.get_json(force=True, silent=True) or {}
    clean = {}
    for key, value in patch.items():
        if key in ('idle_seconds', 'retention_days', 'behavior_days', 'behavior_interval_seconds',
                   'vpn_scan_interval_seconds', 'retention_interval_seconds',
                   'sessionizer_flush_seconds'):
            try:
                clean[key] = max(5, int(value))
            except Exception:
                continue
        elif key in ('enabled', 'capture_enabled', 'mirror_legacy_tables', 'feeds_enabled',
                     'track_private_macs'):
            clean[key] = bool(value)
        elif key == 'interface':
            clean[key] = value or None
    engine.settings.update(clean)
    if 'idle_seconds' in clean:
        engine.sessionizer.idle_seconds = int(clean['idle_seconds'])
        engine.behavior.idle_seconds = int(clean['idle_seconds'])
    return jsonify(engine.settings.to_dict())


@intel_bp.route('/quality')
def quality():
    """Data-quality dashboard: what is live, what is delayed, what is missing."""
    engine = _engine()
    payload = {
        'generated_at': datetime.utcnow().isoformat(),
        'catalog': catalog_summary(),
        'database': intel_store.database_stats(),
        'health': engine.health_summary() if engine else None,
        'retention_days': (engine.settings.get('retention_days') if engine else None),
    }
    try:
        now = datetime.utcnow()
        windows = {'1h': 1, '24h': 24, '7d': 24 * 7}
        observations = {}
        for label, hours in windows.items():
            since = now - timedelta(hours=hours)
            rows = IntelObservation.query.filter(IntelObservation.observed_at >= since).all()
            observations[label] = {
                'count': len(rows),
                'named': len([r for r in rows if r.sni or r.http_host or r.dns_qname or r.quic_sni]),
                'estimated': len([r for r in rows if r.is_estimated]),
                'avg_lag_ms': round(sum((r.latency_ms or 0) for r in rows) / len(rows), 1) if rows else 0,
                'by_source': _count_by(rows, 'source'),
                'by_collector': _count_by(rows, 'collector'),
                'by_name_source': _count_by([
                    {'key': (r.sni and 'sni') or (r.quic_sni and 'quic') or (r.http_host and 'http')
                     or (r.dns_qname and 'dns') or 'ip-only'} for r in rows], 'key'),
            }
        payload['observations'] = observations
        payload['flows'] = {
            'live': IntelFlow.query.filter(IntelFlow.state == 'live').count(),
            'idle': IntelFlow.query.filter(IntelFlow.state == 'idle').count(),
            'closed_24h': IntelFlow.query.filter(
                IntelFlow.closed_at >= now - timedelta(hours=24)).count(),
            'estimated_24h': IntelFlow.query.filter(
                IntelFlow.last_seen >= now - timedelta(hours=24),
                IntelFlow.is_estimated == True).count(),  # noqa: E712
        }
        payload['revisions_24h'] = IntelRevision.query.filter(
            IntelRevision.created_at >= now - timedelta(hours=24)).count()
    except Exception as exc:
        payload['error'] = str(exc)
    return jsonify(payload)


def _count_by(rows, attr):
    out = {}
    for row in rows:
        key = getattr(row, attr, None) if not isinstance(row, dict) else row.get(attr)
        key = key or 'unknown'
        out[key] = out.get(key, 0) + 1
    return out


# ---------------------------------------------------------------------------
# live / recent activity
# ---------------------------------------------------------------------------

@intel_bp.route('/live')
def live():
    """What is being used right now, with names, stars and identity hints."""
    idle = _idle_seconds()
    now = datetime.utcnow()
    window = now - timedelta(minutes=max(2, idle // 30))
    labels = _device_labels()
    identities = _identity_map()
    stars = _star_map()

    flows = IntelFlow.query.filter(IntelFlow.last_seen >= window).order_by(
        IntelFlow.last_seen.desc()).limit(_limit(300, 1000)).all()
    sites = IntelSiteSession.query.filter(IntelSiteSession.last_seen >= window).order_by(
        IntelSiteSession.dwell_seconds.desc()).limit(_limit(200, 1000)).all()

    rows = []
    for site in sites:
        mac = (site.device_mac or '').lower()
        label = labels.get(mac, {})
        second_mac = None
        for other, info in labels.items():
            if other != mac and info.get('device_key') and info['device_key'] == label.get('device_key'):
                second_mac = other
                break
        rows.append({
            'device_mac': mac or None,
            'device': label.get('name') or mac or 'unknown',
            'device_vendor': label.get('vendor'),
            'device_randomized_mac': label.get('is_randomized'),
            'alt_mac': second_mac,
            'app': site.app,
            'site': site.root_domain,
            'url': site.url_last,
            'category': site.category,
            'seconds': site.dwell_seconds or 0,
            'duration_human': _seconds_to_hms(site.dwell_seconds),
            'pageviews': site.pageviews,
            'bytes_total': site.bytes_total,
            'state': site.state,
            'identity': identities.get(mac),
            'star': stars.get(mac),
            'freshness': freshness(site.last_seen, site.source, site.is_estimated, idle),
            'last_seen': site.last_seen.isoformat() if site.last_seen else None,
            'first_seen': site.first_seen.isoformat() if site.first_seen else None,
        })

    return jsonify({
        'now': now.isoformat(),
        'idle_seconds': idle,
        'count': len(rows),
        'sessions': rows,
        'flows_active': len(flows),
        'generated_at': now.isoformat(),
    })


@intel_bp.route('/sessions')
def sessions():
    """Unified session list for the Live table (flows + site visits)."""
    idle = _idle_seconds()
    hours = _window_hours()
    since = datetime.utcnow() - timedelta(hours=hours)
    labels = _device_labels()
    identities = _identity_map()
    stars = _star_map()
    only = request.args.get('state')

    query = IntelFlow.query.filter(IntelFlow.last_seen >= since)
    if only in ('live', 'idle', 'closed'):
        query = query.filter(IntelFlow.state == only)
    flows = query.order_by(IntelFlow.last_seen.desc()).limit(_limit(300, 2000)).all()

    rows = []
    for flow in flows:
        mac = (flow.device_mac or '').lower()
        label = labels.get(mac, {})
        rows.append({
            'id': flow.id,
            'device_mac': mac or None,
            'device': label.get('name') or mac or flow.src_ip or 'unknown',
            'vendor': label.get('vendor'),
            'randomized_mac': label.get('is_randomized'),
            'app': flow.app,
            'site': flow.root_domain,
            'url': flow.url_sample,
            'hostname': flow.hostname,
            'category': flow.category,
            'protocol': flow.protocol,
            'dst_port': flow.dst_port,
            'bytes_up': flow.bytes_up,
            'bytes_down': flow.bytes_down,
            'bytes_total': flow.total_bytes(),
            'packets': flow.packets,
            'duration_seconds': flow.duration_seconds,
            'duration_human': _seconds_to_hms(flow.duration_seconds),
            'name_source': flow.name_source,
            'name_confidence': flow.name_confidence,
            'first_seen': flow.first_seen.isoformat() if flow.first_seen else None,
            'last_seen': flow.last_seen.isoformat() if flow.last_seen else None,
            'closed_at': flow.closed_at.isoformat() if flow.closed_at else None,
            'close_reason': flow.close_reason,
            'state': flow.state,
            'source': flow.source,
            'is_estimated': bool(flow.is_estimated),
            'identity': identities.get(mac),
            'star': stars.get(mac),
            'freshness': freshness(flow.last_seen, flow.source, flow.is_estimated, idle),
        })
    return jsonify({'count': len(rows), 'hours': hours, 'sessions': rows,
                    'generated_at': datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# usage: what was used today / per app / per site
# ---------------------------------------------------------------------------

@intel_bp.route('/apps')
def apps():
    return _usage_report(dimension='app')


@intel_bp.route('/sites')
def sites():
    return _usage_report(dimension='site')


@intel_bp.route('/categories')
def categories():
    return _usage_report(dimension='category')


def _usage_report(dimension, day=None):
    day = day or _day_param()
    hours = request.args.get('hours')
    mac = request.args.get('mac')
    mac = (mac or '').lower() or None
    labels = _device_labels()
    stars = _star_map()

    since = None
    if hours:
        since = datetime.utcnow() - timedelta(hours=_window_hours())
        rows = IntelUsageBucket.query.filter(
            IntelUsageBucket.dimension == dimension,
            IntelUsageBucket.bucket_start >= since).all()
        if mac:
            rows = [r for r in rows if (r.device_mac or '').lower() == mac]
        aggregated = {}
        for row in rows:
            entry = aggregated.setdefault(row.key, {
                'key': row.key, 'seconds': 0, 'bytes': 0, 'sessions': 0,
                'devices': set(), 'source': row.source, 'is_estimated': bool(row.is_estimated),
                'first_seen': row.bucket_start, 'last_seen': row.bucket_start})
            entry['seconds'] += row.seconds or 0
            entry['bytes'] += row.bytes_total or 0
            entry['sessions'] += row.sessions or 0
            entry['devices'].add(row.device_mac)
            entry['first_seen'] = min(entry['first_seen'], row.bucket_start)
            entry['last_seen'] = max(entry['last_seen'], row.bucket_start)
    else:
        query = IntelDailyUsage.query.filter(IntelDailyUsage.day == day,
                                             IntelDailyUsage.dimension == dimension)
        if mac:
            query = query.filter(IntelDailyUsage.device_mac == mac)
        rows = query.all()
        aggregated = {}
        for row in rows:
            entry = aggregated.setdefault(row.key, {
                'key': row.key, 'seconds': 0, 'bytes': 0, 'sessions': 0,
                'devices': set(), 'source': 'live', 'is_estimated': bool(row.is_estimated),
                'first_seen': row.first_seen, 'last_seen': row.last_seen})
            entry['seconds'] += row.seconds or 0
            entry['bytes'] += row.bytes_total or 0
            entry['sessions'] += row.sessions or 0
            entry['devices'].add(row.device_mac)
            if row.first_seen and (not entry['first_seen'] or row.first_seen < entry['first_seen']):
                entry['first_seen'] = row.first_seen
            if row.last_seen and (not entry['last_seen'] or row.last_seen > entry['last_seen']):
                entry['last_seen'] = row.last_seen

    items = []
    for key, entry in aggregated.items():
        devices = []
        for device_mac in entry['devices']:
            if not device_mac:
                continue
            device_mac = device_mac.lower()
            info = labels.get(device_mac, {})
            devices.append({
                'mac': device_mac,
                'name': info.get('name') or device_mac,
                'randomized': info.get('is_randomized'),
                'star': stars.get(device_mac),
            })
        name_info = DEFAULT_CATALOG.lookup_host(key) if dimension == 'site' else None
        items.append({
            'key': key,
            'name': (name_info or {}).get('owner') or key,
            'category': (name_info or {}).get('category') if name_info else None,
            'seconds': int(entry['seconds']),
            'duration_human': _seconds_to_hms(entry['seconds']),
            'bytes': int(entry['bytes']),
            'sessions': int(entry['sessions']),
            'devices': devices,
            'device_count': len(devices),
            'first_seen': entry['first_seen'].isoformat() if entry.get('first_seen') else None,
            'last_seen': entry['last_seen'].isoformat() if entry.get('last_seen') else None,
            'is_estimated': bool(entry.get('is_estimated')),
            'source': entry.get('source'),
        })
    items.sort(key=lambda x: -x['seconds'])
    total = sum(i['seconds'] for i in items)
    return jsonify({
        'dimension': dimension,
        'day': day if not hours else None,
        'hours': hours,
        'total_seconds': total,
        'total_human': _seconds_to_hms(total),
        'count': len(items),
        'items': items[:_limit(200)],
        'generated_at': datetime.utcnow().isoformat(),
    })


@intel_bp.route('/timeline')
def timeline():
    """5-minute buckets for a device/day (stacked per app or category)."""
    day = _day_param()
    mac = (request.args.get('mac') or '').lower() or None
    dimension = request.args.get('dimension', 'category')
    if dimension not in ('app', 'site', 'category', 'device'):
        dimension = 'category'
    start = datetime.strptime(day, '%Y-%m-%d')
    end = start + timedelta(days=1)
    query = IntelUsageBucket.query.filter(IntelUsageBucket.bucket_start >= start,
                                          IntelUsageBucket.bucket_start < end,
                                          IntelUsageBucket.dimension == dimension)
    if mac:
        query = query.filter(IntelUsageBucket.device_mac == mac)
    rows = query.all()
    buckets = {}
    series = {}
    for row in rows:
        key = row.bucket_start.strftime('%H:%M')
        entry = buckets.setdefault(key, {'time': key, 'bucket_start': row.bucket_start.isoformat(),
                                         'seconds': 0, 'online_seconds': 0, 'bytes': 0})
        entry['seconds'] += row.seconds or 0
        entry['online_seconds'] += row.online_seconds or 0
        entry['bytes'] += row.bytes_total or 0
        series.setdefault(row.key, {})[key] = (row.seconds or 0)
    keys = sorted(buckets.keys())
    return jsonify({
        'day': day, 'dimension': dimension, 'device_mac': mac,
        'buckets': [buckets[k] for k in keys],
        'series': [{'key': k, 'points': [{'time': t, 'seconds': v} for t, v in sorted(vals.items())]}
                   for k, vals in sorted(series.items(), key=lambda x: -sum(x[1].values()))[:12]],
        'generated_at': datetime.utcnow().isoformat(),
    })


@intel_bp.route('/devices')
def devices():
    """Registered devices with MAC/history/identity/star detail."""
    labels = _device_labels()
    identities = _identity_map()
    stars = _star_map(hours=72)
    today = datetime.utcnow().strftime('%Y-%m-%d')
    online = {row.device_mac: row for row in IntelOnlineDay.query.filter_by(day=today).all()}

    out = []
    for mac, info in labels.items():
        device_online = online.get(mac)
        out.append({
            **info,
            'online_today_seconds': device_online.online_seconds if device_online else 0,
            'online_today_human': _seconds_to_hms(device_online.online_seconds if device_online else 0),
            'identity': identities.get(mac),
            'star': stars.get(mac),
            'freshness': freshness(
                datetime.fromisoformat(info['last_seen']) if info.get('last_seen') else None,
                'live', False),
        })
    out.sort(key=lambda x: (-(x.get('online_today_seconds') or 0), x.get('name') or ''))
    return jsonify({'count': len(out), 'devices': out,
                    'generated_at': datetime.utcnow().isoformat()})


@intel_bp.route('/device/<path:mac>')
def device_detail(mac):
    norm = normalize_mac(mac) or mac.lower()
    row = IntelDeviceMac.query.filter_by(normalized=norm).first()
    if row is None:
        return jsonify({'error': 'device not found'}), 404
    labels = _device_labels()
    stars = _star_map(hours=24 * 7)

    siblings = []
    if row.device_key:
        siblings = [{
            'mac': sib.normalized, 'first_seen': sib.first_seen.isoformat() if sib.first_seen else None,
            'last_seen': sib.last_seen.isoformat() if sib.last_seen else None,
            'randomized': bool(sib.is_randomized), 'vendor': sib.vendor,
            'hostname': sib.hostname,
        } for sib in IntelDeviceMac.query.filter_by(device_key=row.device_key).all()
            if sib.normalized != norm]

    flows = IntelFlow.query.filter(
        IntelFlow.device_mac.in_([norm, row.mac] + [s['mac'] for s in siblings if s['mac']])
    ).order_by(IntelFlow.last_seen.desc()).limit(200).all()
    sites = IntelSiteSession.query.filter(
        IntelSiteSession.device_mac.in_([norm, row.mac] + [s['mac'] for s in siblings if s['mac']])
    ).order_by(IntelSiteSession.dwell_seconds.desc()).limit(50).all()
    events = IntelDeviceEvent.query.filter(
        db.or_(IntelDeviceEvent.device_mac == norm, IntelDeviceEvent.related_mac == norm)
    ).order_by(IntelDeviceEvent.event_at.desc()).limit(50).all()
    findings = IntelVpnFinding.query.filter(
        IntelVpnFinding.device_mac.in_([norm, row.mac] + [s['mac'] for s in siblings if s['mac']])
    ).order_by(IntelVpnFinding.last_seen.desc()).limit(50).all()
    scores = IntelIdentityScore.query.filter(
        IntelIdentityScore.device_mac.in_([norm, row.mac] + [s['mac'] for s in siblings if s['mac']])
    ).order_by(IntelIdentityScore.probability.desc()).limit(10).all()

    return jsonify({
        'device': row.to_dict(),
        'label': labels.get(norm),
        'star': stars.get(norm),
        'sibling_macs': siblings,
        'flows': [f.to_dict() for f in flows],
        'sites': [s.to_dict() for s in sites],
        'events': [e.to_dict() for e in events],
        'vpn_findings': [f.to_dict() for f in findings],
        'identity_scores': [s.to_dict() for s in scores],
        'generated_at': datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# identity / behaviour
# ---------------------------------------------------------------------------

@intel_bp.route('/identity')
def identity():
    """Per-device identity probabilities with the reasons behind them."""
    engine = _engine()
    scores = {}
    try:
        for row in IntelIdentityScore.query.order_by(IntelIdentityScore.probability.desc()).all():
            mac = (row.device_mac or '').lower()
            scores.setdefault(mac, []).append(row.to_dict())
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    profiles = {}
    try:
        for row in IntelBehaviorProfile.query.filter_by(subject_type='person').all():
            profiles[row.subject_key] = row.to_dict()
    except Exception:
        pass
    labels = _device_labels()
    stars = _star_map(hours=24 * 7)
    out = []
    for mac, cands in scores.items():
        best = cands[0] if cands else None
        out.append({
            'device_mac': mac,
            'device': (labels.get(mac) or {}).get('name') or mac,
            'is_randomized': (labels.get(mac) or {}).get('is_randomized'),
            'best': best,
            'candidates': cands[:4],
            'star': stars.get(mac),
            'needs_review': bool(best and (best.get('probability') or 0) < 0.5),
        })
    out.sort(key=lambda x: -((x['best'] or {}).get('probability') or 0))
    return jsonify({
        'count': len(out),
        'devices': out,
        'people': [p.to_dict() for p in IntelPerson.query.all()],
        'person_profiles': profiles,
        'generated_at': datetime.utcnow().isoformat(),
    })


@intel_bp.route('/identity/rescore', methods=['POST'])
def rescore():
    engine = _engine()
    if not engine:
        return jsonify({'error': 'engine unavailable'}), 503
    try:
        profiles = engine.behavior.update_profiles()
        summary = engine.behavior.score_all()
        return jsonify({'profiles': profiles, 'scores': summary,
                        'generated_at': datetime.utcnow().isoformat()})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@intel_bp.route('/people', methods=['GET'])
def list_people():
    people = IntelPerson.query.order_by(IntelPerson.name).all()
    result = []
    for person in people:
        from src.intel.behavior import bound_macs_for_person_id
        macs = sorted(bound_macs_for_person_id(person.id))
        result.append({**person.to_dict(), 'macs': macs, 'mac_count': len(macs)})
    return jsonify({'people': result})


@intel_bp.route('/people', methods=['POST'])
def create_person():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400
    existing = IntelPerson.query.filter_by(name=name).first()
    if existing:
        return jsonify({'error': 'person already exists', 'person': existing.to_dict()}), 409
    person = IntelPerson(name=name, display_name=data.get('display_name') or name,
                         profile_id=data.get('profile_id'), color=data.get('color') or '#3498db',
                         is_child=bool(data.get('is_child')), notes=data.get('notes'))
    db.session.add(person)
    db.session.commit()
    return jsonify({'person': person.to_dict()}), 201


@intel_bp.route('/people/<int:person_id>/bind', methods=['POST'])
def bind_device(person_id):
    """Confirm (or reject) that a MAC belongs to a person."""
    person = IntelPerson.query.get(person_id)
    if person is None:
        return jsonify({'error': 'person not found'}), 404
    data = request.get_json(force=True, silent=True) or {}
    mac = normalize_mac(data.get('mac') or '') or (data.get('mac') or '').lower()
    if not mac:
        return jsonify({'error': 'mac is required'}), 400
    locked = bool(data.get('locked', True))
    row = IntelIdentityScore.query.filter_by(device_mac=mac, person_id=person_id).first()
    if row is None:
        row = IntelIdentityScore(device_mac=mac, person_id=person_id, person_name=person.name)
        db.session.add(row)
    row.locked = locked
    row.is_binding = locked
    row.probability = 0.99 if locked else row.probability
    row.method = 'user_confirmed' if locked else row.method
    row.is_estimated = False if locked else True
    # Keep the reason visible in the UI and in the score explanation, so a
    # confirmed binding never looks like a behaviour guess.
    explanation = json.loads(row.explanation or '{}') if row.explanation else {}
    explanation['prior_reason'] = 'confirmed' if locked else 'rejected_by_user'
    explanation['note'] = ('Confirmed by the user' if locked
                           else 'Rejected by the user - do not suggest this match')
    row.explanation = json.dumps(explanation)
    db.session.commit()
    return jsonify({'score': row.to_dict(), 'message': 'binding saved'})


# ---------------------------------------------------------------------------
# VPN / bypass
# ---------------------------------------------------------------------------

@intel_bp.route('/vpn')
def vpn_findings():
    engine = _engine()
    hours = _window_hours()
    since = datetime.utcnow() - timedelta(hours=hours)
    labels = _device_labels()
    rows = IntelVpnFinding.query.filter(IntelVpnFinding.last_seen >= since).order_by(
        IntelVpnFinding.score.desc()).limit(_limit(300)).all()
    findings = []
    for row in rows:
        entry = row.to_dict()
        label = labels.get((row.device_mac or '').lower(), {})
        entry['device'] = label.get('name') or row.device_mac
        entry['freshness'] = freshness(row.last_seen, 'live', row.is_estimated)
        findings.append(entry)
    device_scores = engine.vpn.device_scores(hours=hours) if engine else []
    for entry in device_scores:
        label = labels.get((entry.get('device_mac') or '').lower(), {})
        entry['device'] = label.get('name') or entry.get('device_mac')
        if entry.get('top'):
            entry['top']['freshness'] = freshness(
                datetime.fromisoformat(entry['top']['last_seen']) if entry['top'].get('last_seen') else None,
                'live', entry['top'].get('is_estimated'))
    return jsonify({
        'hours': hours,
        'findings': findings,
        'devices': device_scores,
        'flagged_devices': len([d for d in device_scores if d['score'] >= 40]),
        'generated_at': datetime.utcnow().isoformat(),
    })


@intel_bp.route('/vpn/scan', methods=['POST'])
def vpn_scan():
    engine = _engine()
    if not engine:
        return jsonify({'error': 'engine unavailable'}), 503
    hours = _window_hours()
    found = engine.vpn.scan_flows(hours=hours)
    found += engine.vpn.scan_dns_bypass(hours=min(hours, 24))
    return jsonify({'findings_recorded': found, 'hours': hours})


@intel_bp.route('/vpn/<int:finding_id>/seen', methods=['POST'])
def vpn_seen(finding_id):
    row = IntelVpnFinding.query.get(finding_id)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    row.seen = True
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# events (stars / alerts)
# ---------------------------------------------------------------------------

@intel_bp.route('/events')
def events():
    kind = request.args.get('kind')
    query = IntelDeviceEvent.query
    if kind:
        query = query.filter(IntelDeviceEvent.kind == kind)
    if request.args.get('hours'):
        since = datetime.utcnow() - timedelta(hours=_window_hours())
        query = query.filter(IntelDeviceEvent.event_at >= since)
    rows = query.order_by(IntelDeviceEvent.event_at.desc()).limit(_limit(200)).all()
    labels = _device_labels()
    out = []
    for row in rows:
        entry = row.to_dict()
        label = labels.get((row.device_mac or '').lower(), {})
        entry['device'] = label.get('name') or row.device_mac
        out.append(entry)
    return jsonify({'count': len(out), 'events': out,
                    'unseen': IntelDeviceEvent.query.filter_by(seen=False).count(),
                    'generated_at': datetime.utcnow().isoformat()})


@intel_bp.route('/events/seen', methods=['POST'])
def events_seen():
    """Mark every unseen event as seen (bulk acknowledge from the UI)."""
    updated = IntelDeviceEvent.query.filter_by(seen=False).update({'seen': True})
    db.session.commit()
    return jsonify({'updated': updated})


@intel_bp.route('/events/<int:event_id>/seen', methods=['POST'])
def event_seen(event_id):
    row = IntelDeviceEvent.query.get(event_id)
    if row is None:
        return jsonify({'error': 'not found'}), 404
    row.seen = True
    db.session.commit()
    return jsonify({'ok': True})


@intel_bp.route('/events/clear', methods=['POST'])
def events_clear():
    data = request.get_json(force=True, silent=True) or {}
    query = IntelDeviceEvent.query
    if data.get('seen_only', True):
        query = query.filter_by(seen=True)
    deleted = query.delete()
    db.session.commit()
    return jsonify({'deleted': deleted})


# ---------------------------------------------------------------------------
# naming / lookup
# ---------------------------------------------------------------------------

@intel_bp.route('/name')
def name_lookup():
    """Identify a URL, hostname, IP or app name."""
    host = request.args.get('host') or request.args.get('url') or ''
    ip = request.args.get('ip')
    if host.startswith('http'):
        from urllib.parse import urlparse
        host = urlparse(host).hostname or ''
    name = DEFAULT_CATALOG.lookup_host(host) if host else None
    payload = {'query': request.args.get('host') or request.args.get('url') or ip,
               'host': host, 'name': name}
    if ip:
        payload['ip_info'] = DEFAULT_CATALOG.lookup_ip(ip)
    if not name and ip:
        info = DEFAULT_CATALOG.lookup_ip(ip)
        if info and info.get('hostname'):
            payload['name'] = DEFAULT_CATALOG.lookup_host(info['hostname'])
    cached = None
    try:
        from src.intel.models import IntelNameCache
        row = IntelNameCache.query.filter_by(key=(host or '').lower()).first()
        cached = row.to_dict() if row else None
    except Exception:
        pass
    payload['cached'] = cached
    if not payload.get('name') and not payload.get('ip_info') and not cached:
        return jsonify({'error': 'nothing known about that host'}), 404
    return jsonify(payload)


@intel_bp.route('/lookup')
def lookup():
    """Search sites/apps/domains the system has seen (autocomplete helper)."""
    q = (request.args.get('q') or '').strip().lower()
    if len(q) < 2:
        return jsonify({'matches': []})
    matches = []
    try:
        rows = IntelDailyUsage.query.filter(
            IntelDailyUsage.key.like(f'%{q}%')).order_by(
            IntelDailyUsage.seconds.desc()).limit(60).all()
        seen = set()
        for row in rows:
            key = (row.dimension, row.key)
            if key in seen:
                continue
            seen.add(key)
            info = DEFAULT_CATALOG.lookup_host(row.key) if row.dimension == 'site' else None
            matches.append({
                'key': row.key, 'dimension': row.dimension,
                'seconds': row.seconds, 'category': (info or {}).get('category'),
                'owner': (info or {}).get('owner'),
                'last_seen': row.last_seen.isoformat() if row.last_seen else None,
            })
    except Exception:
        pass
    return jsonify({'query': q, 'matches': matches[:25]})


# ---------------------------------------------------------------------------
# ingest (for external collectors, tests and simulations)
# ---------------------------------------------------------------------------

@intel_bp.route('/observe', methods=['POST'])
def observe():
    """Accept one evidence record (or a list) from an external collector.

    Body: ``{"source": "live", "device_mac": "...", "src_ip": "...",
             "dst_ip": "...", "dst_port": 443, "sni": "example.com",
             "bytes_up": 1200, "observed_at": "2026-01-01T10:00:00"}``
    """
    engine = _engine()
    if not engine:
        return jsonify({'error': 'engine unavailable'}), 503
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({'error': 'invalid JSON'}), 400
    records = data if isinstance(data, list) else [data]
    if len(records) > 2000:
        return jsonify({'error': 'too many records in one request (max 2000)'}), 413

    from src.intel.flow import Evidence
    accepted = 0
    results = []
    for record in records:
        try:
            ev = Evidence(
                source=record.get('source') or 'api', collector=record.get('collector') or 'api',
                device_mac=record.get('device_mac'), src_ip=record.get('src_ip'),
                dst_ip=record.get('dst_ip'), src_port=record.get('src_port'),
                dst_port=record.get('dst_port'), protocol=record.get('protocol'),
                direction=record.get('direction') or 'out',
                dns_qname=record.get('dns_qname'), sni=record.get('sni'),
                http_host=record.get('http_host'), http_path=record.get('http_path'),
                quic_sni=record.get('quic_sni'), tls_fingerprint=record.get('tls_fingerprint'),
                dhcp_hostname=record.get('dhcp_hostname'), mdns_name=record.get('mdns_name'),
                user_agent=record.get('user_agent'),
                bytes_up=int(record.get('bytes_up') or 0),
                bytes_down=int(record.get('bytes_down') or 0),
                packets=int(record.get('packets') or 1),
                is_estimated=bool(record.get('is_estimated', False)),
                confidence=float(record.get('confidence') or 0.6),
                process_name=record.get('process_name'),
                detail=dict(record.get('detail') or {}),
            )
            if record.get('search_term'):
                ev.detail['search_term'] = str(record['search_term'])[:300]
                ev.detail.setdefault('search_engine', record.get('search_engine') or 'supplied')
            if record.get('observed_at'):
                try:
                    ev.observed_at = datetime.fromisoformat(str(record['observed_at']).replace('Z', ''))
                except Exception:
                    pass
            result = engine.process_evidence(ev)
            accepted += 1
            if len(results) < 20:
                results.append({
                    'name': ev.hostname(), 'app': (result or {}).get('app'),
                    'category': (result or {}).get('category'),
                })
        except Exception as exc:
            results.append({'error': str(exc)})
    # Hand the batch to the engine so it lands in the engine-owned session; the
    # request session is rolled back at teardown.
    engine.flush_now()
    return jsonify({'accepted': accepted, 'of': len(records), 'sample': results})


# ---------------------------------------------------------------------------
# maintenance / export
# ---------------------------------------------------------------------------

@intel_bp.route('/maintenance', methods=['POST'])
def maintenance():
    engine = _engine()
    if not engine:
        return jsonify({'error': 'engine unavailable'}), 503
    data = request.get_json(force=True, silent=True) or {}
    actions = []
    if data.get('flush', True):
        actions.append({'flush': engine.sessionizer.flush()})
        actions.append({'writer_flush': engine.writer.flush()})
    if data.get('behavior'):
        actions.append({'behavior': engine.behavior.update_profiles()})
        actions.append({'scores': engine.behavior.score_all()})
    if data.get('vpn_scan'):
        actions.append({'vpn': engine.vpn.scan_flows(hours=24)})
    if data.get('retention_days'):
        actions.append({'retention': intel_store.apply_retention(
            days=int(data['retention_days']), dry_run=bool(data.get('dry_run')))})
    if data.get('indexes'):
        actions.append({'indexes': intel_store.ensure_indexes()})
    return jsonify({'actions': actions, 'generated_at': datetime.utcnow().isoformat()})


@intel_bp.route('/export/<entity>')
def export(entity):
    fmt = request.args.get('format', 'json')
    hours = _window_hours()
    since = datetime.utcnow() - timedelta(hours=hours)
    data = []
    if entity == 'sessions':
        data = [f.to_dict() for f in IntelFlow.query.filter(
            IntelFlow.last_seen >= since).order_by(IntelFlow.last_seen.desc()).limit(5000).all()]
    elif entity == 'sites':
        data = [s.to_dict() for s in IntelSiteSession.query.filter(
            IntelSiteSession.last_seen >= since).order_by(
            IntelSiteSession.dwell_seconds.desc()).limit(5000).all()]
    elif entity == 'devices':
        data = [d.to_dict() for d in IntelDeviceMac.query.all()]
    elif entity == 'events':
        data = [e.to_dict() for e in IntelDeviceEvent.query.order_by(
            IntelDeviceEvent.event_at.desc()).limit(5000).all()]
    elif entity == 'vpn':
        data = [f.to_dict() for f in IntelVpnFinding.query.filter(
            IntelVpnFinding.last_seen >= since).order_by(
            IntelVpnFinding.score.desc()).limit(5000).all()]
    else:
        return jsonify({'error': 'unknown entity'}), 400

    if fmt == 'csv':
        if not data:
            return '', 204
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(data[0].keys()))
        writer.writeheader()
        for row in data:
            writer.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
                             for k, v in row.items()})
        return buffer.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=netscanner_{entity}_{hours}h.csv'}
    return jsonify(data)
