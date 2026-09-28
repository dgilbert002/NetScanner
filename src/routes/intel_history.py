"""
History and calendar endpoints: "how long, per person, per day, per app".

Everything here reads the daily rollups and the session tables the sessionizer
already maintains, so a six-month question is a handful of indexed range scans
rather than a replay of the observation log.

Two ideas carry the whole surface:

* **person** - a MAC is mapped to a person through the identity layer (locked
  binding beats a probabilistic match).  Unmatched devices fall back to the
  device/hostname, never to an invented name.
* **range** - any window is described by ``range`` (day/week/month/quarter/
  6months/year/all) or explicit ``start``/``end`` dates, and is answered with a
  total plus a per-day breakdown, which is exactly what a calendar needs.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request

from src.intel import store as intel_store
from src.intel.alerts import DEFAULT_RULES, ALERT_KINDS, alert_summary
from src.intel.catalog import DEFAULT_CATALOG, app_categories, apps_in_category
from src.intel.models import (
    IntelDailyUsage,
    IntelDeviceEvent,
    IntelDeviceMac,
    IntelIdentityScore,
    IntelOnlineDay,
    IntelPerson,
    IntelSearch,
    IntelSiteSession,
    IntelUsageBucket,
)

history_bp = Blueprint('intel_history', __name__, url_prefix='/api/intel')

RANGES = {
    'day': 1, 'yesterday': 1, 'week': 7, 'fortnight': 14, 'month': 30,
    'quarter': 90, '6months': 182, 'year': 365, 'all': 3650,
}


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def _hms(seconds):
    seconds = int(seconds or 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f'{hours}h {minutes}m {secs}s'
    if minutes:
        return f'{minutes}m {secs}s'
    return f'{secs}s'


def _filters():
    """Shared query parameters: window + person/device scope."""
    anchor = request.args.get('date')
    try:
        anchor_date = datetime.strptime(anchor, '%Y-%m-%d') if anchor else datetime.utcnow()
    except Exception:
        anchor_date = datetime.utcnow()
    range_key = (request.args.get('range') or 'week').lower()
    start_arg = request.args.get('start')
    end_arg = request.args.get('end')
    if start_arg and end_arg:
        try:
            start = datetime.strptime(start_arg, '%Y-%m-%d')
            end = datetime.strptime(end_arg, '%Y-%m-%d')
        except Exception:
            start, end = None, None
    else:
        start, end = None, None
    if start is None:
        if range_key == 'yesterday':
            end = datetime(anchor_date.year, anchor_date.month, anchor_date.day)
            start = end - timedelta(days=1)
        elif range_key == 'day':
            start = datetime(anchor_date.year, anchor_date.month, anchor_date.day)
            end = start + timedelta(days=1)
        else:
            days = RANGES.get(range_key, 7)
            end = datetime(anchor_date.year, anchor_date.month, anchor_date.day) + timedelta(days=1)
            start = end - timedelta(days=days)
    return {
        'range': range_key,
        'start': start,
        'end': end,
        'start_date': start.strftime('%Y-%m-%d'),
        'end_date': end.strftime('%Y-%m-%d'),
        'person': (request.args.get('person') or '').strip(),
        'dimension': (request.args.get('dimension') or 'app').lower(),
        'mac': (request.args.get('mac') or '').lower().strip() or None,
    }


def identity_maps():
    """MAC -> person (best/locked) and person -> MACs, plus readable names."""
    by_mac = {}
    by_person = {}
    try:
        rows = intel_store.equery(IntelIdentityScore).order_by(
            IntelIdentityScore.probability.desc()).all()
    except Exception:
        rows = []
    for row in rows:
        mac = (row.device_mac or '').lower()
        if not mac:
            continue
        current = by_mac.get(mac)
        candidate = {
            'person_id': row.person_id,
            'person_name': row.person_name,
            'probability': round(row.probability or 0, 3),
            'locked': bool(row.locked or row.is_binding),
        }
        if current is None or (candidate['locked'] and not current['locked']) \
                or (candidate['probability'] > current['probability'] and not current['locked']):
            by_mac[mac] = candidate
    # a probabilistic guess below 50% is not an identification, it is a question
    for mac, candidate in list(by_mac.items()):
        if not candidate['locked'] and candidate['probability'] < 0.5:
            candidate = dict(candidate, person_id=None, person_name=None, uncertain=True)
            by_mac[mac] = candidate
    for mac, candidate in by_mac.items():
        if candidate.get('person_id'):
            by_person.setdefault(candidate['person_id'], []).append(mac)
    return by_mac, by_person


def device_labels():
    labels = {}
    try:
        for row in intel_store.equery(IntelDeviceMac).all():
            mac = (row.normalized or row.mac or '').lower()
            labels[mac] = {
                'mac': mac,
                'name': row.hostname or row.mac,
                'vendor': row.vendor,
                'is_randomized': bool(row.is_randomized),
                'device_key': row.device_key,
                'last_seen': _iso(row.last_seen),
            }
    except Exception:
        pass
    return labels


def _person_scope(spec, by_mac, by_person):
    """Resolve ?person= to person row + MAC set (empty set = no restriction)."""
    if not spec['person']:
        if spec['mac']:
            return None, {spec['mac']}
        return None, set()
    person = None
    try:
        if str(spec['person']).isdigit():
            person = intel_store.equery(IntelPerson).get(int(spec['person']))
        if person is None:
            person = intel_store.equery(IntelPerson).filter(
                (IntelPerson.name == spec['person'])
                | (IntelPerson.display_name == spec['person'])).first()
    except Exception:
        person = None
    macs = set(by_person.get(person.id, [])) if person else set()
    if spec['mac']:
        macs = {spec['mac']} if spec['mac'] in macs or not macs else macs & {spec['mac']}
    return person, macs


# ---------------------------------------------------------------------------
# /usage - totals + per-day breakdown for one dimension and window
# ---------------------------------------------------------------------------

@history_bp.route('/usage')
def usage():
    spec = _filters()
    by_mac, by_person = identity_maps()
    labels = device_labels()
    person, macs = _person_scope(spec, by_mac, by_person)
    dimension = spec['dimension']
    if dimension not in ('app', 'site', 'category', 'device', 'game', 'vpn'):
        dimension = 'app'
    stored_dimension = 'app' if dimension == 'game' else dimension
    start_day = spec['start_date']
    end_day = spec['end_date']

    try:
        query = intel_store.equery(IntelDailyUsage).filter(
            IntelDailyUsage.day >= start_day, IntelDailyUsage.day <= end_day,
            IntelDailyUsage.dimension == stored_dimension)
        rows = query.all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    if macs:
        rows = [r for r in rows if (r.device_mac or '').lower() in macs]
    if dimension == 'game':
        # Not a stored dimension: the daily rollups hold *app names*, so the
        # Gaming slice is resolved through the catalogue rather than through a
        # domain lookup (which would always miss for 'Roblox').
        games = {name.lower() for name in apps_in_category('Gaming')}
        rows = [r for r in rows if (r.key or '').lower() in games]

    items = {}
    days_seen = set()
    for row in rows:
        entry = items.setdefault(row.key or 'Unknown', {
            'key': row.key or 'Unknown', 'seconds': 0, 'bytes': 0, 'sessions': 0,
            'days': {}, 'devices': set(), 'first_seen': None, 'last_seen': None,
            'is_estimated': bool(row.is_estimated),
        })
        seconds = int(row.seconds or 0)
        entry['seconds'] += seconds
        entry['bytes'] += int(row.bytes_total or 0)
        entry['sessions'] += int(row.sessions or 0)
        entry['days'][row.day] = entry['days'].get(row.day, 0) + seconds
        if row.device_mac:
            entry['devices'].add((row.device_mac or '').lower())
        if row.first_seen and (not entry['first_seen'] or row.first_seen < entry['first_seen']):
            entry['first_seen'] = row.first_seen
        if row.last_seen and (not entry['last_seen'] or row.last_seen > entry['last_seen']):
            entry['last_seen'] = row.last_seen
        days_seen.add(row.day)

    name_categories = app_categories() if dimension in ('app', 'game') else None
    out = []
    for key, entry in items.items():
        info = DEFAULT_CATALOG.lookup_host(key) if dimension in ('site', 'vpn') else None
        people = []
        for mac in entry['devices']:
            mapped = by_mac.get(mac)
            label = labels.get(mac) or {}
            people.append({
                'mac': mac,
                'device': label.get('name') or mac,
                'randomized': label.get('is_randomized'),
                'person': (mapped or {}).get('person_name'),
                'person_id': (mapped or {}).get('person_id'),
                'certain': bool((mapped or {}).get('locked')),
            })
        out.append({
            'key': key,
            'name': (info or {}).get('app') or key,
            'category': ((info or {}).get('category') if info
                         else (name_categories or {}).get((key or '').lower())),
            'seconds': entry['seconds'],
            'human': _hms(entry['seconds']),
            'hours': round(entry['seconds'] / 3600.0, 2),
            'minutes': round(entry['seconds'] / 60.0, 1),
            'sessions': entry['sessions'],
            'bytes': entry['bytes'],
            'active_days': len(entry['days']),
            'avg_per_active_day': (int(entry['seconds'] / len(entry['days']))
                                   if entry['days'] else 0),
            # NOTE: active vs span is a *session* property; it is reported by
            # /calendar per session rather than summed per app here, where it
            # would be meaningless (a span cannot be added up across days).
            'first_seen': _iso(entry['first_seen']),
            'last_seen': _iso(entry['last_seen']),
            'devices': people,
            'device_count': len(people),
            'is_estimated': entry['is_estimated'],
            'days': {day: {'seconds': sec, 'human': _hms(sec)}
                     for day, sec in sorted(entry['days'].items())},
        })
    out.sort(key=lambda x: -x['seconds'])
    total = sum(i['seconds'] for i in out)

    # device/online totals for the same window (union time, not summed apps)
    online_total = 0
    try:
        online_rows = intel_store.equery(IntelOnlineDay).filter(
            IntelOnlineDay.day >= start_day, IntelOnlineDay.day <= end_day).all()
        if macs:
            online_rows = [r for r in online_rows if (r.device_mac or '').lower() in macs]
        online_total = sum(int(r.online_seconds or 0) for r in online_rows)
    except Exception:
        pass

    return jsonify({
        'dimension': dimension,
        'range': spec['range'],
        'start': start_day,
        'end': end_day,
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'macs': sorted(macs),
        'totals': {
            'seconds': total,
            'human': _hms(total),
            'hours': round(total / 3600.0, 2),
            'online_seconds': online_total,
            'online_human': _hms(online_total),
            'distinct_keys': len(out),
            'active_days': len(days_seen),
            'sessions': sum(i['sessions'] for i in out),
            'bytes': sum(i['bytes'] for i in out),
        },
        'items': out[:int(request.args.get('limit', 300) or 300)],
        'generated_at': datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# /calendar - one key (app/site/category), day by day, for a calendar view
# ---------------------------------------------------------------------------

@history_bp.route('/calendar')
def calendar():
    spec = _filters()
    key = request.args.get('key')
    dimension = spec['dimension'] if spec['dimension'] in ('app', 'site', 'category', 'game') else 'app'
    by_mac, by_person = identity_maps()
    person, macs = _person_scope(spec, by_mac, by_person)

    start_day, end_day = spec['start_date'], spec['end_date']
    days = {}
    sessions = []
    if key:
        try:
            rows = intel_store.equery(IntelDailyUsage).filter(
                IntelDailyUsage.dimension == dimension,
                IntelDailyUsage.key == key,
                IntelDailyUsage.day >= start_day,
                IntelDailyUsage.day <= end_day).all()
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500
        if macs:
            rows = [r for r in rows if (r.device_mac or '').lower() in macs]
        for row in rows:
            entry = days.setdefault(row.day, {'day': row.day, 'seconds': 0, 'sessions': 0,
                                              'bytes': 0, 'devices': set(),
                                              'first': None, 'last': None})
            entry['seconds'] += int(row.seconds or 0)
            entry['sessions'] += int(row.sessions or 0)
            entry['bytes'] += int(row.bytes_total or 0)
            if row.device_mac:
                entry['devices'].add((row.device_mac or '').lower())
            if row.first_seen and (not entry['first'] or row.first_seen < entry['first']):
                entry['first'] = row.first_seen
            if row.last_seen and (not entry['last'] or row.last_seen > entry['last']):
                entry['last'] = row.last_seen
        # real sessions for the drill-down (capped - this is a UI detail view)
        try:
            field = {'app': IntelSiteSession.app, 'site': IntelSiteSession.root_domain,
                     'category': IntelSiteSession.category}.get(dimension)
            query = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.first_seen >= spec['start'],
                IntelSiteSession.first_seen < spec['end'])
            if field is not None:
                query = query.filter(field == key)
            rows_sessions = query.order_by(IntelSiteSession.first_seen.desc()).limit(500).all()
            if macs:
                rows_sessions = [r for r in rows_sessions if (r.device_mac or '').lower() in macs]
            for row in rows_sessions:
                mapped = by_mac.get((row.device_mac or '').lower()) or {}
                sessions.append({
                    'id': row.id,
                    'day': row.first_seen.strftime('%Y-%m-%d') if row.first_seen else None,
                    'first_seen': _iso(row.first_seen),
                    'last_seen': _iso(row.last_seen),
                    'seconds': int(row.dwell_seconds or 0),
                    'human': _hms(row.dwell_seconds),
                    'span_seconds': int(row.span_seconds or 0),
                    'span_human': _hms(row.span_seconds),
                    'idle_seconds': int(getattr(row, 'idle_seconds', 0) or 0),
                    'idle_human': _hms(getattr(row, 'idle_seconds', 0)),
                    'app': row.app,
                    'domain': row.root_domain,
                    'url': row.url_last,
                    'device_mac': row.device_mac,
                    'device': (macs and None) or None,
                    'person': mapped.get('person_name'),
                    'state': row.state,
                    'source': row.source,
                    'is_estimated': bool(row.is_estimated),
                })
        except Exception:
            pass

    day_list = []
    for day, entry in sorted(days.items()):
        day_list.append({
            'day': day,
            'seconds': entry['seconds'],
            'human': _hms(entry['seconds']),
            'sessions': entry['sessions'],
            'bytes': entry['bytes'],
            'first': _iso(entry['first']),
            'last': _iso(entry['last']),
            'devices': sorted(entry['devices']),
        })
    # fill gaps so a calendar/heatmap has every day in the window
    filled = []
    cursor = spec['start']
    while cursor < spec['end']:
        day = cursor.strftime('%Y-%m-%d')
        found = next((d for d in day_list if d['day'] == day), None)
        filled.append(found or {'day': day, 'seconds': 0, 'human': '0s',
                                'sessions': 0, 'bytes': 0, 'first': None, 'last': None,
                                'devices': []})
        cursor += timedelta(days=1)
    total = sum(d['seconds'] for d in day_list)
    info = DEFAULT_CATALOG.lookup_host(key) if key else None
    return jsonify({
        'key': key,
        'dimension': dimension,
        'name': (info or {}).get('app') or key,
        'category': (info or {}).get('category') if info else None,
        'owner': (info or {}).get('owner') if info else None,
        'range': spec['range'],
        'start': start_day,
        'end': end_day,
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'totals': {
            'seconds': total, 'human': _hms(total), 'hours': round(total / 3600.0, 2),
            'active_days': len([d for d in day_list if d['seconds'] > 0]),
            'sessions': sum(d['sessions'] for d in day_list),
            'best_day': max(day_list, key=lambda d: d['seconds'])['day'] if day_list else None,
            'avg_per_active_day': int(total / len(day_list)) if day_list else 0,
        },
        'days': filled,
        'sessions': sessions,
        'generated_at': datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# people + per-person summary
# ---------------------------------------------------------------------------

@history_bp.route('/people/<int:person_id>/summary')
def person_summary(person_id):
    spec = _filters()
    spec['person'] = str(person_id)
    by_mac, by_person = identity_maps()
    labels = device_labels()
    person, macs = _person_scope(spec, by_mac, by_person)
    if person is None:
        return jsonify({'error': 'person not found'}), 404

    frames = {}
    for dimension in ('category', 'app', 'site', 'device'):
        spec2 = dict(spec, dimension=dimension)
        with_macs = macs
        try:
            rows = intel_store.equery(IntelDailyUsage).filter(
                IntelDailyUsage.dimension == dimension,
                IntelDailyUsage.day >= spec2['start_date'],
                IntelDailyUsage.day <= spec2['end_date']).all()
        except Exception:
            rows = []
        rows = [r for r in rows if (r.device_mac or '').lower() in with_macs]
        totals = {}
        for row in rows:
            totals[row.key] = totals.get(row.key, 0) + int(row.seconds or 0)
        cats = app_categories() if dimension == 'app' else None
        frames[dimension] = sorted(
            [{'key': k, 'seconds': v, 'human': _hms(v),
              'category': ((DEFAULT_CATALOG.lookup_host(k) or {}).get('category')
                           if dimension == 'site' else (cats or {}).get(k.lower()))}
             for k, v in totals.items()],
            key=lambda x: -x['seconds'])

    online = 0
    try:
        rows = intel_store.equery(IntelOnlineDay).filter(
            IntelOnlineDay.day >= spec['start_date'],
            IntelOnlineDay.day <= spec['end_date']).all()
        online = sum(int(r.online_seconds or 0) for r in rows
                     if (r.device_mac or '').lower() in macs)
    except Exception:
        pass

    alerts = []
    try:
        rows = intel_store.equery(IntelDeviceEvent).filter(
            IntelDeviceEvent.kind.in_(ALERT_KINDS),
            IntelDeviceEvent.event_at >= spec['start']).order_by(
            IntelDeviceEvent.event_at.desc()).limit(100).all()
        for row in rows:
            if (row.device_mac or '').lower() in macs:
                alerts.append(row.to_dict())
    except Exception:
        pass

    searches = []
    try:
        rows = intel_store.equery(IntelSearch).filter(
            IntelSearch.seen_at >= spec['start'],
            IntelSearch.seen_at <= spec['end']).order_by(
            IntelSearch.seen_at.desc()).limit(100).all()
        searches = [r.to_dict() for r in rows if (r.device_mac or '').lower() in macs]
    except Exception:
        pass

    games = [i for i in frames['category'] if i['key'] == 'Gaming']
    return jsonify({
        'person': {'id': person.id, 'name': person.display_name or person.name,
                   'is_child': bool(getattr(person, 'is_child', False)),
                   'macs': sorted(macs)},
        'devices': [labels.get(mac, {'mac': mac}) for mac in sorted(macs)],
        'range': spec['range'], 'start': spec['start_date'], 'end': spec['end_date'],
        'online_seconds': online, 'online_human': _hms(online),
        'gaming_seconds': games[0]['seconds'] if games else 0,
        'gaming_human': _hms(games[0]['seconds'] if games else 0),
        'games': [i for i in frames['app']
                  if (i.get('category') or '').lower() == 'gaming'],
        'adult_apps': [i for i in frames['app']
                       if (i.get('category') or '').lower() == 'adult'],
        'categories': frames['category'],
        'apps': frames['app'][:50],
        'sites': frames['site'][:50],
        'devices_usage': frames['device'],
        'alerts': alerts,
        'alert_count': len(alerts),
        'searches': searches,
        'search_count': len(searches),
        'generated_at': datetime.utcnow().isoformat(),
    })


@history_bp.route('/people/overview')
def people_overview():
    """One row per person: today and this week, ready for a dashboard table."""
    spec = _filters()
    name_categories = app_categories()
    by_mac, by_person = identity_maps()
    labels = device_labels()
    out = []
    try:
        people = intel_store.equery(IntelPerson).all()
    except Exception:
        people = []
    today = datetime.utcnow().strftime('%Y-%m-%d')
    week_start = (datetime.utcnow() - timedelta(days=6)).strftime('%Y-%m-%d')
    for person in people:
        macs = {m.lower() for m in by_person.get(person.id, [])}
        rows = []
        if macs:
            try:
                rows = intel_store.equery(IntelDailyUsage).filter(
                    IntelDailyUsage.day >= week_start).all()
            except Exception:
                rows = []
        rows = [r for r in rows if (r.device_mac or '').lower() in macs]
        # app dimension only: adding the category dimension as well would
        # double-count the same seconds under two labels.
        today_seconds = sum(int(r.seconds or 0) for r in rows
                            if r.day == today and r.dimension == 'app')
        week_seconds = sum(int(r.seconds or 0) for r in rows if r.dimension == 'app')
        categories = {}
        apps = {}
        for row in rows:
            if row.dimension == 'category':
                categories[row.key] = categories.get(row.key, 0) + int(row.seconds or 0)
            elif row.dimension == 'app':
                apps[row.key] = apps.get(row.key, 0) + int(row.seconds or 0)
        online = 0
        try:
            online_rows = intel_store.equery(IntelOnlineDay).filter(
                IntelOnlineDay.day >= week_start).all()
            online = sum(int(r.online_seconds or 0) for r in online_rows
                         if (r.device_mac or '').lower() in macs)
        except Exception:
            pass
        alert_rows = []
        try:
            alert_rows = intel_store.equery(IntelDeviceEvent).filter(
                IntelDeviceEvent.kind.in_(ALERT_KINDS),
                IntelDeviceEvent.event_at >= datetime.utcnow() - timedelta(days=7)).all()
        except Exception:
            pass
        device_alerts = [r for r in alert_rows if (r.device_mac or '').lower() in macs]
        out.append({
            'person_id': person.id,
            'name': person.display_name or person.name,
            'is_child': bool(getattr(person, 'is_child', False)),
            'devices': [labels.get(m, {'mac': m}) for m in sorted(macs)],
            'device_count': len(macs),
            'today_seconds': today_seconds, 'today_human': _hms(today_seconds),
            'week_seconds': week_seconds, 'week_human': _hms(week_seconds),
            'online_week_seconds': online, 'online_week_human': _hms(online),
            'top_categories': sorted(
                [{'key': k, 'seconds': v, 'human': _hms(v)} for k, v in categories.items()],
                key=lambda x: -x['seconds'])[:5],
            'top_apps': sorted(
                [{'key': k, 'seconds': v, 'human': _hms(v)} for k, v in apps.items()],
                key=lambda x: -x['seconds'])[:5],
            'alerts': len(device_alerts),
            'critical_alerts': len([r for r in device_alerts
                                    if (r.severity or '') in ('critical', 'error')]),
            'gaming_seconds': categories.get('Gaming', 0),
            'gaming_human': _hms(categories.get('Gaming', 0)),
            'adult_seconds': categories.get('Adult', 0),
            'games': sorted([{'key': k, 'seconds': v, 'human': _hms(v)}
                             for k, v in apps.items()
                             if (name_categories.get(k.lower()) == 'Gaming')],
                            key=lambda x: -x['seconds'])[:8],
            'adult_apps': sorted([{'key': k, 'seconds': v, 'human': _hms(v)}
                                  for k, v in apps.items()
                                  if (name_categories.get(k.lower()) == 'Adult')],
                                 key=lambda x: -x['seconds'])[:8],
        })
    out.sort(key=lambda x: -x['today_seconds'])
    return jsonify({'range': spec['range'], 'people': out,
                    'generated_at': datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# alerts + searches
# ---------------------------------------------------------------------------

@history_bp.route('/alerts')
def alerts():
    hours = int(request.args.get('hours', 168) or 168)
    since = datetime.utcnow() - timedelta(hours=hours)
    by_mac, _ = identity_maps()
    labels = device_labels()
    kinds = request.args.get('kind')
    try:
        query = intel_store.equery(IntelDeviceEvent).filter(
            IntelDeviceEvent.event_at >= since,
            IntelDeviceEvent.kind.in_(tuple(kinds.split(',')) if kinds else ALERT_KINDS))
        rows = query.order_by(IntelDeviceEvent.event_at.desc()).limit(
            int(request.args.get('limit', 300) or 300)).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    out = []
    for row in rows:
        entry = row.to_dict()
        mac = (row.device_mac or '').lower()
        label = labels.get(mac) or {}
        entry['device'] = label.get('name') or row.device_mac
        entry['person'] = (by_mac.get(mac) or {}).get('person_name')
        entry['certain'] = bool((by_mac.get(mac) or {}).get('locked'))
        entry['age_seconds'] = int((datetime.utcnow() - row.event_at).total_seconds())
        out.append(entry)
    return jsonify({
        'hours': hours,
        'summary': alert_summary(hours),
        'count': len(out),
        'alerts': out,
        'rules': _alert_rules(),
        'generated_at': datetime.utcnow().isoformat(),
    })


def _alert_rules():
    """Rules as stored in settings, with the defaults filled in."""
    rules = dict(DEFAULT_RULES)
    try:
        from src.intel.engine import get_engine
        engine = get_engine()
        if engine is not None:
            for key in list(DEFAULT_RULES):
                value = engine.settings.get(f'alert_{key}', None)
                if value is None:
                    value = engine.settings.get(key, None)
                if value is not None:
                    rules[key] = value
    except Exception:
        pass
    return rules


@history_bp.route('/alerts/rules', methods=['GET', 'POST'])
def alert_rules():
    from src.intel.engine import get_engine
    engine = get_engine()
    if request.method == 'GET':
        return jsonify(_alert_rules())
    if engine is None:
        return jsonify({'error': 'engine unavailable'}), 503
    patch = request.get_json(force=True, silent=True) or {}
    clean = {}
    for key, value in patch.items():
        if key not in DEFAULT_RULES:
            continue
        if isinstance(DEFAULT_RULES[key], bool):
            clean[f'alert_{key}'] = bool(value)
        elif isinstance(DEFAULT_RULES[key], int):
            try:
                clean[f'alert_{key}'] = max(0, int(value))
            except Exception:
                continue
        else:
            clean[f'alert_{key}'] = value
    engine.settings.update(clean)
    return jsonify({'saved': clean, 'effective': _alert_rules()})


@history_bp.route('/alerts/evaluate', methods=['POST'])
def alerts_evaluate():
    from src.intel.engine import get_engine
    engine = get_engine()
    if engine is None or getattr(engine, 'alerts', None) is None:
        return jsonify({'error': 'engine unavailable'}), 503
    hours = int(request.args.get('hours', 26) or 26)
    with intel_store.forced_engine_session():
        summary = engine.alerts.evaluate(hours=hours)
        intel_store.engine_commit()
    return jsonify({'summary': summary, 'generated_at': datetime.utcnow().isoformat()})


@history_bp.route('/searches')
def searches():
    """Search queries that were genuinely observable (plain HTTP only)."""
    hours = int(request.args.get('hours', 168) or 168)
    since = datetime.utcnow() - timedelta(hours=hours)
    by_mac, _ = identity_maps()
    labels = device_labels()
    term = (request.args.get('term') or '').strip().lower()
    person_filter = (request.args.get('person') or '').strip()
    try:
        rows = intel_store.equery(IntelSearch).filter(
            IntelSearch.seen_at >= since).order_by(
            IntelSearch.seen_at.desc()).limit(int(request.args.get('limit', 300) or 300)).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    out = []
    engines = {}
    for row in rows:
        entry = row.to_dict()
        mac = (row.device_mac or '').lower()
        label = labels.get(mac) or {}
        entry['device'] = label.get('name') or row.device_mac
        entry['person'] = (by_mac.get(mac) or {}).get('person_name')
        engines[row.engine] = engines.get(row.engine, 0) + 1
        if term and term not in (row.term or '').lower():
            continue
        if person_filter and entry.get('person') != person_filter:
            continue
        out.append(entry)
    return jsonify({
        'hours': hours, 'count': len(out), 'searches': out, 'engines': engines,
        'note': ('Search terms are only visible when the request was sent in clear text. '
                 'HTTPS searches (essentially all of them today) cannot be read locally, '
                 'by this or any other tool, without breaking TLS.'),
        'generated_at': datetime.utcnow().isoformat(),
    })
