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
                'device_class': getattr(row, 'device_class', None),
                'last_seen': _iso(row.last_seen),
            }
        # today's online time, so the family screen can show it per device
        try:
            today = datetime.utcnow().strftime('%Y-%m-%d')
            for row in intel_store.equery(IntelOnlineDay).filter_by(day=today).all():
                mac = (row.device_mac or '').lower()
                if mac in labels:
                    seconds = int(row.online_seconds or 0)
                    labels[mac]['online_today_seconds'] = seconds
                    labels[mac]['online_today_human'] = _hms(seconds)
        except Exception:
            pass
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


# ---------------------------------------------------------------------------
# /assignment - who is which device, and what still needs allocating
# ---------------------------------------------------------------------------

@history_bp.route('/assignment')
def assignment():
    """Everything the "family & devices" screen needs in one call.

    ``people`` carry their devices, ``devices`` carry their person (locked
    binding wins, otherwise the best guess is flagged as uncertain) and
    ``unassigned`` lists devices nobody has claimed - so an operator can
    allocate them from a dropdown instead of typing a MAC address.
    """
    by_mac, by_person = identity_maps()
    labels = device_labels()
    try:
        people = intel_store.equery(IntelPerson).all()
    except Exception:
        people = []
    try:
        scores = intel_store.equery(IntelIdentityScore).all()
    except Exception:
        scores = []
    try:
        devices = intel_store.equery(IntelDeviceMac).all()
    except Exception:
        devices = []

    best = {}
    for score in scores:
        mac = (score.device_mac or '').lower()
        current = best.get(mac)
        rank = (bool(score.locked or score.is_binding), float(score.probability or 0))
        if current is None or rank > current[0]:
            best[mac] = (rank, score)

    people_out = []
    for person in people:
        macs = sorted({m.lower() for m in by_person.get(person.id, [])})
        people_out.append({
            'id': person.id,
            'name': person.name,
            'display_name': person.display_name or person.name,
            'color': getattr(person, 'color', None) or '#3498db',
            'is_child': bool(getattr(person, 'is_child', False)),
            'notes': getattr(person, 'notes', None),
            'macs': macs,
            'devices': [labels.get(mac, {'mac': mac}) for mac in macs],
        })

    devices_out = []
    for mac, label in sorted(labels.items()):
        mapped = by_mac.get(mac) or {}
        rank_score = best.get(mac)
        score = rank_score[1] if rank_score else None
        devices_out.append({
            'mac': mac,
            'name': label.get('name') or mac,
            'vendor': label.get('vendor'),
            'device_class': label.get('device_class'),
            'is_randomized': label.get('is_randomized'),
            'online_today_seconds': label.get('online_today_seconds'),
            'online_today_human': label.get('online_today_human'),
            'last_seen': label.get('last_seen'),
            'person_id': mapped.get('person_id'),
            'person': mapped.get('person_name'),
            'certain': bool(mapped.get('locked')),
            'probability': round(float(mapped.get('probability') or 0), 3) if mapped else None,
            'star': (label.get('star') or {}).get('kind') if isinstance(label.get('star'), dict) else None,
            'suggestion': None if mapped.get('person_name') else (
                {'person_id': score.person_id,
                 'person': score.person_name,
                 'probability': round(float(score.probability or 0), 3),
                 'reason': (score.explanation or {}).get('prior_reason')
                           if isinstance(score.explanation, dict) else None}
                if score is not None and score.person_name and (score.probability or 0) >= 0.5
                else None),
        })
    unassigned = [d for d in devices_out if not d['person']]
    return jsonify({
        'people': people_out,
        'devices': devices_out,
        'unassigned': unassigned,
        'assigned_count': len(devices_out) - len(unassigned),
        'device_count': len(devices_out),
        'generated_at': datetime.utcnow().isoformat(),
    })


@history_bp.route('/people/<int:person_id>/unbind', methods=['POST'])
def unbind_person(person_id):
    """Release a device from a person (the device keeps its history)."""
    mac = ((request.get_json(silent=True) or {}).get('mac') or '').lower()
    try:
        from src.intel.maclab import normalize_mac
        mac = normalize_mac(mac) or mac
    except Exception:
        pass
    if not mac:
        return jsonify({'error': 'mac is required'}), 400
    removed = 0
    try:
        rows = intel_store.equery(IntelIdentityScore).filter_by(
            device_mac=mac, person_id=person_id).all()
        for row in rows:
            intel_store.engine_session().delete(row)
            removed += 1
        intel_store.engine_session().commit()
    except Exception as exc:
        intel_store.engine_session().rollback()
        return jsonify({'error': str(exc)}), 500
    if not removed:
        return jsonify({'error': 'no binding found for that device'}), 404
    return jsonify({'message': 'device released', 'mac': mac, 'removed': removed})


@history_bp.route('/people/<int:person_id>', methods=['PATCH', 'POST'])
def update_person(person_id):
    """Rename a person, change their colour or child flag."""
    payload = request.get_json(silent=True) or {}
    try:
        person = intel_store.equery(IntelPerson).get(person_id)
    except Exception:
        person = None
    if person is None:
        return jsonify({'error': 'person not found'}), 404
    for field in ('name', 'display_name', 'notes'):
        if payload.get(field) is not None:
            setattr(person, field, str(payload[field])[:120])
    if payload.get('color'):
        person.color = str(payload['color'])[:16]
    if payload.get('is_child') is not None:
        person.is_child = bool(payload['is_child'])
    try:
        intel_store.engine_session().commit()
    except Exception as exc:
        intel_store.engine_session().rollback()
        return jsonify({'error': str(exc)}), 500
    return jsonify({'message': 'person updated', 'person': person.to_dict()})


@history_bp.route('/people/<int:person_id>', methods=['DELETE'])
def delete_person(person_id):
    """Delete a person, their bindings and their usage attribution."""
    try:
        person = intel_store.equery(IntelPerson).get(person_id)
    except Exception:
        person = None
    if person is None:
        return jsonify({'error': 'person not found'}), 404
    session = intel_store.engine_session()
    removed = {'bindings': 0}
    try:
        rows = intel_store.equery(IntelIdentityScore).filter_by(person_id=person_id).all()
        for row in rows:
            row.person_id = None
            row.person_name = None
            row.is_binding = False
            row.locked = False
            removed['bindings'] += 1
        for model in (IntelSearch, IntelDeviceEvent):
            for row in intel_store.equery(model).filter_by(person_id=person_id).all():
                row.person_id = None
        session.delete(person)
        session.commit()
    except Exception as exc:
        session.rollback()
        return jsonify({'error': str(exc)}), 500
    return jsonify({'message': 'person deleted', 'released_devices': removed['bindings']})


# ---------------------------------------------------------------------------
# /series - the numbers behind the graphs (daily bars, stacked categories,
#           per-person comparison and the 24-hour profile)
# ---------------------------------------------------------------------------

@history_bp.route('/series')
def series():
    spec = _filters()
    by_mac, by_person = identity_maps()
    person, macs = _person_scope(spec, by_mac, by_person)
    dimension = spec['dimension']
    if dimension not in ('app', 'site', 'category', 'device'):
        dimension = 'category'
    top_n = min(max(int(request.args.get('top', 6) or 6), 1), 12)
    start_day = spec['start_date']
    end_day = spec['end_date']

    # a gap-filled day axis, so a chart never has holes in it
    day_axis = []
    cursor = datetime.strptime(start_day, '%Y-%m-%d')
    last = datetime.strptime(end_day, '%Y-%m-%d')
    while cursor < last and len(day_axis) < 400:
        day_axis.append(cursor.strftime('%Y-%m-%d'))
        cursor += timedelta(days=1)

    try:
        rows = intel_store.equery(IntelDailyUsage).filter(
            IntelDailyUsage.day >= start_day, IntelDailyUsage.day <= end_day,
            IntelDailyUsage.dimension == dimension).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    if macs:
        rows = [r for r in rows if (r.device_mac or '').lower() in macs]

    name_categories = app_categories() if dimension == 'app' else {}

    def label_for(key):
        info = DEFAULT_CATALOG.lookup_host(key) or {}
        return {'name': info.get('app') or key,
                'category': (info.get('category') if dimension in ('site', 'category')
                             else name_categories.get((key or '').lower())) or 'Unknown'}

    daily = {day: 0 for day in day_axis}
    daily_bytes = {day: 0 for day in day_axis}
    daily_sessions = {day: 0 for day in day_axis}
    per_key = {}
    per_day_key = {}
    for row in rows:
        day = row.day
        seconds = int(row.seconds or 0)
        if day not in daily:
            continue
        daily[day] += seconds
        daily_bytes[day] += int(row.bytes_total or 0)
        daily_sessions[day] += int(row.sessions or 0)
        entry = per_key.setdefault(row.key or 'Unknown', {'seconds': 0, 'days': {}})
        entry['seconds'] += seconds
        entry['days'][day] = entry['days'].get(day, 0) + seconds
        per_day_key.setdefault(day, {})[row.key or 'Unknown'] = \
            per_day_key.get(day, {}).get(row.key or 'Unknown', 0) + seconds

    ordered = sorted(per_key.items(), key=lambda kv: -kv[1]['seconds'])
    top = ordered[:top_n]
    rest_seconds = sum(v['seconds'] for _k, v in ordered[top_n:])

    stacked = []
    for key, entry in top:
        meta = label_for(key)
        stacked.append({
            'key': key, 'name': meta['name'], 'category': meta['category'],
            'seconds': entry['seconds'], 'human': _hms(entry['seconds']),
            'points': [{'day': day, 'seconds': entry['days'].get(day, 0)} for day in day_axis],
        })
    if rest_seconds:
        stacked.append({
            'key': '(other)', 'name': 'Other', 'category': 'Unknown',
            'seconds': rest_seconds, 'human': _hms(rest_seconds),
            'points': [{'day': day, 'seconds': sum(
                per_day_key.get(day, {}).get(k, 0) for k, _v in ordered[top_n:])}
                for day in day_axis],
        })

    # per-person comparison (only when nobody specific was requested)
    people_series = []
    if not spec['person'] and not macs:
        try:
            people = intel_store.equery(IntelPerson).all()
        except Exception:
            people = []
        person_rows = []
        try:
            person_rows = intel_store.equery(IntelDailyUsage).filter(
                IntelDailyUsage.day >= start_day, IntelDailyUsage.day <= end_day,
                IntelDailyUsage.dimension == dimension).all()
        except Exception:
            person_rows = []
        for p in people:
            mine = {m.lower() for m in by_person.get(p.id, [])}
            days = {day: 0 for day in day_axis}
            total = 0
            for row in person_rows:
                if (row.device_mac or '').lower() in mine and row.day in days:
                    value = int(row.seconds or 0)
                    days[row.day] += value
                    total += value
            people_series.append({
                'person_id': p.id, 'name': p.display_name or p.name,
                'color': getattr(p, 'color', None) or '#3498db',
                'seconds': total, 'human': _hms(total),
                'points': [{'day': day, 'seconds': days[day]} for day in day_axis],
            })
        people_series.sort(key=lambda p: -p['seconds'])

    # 24-hour profile across the window, from the 5-minute buckets
    hours = [{'hour': h, 'seconds': 0} for h in range(24)]
    try:
        buckets = intel_store.equery(IntelUsageBucket).filter(
            IntelUsageBucket.bucket_start >= spec['start'],
            IntelUsageBucket.bucket_start < spec['end'],
            IntelUsageBucket.dimension == 'device').all()
        for bucket in buckets:
            if macs and (bucket.device_mac or '').lower() not in macs:
                continue
            # The device dimension keeps its time in online_seconds (a device can
            # be online without a named app); app/site/category rows use seconds.
            value = bucket.online_seconds or bucket.seconds or 0
            hours[bucket.bucket_start.hour]['seconds'] += int(value)
    except Exception:
        pass
    hour_total = sum(h['seconds'] for h in hours)
    for hour in hours:
        hour['human'] = _hms(hour['seconds'])
        hour['share'] = round(hour['seconds'] / hour_total, 4) if hour_total else 0

    peak_hour = max(hours, key=lambda h: h['seconds'])['hour'] if hour_total else None
    return jsonify({
        'dimension': dimension, 'range': spec['range'],
        'start': start_day, 'end': end_day,
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'days': [{'day': day, 'seconds': daily[day], 'human': _hms(daily[day]),
                  'bytes': daily_bytes[day], 'sessions': daily_sessions[day]}
                 for day in day_axis],
        'stacked': stacked,
        'people': people_series,
        'hours': hours,
        'totals': {
            'seconds': sum(daily.values()), 'human': _hms(sum(daily.values())),
            'best_day': max(daily, key=lambda d: daily[d]) if daily and any(daily.values()) else None,
            'bytes': sum(daily_bytes.values()),
            'sessions': sum(daily_sessions.values()),
            'peak_hour': peak_hour,
            'active_days': len([d for d, v in daily.items() if v]),
        },
    })


# ---------------------------------------------------------------------------
# /gantt - one day of activity as bands, per person or per device
# ---------------------------------------------------------------------------

@history_bp.route('/gantt')
def gantt():
    """Who was online when, for a single day (a real timeline, not a total).

    Each band is one device (or one person, when every device of that person is
    folded together) and each interval is a merged stretch of activity, with the
    dominant app/category for that stretch so the timeline is readable.
    """
    spec = _filters()
    day = request.args.get('date') or datetime.utcnow().strftime('%Y-%m-%d')
    try:
        start = datetime.strptime(day, '%Y-%m-%d')
    except Exception:
        start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        day = start.strftime('%Y-%m-%d')
    end = start + timedelta(days=1)
    by_mac, by_person = identity_maps()
    labels = device_labels()
    group_by = (request.args.get('by') or 'person').lower()
    person_filter, macs = _person_scope(spec, by_mac, by_person)

    try:
        rows = intel_store.equery(IntelSiteSession).filter(
            IntelSiteSession.last_seen >= start,
            IntelSiteSession.first_seen < end).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    if macs:
        rows = [r for r in rows if (r.device_mac or '').lower() in macs]

    bands = {}
    for row in rows:
        mac = (row.device_mac or '').lower()
        mapped = by_mac.get(mac) or {}
        if group_by == 'device':
            band_key = mac
            band_name = (labels.get(mac) or {}).get('name') or mac
            person_name = mapped.get('person_name')
        else:
            if mapped.get('person_id'):
                band_key = f"person:{mapped['person_id']}"
                band_name = mapped.get('person_name') or mac
            else:
                band_key = f'device:{mac}'
                band_name = ((labels.get(mac) or {}).get('name') or mac) + ' (unassigned)'
            person_name = mapped.get('person_name')
        band = bands.setdefault(band_key, {
            'key': band_key, 'name': band_name,
            'person': person_name,
            'macs': set(),
            'seconds': 0, 'intervals': [],
        })
        band['macs'].add(mac)
        band['seconds'] += int(row.dwell_seconds or 0)
        first = max(row.first_seen or start, start)
        last = min(row.last_seen or end, end)
        # clip to the requested day and turn it into minutes-from-midnight,
        # which is what a timeline needs
        start_min = max(0, int((first - start).total_seconds() // 60))
        end_min = min(1440, max(start_min + 1, int((last - start).total_seconds() // 60) + 1))
        band['intervals'].append({
            'start': start_min, 'end': end_min,
            'start_time': first.strftime('%H:%M'), 'end_time': last.strftime('%H:%M'),
            'seconds': int(row.dwell_seconds or 0),
            'human': _hms(row.dwell_seconds),
            'app': row.app, 'category': row.category,
            'domain': row.root_domain,
            'url': row.url_last,
            'estimated': bool(row.is_estimated),
        })

    out = []
    for band in bands.values():
        band['intervals'].sort(key=lambda i: i['start'])
        band['macs'] = sorted(band['macs'])
        band['human'] = _hms(band['seconds'])
        out.append(band)
    out.sort(key=lambda b: -b['seconds'])
    return jsonify({
        'day': day, 'by': group_by, 'bands': out,
        'total_seconds': sum(b['seconds'] for b in out),
        'total_human': _hms(sum(b['seconds'] for b in out)),
        'person': ({'id': person_filter.id,
                    'name': person_filter.display_name or person_filter.name}
                   if person_filter else None),
    })


# ---------------------------------------------------------------------------
# /heatmap - hours x days grid of usage (the "when is the house busy" view)
# ---------------------------------------------------------------------------

@history_bp.route('/heatmap')
def heatmap():
    """One row per day, 24 columns of hours, coloured by time used.

    Built from the 5-minute buckets, so it is a real picture of *when* activity
    happened rather than a daily total: midnight -> 23:59, every day in the
    window.  ``dimension=app|category`` with ``key=`` restricts the grid to one
    app ("when is Roblox played?"); the default is all device activity.
    """
    spec = _filters()
    by_mac, by_person = identity_maps()
    person, macs = _person_scope(spec, by_mac, by_person)
    dimension = (request.args.get('dimension') or 'device').lower()
    if dimension not in ('device', 'app', 'site', 'category'):
        dimension = 'device'
    key = (request.args.get('key') or '').strip() or None

    day_axis = []
    cursor = datetime.strptime(spec['start_date'], '%Y-%m-%d')
    last = datetime.strptime(spec['end_date'], '%Y-%m-%d')
    while cursor < last and len(day_axis) < 400:
        day_axis.append(cursor.strftime('%Y-%m-%d'))
        cursor += timedelta(days=1)

    grid = {day: [0] * 24 for day in day_axis}
    hour_totals = [0] * 24
    day_totals = {day: 0 for day in day_axis}
    try:
        rows = intel_store.equery(IntelUsageBucket).filter(
            IntelUsageBucket.bucket_start >= spec['start'],
            IntelUsageBucket.bucket_start < spec['end'],
            IntelUsageBucket.dimension == dimension).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    for row in rows:
        if macs and (row.device_mac or '').lower() not in macs:
            continue
        if key and (row.key or '').lower() != key.lower():
            continue
        day = row.bucket_start.strftime('%Y-%m-%d')
        if day not in grid:
            continue
        # the device dimension keeps its time in online_seconds, everything else
        # in seconds (a device can be online with no identifiable app)
        value = int(row.online_seconds or row.seconds or 0)
        if value <= 0:
            continue
        hour = row.bucket_start.hour
        grid[day][hour] += value
        hour_totals[hour] += value
        day_totals[day] += value

    peak = max([max(values) for values in grid.values()] or [0])
    return jsonify({
        'dimension': dimension, 'key': key,
        'range': spec['range'], 'start': spec['start_date'], 'end': spec['end_date'],
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'hour_totals': hour_totals,
        'hours': [{'hour': h, 'seconds': hour_totals[h], 'human': _hms(hour_totals[h])}
                  for h in range(24)],
        'days': [{'day': day, 'hours': grid[day], 'seconds': day_totals[day],
                  'human': _hms(day_totals[day]),
                  'peak_hour': (max(range(24), key=lambda h: grid[day][h])
                                if day_totals[day] else None)}
                 for day in day_axis],
        'max_seconds': peak,
        'totals': {
            'seconds': sum(day_totals.values()), 'human': _hms(sum(day_totals.values())),
            'busiest_hour': (max(range(24), key=lambda h: hour_totals[h])
                             if sum(hour_totals) else None),
            'busiest_day': (max(day_totals, key=lambda d: day_totals[d])
                            if any(day_totals.values()) else None),
            'active_days': len([d for d, v in day_totals.items() if v]),
        },
    })


# ---------------------------------------------------------------------------
# /daylog - the mobile "History" view: newest day first, newest visit first
# ---------------------------------------------------------------------------

@history_bp.route('/daylog')
def daylog():
    """Days of visited sites, ready to render as a timeline.

    Each entry is one site session with the time it started, what was visited
    (URL + domain), the app and category the catalogue resolved, and how long it
    lasted - which is exactly the shape a phone screen can show.
    """
    spec = _filters()
    by_mac, by_person = identity_maps()
    labels = device_labels()
    person, macs = _person_scope(spec, by_mac, by_person)
    per_day = min(max(int(request.args.get('per_day', 200) or 200), 1), 1000)
    now = datetime.utcnow()

    try:
        rows = intel_store.equery(IntelSiteSession).filter(
            IntelSiteSession.last_seen >= spec['start'],
            IntelSiteSession.last_seen < spec['end']).all()
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    if macs:
        rows = [r for r in rows if (r.device_mac or '').lower() in macs]

    days = {}
    for row in sorted(rows, key=lambda r: r.last_seen or now, reverse=True):
        day = (row.last_seen or row.first_seen or now).strftime('%Y-%m-%d')
        bucket = days.setdefault(day, {'day': day, 'seconds': 0, 'entries': [],
                                       'categories': {}, 'apps': {}, 'bytes': 0})
        seconds = int(row.dwell_seconds or 0)
        bucket['seconds'] += seconds
        bucket['bytes'] += int(row.bytes_total or 0)
        if row.category:
            bucket['categories'][row.category] = bucket['categories'].get(row.category, 0) + seconds
        if row.app:
            bucket['apps'][row.app] = bucket['apps'].get(row.app, 0) + seconds
        if len(bucket['entries']) >= per_day:
            continue
        started = row.first_seen or row.last_seen or now
        mac = (row.device_mac or '').lower()
        mapped = by_mac.get(mac) or {}
        age = (now - (row.last_seen or now)).total_seconds()
        bucket['entries'].append({
            'time': started.strftime('%H:%M'),
            'end_time': (row.last_seen or started).strftime('%H:%M'),
            'at': started.isoformat(),
            'url': row.url_last or (f'https://{row.hostname}/' if row.hostname else None),
            'domain': row.root_domain,
            'hostname': row.hostname,
            'app': row.app,
            'category': row.category,
            'seconds': seconds,
            'human': _hms(seconds),
            'span_human': _hms(row.span_seconds),
            'bytes': int(row.bytes_total or 0),
            'device': mac,
            'device_name': (labels.get(mac) or {}).get('name') or mac,
            'person': mapped.get('person_name'),
            'certain': bool(mapped.get('locked')),
            'estimated': bool(row.is_estimated),
            'is_live': age <= 60,
            'is_delayed': bool(row.source and row.source != 'live'),
            'freshness': 'live' if age <= 60 else ('recent' if age <= 900 else 'delayed'),
        })

    out = []
    for day in sorted(days, reverse=True):
        bucket = days[day]
        bucket['human'] = _hms(bucket['seconds'])
        bucket['visit_count'] = len(bucket['entries'])
        bucket['top_categories'] = sorted(
            [{'key': k, 'seconds': v, 'human': _hms(v)} for k, v in bucket['categories'].items()],
            key=lambda x: -x['seconds'])[:4]
        bucket['top_apps'] = sorted(
            [{'key': k, 'seconds': v, 'human': _hms(v)} for k, v in bucket['apps'].items()],
            key=lambda x: -x['seconds'])[:4]
        bucket.pop('categories', None)
        bucket.pop('apps', None)
        out.append(bucket)

    return jsonify({
        'range': spec['range'], 'start': spec['start_date'], 'end': spec['end_date'],
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'days': out,
        'totals': {
            'seconds': sum(d['seconds'] for d in out),
            'human': _hms(sum(d['seconds'] for d in out)),
            'visits': sum(d['visit_count'] for d in out),
            'days': len(out),
        },
    })


# ---------------------------------------------------------------------------
# /top - most frequent URLs / sites / apps / categories
# ---------------------------------------------------------------------------

@history_bp.route('/top')
def top_items():
    """The "most frequent" lists: by visits and by time, with byte volume."""
    spec = _filters()
    by_mac, by_person = identity_maps()
    person, macs = _person_scope(spec, by_mac, by_person)
    dimension = (request.args.get('dimension') or 'url').lower()
    limit = min(max(int(request.args.get('limit', 20) or 20), 1), 100)
    order = (request.args.get('order') or 'seconds').lower()   # seconds | visits | bytes

    items = {}
    if dimension in ('url', 'site'):
        try:
            rows = intel_store.equery(IntelSiteSession).filter(
                IntelSiteSession.last_seen >= spec['start'],
                IntelSiteSession.last_seen < spec['end']).all()
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500
        if macs:
            rows = [r for r in rows if (r.device_mac or '').lower() in macs]
        for row in rows:
            key = (row.url_last or row.hostname or row.root_domain
                   if dimension == 'url' else row.root_domain)
            if not key:
                continue
            entry = items.setdefault(key, {
                'key': key, 'domain': row.root_domain,
                'app': row.app, 'category': row.category,
                'seconds': 0, 'visits': 0, 'bytes': 0, 'devices': set(),
                'last_seen': None, 'first_seen': None})
            entry['seconds'] += int(row.dwell_seconds or 0)
            entry['visits'] += 1
            entry['bytes'] += int(row.bytes_total or 0)
            if row.device_mac:
                entry['devices'].add((row.device_mac or '').lower())
            if row.last_seen and (not entry['last_seen'] or row.last_seen > entry['last_seen']):
                entry['last_seen'] = row.last_seen
            if row.first_seen and (not entry['first_seen'] or row.first_seen < entry['first_seen']):
                entry['first_seen'] = row.first_seen
    else:
        if dimension not in ('app', 'category', 'device'):
            dimension = 'app'
        try:
            rows = intel_store.equery(IntelDailyUsage).filter(
                IntelDailyUsage.day >= spec['start_date'],
                IntelDailyUsage.day <= spec['end_date'],
                IntelDailyUsage.dimension == dimension).all()
        except Exception as exc:
            return jsonify({'error': str(exc)}), 500
        if macs:
            rows = [r for r in rows if (r.device_mac or '').lower() in macs]
        name_categories = app_categories() if dimension == 'app' else {}
        for row in rows:
            key = row.key or 'Unknown'
            entry = items.setdefault(key, {
                'key': key, 'domain': key if dimension == 'category' else None,
                'app': key if dimension in ('app', 'device') else None,
                'category': (row.key if dimension == 'category'
                             else (name_categories.get(key.lower()) if dimension == 'app'
                                   else None)),
                'seconds': 0, 'visits': 0, 'bytes': 0, 'devices': set(),
                'last_seen': None, 'first_seen': None})
            entry['seconds'] += int(row.seconds or 0)
            entry['visits'] += int(row.sessions or 0)
            entry['bytes'] += int(row.bytes_total or 0)
            if row.device_mac:
                entry['devices'].add((row.device_mac or '').lower())
            if row.last_seen and (not entry['last_seen'] or row.last_seen > entry['last_seen']):
                entry['last_seen'] = row.last_seen
            if row.first_seen and (not entry['first_seen'] or row.first_seen < entry['first_seen']):
                entry['first_seen'] = row.first_seen

    total_seconds = sum(v['seconds'] for v in items.values()) or 1
    out = []
    for entry in items.values():
        out.append({
            'key': entry['key'],
            'label': entry['app'] or entry['key'],
            'domain': entry['domain'],
            'app': entry['app'],
            'category': entry['category'],
            'seconds': entry['seconds'],
            'human': _hms(entry['seconds']),
            'visits': entry['visits'],
            'bytes': entry['bytes'],
            'mb': round(entry['bytes'] / (1024 * 1024.0), 2),
            'share': round(entry['seconds'] / total_seconds, 4),
            'devices': sorted(entry['devices']),
            'first_seen': _iso(entry['first_seen']),
            'last_seen': _iso(entry['last_seen']),
        })
    key_func = {'visits': lambda x: -x['visits'], 'bytes': lambda x: -x['bytes']}.get(
        order, lambda x: -x['seconds'])
    out.sort(key=key_func)
    return jsonify({
        'dimension': dimension, 'order': order, 'range': spec['range'],
        'start': spec['start_date'], 'end': spec['end_date'],
        'person': ({'id': person.id, 'name': person.display_name or person.name}
                   if person else None),
        'items': out[:limit],
        'totals': {'distinct': len(out), 'seconds': sum(v['seconds'] for v in items.values()),
                   'visits': sum(v['visits'] for v in items.values()),
                   'bytes': sum(v['bytes'] for v in items.values())},
    })
