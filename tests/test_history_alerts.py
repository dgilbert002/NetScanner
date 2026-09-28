"""Parental surface: search extraction, alert rules/dedupe, history rollups."""

import json
from datetime import datetime, timedelta

import pytest

from src.intel.flow import search_term_from_url


# ---------------------------------------------------------------------------
# search extraction
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('host,path,engine,term', [
    ('www.google.com', '/search?q=lego+fortnite+cheats', 'google.com', 'lego fortnite cheats'),
    ('google.com', '/search?q=%22how+to+unblock%22&hl=en', 'google.com', '"how to unblock"'),
    ('duckduckgo.com', '/?q=minecraft+mods', 'duckduckgo.com', 'minecraft mods'),
    ('www.bing.com', '/search?q=free+roblox+robux', 'bing.com', 'free roblox robux'),
    ('yandex.ru', '/search/?text=погода', 'yandex.ru', 'погода'),
    ('www.youtube.com', '/results?search_query=lofi+beats', 'youtube.com', 'lofi beats'),
    ('www.google.com', '/url?q=https://example.com/&sa=U', None, None),
    ('discord.com', '/api/v9/channels', None, None),
    ('example.com', '/search', None, None),
])
def test_search_terms_are_extracted_from_urls(host, path, engine, term):
    found_engine, found_term = search_term_from_url(host, path)
    assert found_term == term
    if term:
        assert found_engine == engine


def test_search_engine_is_reported_on_http_evidence(client):
    """A plain-HTTP search arrives with its engine and term attached."""
    from src.intel.engine import get_engine
    now = datetime.utcnow()
    payload = [{
        'source': 'live', 'device_mac': 'aa:bb:cc:11:99:77', 'src_ip': '192.168.50.41',
        'dst_ip': '142.250.0.9', 'dst_port': 80, 'src_port': 50000, 'protocol': 'TCP',
        'http_host': 'www.google.com', 'http_path': '/search?q=youtube+unblocked',
        'observed_at': (now - timedelta(seconds=30)).isoformat(),
    }]
    response = client.post('/api/intel/observe', json=payload)
    assert response.status_code == 200
    assert response.get_json()['accepted'] == 1
    with client.application.app_context():
        engine_obj = get_engine()
        from src.intel import store as intel_store
        with intel_store.forced_engine_session():
            engine_obj.flush_now()
    rows = client.get('/api/intel/searches?hours=24').get_json()['searches']
    assert any(r['term'] == 'youtube unblocked' and r['engine'] == 'google.com' for r in rows)


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

def _seed_hour(engine, mac, host, minutes, ago_hours=1, start_minute=0):
    """Feed one continuous block of evidence for a single site.

    Only the SNI is supplied: the app name and category come from the catalogue,
    exactly as they do for captured traffic.
    """
    from src.intel.flow import Evidence
    from src.intel import store as intel_store
    base = datetime.utcnow() - timedelta(hours=ago_hours) + timedelta(minutes=start_minute)
    for minute in range(minutes):
        ev = Evidence(observed_at=base + timedelta(minutes=minute), source='forecast',
                      collector='test', device_mac=mac, src_ip='192.168.50.50',
                      dst_ip='203.0.113.9', src_port=40000 + minute, dst_port=443,
                      protocol='TCP', sni=host, bytes_down=150000, packets=20,
                      confidence=0.9)
        engine.process_evidence(ev)
    with intel_store.forced_engine_session():
        engine.flush_now()


def test_alert_rules_round_trip(client):
    rules = client.get('/api/intel/alerts/rules').get_json()
    assert 'adult_alert' in rules and 'bypass_alert' in rules
    updated = client.post('/api/intel/alerts/rules',
                          json={'gaming_minutes': 45, 'bypass_score_threshold': 25}).get_json()
    effective = updated.get('effective') or updated
    assert str(effective.get('gaming_minutes')) == '45'
    assert str(client.get('/api/intel/alerts/rules').get_json()['gaming_minutes']) == '45'
    # restore
    client.post('/api/intel/alerts/rules', json={'gaming_minutes': 120, 'bypass_score_threshold': 40})


def test_adult_content_raises_a_critical_alert_once(client, engine):
    mac = 'aa:bb:cc:77:00:01'
    _seed_hour(engine, mac, 'www.pornhub.com', 5, ago_hours=2)
    summary = client.post('/api/intel/alerts/evaluate?hours=6').get_json()['summary']
    assert summary.get('adult', 0) >= 1
    # second evaluation inside the dedupe window must not raise it again
    before = len(client.get('/api/intel/alerts?hours=6').get_json()['alerts'])
    client.post('/api/intel/alerts/evaluate?hours=6')
    after = len(client.get('/api/intel/alerts?hours=6').get_json()['alerts'])
    assert after == before
    rows = client.get('/api/intel/alerts?hours=6').get_json()['alerts']
    adult = [r for r in rows if r['kind'] == 'adult_content' and r['device_mac'] == mac]
    assert adult and adult[0]['severity'] == 'critical'


def test_person_binding_attributes_alerts_and_usage(client, engine):
    mac = 'aa:bb:cc:77:00:02'
    person = client.post('/api/intel/people', json={'name': 'TestKid', 'is_child': True}).get_json()['person']
    client.post(f"/api/intel/people/{person['id']}/bind", json={'mac': mac, 'locked': True})
    _seed_hour(engine, mac, 'roblox.com', 30, ago_hours=3)
    client.post('/api/intel/alerts/evaluate?hours=8')
    rows = client.get('/api/intel/alerts?hours=8').get_json()['alerts']
    mine = [r for r in rows if r['device_mac'] == mac]
    assert mine, 'expected at least the new_app alert for this device'
    assert all(r['person'] == 'TestKid' for r in mine)
    assert any(r['certain'] for r in mine)


# ---------------------------------------------------------------------------
# history rollups
# ---------------------------------------------------------------------------

def test_usage_and_calendar_agree(client, engine):
    mac = 'aa:bb:cc:77:00:03'
    person = client.post('/api/intel/people', json={'name': 'CalKid', 'is_child': True}).get_json()['person']
    client.post(f"/api/intel/people/{person['id']}/bind", json={'mac': mac, 'locked': True})
    _seed_hour(engine, mac, 'store.steampowered.com', 45, ago_hours=4)

    usage = client.get(f"/api/intel/usage?range=week&dimension=app&person={person['id']}").get_json()
    steam = [i for i in usage['items'] if i['key'] == 'Steam']
    assert steam, usage['items']
    assert steam[0]['seconds'] >= 44 * 60

    calendar = client.get(
        f"/api/intel/calendar?dimension=app&key=Steam&range=week&person={person['id']}").get_json()
    assert calendar['totals']['seconds'] == pytest.approx(steam[0]['seconds'], abs=90)
    assert calendar['totals']['active_days'] >= 1
    assert calendar['sessions']
    session = calendar['sessions'][0]
    assert session['span_seconds'] >= session['seconds'] >= 0
    assert session['person'] == 'CalKid'
    assert len(calendar['days']) >= 7


def test_usage_ranges_are_ordered(client):
    week = client.get('/api/intel/usage?range=week&dimension=app').get_json()
    month = client.get('/api/intel/usage?range=month&dimension=app').get_json()
    half = client.get('/api/intel/usage?range=6months&dimension=app').get_json()
    assert month['totals']['seconds'] >= week['totals']['seconds']
    assert half['totals']['seconds'] >= month['totals']['seconds']
    assert month['start'] < week['start']


def test_games_dimension_only_returns_games(client, engine):
    mac = 'aa:bb:cc:77:00:04'
    _seed_hour(engine, mac, 'roblox.com', 20, ago_hours=5)
    _seed_hour(engine, mac, 'discord.com', 20, ago_hours=6)
    games = client.get('/api/intel/usage?range=week&dimension=game').get_json()
    keys = {i['key'] for i in games['items']}
    assert 'Roblox' in keys
    assert 'Discord' not in keys
    assert all(i['category'] == 'Gaming' for i in games['items'])


def test_unknown_person_is_a_404(client):
    assert client.get('/api/intel/people/999999/summary').status_code == 404
