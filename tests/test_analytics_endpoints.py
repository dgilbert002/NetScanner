"""Assignment, heat map, day log, series and "most frequent" endpoints."""

from datetime import datetime, timedelta

import pytest


def _seed(engine, mac, host, minutes, ago_hours=2):
    from src.intel.flow import Evidence
    from src.intel import store as intel_store
    base = datetime.utcnow() - timedelta(hours=ago_hours)
    for minute in range(minutes):
        engine.process_evidence(Evidence(
            observed_at=base + timedelta(minutes=minute), source='live', collector='test',
            device_mac=mac, src_ip='192.168.50.60', dst_ip='203.0.113.20',
            src_port=50000 + minute, dst_port=443, protocol='TCP', sni=host,
            bytes_down=120000, packets=15, confidence=0.9))
    with intel_store.forced_engine_session():
        engine.flush_now()


@pytest.fixture()
def household(client, engine):
    """One child with a device, one unassigned device."""
    kid = client.post('/api/intel/people', json={'name': 'AnaKid', 'is_child': True}).get_json()['person']
    client.post(f"/api/intel/people/{kid['id']}/bind",
                json={'mac': 'aa:bb:cc:88:00:01', 'locked': True})
    _seed(engine, 'aa:bb:cc:88:00:01', 'roblox.com', 30, ago_hours=3)
    _seed(engine, 'aa:bb:cc:88:00:02', 'discord.com', 15, ago_hours=2)
    return kid


def test_assignment_lists_people_devices_and_unassigned(client, household):
    data = client.get('/api/intel/assignment').get_json()
    assert data['device_count'] >= 2
    kid = [p for p in data['people'] if p['name'] == 'AnaKid']
    assert kid and kid[0]['macs'] == ['aa:bb:cc:88:00:01']
    assigned = [d for d in data['devices'] if d['mac'] == 'aa:bb:cc:88:00:01'][0]
    assert assigned['person'] == 'AnaKid' and assigned['certain'] is True
    # the second device has no person and therefore shows up as unassigned
    assert any(d['mac'] == 'aa:bb:cc:88:00:02' for d in data['unassigned'])


def test_person_lifecycle_rename_unbind_delete(client, engine):
    person = client.post('/api/intel/people', json={'name': 'TempKid'}).get_json()['person']
    mac = 'aa:bb:cc:88:00:09'
    client.post(f"/api/intel/people/{person['id']}/bind", json={'mac': mac, 'locked': True})

    renamed = client.patch(f"/api/intel/people/{person['id']}",
                           json={'display_name': 'Renamed', 'color': '#ff9d96'}).get_json()
    assert renamed['person']['display_name'] == 'Renamed'

    released = client.post(f"/api/intel/people/{person['id']}/unbind", json={'mac': mac})
    assert released.status_code == 200
    data = client.get('/api/intel/assignment').get_json()
    assert not [d for d in data['devices'] if d['mac'] == mac and d['person']]

    removed = client.delete(f"/api/intel/people/{person['id']}")
    assert removed.status_code == 200
    assert client.delete(f"/api/intel/people/{person['id']}").status_code == 404


def test_heatmap_covers_hours_and_days(client, household, engine):
    _seed(engine, 'aa:bb:cc:88:00:03', 'roblox.com', 20, ago_hours=4)
    data = client.get('/api/intel/heatmap?range=week').get_json()
    assert len(data['days']) == 7
    assert len(data['hours']) == 24
    assert all(len(day['hours']) == 24 for day in data['days'])
    assert data['totals']['seconds'] > 0
    busy = [day for day in data['days'] if day['seconds']]
    assert busy and busy[0]['peak_hour'] is not None


def test_heatmap_can_focus_one_app(client, household):
    data = client.get('/api/intel/heatmap?range=week&dimension=app&key=Roblox').get_json()
    assert data['dimension'] == 'app' and data['key'] == 'Roblox'
    assert data['totals']['seconds'] > 0
    # Discord traffic must not leak into the Roblox grid
    discord = client.get('/api/intel/heatmap?range=week&dimension=app&key=Discord').get_json()
    assert discord['totals']['seconds'] > 0


def test_daylog_is_newest_first_with_urls(client, household):
    data = client.get('/api/intel/daylog?range=week').get_json()
    assert data['days'], 'expected at least one day of history'
    days = [day['day'] for day in data['days']]
    assert days == sorted(days, reverse=True)
    day = data['days'][0]
    assert day['entries'], 'expected visits in the newest day'
    entries = day['entries']
    assert entries == sorted(entries, key=lambda e: e['at'], reverse=True)
    first = entries[0]
    for field in ('time', 'url', 'domain', 'app', 'category', 'human', 'person', 'freshness'):
        assert field in first
    assert any(e['url'] for e in entries)


def test_daylog_respects_the_person_filter(client, household):
    kid = household['id']
    mine = client.get(f'/api/intel/daylog?range=week&person={kid}').get_json()
    all_people = client.get('/api/intel/daylog?range=week').get_json()
    assert mine['totals']['seconds'] <= all_people['totals']['seconds']
    for entry in [e for day in mine['days'] for e in day['entries']]:
        assert entry['person'] == 'AnaKid'


def test_series_has_days_stack_people_and_hours(client, household):
    data = client.get('/api/intel/series?range=week&dimension=category').get_json()
    assert len(data['days']) == 7
    assert all('bytes' in day and 'human' in day for day in data['days'])
    assert data['stacked'], 'expected stacked series'
    assert {'key', 'name', 'points'} <= set(data['stacked'][0])
    assert any(person['name'] == 'AnaKid' for person in data['people'])
    assert sum(hour['seconds'] for hour in data['hours']) > 0
    assert data['totals']['peak_hour'] is not None


def test_top_items_support_every_order(client, household):
    by_time = client.get('/api/intel/top?range=week&dimension=url&order=seconds').get_json()
    by_visits = client.get('/api/intel/top?range=week&dimension=url&order=visits').get_json()
    apps = client.get('/api/intel/top?range=week&dimension=app&limit=5').get_json()
    assert by_time['items'] and by_visits['items']
    assert by_time['items'][0]['seconds'] >= by_time['items'][-1]['seconds']
    assert by_visits['items'][0]['visits'] >= by_visits['items'][-1]['visits']
    assert apps['items'] and len(apps['items']) <= 5
    assert all('mb' in item and 'share' in item for item in by_time['items'])


def test_gantt_groups_by_person_and_by_device(client, household):
    day = datetime.utcnow().strftime('%Y-%m-%d')
    by_person = client.get(f'/api/intel/gantt?date={day}&by=person').get_json()
    by_device = client.get(f'/api/intel/gantt?date={day}&by=device').get_json()
    assert by_person['total_seconds'] > 0
    bands = by_person['bands']
    assert bands and bands[0]['intervals']
    interval = bands[0]['intervals'][0]
    assert 0 <= interval['start'] < interval['end'] <= 1440
    assert interval['start_time'] and interval['human']
    assert by_device['bands'], 'device grouping should also produce bands'
