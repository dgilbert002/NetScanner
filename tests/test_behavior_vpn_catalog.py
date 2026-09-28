"""Behavioural maths, identity probability and VPN/proxy detection."""

import math
from datetime import datetime, timedelta

from src.intel.behavior import (
    BehaviorEngine,
    cosine,
    distinctiveness,
    dwell_buckets,
    features_similarity,
    jaccard,
    jensen_shannon,
    normalized_entropy,
    shannon_entropy,
    softmax,
)
from src.intel.catalog import DEFAULT_CATALOG, root_domain
from src.intel.models import (
    IntelDailyUsage,
    IntelDeviceMac,
    IntelIdentityScore,
    IntelOnlineDay,
    IntelPerson,
    IntelUsageBucket,
)
from src.intel.vpnwatch import VpnWatch, label_for


# ---------------------------------------------------------------------------
# maths
# ---------------------------------------------------------------------------

def test_entropy_and_distinctiveness():
    flat = [1.0] * 24
    peaky = [0.0] * 24
    peaky[8] = 10.0
    assert shannon_entropy(flat) > 4.0
    assert normalized_entropy(flat) == 1.0
    assert distinctiveness(flat) == 0.0
    assert distinctiveness(peaky) == 1.0
    assert shannon_entropy(peaky) == 0


def test_cosine_and_jaccard_bounds():
    assert cosine([1, 0], [1, 0]) == 1.0
    assert cosine([1, 0], [0, 1]) == 0.0
    assert jaccard(['a', 'b'], ['b', 'c']) == 1 / 3
    assert jaccard([], []) == 0.0


def test_jensen_shannon_is_symmetric_and_bounded():
    a = [0.8, 0.2, 0.0]
    b = [0.1, 0.1, 0.8]
    assert math.isclose(jensen_shannon(a, b), jensen_shannon(b, a), rel_tol=1e-9)
    assert 0.0 <= jensen_shannon(a, b) <= 1.0
    assert jensen_shannon(a, a) < 1e-9


def test_softmax_normalises():
    probs = softmax([1.0, 2.0, 3.0])
    assert math.isclose(sum(probs), 1.0, rel_tol=1e-9)
    assert probs[2] > probs[1] > probs[0]


def test_dwell_buckets():
    buckets = dwell_buckets([5, 20, 60, 300, 1800, 7200])
    assert buckets == [1, 1, 1, 1, 1, 1]


def test_similarity_is_higher_for_matching_profiles():
    a = {'hours': [0.0] * 8 + [0.5, 0.5] + [0.0] * 14,
         'days': [1 / 7] * 7,
         'categories': {'Gaming': 0.8, 'Video': 0.2},
         'apps': {'Steam': 0.6, 'YouTube': 0.4},
         'sites': {'steampowered.com': 0.6, 'youtube.com': 0.4},
         'dwell': [0, 0, 0, 1, 0, 0],
         'stats': {'sessions_per_day': 20, 'mean_dwell': 300, 'night_ratio': 0.1}}
    b = dict(a)
    c = {'hours': [0.5] * 4 + [0.0] * 12 + [0.25, 0.25] + [0.0] * 6,
         'days': [1 / 7] * 7,
         'categories': {'Work': 0.9},
         'apps': {'Teams': 1.0},
         'sites': {'microsoft.com': 1.0},
         'dwell': [1, 0, 0, 0, 0, 0],
         'stats': {'sessions_per_day': 3, 'mean_dwell': 20, 'night_ratio': 0.05}}
    same, _ = features_similarity(a, b)
    different, _ = features_similarity(a, c)
    assert same > 0.95
    assert different < same - 0.3


# ---------------------------------------------------------------------------
# identity probability
# ---------------------------------------------------------------------------

def _seed_device_usage(mac, app, hours, days_back=6, seconds=600):
    for offset in range(days_back):
        day = (datetime.utcnow() - timedelta(days=offset)).strftime('%Y-%m-%d')
        row = IntelDailyUsage(day=day, dimension='app', key=app, device_mac=mac,
                              seconds=seconds, sessions=2,
                              first_seen=datetime.utcnow() - timedelta(days=offset, hours=1),
                              last_seen=datetime.utcnow() - timedelta(days=offset))
        from src.models.user import db
        db.session.add(row)
        for hour in hours:
            bucket = datetime.utcnow().replace(hour=hour, minute=0, second=0, microsecond=0)
            bucket = bucket - timedelta(days=offset)
            db.session.add(IntelUsageBucket(bucket_start=bucket, dimension='device',
                                            key=mac, device_mac=mac, online_seconds=seconds,
                                            seconds=seconds))
            db.session.add(IntelUsageBucket(bucket_start=bucket, dimension='app', key=app,
                                            device_mac=mac, seconds=seconds, sessions=1))
    db.session.commit()


def test_identity_probability_prefers_matching_behaviour(ctx):
    from src.models.user import db
    mac_a = 'aa:00:00:00:00:0a'
    mac_b = 'bb:00:00:00:00:0b'
    new_mac = 'de:ad:be:ef:00:ff'                # fresh private MAC with no history
    for mac in (mac_a, mac_b, new_mac):
        if not IntelDeviceMac.query.filter_by(normalized=mac).first():
            db.session.add(IntelDeviceMac(mac=mac, normalized=mac, vendor='Test',
                                          device_key=mac, is_randomized=mac == new_mac))
    db.session.commit()

    # Alex: gaming in the evening.  Sam: work in the morning.
    _seed_device_usage(mac_a, 'Steam', [19, 20, 21])
    _seed_device_usage(mac_b, 'Microsoft 365', [9, 10, 11])

    alex = IntelPerson(name='Alex', display_name='Alex')
    sam = IntelPerson(name='Sam', display_name='Sam')
    db.session.add_all([alex, sam])
    db.session.commit()

    engine = BehaviorEngine(days=14)
    for person, mac in ((alex, mac_a), (sam, mac_b)):
        row = IntelIdentityScore(device_mac=mac, person_id=person.id, person_name=person.name,
                                 probability=0.95, locked=True, is_binding=True)
        db.session.add(row)
    db.session.commit()

    engine.update_profiles()
    # Give the new MAC the same behaviour as Alex's device
    _seed_device_usage(new_mac, 'Steam', [19, 20, 21])
    candidates = engine.candidates_for_device(new_mac, days=14)
    assert candidates, 'expected identity candidates'
    assert candidates[0]['person_name'] == 'Alex'
    assert candidates[0]['probability'] > candidates[-1]['probability']


def test_profile_prior_beats_uniform(ctx):
    from src.models.user import db
    mac = 'cc:00:00:00:00:0c'
    if not IntelDeviceMac.query.filter_by(normalized=mac).first():
        db.session.add(IntelDeviceMac(mac=mac, normalized=mac, device_key='kids-iphone',
                                      hostname='kids-iphone'))
    person = IntelPerson.query.filter_by(name='Kid').first()
    if person is None:
        person = IntelPerson(name='Kid', display_name='Kid')
        db.session.add(person)
    db.session.commit()
    engine = BehaviorEngine()
    cands = engine.candidates_for_device(mac)
    assert cands
    top = cands[0]
    assert top['prior_reason'] in ('hostname', 'device_key', 'uniform', 'confirmed', 'profile')


# ---------------------------------------------------------------------------
# VPN / proxy detection
# ---------------------------------------------------------------------------

def test_label_thresholds():
    assert label_for(0) == 'none'
    assert label_for(25) == 'low'
    assert label_for(45) == 'medium'
    assert label_for(70) == 'high'
    assert label_for(95) == 'critical'


def test_known_vpn_domain_is_flagged(ctx):
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:01', dst_ip='185.130.44.10',
                             dst_port=443, hostname='us-nyc-1.nordvpn.com')
    assert finding is not None
    assert finding['provider'] == 'NordVPN'
    assert finding['score'] >= 40
    assert finding['label'] in ('medium', 'high', 'critical')
    signals = {e['signal'] for e in finding['evidence']}
    assert 'provider_domain' in signals


def test_openvpn_port_flagged(ctx):
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:02', dst_ip='203.0.113.9',
                             dst_port=1194, protocol='UDP')
    assert finding is not None
    assert 'tunnel_port' in {e['signal'] for e in finding['evidence']}


def test_dns_bypass_detection(ctx):
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:03', dst_ip='8.8.8.8', dst_port=53,
                             protocol='UDP')
    assert finding is not None
    assert finding['kind'] == 'dns_bypass'
    assert 'public_dns' in {e['signal'] for e in finding['evidence']}

    finding2 = watch.evaluate(device_mac='aa:bb:cc:dd:ee:03', dst_ip='104.16.248.249',
                              dst_port=443, hostname='cloudflare-dns.com')
    assert finding2 is not None
    assert 'doh_domain' in {e['signal'] for e in finding2['evidence']}


def test_tor_detected(ctx):
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:04', dst_ip='198.51.100.7',
                             dst_port=9050, protocol='TCP')
    assert finding is not None
    assert finding['kind'] == 'tor'
    assert finding['score'] >= 55


def test_plain_traffic_is_not_flagged(ctx):
    watch = VpnWatch()
    assert watch.evaluate(device_mac='aa:bb:cc:dd:ee:05', dst_ip='142.250.185.78',
                          dst_port=443, hostname='www.google.com') is None


def test_datacenter_asn_alone_is_not_a_vpn():
    """AWS traffic must not be reported as a VPN without corroboration."""
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:06', dst_ip='52.94.236.248',
                             dst_port=443, hostname=None)
    assert finding is None


def test_private_relay_flagged(ctx):
    watch = VpnWatch()
    finding = watch.evaluate(device_mac='aa:bb:cc:dd:ee:07', dst_ip='172.64.0.1', dst_port=443,
                             hostname='mask.icloud.com')
    assert finding is not None
    assert 'private_relay' in {e['signal'] for e in finding['evidence']}


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

def test_catalog_root_domain():
    assert root_domain('r4---sn-abc123.googlevideo.com') == 'googlevideo.com'
    assert root_domain('a.b.c.example.co.uk') == 'example.co.uk'
    assert root_domain('localhost') == 'localhost'


def test_catalog_names_are_specific():
    info = DEFAULT_CATALOG.lookup_host('r5---sn-p5qlsn7d.googlevideo.com')
    assert info['app'] == 'YouTube'
    assert info['category'] == 'Video'
    assert info['source'] == 'catalog'

    insta = DEFAULT_CATALOG.lookup_host('scontent.cdninstagram.com')
    assert insta['app'] == 'Instagram'
    assert insta['category'] == 'Social'

    adult = DEFAULT_CATALOG.lookup_host('www.pornhub.com')
    assert adult['category'] == 'Adult'

    unknown = DEFAULT_CATALOG.lookup_host('some-random-blog-xyz.example')
    assert unknown['source'] == 'root_domain'
    assert unknown['confidence'] < 0.5


def test_catalog_vpn_and_doh_helpers():
    assert DEFAULT_CATALOG.vpn_provider_for('nordvpn.com') == 'NordVPN'
    assert DEFAULT_CATALOG.vpn_provider_for('google.com') is None
    assert DEFAULT_CATALOG.is_doh_domain('cloudflare-dns.com') is True
    assert DEFAULT_CATALOG.is_doh_domain('example.com') is False
    assert DEFAULT_CATALOG.public_dns_provider('8.8.8.8') == 'Google DNS'
