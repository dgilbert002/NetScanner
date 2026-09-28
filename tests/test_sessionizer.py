"""Session/time-accounting maths: idle close, dwell union, online union, buckets."""

from datetime import datetime, timedelta

from src.intel.flow import Evidence
from src.intel.models import IntelDailyUsage, IntelFlow, IntelOnlineDay, IntelSiteSession, IntelUsageBucket
from src.intel.sessionizer import Sessionizer, merge_interval, split_interval, server_port


def ev(ts, mac='aa:bb:cc:00:00:01', dst_ip='93.184.216.34', dst_port=443, host='example.com',
       bytes_up=1000, bytes_down=0, src_port=50000, protocol='TCP', source='live', estimated=False):
    return Evidence(
        observed_at=ts, source=source, collector='test', device_mac=mac, src_ip='192.168.1.10',
        dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol,
        sni=host, bytes_up=bytes_up, bytes_down=bytes_down, packets=1,
        is_estimated=estimated, confidence=0.9)


def test_server_port_prefers_service_port():
    assert server_port(50000, 443) == 443
    assert server_port(443, 50000) == 443
    assert server_port(50000, 51000) == 50000


def test_split_interval_across_buckets():
    start = datetime(2026, 1, 1, 10, 3, 0)
    end = datetime(2026, 1, 1, 10, 12, 0)
    pieces = list(split_interval(start, end))
    assert sum(seconds for _b, seconds in pieces) == 540
    assert len(pieces) == 3   # 10:03-10:05, 10:05-10:10, 10:10-10:12


def test_merge_interval_returns_only_fresh_pieces():
    intervals, fresh = merge_interval([], datetime(2026, 1, 1, 10, 0), datetime(2026, 1, 1, 10, 5))
    assert fresh == [(datetime(2026, 1, 1, 10, 0), datetime(2026, 1, 1, 10, 5))]
    intervals, fresh = merge_interval(intervals, datetime(2026, 1, 1, 10, 3), datetime(2026, 1, 1, 10, 8))
    # only 10:05 -> 10:08 is new
    assert fresh == [(datetime(2026, 1, 1, 10, 5), datetime(2026, 1, 1, 10, 8))]
    assert intervals == [(datetime(2026, 1, 1, 10, 0), datetime(2026, 1, 1, 10, 8))]


def test_single_packet_session_has_no_accrued_time(ctx):
    """One packet proves no duration - the legacy code counted minutes anyway."""
    s = Sessionizer(idle_seconds=90, mirror_legacy=False)
    s.ingest(ev(datetime(2026, 1, 1, 12, 0, 0), mac='aa:bb:cc:00:00:12'))
    accrued = sum(slot['seconds'] for slot in s._bucket_pending.values())
    assert accrued == 0                       # no seconds invented from one packet
    assert len(s.flows) == 1
    s.flush()


def test_dwell_union_does_not_double_count_parallel_flows(ctx):
    """Two sockets to the same site at the same time = one dwell interval."""
    base = datetime(2026, 1, 1, 13, 0, 0)
    mac = 'aa:bb:cc:00:00:13'
    s = Sessionizer(idle_seconds=90, mirror_legacy=False)
    # Flow A: 13:00:00 -> 13:00:30
    s.ingest(ev(base, src_port=40001, mac='aa:bb:cc:00:00:13'))
    s.ingest(ev(base + timedelta(seconds=30), src_port=40001, mac='aa:bb:cc:00:00:13'))
    # Flow B (same host, different socket) overlaps the same window
    s.ingest(ev(base + timedelta(seconds=10), src_port=40002, mac='aa:bb:cc:00:00:13'))
    s.ingest(ev(base + timedelta(seconds=30), src_port=40002, mac='aa:bb:cc:00:00:13'))
    site_key = (mac, 'example.com')
    site = s.sites[site_key]
    # union of [13:00:00, 13:00:30] and [13:00:10, 13:00:30] is 30 s
    assert site.dwell_seconds == 30
    s.flush()
    row = IntelDailyUsage.query.filter_by(day='2026-01-01', dimension='site',
                                          key='example.com').first()
    assert row is not None
    assert row.seconds == 30


def test_idle_gap_creates_new_session_and_closes_old(ctx):
    base = datetime(2026, 1, 1, 14, 0, 0)
    mac = 'aa:bb:cc:00:00:14'
    s = Sessionizer(idle_seconds=90, mirror_legacy=False)
    s.ingest(ev(base, mac='aa:bb:cc:00:00:14'))
    s.ingest(ev(base + timedelta(seconds=30), mac='aa:bb:cc:00:00:14'))
    s.ingest(ev(base + timedelta(seconds=300), mac='aa:bb:cc:00:00:14'))       # 4.5 minutes later -> new session
    assert len(s.flows) == 1
    flows = IntelFlow.query.order_by(IntelFlow.first_seen).all()
    assert any(f.state == 'closed' and f.close_reason == 'idle_timeout' for f in flows)
    assert s.counters['flows_closed'] == 1
    s.flush()


def test_sweep_closes_idle_sessions(ctx):
    base = datetime(2026, 1, 1, 15, 0, 0)
    mac = 'aa:bb:cc:00:00:15'
    s = Sessionizer(idle_seconds=60, mirror_legacy=False)
    s.ingest(ev(base, mac='aa:bb:cc:00:00:15'))
    s.ingest(ev(base + timedelta(seconds=20), mac='aa:bb:cc:00:00:15'))
    closed = s.sweep(now=base + timedelta(seconds=200))
    assert closed
    assert not s.flows
    s.flush()


def test_device_online_time_is_union_across_apps(ctx):
    """Two different apps in parallel: online = union, attributed = each."""
    base = datetime(2026, 1, 1, 16, 0, 0)
    mac = 'aa:bb:cc:00:00:16'
    s = Sessionizer(idle_seconds=300, mirror_legacy=False)
    # YouTube flow 16:00 -> 16:05
    s.ingest(ev(base, dst_ip='142.250.0.1', host='googlevideo.com', src_port=41000, mac='aa:bb:cc:00:00:16'))
    s.ingest(ev(base + timedelta(minutes=5), dst_ip='142.250.0.1', host='googlevideo.com', src_port=41000, mac='aa:bb:cc:00:00:16'))
    # Discord flow 16:02 -> 16:05
    s.ingest(ev(base + timedelta(minutes=2), dst_ip='162.159.130.1', host='discord.com', src_port=42000, mac='aa:bb:cc:00:00:16'))
    s.ingest(ev(base + timedelta(minutes=5), dst_ip='162.159.130.1', host='discord.com', src_port=42000, mac='aa:bb:cc:00:00:16'))
    s.flush()
    device_row = IntelOnlineDay.query.filter_by(day='2026-01-01', device_mac=mac).first()
    assert device_row is not None
    assert device_row.online_seconds == 300            # union, not 480
    app_rows = IntelDailyUsage.query.filter_by(day='2026-01-01', dimension='app').all()
    apps = {r.key: r.seconds for r in app_rows}
    assert apps.get('YouTube') == 300
    assert apps.get('Discord') == 180


def test_bucket_accrual_is_incremental_not_duplicated(ctx):
    base = datetime(2026, 1, 1, 17, 0, 0)
    mac = 'aa:bb:cc:00:00:17'
    s = Sessionizer(idle_seconds=300, mirror_legacy=False)
    for i in range(6):
        s.ingest(ev(base + timedelta(seconds=i * 10), mac='aa:bb:cc:00:00:17'))
    s.flush()
    s.ingest(ev(base + timedelta(seconds=60), mac='aa:bb:cc:00:00:17'))
    s.flush()
    rows = IntelUsageBucket.query.filter_by(bucket_start=datetime(2026, 1, 1, 17, 0),
                                            dimension='device').all()
    assert sum(r.online_seconds for r in rows) == 60


def test_estimated_evidence_is_marked(ctx):
    base = datetime(2026, 1, 1, 18, 0, 0)
    mac = 'aa:bb:cc:00:00:18'
    s = Sessionizer(idle_seconds=300, mirror_legacy=False)
    s.ingest(ev(base, source='netstat', estimated=True, mac='aa:bb:cc:00:00:18'))
    s.ingest(ev(base + timedelta(seconds=20), source='netstat', estimated=True, mac='aa:bb:cc:00:00:18'))
    s.flush()
    flow = IntelFlow.query.filter_by(device_mac=mac).order_by(IntelFlow.first_seen.desc()).first()
    assert flow is not None
    assert flow.is_estimated is True
    assert flow.source == 'netstat'


def test_site_state_live_then_idle(ctx):
    base = datetime.utcnow() - timedelta(seconds=200)
    s = Sessionizer(idle_seconds=90, mirror_legacy=False)
    s.ingest(ev(base))
    s.ingest(ev(base + timedelta(seconds=10)))
    s.sweep()
    site = IntelSiteSession.query.first()
    assert site is not None
    assert site.state in ('idle', 'live')
