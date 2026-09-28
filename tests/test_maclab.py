"""MAC intelligence: normalisation, private-address detection, handoff stars."""

from datetime import datetime, timedelta

from src.intel import maclab
from src.intel.models import IntelDeviceMac, IntelDeviceEvent


def test_normalisation_and_validation():
    assert maclab.normalize_mac('AA-BB-CC-DD-EE-FF') == 'aa:bb:cc:dd:ee:ff'
    assert maclab.normalize_mac('aabb.ccdd.eeff') == 'aa:bb:cc:dd:ee:ff'
    assert maclab.normalize_mac('nonsense') is None
    assert maclab.is_valid_mac('aa:bb:cc:dd:ee:ff')
    assert not maclab.is_valid_mac('device-192.168.1.5')     # legacy synthetic MAC
    assert not maclab.is_valid_mac('remote-8.8.8.8')
    assert not maclab.is_valid_mac('ff:ff:ff:ff:ff:ff')
    assert not maclab.is_valid_mac('01:00:5e:00:00:01')      # multicast


def test_private_randomised_mac_detection():
    # iOS / Android private Wi-Fi addresses set the locally-administered bit
    assert maclab.is_locally_administered('de:ad:be:ef:00:01')
    assert maclab.is_locally_administered('06:1c:22:33:44:55')
    assert maclab.is_locally_administered('f2:9a:11:22:33:44')
    assert not maclab.is_locally_administered('00:1b:63:11:22:33')    # Apple OUI, bit clear
    assert not maclab.is_locally_administered('b8:27:eb:12:34:56')    # Raspberry Pi, bit clear
    assert maclab.is_locally_administered('aa:bb:cc:dd:ee:ff')        # 0xAA has the LA bit
    assert maclab.randomization_kind('de:ad:be:ef:00:01') == 'locally_administered'
    assert maclab.randomization_kind('00:1b:63:11:22:33') is None


def test_vendor_lookup_offline():
    vendor = maclab.vendor_for('b8:27:eb:12:34:56')
    assert vendor is not None
    assert 'raspberry' in vendor.lower() or 'raspberry' in str(maclab.FALLBACK_OUI.get('b8:27:eb', '')).lower()
    # randomised MACs must never be attributed to a vendor
    assert maclab.vendor_for('de:ad:be:ef:00:01') is None


def test_device_key_uses_names_over_mac():
    key = maclab.device_key_for('de:ad:be:ef:00:01', hostname='Maries-iPhone.local')
    assert 'maries-iphone' in key
    key2 = maclab.device_key_for('de:ad:be:ef:00:02', hostname='Maries-iPhone.local')
    assert key == key2                     # same device key across MAC rotation


def test_registry_records_and_detects_handoff(ctx):
    registry = maclab.MacRegistry(handoff_window=timedelta(hours=3))
    when = datetime(2026, 3, 1, 9, 0, 0)
    row1, events1 = registry.observe('aa:bb:cc:11:22:33', ip='192.168.1.50',
                                     hostname='Pixel-7', when=when, source='dhcp')
    assert row1 is not None
    assert any(e['kind'] == 'device_new' for e in events1)

    # The same person's phone comes back with a new private MAC two hours later
    row2, events2 = registry.observe('de:ad:be:ef:00:99', ip='192.168.1.51',
                                     hostname='Pixel-7', when=when + timedelta(hours=2),
                                     source='dhcp')
    kinds = {e['kind'] for e in events2}
    assert 'mac_handoff' in kinds
    handoff = [e for e in events2 if e['kind'] == 'mac_handoff'][0]
    assert handoff['related_mac'] == 'aa:bb:cc:11:22:33'
    assert handoff['confidence'] > 0.5
    assert row2.is_randomized is True
    from src.models.user import db
    db.session.commit()


def test_randomised_mac_still_tracked_persistently(ctx):
    registry = maclab.MacRegistry()
    when = datetime(2026, 3, 2, 8, 0, 0)
    mac = 'f2:11:22:33:44:55'
    registry.observe(mac, ip='192.168.1.60', hostname='iPad', when=when)
    registry.observe(mac, ip='192.168.1.60', hostname='iPad', when=when + timedelta(hours=3))
    row = IntelDeviceMac.query.filter_by(normalized=mac).first()
    assert row is not None
    assert row.is_randomized is True
    assert row.last_seen > row.first_seen            # tracked across time
    assert (row.bytes_total or 0) >= 0
    from src.models.user import db
    db.session.commit()
