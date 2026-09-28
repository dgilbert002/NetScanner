"""
MAC address intelligence.

Answers three questions the original code could not:

1. *Is this MAC real or randomised?*  iOS "Private Wi-Fi Address" and Android
   per-network randomisation set the locally-administered bit (bit 1 of the
   first octet) and do not use a registered OUI.  Those MACs are still
   trackable while they last, but they must be flagged so the UI can say
   "private address" instead of pretending it is a NIC.
2. *Which physical device is this?*  MACs rotate; the device does not.  We group
   MACs under a stable ``device_key`` built from the strongest evidence
   available (DHCP/mDNS/hostname > vendor+class > IP history).
3. *Has a person moved to a new device/MAC?*  Handoffs (old MAC goes quiet, new
   MAC of the same ``device_key`` appears) raise ``mac_handoff`` events which
   the UI shows as a star.

Everything here is offline and free: the OUI database is the bundled ``manuf``
package with an embedded fallback table for the common consumer vendors.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from src.intel.models import IntelDeviceEvent, IntelDeviceMac
from src.intel import store as intel_store

try:  # optional, bundled in requirements.txt
    from manuf import manuf as _manuf_mod
except Exception:  # pragma: no cover - optional dependency
    _manuf_mod = None


# Locally administered bit: second nibble of first octet in {2,6,a,e}
_RANDOM_NIBBLES = {'2', '6', 'a', 'e'}

# Small embedded fallback so the app is useful without ``manuf`` installed.
FALLBACK_OUI = {
    '00:1a:11': 'Google',
    '00:1b:63': 'Apple',
    '00:1e:c2': 'Apple',
    '00:23:12': 'Apple',
    '00:25:00': 'Apple',
    '00:26:bb': 'Apple',
    '00:3e:e1': 'Apple',
    '00:50:56': 'VMware',
    '00:61:71': 'Apple',
    '00:88:65': 'Apple',
    '04:0c:ce': 'Apple',
    '04:15:52': 'Apple',
    '04:1e:64': 'Apple',
    '04:52:f3': 'Apple',
    '04:54:53': 'Apple',
    '04:d3:cf': 'Apple',
    '04:db:56': 'Apple',
    '04:e5:36': 'Apple',
    '04:f1:3e': 'Apple',
    '04:f7:e4': 'Apple',
    '08:66:98': 'Apple',
    '0c:30:21': 'Apple',
    '0c:4d:e9': 'Apple',
    '0c:74:c2': 'Apple',
    '0c:77:1a': 'Apple',
    '10:40:f3': 'Apple',
    '10:93:e9': 'Apple',
    '10:9a:dd': 'Apple',
    '14:10:9f': 'Apple',
    '18:65:90': 'Apple',
    '18:af:61': 'Apple',
    '1c:1a:c0': 'Apple',
    '1c:ab:a7': 'Apple',
    '20:78:f0': 'Apple',
    '20:7d:74': 'Apple',
    '24:1e:eb': 'Apple',
    '28:37:37': 'Apple',
    '28:6a:ba': 'Apple',
    '28:cf:e9': 'Apple',
    '2c:1f:23': 'Apple',
    '2c:be:08': 'Apple',
    '30:63:6b': 'Apple',
    '34:08:bc': 'Apple',
    '34:12:98': 'Apple',
    '34:c0:59': 'Apple',
    '38:48:4c': 'Apple',
    '3c:07:54': 'Apple',
    '3c:ab:8e': 'Apple',
    '40:6c:8f': 'Apple',
    '40:98:ad': 'Apple',
    '44:00:10': 'Apple',
    '44:4c:0c': 'Apple',
    '48:60:bc': 'Apple',
    '4c:57:ca': 'Apple',
    '50:32:37': 'Apple',
    '54:26:96': 'Apple',
    '58:1f:aa': 'Apple',
    '5c:59:48': 'Apple',
    '5c:95:ae': 'Apple',
    '5c:f9:38': 'Apple',
    '60:03:08': 'Apple',
    '60:92:17': 'Apple',
    '60:c5:47': 'Apple',
    '64:76:ba': 'Apple',
    '64:b9:e8': 'Apple',
    '68:09:27': 'Apple',
    '68:96:7b': 'Apple',
    '6c:40:08': 'Apple',
    '6c:70:9f': 'Apple',
    '6c:94:66': 'Apple',
    '70:11:24': 'Apple',
    '70:3e:ac': 'Apple',
    '74:1b:b2': 'Apple',
    '74:e1:b6': 'Apple',
    '78:31:c1': 'Apple',
    '78:4f:43': 'Apple',
    '78:6c:1c': 'Apple',
    '7c:11:be': 'Apple',
    '7c:6d:62': 'Apple',
    '7c:c3:a1': 'Apple',
    '7c:f0:5f': 'Apple',
    '80:be:05': 'Apple',
    '80:e6:50': 'Apple',
    '84:38:35': 'Apple',
    '84:78:8b': 'Apple',
    '84:fc:fe': 'Apple',
    '88:1f:a1': 'Apple',
    '88:53:95': 'Apple',
    '88:66:a5': 'Apple',
    '8c:29:37': 'Apple',
    '8c:58:77': 'Apple',
    '8c:7b:9d': 'Apple',
    '8c:8e:f2': 'Apple',
    '90:72:40': 'Apple',
    '90:b0:ed': 'Apple',
    '94:94:26': 'Apple',
    '98:01:a7': 'Apple',
    '98:03:9b': 'Apple',
    '98:9e:63': 'Apple',
    '9c:04:eb': 'Apple',
    '9c:20:7b': 'Apple',
    '9c:35:eb': 'Apple',
    '9c:f3:87': 'Apple',
    '9c:fc:01': 'Apple',
    'a0:99:9b': 'Apple',
    'a4:5e:60': 'Apple',
    'a4:c3:61': 'Apple',
    'a8:51:ab': 'Apple',
    'a8:88:08': 'Apple',
    'a8:be:27': 'Apple',
    'ac:29:3a': 'Apple',
    'ac:3c:0b': 'Apple',
    'ac:61:ea': 'Apple',
    'ac:bc:32': 'Apple',
    'ac:cf:5c': 'Apple',
    'b0:34:95': 'Apple',
    'b0:65:bd': 'Apple',
    'b0:9f:ba': 'Apple',
    'b4:18:d1': 'Apple',
    'b4:f0:ab': 'Apple',
    'b8:09:8a': 'Apple',
    'b8:17:c2': 'Apple',
    'b8:41:a4': 'Apple',
    'b8:44:d9': 'Apple',
    'b8:53:ac': 'Apple',
    'b8:c1:11': 'Apple',
    'b8:e8:56': 'Apple',
    'bc:52:b7': 'Apple',
    'bc:67:78': 'Apple',
    'bc:9f:ef': 'Apple',
    'c0:1a:da': 'Apple',
    'c0:63:94': 'Apple',
    'c0:84:7a': 'Apple',
    'c0:9f:42': 'Apple',
    'c4:2c:03': 'Apple',
    'c8:1e:e7': 'Apple',
    'c8:2a:14': 'Apple',
    'c8:69:cd': 'Apple',
    'c8:b5:b7': 'Apple',
    'c8:bc:c8': 'Apple',
    'cc:08:8d': 'Apple',
    'cc:25:ef': 'Apple',
    'cc:29:f5': 'Apple',
    'cc:c7:60': 'Apple',
    'd0:03:4b': 'Apple',
    'd0:23:db': 'Apple',
    'd0:25:98': 'Apple',
    'd0:81:7a': 'Apple',
    'd0:e1:40': 'Apple',
    'd4:61:9d': 'Apple',
    'd4:9a:20': 'Apple',
    'd4:f4:6f': 'Apple',
    'd8:00:4d': 'Apple',
    'd8:1d:72': 'Apple',
    'd8:30:62': 'Apple',
    'd8:96:95': 'Apple',
    'd8:9e:3f': 'Apple',
    'd8:a2:5e': 'Apple',
    'dc:2b:2a': 'Apple',
    'dc:37:14': 'Apple',
    'dc:41:5f': 'Apple',
    'dc:86:d8': 'Apple',
    'dc:9b:9c': 'Apple',
    'dc:a4:ca': 'Apple',
    'dc:d3:21': 'Apple',
    'e0:5f:45': 'Apple',
    'e0:ac:cb': 'Apple',
    'e0:b5:2d': 'Apple',
    'e0:c9:7a': 'Apple',
    'e4:8b:7f': 'Apple',
    'e4:ce:8f': 'Apple',
    'e8:04:0b': 'Apple',
    'e8:80:2e': 'Apple',
    'e8:8d:28': 'Apple',
    'ec:35:86': 'Apple',
    'f0:18:98': 'Apple',
    'f0:99:bf': 'Apple',
    'f0:b0:e7': 'Apple',
    'f0:c1:f1': 'Apple',
    'f0:d1:a9': 'Apple',
    'f0:db:e2': 'Apple',
    'f0:dc:e2': 'Apple',
    'f4:0f:24': 'Apple',
    'f4:1b:a1': 'Apple',
    'f4:31:c3': 'Apple',
    'f4:5c:89': 'Apple',
    'f4:f1:5a': 'Apple',
    'f8:1e:df': 'Apple',
    'f8:27:93': 'Apple',
    'f8:38:80': 'Apple',
    'f8:4d:89': 'Apple',
    'f8:95:ea': 'Apple',
    'fc:25:3f': 'Apple',
    'fc:e9:98': 'Apple',
    '00:12:fb': 'Samsung',
    '00:15:b9': 'Samsung',
    '00:16:32': 'Samsung',
    '00:17:c9': 'Samsung',
    '00:1d:25': 'Samsung',
    '00:21:19': 'Samsung',
    '00:23:39': 'Samsung',
    '00:24:54': 'Samsung',
    '00:26:37': 'Samsung',
    '04:18:d6': 'Samsung',
    '08:37:3d': 'Samsung',
    '0c:71:5d': 'Samsung',
    '10:1d:c0': 'Samsung',
    '18:3a:2d': 'Samsung',
    '1c:66:aa': 'Samsung',
    '20:13:e0': 'Samsung',
    '24:4b:03': 'Samsung',
    '28:39:5e': 'Samsung',
    '2c:ae:2b': 'Samsung',
    '30:19:66': 'Samsung',
    '34:23:ba': 'Samsung',
    '38:aa:3c': 'Samsung',
    '3c:5a:37': 'Samsung',
    '40:0e:85': 'Samsung',
    '44:4e:1a': 'Samsung',
    '48:5a:3f': 'Samsung',
    '4c:3c:16': 'Samsung',
    '50:32:75': 'Samsung',
    '54:9b:12': 'Samsung',
    '58:21:e9': 'Samsung',
    '5c:0a:5b': 'Samsung',
    '60:6b:bd': 'Samsung',
    '64:b3:10': 'Samsung',
    '68:eb:ae': 'Samsung',
    '6c:2f:2c': 'Samsung',
    '70:f9:27': 'Samsung',
    '78:1f:db': 'Samsung',
    '7c:61:66': 'Samsung',
    '80:57:19': 'Samsung',
    '84:25:db': 'Samsung',
    '88:32:9b': 'Samsung',
    '8c:77:12': 'Samsung',
    '90:18:7c': 'Samsung',
    '94:35:0a': 'Samsung',
    '98:0c:82': 'Samsung',
    '9c:02:98': 'Samsung',
    'a0:21:95': 'Samsung',
    'a4:eb:d3': 'Samsung',
    'a8:06:00': 'Samsung',
    'ac:5f:3e': 'Samsung',
    'b0:72:bf': 'Samsung',
    'b4:3a:28': 'Samsung',
    'b8:5e:7b': 'Samsung',
    'bc:14:85': 'Samsung',
    'c0:bd:d1': 'Samsung',
    'c4:57:6e': 'Samsung',
    'c8:19:f7': 'Samsung',
    'cc:07:ab': 'Samsung',
    'd0:22:be': 'Samsung',
    'd4:87:d8': 'Samsung',
    'd8:57:ef': 'Samsung',
    'dc:71:44': 'Samsung',
    'e0:99:71': 'Samsung',
    'e4:58:b8': 'Samsung',
    'e8:50:8b': 'Samsung',
    'ec:1f:72': 'Samsung',
    'f0:25:b7': 'Samsung',
    'f4:0e:22': 'Samsung',
    'f8:0f:f9': 'Samsung',
    'fc:a1:3e': 'Samsung',
    '00:1c:b3': 'Xiaomi',
    '00:9e:c8': 'Xiaomi',
    '04:cf:8c': 'Xiaomi',
    '0c:1d:af': 'Xiaomi',
    '10:2a:b3': 'Xiaomi',
    '14:f6:5a': 'Xiaomi',
    '18:59:36': 'Xiaomi',
    '20:47:da': 'Xiaomi',
    '28:6c:07': 'Xiaomi',
    '34:ce:00': 'Xiaomi',
    '38:a4:ed': 'Xiaomi',
    '3c:bd:3e': 'Xiaomi',
    '40:31:3c': 'Xiaomi',
    '4c:49:e3': 'Xiaomi',
    '50:64:2b': 'Xiaomi',
    '58:44:98': 'Xiaomi',
    '64:09:80': 'Xiaomi',
    '64:cc:2e': 'Xiaomi',
    '68:ab:bc': 'Xiaomi',
    '74:23:44': 'Xiaomi',
    '78:11:dc': 'Xiaomi',
    '7c:1d:d9': 'Xiaomi',
    '8c:be:be': 'Xiaomi',
    '98:fa:e3': 'Xiaomi',
    'a4:da:22': 'Xiaomi',
    'ac:c1:ee': 'Xiaomi',
    'b0:e2:35': 'Xiaomi',
    'c4:0b:cb': 'Xiaomi',
    'd4:97:0b': 'Xiaomi',
    'e4:aa:ec': 'Xiaomi',
    'f0:b4:29': 'Xiaomi',
    'f8:a4:5f': 'Xiaomi',
    '00:0c:29': 'VMware',
    '08:00:27': 'VirtualBox',
    'b8:27:eb': 'Raspberry Pi Foundation',
    'dc:a6:32': 'Raspberry Pi Trading',
    'e4:5f:01': 'Raspberry Pi Trading',
    '28:cd:c1': 'Raspberry Pi Trading',
    'd8:3a:dd': 'Raspberry Pi Trading',
    '00:1e:06': 'WIBRAIN',
    'b0:be:76': 'TP-Link',
    '50:c7:bf': 'TP-Link',
    '60:32:b1': 'TP-Link',
    'a4:2b:b0': 'TP-Link',
    'e8:de:27': 'TP-Link',
    'f4:ec:38': 'TP-Link',
    '00:0c:43': 'Ralink',
    '04:a1:51': 'NETGEAR',
    '20:4e:7f': 'NETGEAR',
    '2c:30:33': 'NETGEAR',
    'a0:40:a0': 'NETGEAR',
    'c0:3f:0e': 'NETGEAR',
    '00:24:b2': 'Netgear',
    '00:1b:2f': 'NETGEAR',
    '00:26:5a': 'D-Link',
    '1c:7e:e5': 'D-Link',
    '28:10:7b': 'D-Link',
    '3c:1e:04': 'D-Link',
    '78:54:2e': 'D-Link',
    '84:c9:b2': 'D-Link',
    'b8:a3:86': 'D-Link',
    'cc:b2:55': 'D-Link',
    '00:1d:7e': 'Cisco-Linksys',
    '48:f8:b3': 'Cisco-Linksys',
    'c0:56:27': 'Belkin',
    'ec:1a:59': 'Belkin',
    '08:cc:68': 'Cisco',
    '00:17:94': 'Cisco',
    '00:26:cb': 'Cisco',
    '3c:ce:73': 'Cisco',
    '70:6b:b9': 'Cisco',
    'a0:3d:6f': 'Cisco',
    '00:11:32': 'Synology',
    '00:1c:c4': 'Hewlett Packard',
    '00:22:64': 'Hewlett Packard',
    '3c:d9:2b': 'Hewlett Packard',
    '94:57:a5': 'Hewlett Packard',
    '00:1a:a0': 'Dell',
    '00:21:9b': 'Dell',
    '14:18:77': 'Dell',
    '18:03:73': 'Dell',
    '24:b6:fd': 'Dell',
    '5c:f9:dd': 'Dell',
    '78:2b:cb': 'Dell',
    'b8:2a:72': 'Dell',
    'd4:ae:52': 'Dell',
    'f8:bc:12': 'Dell',
    '00:15:5d': 'Microsoft',
    '00:50:f2': 'Microsoft',
    '28:18:78': 'Microsoft',
    '7c:1e:52': 'Microsoft',
    'c8:3f:26': 'Microsoft',
    'dc:b4:c4': 'Microsoft',
    '00:1b:21': 'Intel',
    '00:1e:64': 'Intel',
    '00:21:6a': 'Intel',
    '00:24:d7': 'Intel',
    '3c:97:0e': 'Intel',
    '48:51:b7': 'Intel',
    '54:27:1e': 'Intel',
    '68:05:ca': 'Intel',
    '7c:7a:91': 'Intel',
    '94:65:9c': 'Intel',
    'a0:36:9f': 'Intel',
    'b4:6b:fc': 'Intel',
    'cc:2f:71': 'Intel',
    'e4:a4:71': 'Intel',
    'f8:16:54': 'Intel',
    '00:1f:3b': 'Intel',
    '00:26:c7': 'Intel',
    '00:0e:58': 'Sonos',
    '48:a6:b8': 'Sonos',
    '5c:aa:fd': 'Sonos',
    '78:28:ca': 'Sonos',
    '94:9f:3e': 'Sonos',
    'b8:e9:37': 'Sonos',
    '00:17:88': 'Philips Lighting',
    '00:55:da': 'Amazon',
    '08:84:9d': 'Amazon',
    '0c:47:c9': 'Amazon',
    '18:74:2e': 'Amazon',
    '34:d2:70': 'Amazon',
    '40:b4:cd': 'Amazon',
    '44:65:0d': 'Amazon',
    '4c:ef:c0': 'Amazon',
    '68:54:fd': 'Amazon',
    '74:c2:46': 'Amazon',
    '84:d6:d0': 'Amazon',
    'a0:02:dc': 'Amazon',
    'b4:7c:9c': 'Amazon',
    'f0:27:2d': 'Amazon',
    'f0:81:73': 'Amazon',
    'fc:a1:83': 'Amazon',
    '00:04:4b': 'NVIDIA',
    '00:0d:3a': 'Microsoft',
    '00:25:22': 'ASUSTek',
    '00:1f:c6': 'ASUSTek',
    '04:d4:c4': 'ASUSTek',
    '08:60:6e': 'ASUSTek',
    '1c:87:2c': 'ASUSTek',
    '2c:56:dc': 'ASUSTek',
    '38:d5:47': 'ASUSTek',
    '40:16:7e': 'ASUSTek',
    '50:46:5d': 'ASUSTek',
    '54:04:a6': 'ASUSTek',
    '70:4d:7b': 'ASUSTek',
    '74:d0:2b': 'ASUSTek',
    '88:d7:f6': 'ASUSTek',
    '9c:5c:8e': 'ASUSTek',
    'ac:22:0b': 'ASUSTek',
    'b0:6e:bf': 'ASUSTek',
    'bc:ae:c5': 'ASUSTek',
    'd0:17:c2': 'ASUSTek',
    'e0:3f:49': 'ASUSTek',
    'f4:6d:04': 'ASUSTek',
    'fc:aa:14': 'ASUSTek',
    '00:22:43': 'Roku',
    '00:0d:93': 'Roku',
    '88:de:a9': 'Roku',
    'ac:3a:7a': 'Roku',
    'b0:a7:37': 'Roku',
    'cc:6d:a0': 'Roku',
    'd8:31:34': 'Roku',
    '00:1a:79': 'LG Electronics',
    '10:f1:f2': 'LG Electronics',
    '20:21:41': 'LG Electronics',
    '2c:54:cf': 'LG Electronics',
    '40:b0:76': 'LG Electronics',
    '58:fd:b1': 'LG Electronics',
    '8c:3a:e3': 'LG Electronics',
    'a8:16:b2': 'LG Electronics',
    'c4:36:6c': 'LG Electronics',
    'cc:2d:8c': 'LG Electronics',
    '00:04:4b': 'NVIDIA',
    '00:0c:6e': 'ASUSTek',
    'f0:18:98': 'Apple',
}

# Vendor keywords -> device class
_CLASS_HINTS = (
    (('apple',), 'apple'),
    (('samsung', 'xiaomi', 'huawei', 'oppo', 'oneplus', 'vivo', 'motorola', 'lg electronics', 'sony', 'google'), 'phone'),
    (('intel', 'dell', 'hewlett', 'lenovo', 'asustek', 'micro-star', 'toshiba', 'acer', 'vmware', 'virtualbox', 'parallels'), 'computer'),
    (('raspberry', 'espressif', 'tuya', 'shelly', 'sonoff', 'wibrain', 'philips lighting', 'amazon', 'roku', 'sonos', 'google', 'chromecast', 'nest', 'ring', 'wyze', 'tp-link', 'netgear', 'd-link', 'belkin', 'ubiquiti', 'aruba', 'cisco', 'zyxel', 'mikrotik', 'synology', 'qnap'), 'iot'),
    (('nintendo', 'sony interactive', 'microsoft', 'nvidia'), 'console'),
)


# Accepted textual forms.  Anything else (including the legacy synthetic
# ``device-192.168.1.5`` / ``remote-8.8.8.8`` strings) is rejected outright:
# collapsing those to hex digits would silently create a "valid" MAC.
_MAC_PATTERNS = (
    re.compile(r'^[0-9a-f]{12}$'),
    re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$'),
    re.compile(r'^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$'),
    re.compile(r'^(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}$'),
)


def normalize_mac(mac):
    """Return ``aa:bb:cc:dd:ee:ff`` (lowercase) or ``None`` if not a MAC."""
    if not mac:
        return None
    s = str(mac).strip().lower()
    if not any(pattern.match(s) for pattern in _MAC_PATTERNS):
        return None
    hexonly = re.sub(r'[^0-9a-f]', '', s)
    if len(hexonly) != 12:
        return None
    return ':'.join(hexonly[i:i + 2] for i in range(0, 12, 2))


def oui_of(mac):
    norm = normalize_mac(mac)
    return norm[:8] if norm else None


def is_valid_mac(mac):
    """Only real 48-bit hardware-style addresses qualify.

    This rejects the synthetic ``device-192.168.1.5`` / ``remote-8.8.8.8``
    strings the legacy capture paths write into ``devices.mac_address``.
    """
    norm = normalize_mac(mac)
    if not norm:
        return False
    if norm == 'ff:ff:ff:ff:ff:ff':
        return False
    if norm.startswith('01:00:5e') or norm.startswith('33:33'):
        return False  # multicast
    first = int(norm[:2], 16)
    return not (first & 0x01)  # unicast


def is_locally_administered(mac):
    norm = normalize_mac(mac)
    if not norm:
        return False
    return norm[1] in _RANDOM_NIBBLES


def vendor_for(mac, parser=None):
    """Vendor name for a MAC using ``manuf`` (preferred) or the fallback table."""
    norm = normalize_mac(mac)
    if not norm:
        return None
    if is_locally_administered(norm):
        return None
    if parser is None and _manuf_mod is not None:
        try:
            parser = _manuf_mod.MacParser(update=False)
        except Exception:
            parser = None
    if parser is not None:
        for getter in ('get_manuf_long', 'get_manuf'):
            try:
                name = getattr(parser, getter)(norm)
                if name:
                    return str(name)
            except Exception:
                continue
    return FALLBACK_OUI.get(norm[:8])


def classify_vendor(vendor, hostname=None, port_hint=None):
    """Coarse device class: phone / computer / iot / console / apple / unknown."""
    v = (vendor or '').lower()
    for keys, cls in _CLASS_HINTS:
        for key in keys:
            if key in v:
                return cls
    h = (hostname or '').lower()
    if any(token in h for token in ('iphone', 'ipad', 'android', 'pixel', 'galaxy', 'phone', 'samsung-sm', 'redmi')):
        return 'phone'
    if any(token in h for token in ('macbook', 'laptop', 'desktop', 'pc-', 'windows', 'thinkpad', 'xps')):
        return 'computer'
    if any(token in h for token in ('tv', 'chromecast', 'echo', 'dot-', 'printer', 'camera', 'bulb', 'plug', 'switch', 'thermostat')):
        return 'iot'
    if port_hint in (9100, 515, 631):
        return 'printer'
    return 'unknown'


def randomization_kind(mac, vendor=None):
    """Classify a MAC as hardware / private / random.

    * ``locally_administered`` - bit set, no OUI match (iOS/Android private MAC).
    * ``apple_private`` - locally administered but Apple-typical (iOS uses a
      stable per-SSID address, so it can still be tracked while it lasts).
    * ``None`` - normal vendor MAC.
    """
    if not is_locally_administered(mac):
        return None
    return 'locally_administered'


def device_key_for(mac, hostname=None, dhcp_hostname=None, mdns_name=None, vendor=None, device_class=None):
    """Best-effort stable grouping key that survives MAC rotation.

    Precedence: DHCP/mDNS name > hostname > vendor+class > MAC itself.
    """
    for candidate in (dhcp_hostname, mdns_name, hostname):
        if candidate:
            key = str(candidate).strip().lower()
            # strip instance suffixes like '-2' / '.local' so rotations group
            key = re.sub(r'\.local\.?$', '', key)
            key = re.sub(r'[-_]?\d{1,3}$', '', key) if len(key) > 6 else key
            if len(key) >= 3:
                return key[:120]
    if vendor:
        cls = device_class or classify_vendor(vendor)
        return f'{vendor.lower()}:{cls}'[:120]
    return (normalize_mac(mac) or str(mac))[:120]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class MacRegistry:
    """Upsert MAC rows and detect movements/handoffs.

    ``handoff_window`` is how long an old MAC may stay silent before we no
    longer consider the appearance of a new MAC a "handoff" of the same device.
    """

    def __init__(self, handoff_window=timedelta(hours=3)):
        self.handoff_window = handoff_window
        self._parser = None
        if _manuf_mod is not None:
            try:
                self._parser = _manuf_mod.MacParser(update=False)
            except Exception:
                self._parser = None

    # -- helpers ---------------------------------------------------------
    def _row(self, mac):
        norm = normalize_mac(mac)
        if not norm:
            return None
        return intel_store.equery(IntelDeviceMac).filter_by(normalized=norm).first()

    # -- write path ------------------------------------------------------
    def observe(self, mac, ip=None, hostname=None, dhcp_hostname=None, mdns_name=None,
                bytes_total=0, when=None, source='live', autoflush=True):
        """Record a sighting. Returns ``(row, events)`` where events are dicts."""
        norm = normalize_mac(mac)
        events = []
        if not norm or not is_valid_mac(norm):
            return None, events

        when = when or datetime.utcnow()
        vendor = vendor_for(norm, self._parser)
        randomized = is_locally_administered(norm)
        kind = randomization_kind(norm, vendor)
        device_class = classify_vendor(vendor, hostname or dhcp_hostname or mdns_name)
        dkey = device_key_for(norm, hostname=hostname, dhcp_hostname=dhcp_hostname,
                              mdns_name=mdns_name, vendor=vendor, device_class=device_class)

        row = self._row(norm)
        created = False
        if row is None:
            row = IntelDeviceMac(
                mac=norm, normalized=norm, oui=oui_of(norm), vendor=vendor or 'Unknown',
                is_randomized=bool(randomized), random_kind=kind, device_class=device_class,
                hostname=hostname or dhcp_hostname or mdns_name,
                device_key=dkey, first_seen=when, last_seen=when,
                evidence=json.dumps({'first_source': source}),
            )
            from src.models.user import db
            intel_store.engine_session().add(row)
            created = True
        else:
            row.last_seen = max(row.last_seen or when, when)
            if vendor and (not row.vendor or row.vendor in ('Unknown', '')):
                row.vendor = vendor
            if kind and not row.random_kind:
                row.random_kind = kind
                row.is_randomized = True
            if device_class and device_class != 'unknown' and row.device_class in (None, 'unknown'):
                row.device_class = device_class
            for name in (dhcp_hostname, mdns_name, hostname):
                if name:
                    row.hostname = name
                    break
            if dkey and (not row.device_key or len(dkey) > len(row.device_key or '')):
                row.device_key = dkey

        # IP history
        ips = []
        try:
            ips = json.loads(row.ip_addresses or '[]')
        except Exception:
            ips = []
        if ip and ip not in ips:
            ips = (ips + [ip])[-8:]
            row.ip_addresses = json.dumps(ips)

        row.bytes_total = int((row.bytes_total or 0) + (bytes_total or 0))

        # --- movement detection -----------------------------------------
        if created:
            events.append({
                'kind': 'device_new',
                'severity': 'info',
                'title': f"New device seen: {vendor or 'unknown vendor'} {norm}",
                'confidence': 0.9,
                'detail': {'mac': norm, 'vendor': vendor, 'randomized': bool(randomized)},
            })
            # Handoff: another MAC of the same device_key went quiet recently.
            if row.device_key:
                siblings = intel_store.equery(IntelDeviceMac).filter(
                    IntelDeviceMac.device_key == row.device_key,
                    IntelDeviceMac.normalized != norm,
                ).all()
                for sib in siblings:
                    if not sib.last_seen:
                        continue
                    quiet_for = when - sib.last_seen
                    if timedelta(0) <= quiet_for <= self.handoff_window:
                        events.append({
                            'kind': 'mac_handoff',
                            'severity': 'notice',
                            'title': f"Device moved to a new MAC: {sib.normalized} → {norm}",
                            'related_mac': sib.normalized,
                            'confidence': 0.7 if sibling_random(sib) or randomized else 0.5,
                            'detail': {
                                'previous_mac': sib.normalized,
                                'new_mac': norm,
                                'quiet_seconds': int(quiet_for.total_seconds()),
                                'device_key': row.device_key,
                                'previous_randomized': bool(sib.is_randomized),
                                'new_randomized': bool(randomized),
                            },
                        })
                        row.mac_rotations = int((row.mac_rotations or 0) + 1)
                        sib.mac_rotations = int((sib.mac_rotations or 0) + 1)
                        break
        if autoflush:
            from src.models.user import db
            intel_store.engine_session().flush()
        return row, events


def sibling_random(sib):
    return bool(getattr(sib, 'is_randomized', False))


def movements_for(device_key, limit=20):
    """Return recent movement events for a device key (used by the star UI)."""
    rows = intel_store.equery(IntelDeviceMac).filter_by(device_key=device_key).all()
    macs = [r.normalized for r in rows]
    if not macs:
        return []
    events = intel_store.equery(IntelDeviceEvent).filter(
        IntelDeviceEvent.kind.in_(('mac_handoff', 'mac_rotation')),
    ).order_by(IntelDeviceEvent.event_at.desc()).limit(200).all()
    return [e for e in events if e.device_mac in macs or e.related_mac in macs][:limit]
