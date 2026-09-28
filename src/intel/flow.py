"""
Evidence extraction: packet bytes -> structured observation.

The important parts are pure functions over ``bytes`` so they can be unit
tested without a network card:

``parse_tls_client_hello``  TLS SNI + cipher/extension fingerprint (JA3-like)
``scan_for_client_hello``   finds a ClientHello anywhere in a payload (works for
                            QUIC Initial packets, where the handshake is carried
                            inside CRYPTO frames)
``parse_dns_message``       question + A/AAAA/CNAME answers
``parse_dhcp_options``      hostname + vendor class (DHCP fingerprint)
``decode_qname``            DNS name decoding with compression-pointer guard

Everything else is glue: :class:`PacketExtractor` maps a scapy packet to an
:class:`Evidence`, and :class:`ProcessAttributor` (psutil, optional) maps a local
port to the actual application name on the capture host - that is how we can say
"Discord" instead of "discord.com" for the machine we run on.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime

from src.intel.catalog import DEFAULT_CATALOG, root_domain

try:
    import psutil  # optional, free
    _PSUTIL = True
except Exception:  # pragma: no cover
    _PSUTIL = False


# ---------------------------------------------------------------------------
# Evidence container
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """One observation, ready for :mod:`src.intel.store`."""

    observed_at: datetime = field(default_factory=datetime.utcnow)
    source: str = 'live'                 # live | dns | pihole | netstat | probe | backfill | synthetic
    collector: str = 'scapy'
    device_mac: str = None
    src_ip: str = None
    dst_ip: str = None
    src_port: int = None
    dst_port: int = None
    protocol: str = None
    direction: str = 'out'

    dns_qname: str = None
    sni: str = None
    http_host: str = None
    http_path: str = None
    quic_sni: str = None
    tls_fingerprint: str = None
    dhcp_hostname: str = None
    mdns_name: str = None
    user_agent: str = None

    bytes_up: int = 0
    bytes_down: int = 0
    packets: int = 1
    is_estimated: bool = False
    confidence: float = 0.5
    detail: dict = field(default_factory=dict)

    # process attribution (capture host only)
    process_name: str = None

    def hostname(self):
        """Strongest name evidence available, in order of trust."""
        for value in (self.sni, self.quic_sni, self.http_host, self.dns_qname, self.mdns_name):
            if value:
                return value.strip('.').lower()
        return None

    def name_source(self):
        if self.sni:
            return 'sni'
        if self.quic_sni:
            return 'quic_sni'
        if self.http_host:
            return 'http'
        if self.dns_qname:
            return 'dns'
        if self.mdns_name:
            return 'mdns'
        return None

    def to_observation_kwargs(self):
        data = asdict(self)
        data.pop('process_name', None)
        host = self.hostname()
        if host:
            info = DEFAULT_CATALOG.lookup_host(host)
            data.setdefault('detail', {})
            data['detail'] = dict(data.get('detail') or {})
            if info:
                data['detail']['catalog'] = {
                    'app': info.get('app'), 'category': info.get('category'),
                    'owner': info.get('owner'), 'source': info.get('source'),
                }
                data['detail']['root_domain'] = info.get('root_domain')
        data['detail']['process'] = self.process_name
        return data


# ---------------------------------------------------------------------------
# DNS wire parsing
# ---------------------------------------------------------------------------

def decode_qname(data, offset):
    """Decode a (possibly compressed) DNS name. Returns ``(name, next_offset)``."""
    labels = []
    jumped = False
    next_offset = offset
    hops = 0
    while True:
        if offset >= len(data) or hops > 32:
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumped = True
            hops += 1
            if pointer >= len(data) or pointer == offset:
                break
            offset = pointer
            continue
        offset += 1
        if offset + length > len(data):
            break
        try:
            labels.append(data[offset:offset + length].decode('utf-8', 'ignore'))
        except Exception:
            labels.append('?')
        offset += length
        if not jumped:
            next_offset = offset
    return ('.'.join(labels).lower(), next_offset)


def parse_dns_message(payload):
    """Parse a DNS message. Returns ``{'questions': [...], 'answers': [(name, type, value)]}``.

    ``value`` is the A/AAAA address or the CNAME target; other types are skipped.
    """
    out = {'questions': [], 'answers': [], 'rcode': None, 'id': None}
    if not payload or len(payload) < 12:
        return out
    try:
        txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack('!HHHHHH', payload[:12])
        out['id'] = txid
        out['rcode'] = flags & 0x000F
        offset = 12
        for _ in range(qdcount):
            name, offset = decode_qname(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype, _qclass = struct.unpack('!HH', payload[offset:offset + 4])
            offset += 4
            out['questions'].append((name, qtype))
        for _ in range(ancount):
            name, offset = decode_qname(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack('!HHIH', payload[offset:offset + 10])
            offset += 10
            rdata = payload[offset:offset + rdlength]
            offset += rdlength
            if rtype == 1 and rdlength == 4:            # A
                out['answers'].append((name, 'A', socket.inet_ntoa(rdata)))
            elif rtype == 28 and rdlength == 16:        # AAAA
                try:
                    out['answers'].append((name, 'AAAA', str(ipaddress.IPv6Address(rdata))))
                except Exception:
                    pass
            elif rtype == 5:                            # CNAME
                target, _ = decode_qname(payload, offset - rdlength)
                out['answers'].append((name, 'CNAME', target))
            elif rtype == 12:                           # PTR
                target, _ = decode_qname(payload, offset - rdlength)
                out['answers'].append((name, 'PTR', target))
            elif rtype == 16:                           # TXT (used by mDNS)
                try:
                    txt = rdata[1:1 + rdata[0]].decode('utf-8', 'ignore') if rdata else ''
                    out['answers'].append((name, 'TXT', txt))
                except Exception:
                    pass
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# TLS / QUIC ClientHello parsing
# ---------------------------------------------------------------------------

def _read_u16(buf, i):
    return struct.unpack('!H', buf[i:i + 2])[0]


def parse_tls_client_hello(payload, start=0):
    """Parse a ClientHello starting at ``start``.

    Returns ``{'sni', 'ja3_str', 'ja3', 'cipher_count', 'extensions'}`` or ``None``.
    """
    try:
        if start + 4 > len(payload):
            return None
        # Some callers hand us the handshake record already stripped, some do not.
        if payload[start] in (0x16, 0x14, 0x15, 0x17) and payload[start + 1] == 0x03:
            # TLS record: skip record header, then handshake header
            rec_len = _read_u16(payload, start + 3)
            body = payload[start + 5:start + 5 + rec_len]
            if not body or body[0] != 0x01:
                return None
            hs_len = int.from_bytes(body[1:4], 'big')
            data = body[4:4 + hs_len]
        elif payload[start] == 0x01 and start + 9 <= len(payload) and payload[start + 4] == 0x03:
            # Bare handshake message
            hs_len = int.from_bytes(payload[start + 1:start + 4], 'big')
            data = payload[start + 4:start + 4 + hs_len]
        else:
            return None

        i = 0
        if len(data) < 34:
            return None
        version = data[0:2]
        i = 2 + 32                                   # legacy_version + random
        if i >= len(data):
            return None
        sid_len = data[i]
        i += 1 + sid_len
        if i + 2 > len(data):
            return None
        cipher_len = _read_u16(data, i)
        i += 2
        ciphers = data[i:i + cipher_len]
        i += cipher_len
        if i >= len(data):
            return None
        comp_len = data[i]
        i += 1 + comp_len

        sni = None
        ja3_ext = []
        curves = ''
        point_fmts = ''
        supported_versions = ''
        if i + 2 <= len(data):
            ext_len = _read_u16(data, i)
            i += 2
            end = min(len(data), i + ext_len)
            while i + 4 <= end:
                etype = _read_u16(data, i)
                elen = _read_u16(data, i + 2)
                edata = data[i + 4:i + 4 + elen]
                ja3_ext.append(etype)
                if etype == 0x0000 and len(edata) >= 5:         # server_name
                    # server_name_list
                    list_len = _read_u16(edata, 0)
                    if list_len >= 3:
                        ntype = edata[2]
                        nlen = _read_u16(edata, 3)
                        if ntype == 0 and nlen <= len(edata) - 5:
                            sni = edata[5:5 + nlen].decode('utf-8', 'ignore').lower()
                elif etype == 0x000A and len(edata) >= 2:       # supported_groups
                    g_len = _read_u16(edata, 0)
                    groups = edata[2:2 + g_len]
                    curves = '-'.join(str(_read_u16(groups, k)) for k in range(0, len(groups) - 1, 2))
                elif etype == 0x000B and len(edata) >= 1:       # ec_point_formats
                    fmts = edata[1:1 + edata[0]]
                    point_fmts = '-'.join(str(b) for b in fmts)
                elif etype == 0x002B and len(edata) >= 3:       # supported_versions
                    v_len = edata[0]
                    versions = edata[1:1 + v_len]
                    supported_versions = '-'.join(
                        '0x%s' % versions[k:k + 2].hex() for k in range(0, len(versions) - 1, 2))
                i += 4 + elen

        ja3_str = '{},{},{},{},{}'.format(
            version.hex(),
            '-'.join(str(_read_u16(ciphers, k)) for k in range(0, len(ciphers) - 1, 2)),
            '-'.join(str(e) for e in ja3_ext if e not in (0x0000,)),  # SNI excluded, as in JA3
            curves, point_fmts,
        )
        ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
        return {
            'sni': sni,
            'ja3_str': ja3_str[:512],
            'ja3': ja3,
            'cipher_count': cipher_len // 2,
            'extensions': ja3_ext[:40],
            'supported_versions': supported_versions,
            'tls_version': '0x' + version.hex(),
        }
    except Exception:
        return None


def scan_for_client_hello(payload, max_scan=4096):
    """Find a TLS ClientHello anywhere in ``payload``.

    Used for QUIC Initial packets and for odd framing where the handshake is not
    at offset 0.  Returns the same structure as :func:`parse_tls_client_hello`.
    """
    if not payload:
        return None
    limit = min(len(payload), max_scan)
    for i in range(limit - 9):
        if payload[i] == 0x01:
            hs_len = int.from_bytes(payload[i + 1:i + 4], 'big')
            if not (32 <= hs_len <= 16384):
                continue
            version = payload[i + 4:i + 6]
            if version in (b'\x03\x01', b'\x03\x02', b'\x03\x03'):
                parsed = parse_tls_client_hello(payload, start=i)
                if parsed and (parsed.get('sni') or parsed.get('cipher_count')):
                    return parsed
    return None


def is_quic(payload):
    """Cheap QUIC long-header detection (v1/v2 and drafts)."""
    if not payload or len(payload) < 7:
        return False
    first = payload[0]
    if not (first & 0x80):        # long header bit
        return False
    version = payload[1:5]
    return version in (b'\x00\x00\x00\x01', b'\x6b\x33\x43\xcf') or version[0] == 0x71 or \
        version[0] in range(0x60, 0x80)


# ---------------------------------------------------------------------------
# DHCP
# ---------------------------------------------------------------------------

def parse_dhcp_options(payload):
    """Extract hostname / vendor class / requested IP from a BOOTP+DHCP payload."""
    out = {}
    try:
        if len(payload) < 240:
            return out
        magic = payload[236:240]
        if magic != b'\x63\x82\x53\x63':
            return out
        client_mac = ':'.join('%02x' % b for b in payload[28:34])
        out['client_mac'] = client_mac
        out['client_ip'] = socket.inet_ntoa(payload[12:16])
        i = 240
        while i < len(payload):
            code = payload[i]
            if code == 0:
                i += 1
                continue
            if code == 255:
                break
            if i + 1 >= len(payload):
                break
            length = payload[i + 1]
            value = payload[i + 2:i + 2 + length]
            if code == 12:
                out['hostname'] = value.decode('utf-8', 'ignore').strip('\x00')
            elif code == 60:
                out['vendor_class'] = value.decode('utf-8', 'ignore').strip('\x00')
            elif code == 50 and length == 4:
                out['requested_ip'] = socket.inet_ntoa(value)
            elif code == 55:
                out['param_request_list'] = list(value)
            i += 2 + length
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

_HTTP_METHODS = (b'GET ', b'POST', b'HEAD', b'PUT ', b'DELETE', b'OPTIONS', b'PATCH', b'CONNECT')


def parse_http_request(payload):
    """Return ``{method, path, host, user_agent}`` for a plain HTTP request."""
    if not payload or not payload.startswith(_HTTP_METHODS):
        return None
    out = {}
    try:
        head, _, _body = payload.partition(b'\r\n\r\n')
        lines = head.split(b'\r\n')
        parts = lines[0].split(b' ')
        if len(parts) >= 2:
            out['method'] = parts[0].decode('utf-8', 'ignore')
            out['path'] = parts[1].decode('utf-8', 'ignore')
        for line in lines[1:]:
            key, sep, value = line.partition(b':')
            if not sep:
                continue
            k = key.strip().lower()
            v = value.strip().decode('utf-8', 'ignore')
            if k == b'host':
                out['host'] = v.split(':')[0].lower()
            elif k == b'user-agent':
                out['user_agent'] = v[:300]
            elif k == b'referer':
                out['referer'] = v[:300]
    except Exception:
        return None
    return out or None


# ---------------------------------------------------------------------------
# Process attribution (capture host only, free)
# ---------------------------------------------------------------------------

class ProcessAttributor:
    """Map local ports to process names so apps are identified, not guessed.

    ``psutil`` is used when present.  We keep a short-lived cache because
    enumerating connections is comparatively expensive.
    """

    def __init__(self, ttl_seconds=5.0):
        self.ttl = ttl_seconds
        self._cache = {}             # (proto, port) -> process name
        self._cache_at = 0.0
        self.available = _PSUTIL

    def refresh(self):
        if not self.available:
            return
        now = time.time()
        if now - self._cache_at < self.ttl:
            return
        mapping = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr:
                    continue
                port = getattr(conn.laddr, 'port', None)
                if port is None:
                    continue
                name = None
                if conn.pid:
                    try:
                        name = psutil.Process(conn.pid).name()
                    except Exception:
                        name = None
                if name:
                    mapping[conn.type, port] = name
        except Exception:
            return
        self._cache = mapping
        self._cache_at = now

    def name_for(self, local_port, protocol='TCP'):
        if not self.available or local_port is None:
            return None
        self.refresh()
        kind = socket.SOCK_STREAM if str(protocol).upper().startswith('TCP') else socket.SOCK_DGRAM
        return self._cache.get((kind, int(local_port))) or self._cache.get((socket.SOCK_STREAM, int(local_port)))


# ---------------------------------------------------------------------------
# Scapy packet -> Evidence
# ---------------------------------------------------------------------------

class PacketExtractor:
    """Turn scapy packets into :class:`Evidence` objects.

    Works with or without scapy: :meth:`from_packet` is only called by the
    capture loop when scapy is importable, but the DNS/TLS/HTTP parsers used
    here are pure-python and are also exercised by the tests and by the
    pyshark/netstat paths.
    """

    def __init__(self, local_networks=None, attributor=None, dns_cache=None):
        self.local_networks = list(local_networks or [])
        self.attributor = attributor
        self.dns_cache = dns_cache if dns_cache is not None else {}
        self.mac_by_ip = {}

    # -- helpers --------------------------------------------------------
    def is_local(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        for net in self.local_networks:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            except Exception:
                continue
        return False

    def remember_name(self, ip, name, ttl=1800):
        if ip and name:
            self.dns_cache[ip] = (name.rstrip('.').lower(), time.time() + ttl)

    def name_for_ip(self, ip):
        entry = self.dns_cache.get(ip)
        if not entry:
            return None
        name, expiry = entry
        if expiry and expiry < time.time():
            self.dns_cache.pop(ip, None)
            return None
        return name

    # -- packet handling ------------------------------------------------
    def from_packet(self, packet):
        """Return ``(forward: Evidence|None, reverse: Evidence|None, extra: dict)``."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.l2 import ARP, Ether
            from scapy.layers.dhcp import DHCP
            from scapy.layers.dns import DNS
        except Exception:
            return None, None, {}

        extra = {}
        try:
            if ARP in packet:
                arp = packet[ARP]
                if arp.psrc and arp.hwsrc:
                    self.mac_by_ip[str(arp.psrc)] = str(arp.hwsrc).lower()
                    extra['arp'] = {'ip': str(arp.psrc), 'mac': str(arp.hwsrc).lower()}
                return None, None, extra

            if IP not in packet:
                return None, None, extra

            ip = packet[IP]
            src_ip, dst_ip = str(ip.src), str(ip.dst)
            src_mac = dst_mac = None
            if Ether in packet:
                src_mac = str(packet[Ether].src).lower()
                dst_mac = str(packet[Ether].dst).lower()
            if not src_mac:
                src_mac = self.mac_by_ip.get(src_ip)
            if not dst_mac:
                dst_mac = self.mac_by_ip.get(dst_ip)

            raw = bytes(packet)
            proto_name = 'IP'
            src_port = dst_port = None
            payload = b''
            app_payload_offset = None

            if TCP in packet:
                tcp = packet[TCP]
                src_port, dst_port = int(tcp.sport), int(tcp.dport)
                proto_name = 'TCP'
                payload = bytes(tcp.payload)
                app_payload_offset = 0
            elif UDP in packet:
                udp = packet[UDP]
                src_port, dst_port = int(udp.sport), int(udp.dport)
                proto_name = 'UDP'
                payload = bytes(udp.payload)
            elif ICMP in packet:
                proto_name = 'ICMP'

            ev = Evidence(
                observed_at=datetime.utcnow(),
                source='live', collector='scapy',
                device_mac=src_mac, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, protocol=proto_name,
                bytes_up=len(raw), bytes_down=0, packets=1,
                direction='out' if self.is_local(src_ip) else ('in' if self.is_local(dst_ip) else 'other'),
            )

            # --- application evidence ---------------------------------
            if dst_port == 53 or src_port == 53:
                dns = parse_dns_message(payload)
                if dns['questions']:
                    ev.dns_qname = dns['questions'][0][0]
                    ev.confidence = 0.9
                for name, rtype, value in dns.get('answers', []):
                    if rtype in ('A', 'AAAA'):
                        self.remember_name(value, name)
                        extra.setdefault('dns_answers', []).append({'name': name, 'ip': value})

            if dst_port == 5353 or src_port == 5353:          # mDNS
                dns = parse_dns_message(payload)
                names = [q[0] for q in dns['questions']] or [a[0] for a in dns['answers']]
                if names:
                    ev.mdns_name = names[0].replace('.local', '')
                for name, rtype, value in dns.get('answers', []):
                    if rtype in ('A', 'AAAA'):
                        self.mac_by_ip.setdefault(value, ev.device_mac)

            if dst_port == 67 or dst_port == 68:              # DHCP
                dhcp = parse_dhcp_options(payload)
                if dhcp:
                    ev.dhcp_hostname = dhcp.get('hostname')
                    ev.device_mac = dhcp.get('client_mac') or ev.device_mac
                    extra['dhcp'] = dhcp

            if payload and app_payload_offset is not None:
                if dst_port == 80 or src_port == 80 or payload.startswith(_HTTP_METHODS):
                    http = parse_http_request(payload)
                    if http:
                        ev.http_host = http.get('host')
                        ev.http_path = http.get('path')
                        ev.user_agent = http.get('user_agent')
                        ev.confidence = 0.98
                        ev.detail['referer'] = http.get('referer')

                is_tls_port = dst_port in (443, 8443, 993, 995, 465, 587, 636, 990, 992)
                if payload[:1] == b'\x16' and payload[1:2] == b'\x03' or is_tls_port:
                    hello = parse_tls_client_hello(payload) or parse_tls_client_hello(payload, 0)
                    if hello:
                        if hello.get('sni'):
                            ev.sni = hello['sni']
                            self.remember_name(dst_ip, hello['sni'])
                            ev.confidence = 0.95
                        ev.tls_fingerprint = hello.get('ja3')
                        ev.detail['ja3_str'] = hello.get('ja3_str')
                        ev.detail['tls_version'] = hello.get('tls_version')
                        if not ev.name_source():
                            ev.dns_qname = self.name_for_ip(dst_ip)

                if is_quic(payload):
                    hello = scan_for_client_hello(payload)
                    if hello:
                        ev.quic_sni = hello.get('sni')
                        ev.protocol = 'QUIC'
                        if hello.get('sni'):
                            self.remember_name(dst_ip, hello['sni'])
                        if hello.get('ja3'):
                            ev.tls_fingerprint = hello['ja3']
                        ev.confidence = 0.9

                if not ev.name_source():
                    cached = self.name_for_ip(dst_ip)
                    if cached:
                        ev.dns_qname = cached
                        ev.confidence = max(ev.confidence, 0.6)

            # reverse-direction copy: an inbound packet tells us the server's
            # address and payload size but not the content.
            rev = Evidence(
                observed_at=ev.observed_at, source='live', collector='scapy',
                device_mac=dst_mac, src_ip=dst_ip, dst_ip=src_ip,
                src_port=dst_port, dst_port=src_port, protocol=proto_name,
                bytes_up=0, bytes_down=len(raw), packets=1, direction='in',
            )
            if not self.is_local(dst_ip):
                rev.detail['remote_mac'] = dst_mac
            if ev.hostname():
                rev.sni = ev.sni
                rev.http_host = ev.http_host
                rev.dns_qname = ev.dns_qname
                rev.quic_sni = ev.quic_sni

            if self.attributor is not None and ev.direction == 'out':
                ev.process_name = self.attributor.name_for(src_port, proto_name)

            return ev, rev, extra
        except Exception:
            return None, None, {}


# ---------------------------------------------------------------------------
# Non-packet sources
# ---------------------------------------------------------------------------

def evidence_from_connection(local_ip, local_port, remote_ip, remote_port,
                            protocol='TCP', process_name=None, state='ESTABLISHED',
                            observed_at=None, source='netstat'):
    """Build evidence from an OS connection table row (ss/netstat fallback)."""
    is_udp = str(protocol).upper().startswith('UDP')
    ev = Evidence(
        observed_at=observed_at or datetime.utcnow(),
        source=source, collector='netstat',
        src_ip=local_ip, dst_ip=remote_ip, src_port=local_port, dst_port=remote_port,
        protocol='UDP' if is_udp else 'TCP',
        bytes_up=0, bytes_down=0, packets=0, direction='out',
        is_estimated=True, confidence=0.45,
        process_name=process_name,
    )
    ev.detail['state'] = state
    ev.detail['no_payload'] = True
    return ev


def evidence_from_dns(client_ip, domain, when=None, device_mac=None, source='pihole',
                      query_type='A', collector='pihole'):
    """Build evidence from a DNS log line (Pi-hole FTL, dnsmasq, or our own capture)."""
    ev = Evidence(
        observed_at=when or datetime.utcnow(),
        source=source, collector=collector,
        src_ip=client_ip, device_mac=device_mac,
        protocol='DNS', dst_port=53,
        dns_qname=(domain or '').strip('.').lower() or None,
        bytes_up=0, bytes_down=0, packets=0,
        is_estimated=False, confidence=0.85,
    )
    ev.detail['query_type'] = query_type
    return ev


def merge_evidence(evidences):
    """Merge duplicate evidence rows (same second, same key) for batch efficiency."""
    merged = {}
    for ev in evidences:
        key = (ev.device_mac, ev.src_ip, ev.dst_ip, ev.dst_port, ev.protocol,
               ev.hostname(), int(ev.observed_at.timestamp()))
        if key in merged:
            current = merged[key]
            current.bytes_up += ev.bytes_up
            current.bytes_down += ev.bytes_down
            current.packets += ev.packets
            current.confidence = max(current.confidence, ev.confidence)
            if ev.process_name and not current.process_name:
                current.process_name = ev.process_name
            for attr in ('sni', 'dns_qname', 'http_host', 'quic_sni', 'tls_fingerprint',
                         'dhcp_hostname', 'mdns_name', 'user_agent'):
                if not getattr(current, attr) and getattr(ev, attr):
                    setattr(current, attr, getattr(ev, attr))
        else:
            merged[key] = ev
    return list(merged.values())
