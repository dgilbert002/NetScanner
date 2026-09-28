"""
Capture sources feeding the intelligence engine.

Priority (first available wins, and they can run together for corroboration):

1. **scapy + libpcap/Npcap** - full evidence: DNS, TLS SNI, QUIC SNI, HTTP,
   DHCP/mDNS hostnames, ARP mapping, per-direction byte counts.
2. **pyshark/tshark** - same evidence when scapy cannot open the interface.
3. **OS connection table** (``ss`` on Linux, ``netstat`` on Windows/macOS) -
   no payloads, so no hostnames except via the DNS cache, but it always works
   and it is how we recover on locked-down machines.  Rows are marked
   ``is_estimated`` so the UI never confuses them with observed data.
4. **Pi-hole FTL database** - client-IP -> domain pairs; the most accurate
   naming source available without payload capture.

All sources push :class:`~src.intel.flow.Evidence` objects into
:meth:`src.intel.engine.IntelEngine.process_evidence`, which is thread safe.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import queue
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta

from src.intel.flow import Evidence, PacketExtractor, ProcessAttributor, evidence_from_connection, evidence_from_dns

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def local_ipv4_networks():
    """Return local interface networks as ``['192.168.1.0/24', ...]``."""
    networks = []
    try:
        if psutil is not None:
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:
                        try:
                            net = ipaddress.ip_network(f'{addr.address}/{addr.netmask}', strict=False)
                            if not net.is_loopback:
                                networks.append(str(net))
                        except Exception:
                            continue
    except Exception:
        pass
    if not networks:
        networks = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
    return networks


def arp_table():
    """IP -> MAC map from the OS neighbour table (``ip neigh`` / ``arp -a``)."""
    mapping = {}
    system = platform.system()
    try:
        if system == 'Windows':
            out = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].count('.') == 3:
                    mac = parts[1].replace('-', ':').lower()
                    if len(mac) == 17:
                        mapping[parts[0]] = mac
        else:
            out = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'lladdr' in parts:
                    ip = parts[0]
                    mac = parts[parts.index('lladdr') + 1].lower()
                    if mac != 'failed':
                        mapping[ip] = mac
    except Exception:
        pass
    return mapping


def guess_interface():
    """Best guess at the interface carrying the default route."""
    try:
        system = platform.system()
        if system == 'Linux':
            out = subprocess.run(['ip', 'route', 'get', '1.1.1.1'],
                                 capture_output=True, text=True, timeout=4).stdout
            for token in out.split():
                if token.startswith(('eth', 'wlan', 'en', 'ens', 'enp')):
                    return token
            return 'eth0'
        if system == 'Darwin':
            out = subprocess.run(['route', '-n', 'get', 'default'],
                                 capture_output=True, text=True, timeout=4).stdout
            for line in out.splitlines():
                if 'interface:' in line:
                    return line.split(':')[-1].strip()
            return 'en0'
        if system == 'Windows':
            out = subprocess.run(['route', 'print', '0.0.0.0'],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    return parts[3]
    except Exception:
        pass
    return None


def parse_ss_output(output):
    """Parse ``ss -tun`` output (header columns are stable)."""
    conns = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower().rstrip('46')
        if proto not in ('tcp', 'udp'):
            continue
        local_raw = parts[4]
        remote_raw = parts[5] if len(parts) > 5 else None
        if not remote_raw or remote_raw == '*:*':
            continue
        conns.append((local_raw, remote_raw, 'TCP' if proto == 'tcp' else 'UDP', line))
    return conns


def parse_netstat_output(output):
    """Parse Windows / macOS ``netstat -an`` output."""
    conns = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        proto = parts[0].upper()
        if proto not in ('TCP', 'UDP'):
            continue
        if proto == 'TCP':
            if len(parts) < 4 or parts[3].upper() not in ('ESTABLISHED', 'SYN_SENT'):
                continue
            local_raw, remote_raw = parts[1], parts[2]
        else:
            local_raw, remote_raw = parts[1], parts[2] if parts[2] not in ('*:*',) else None
            if not remote_raw:
                continue
        conns.append((local_raw, remote_raw, proto, line))
    return conns


def split_hostport(raw):
    """Handle IPv4, IPv6 and Windows forms of ``host:port``."""
    if not raw:
        return None, None
    raw = raw.strip()
    if raw.startswith('[') and ']' in raw:
        host, _, port = raw[1:].partition(']:')
        return host, _int_or_none(port)
    if raw.count(':') == 1:
        host, _, port = raw.rpartition(':')
        return host, _int_or_none(port)
    if raw.count(':') > 1:                       # bare IPv6 without port
        return raw, None
    return raw, None


def _int_or_none(value):
    try:
        return int(value)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# capture sources
# ---------------------------------------------------------------------------

class ScapyCapture(threading.Thread):
    """Packet capture via scapy, feeding raw evidence into the engine."""

    def __init__(self, engine, interface=None, bpf='ip'):
        super().__init__(name='intel-scapy', daemon=True)
        self.engine = engine
        self.interface = interface
        self.bpf = bpf
        self.running = False
        self.error = None
        self.packets = 0
        self.dropped = 0
        self.extractor = PacketExtractor(local_networks=engine.local_networks,
                                         attributor=ProcessAttributor(),
                                         dns_cache=engine.dns_cache)
        self._last_mac_refresh = 0.0

    def stop(self):
        self.running = False

    def run(self):
        try:
            from scapy.all import sniff
        except Exception as exc:
            self.error = f'scapy unavailable: {exc}'
            self.engine.health.note('capture', error=self.error, status='degraded')
            return
        self.running = True
        try:
            sniff(iface=self.interface, prn=self._handle, store=False,
                  filter=self.bpf, stop_filter=lambda _p: not self.running)
        except Exception as exc:
            self.error = str(exc)
            self.engine.health.note('capture', error=f'scapy sniff failed: {exc}',
                                    status='degraded')

    def _handle(self, packet):
        if not self.running:
            return
        try:
            forward, reverse, extra = self.extractor.from_packet(packet)
            now = time.time()
            if now - self._last_mac_refresh > 60 and extra.get('arp'):
                self.engine.note_arp(extra['arp'].get('ip'), extra['arp'].get('mac'))
                self._last_mac_refresh = now
            if extra.get('dns_answers'):
                self.engine.note_dns_answers(extra['dns_answers'])
            if extra.get('dhcp'):
                dhcp = extra['dhcp']
                self.engine.note_dhcp(dhcp.get('client_mac'), dhcp.get('client_ip'),
                                      dhcp.get('hostname'), dhcp.get('vendor_class'))
            if forward is not None:
                self.packets += 1
                self.engine.process_evidence(forward)
            if reverse is not None:
                # inbound accounting is useful for byte totals
                self.engine.process_evidence(reverse, count_time=False)
        except Exception:
            self.dropped += 1


class PysharkCapture(threading.Thread):
    """tshark-based fallback capture (no libpcap needed on Windows)."""

    def __init__(self, engine, interface=None):
        super().__init__(name='intel-pyshark', daemon=True)
        self.engine = engine
        self.interface = interface
        self.running = False
        self.error = None

    def stop(self):
        self.running = False

    def run(self):
        try:
            import pyshark
        except Exception as exc:
            self.error = f'pyshark unavailable: {exc}'
            return
        self.running = True
        try:
            capture = pyshark.LiveCapture(interface=self.interface) if self.interface \
                else pyshark.LiveCapture()
            for pkt in capture.sniff_continuously():
                if not self.running:
                    break
                ev = self._to_evidence(pkt)
                if ev:
                    self.engine.process_evidence(ev)
        except Exception as exc:
            self.error = str(exc)
            self.engine.health.note('capture', error=f'pyshark failed: {exc}', status='degraded')

    def _to_evidence(self, pkt):
        try:
            if not hasattr(pkt, 'ip'):
                return None
            ev = Evidence(source='live', collector='pyshark',
                          src_ip=pkt.ip.src, dst_ip=pkt.ip.dst)
            if hasattr(pkt, 'tcp'):
                ev.protocol = 'TCP'
                ev.src_port = int(pkt.tcp.srcport)
                ev.dst_port = int(pkt.tcp.dstport)
            elif hasattr(pkt, 'udp'):
                ev.protocol = 'UDP'
                ev.src_port = int(pkt.udp.srcport)
                ev.dst_port = int(pkt.udp.dstport)
            else:
                ev.protocol = 'IP'
            if hasattr(pkt, 'dns') and getattr(pkt.dns, 'qry_name', None):
                ev.dns_qname = str(pkt.dns.qry_name).rstrip('.').lower()
            if hasattr(pkt, 'tls'):
                sni = getattr(pkt.tls, 'handshake_extensions_server_name', None)
                if sni:
                    ev.sni = str(sni).lower()
            if hasattr(pkt, 'http') and getattr(pkt.http, 'host', None):
                ev.http_host = str(pkt.http.host).lower()
                ev.http_path = str(getattr(pkt.http, 'request_uri', '/') or '/')
            if hasattr(pkt, 'quic'):
                sni = getattr(pkt.quic, 'tls_handshake_extensions_server_name', None)
                if sni:
                    ev.quic_sni = str(sni).lower()
            ev.bytes_up = int(getattr(pkt, 'length', 0) or 0)
            ev.device_mac = self.engine.mac_for_ip(ev.src_ip)
            return ev
        except Exception:
            return None


def normalize_address(ip):
    """Return a plain IPv4/IPv6 string.

    ``ss`` and ``netstat`` report IPv4 sockets as ``::ffff:10.0.0.5`` on dual
    stack hosts.  Left as-is they fail every IPv4 network/ARP lookup, so the row
    looks like an anonymous IPv6 connection.
    """
    if not ip:
        return None
    ip = str(ip).strip().strip('[]')
    if ip.startswith('::ffff:') and '.' in ip:
        return ip.split('::ffff:', 1)[1]
    if ip.count(':') and '%' in ip:                 # fe80::1%eth0
        ip = ip.split('%', 1)[0]
    return ip


def is_private_address(ip):
    ip = normalize_address(ip) or ''
    if not ip:
        return False
    if ip.startswith(('10.', '192.168.', '127.', '169.254.', '0.')):
        return True
    if ip.startswith('172.'):
        try:
            second = int(ip.split('.')[1])
            return 16 <= second <= 31
        except Exception:
            return False
    return ip.lower().startswith(('fe80', 'fc', 'fd', '::1'))


class PtrResolver(threading.Thread):
    """Reverse-DNS names for connections the packet path cannot see.

    The connection-table fallback sees an IP and a port, nothing else.  A PTR
    lookup turns ``142.250.185.78`` into ``fra24s07-in-f14.1e100.net``, which is
    enough for the catalog to name the service.  Lookups run on their own thread
    with a cache and a short timeout so the capture loop never blocks.
    """

    def __init__(self, max_workers=4, timeout=2.0, cache_ttl=3600):
        super().__init__(name='intel-ptr', daemon=True)
        self.queue = queue.Queue(maxsize=2000)
        self.cache = {}
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.running = False
        self.max_workers = max_workers
        self.pending = set()

    def lookup(self, ip):
        """Cached name or ``None``; queues a lookup when unknown."""
        entry = self.cache.get(ip)
        if entry:
            name, when = entry
            if time.time() - when < self.cache_ttl:
                return name
        if ip not in self.pending:
            self.pending.add(ip)
            try:
                self.queue.put_nowait(ip)
            except Exception:
                self.pending.discard(ip)
        return None

    def _resolve(self, ip):
        socket.setdefaulttimeout(self.timeout)
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = None
        finally:
            socket.setdefaulttimeout(None)
        self.cache[ip] = (name, time.time())
        self.pending.discard(ip)
        if len(self.cache) > 20000:
            for key in list(self.cache)[:5000]:
                self.cache.pop(key, None)
        return name

    def start(self):
        if self.resolver is not None and not self.resolver.is_alive():
            self.resolver.start()
        super().start()

    def run(self):
        self.running = True
        while self.running:
            try:
                ip = self.queue.get(timeout=1.0)
            except Exception:
                continue
            try:
                self._resolve(ip)
            except Exception:
                self.pending.discard(ip)


class ConnectionTableCapture(threading.Thread):
    """Poll ``ss``/``netstat`` for new connections (no privileges needed)."""

    def __init__(self, engine, interval=5.0, resolve_names=True):
        super().__init__(name='intel-netstat', daemon=True)
        self.engine = engine
        self.interval = interval
        self.running = False
        self.error = None
        self.seen = {}
        self.attributor = ProcessAttributor()
        self.resolve_names = resolve_names
        self.resolver = PtrResolver() if resolve_names else None

    def stop(self):
        self.running = False
        if self.resolver is not None:
            self.resolver.running = False

    def _snapshot(self):
        system = platform.system()
        try:
            if system == 'Windows':
                out = subprocess.run(['netstat', '-an'], capture_output=True, text=True,
                                     timeout=10).stdout
                return parse_netstat_output(out)
            if system == 'Darwin':
                out = subprocess.run(['netstat', '-an'], capture_output=True, text=True,
                                     timeout=10).stdout
                return parse_netstat_output(out)
            try:
                out = subprocess.run(['ss', '-tun'], capture_output=True, text=True,
                                     timeout=10).stdout
                rows = parse_ss_output(out)
                return rows
            except FileNotFoundError:
                out = subprocess.run(['netstat', '-tun'], capture_output=True, text=True,
                                     timeout=10).stdout
                rows = []
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0].lower() in ('tcp', 'tcp6', 'udp', 'udp6'):
                        rows.append((parts[3], parts[4], parts[0][:3].upper(), line))
                return rows
        except Exception as exc:
            self.error = str(exc)
            return []

    def run(self):
        self.running = True
        while self.running:
            try:
                rows = self._snapshot()
                arp = arp_table()
                for row in rows:
                    local_raw, remote_raw, proto = row[0], row[1], row[2]
                    local_ip, local_port = split_hostport(local_raw)
                    remote_ip, remote_port = split_hostport(remote_raw)
                    local_ip = normalize_address(local_ip)
                    remote_ip = normalize_address(remote_ip)
                    if not remote_ip or remote_ip in ('0.0.0.0', '::'):
                        continue
                    if remote_ip.startswith('127.') or is_private_address(remote_ip):
                        continue
                    if not local_ip or local_ip.startswith(('127.', '::1')):
                        continue
                    key = (local_ip, local_port, remote_ip, remote_port, proto)
                    last = self.seen.get(key)
                    now = time.time()
                    if last and now - last < self.interval * 3:
                        self.seen[key] = now
                        continue
                    self.seen[key] = now
                    process = self.attributor.name_for(local_port, proto)
                    ev = evidence_from_connection(
                        local_ip, local_port, remote_ip, remote_port, protocol=proto,
                        process_name=process, source='netstat')
                    # A PTR name is weaker than SNI/DNS but far better than an IP.
                    if self.resolver is not None:
                        name = self.resolver.lookup(remote_ip)
                        if name:
                            ev.dns_qname = name
                            ev.confidence = max(ev.confidence, 0.5)
                    ev.device_mac = arp.get(local_ip) or self.engine.mac_for_ip(local_ip)
                    self.engine.process_evidence(ev, count_time=False)
                if len(self.seen) > 20000:
                    self.seen = {k: v for k, v in self.seen.items() if time.time() - v < 3600}
            except Exception as exc:
                self.error = str(exc)
            time.sleep(self.interval)


class PiHoleDnsCapture(threading.Thread):
    """Poll the Pi-hole FTL database (or a remote Pi-hole API) for DNS pairs."""

    def __init__(self, engine, interval=10.0, pihole=None):
        super().__init__(name='intel-pihole', daemon=True)
        self.engine = engine
        self.interval = interval
        self.running = False
        self.error = None
        self.last_ts = datetime.utcnow() - timedelta(minutes=5)
        self.pihole = pihole
        self.mode = 'pihole'

    def stop(self):
        self.running = False

    def _poll_local(self):
        try:
            from src.pihole_tap import PiHoleTap
            tap = PiHoleTap()
            if not tap.enabled:
                return []
            return [(ip, host, ts) for ip, host, ts in tap.lookup_recent_a(600)]
        except Exception as exc:
            self.error = str(exc)
            return []

    def _poll_remote(self):
        try:
            from src.pihole_remote import PiHoleRemote
            remote = self.pihole or PiHoleRemote()
            if not remote.enabled:
                return []
            return [(ip, host, ts) for ip, host, ts in remote.get_recent_queries(600)]
        except Exception as exc:
            self.error = str(exc)
            return []

    def run(self):
        self.running = True
        while self.running:
            rows = self._poll_local()
            if not rows:
                self.mode = 'pihole-remote'
                rows = self._poll_remote()
            else:
                self.mode = 'pihole'
            fresh = 0
            for ip, host, when in rows:
                if when and when > self.last_ts:
                    fresh += 1
                    ev = evidence_from_dns(ip, host, when=when,
                                           device_mac=self.engine.mac_for_ip(ip),
                                           source='pihole', collector=self.mode)
                    self.engine.process_evidence(ev, count_time=False)
            if rows:
                self.last_ts = max([r[2] for r in rows if r[2]] or [self.last_ts])
                self.engine.health.note('pihole', events=fresh, status='healthy')
            time.sleep(self.interval)


# ---------------------------------------------------------------------------
# facade
# ---------------------------------------------------------------------------

class CaptureManager:
    """Starts the best available capture source(s) and reports their health."""

    def __init__(self, engine, interface=None):
        self.engine = engine
        self.interface = interface or os.getenv('NETSCANNER_INTERFACE') or guess_interface()
        self.sources = []
        self.mode = 'none'

    def start(self):
        started = []
        scapy_ok = False
        try:
            import scapy  # noqa: F401
            scapy_ok = True
        except Exception:
            scapy_ok = False

        if scapy_ok:
            source = ScapyCapture(self.engine, self.interface)
            source.start()
            time.sleep(1.0)
            if source.error:
                self.engine.health.note('capture', error=source.error, status='degraded')
            else:
                started.append('scapy')
                self.sources.append(source)

        if not started:
            try:
                import pyshark  # noqa: F401
                source = PysharkCapture(self.engine, self.interface)
                source.start()
                started.append('pyshark')
                self.sources.append(source)
            except Exception as exc:
                self.engine.health.note('capture', error=f'pyshark unavailable: {exc}',
                                        status='degraded')

        # The connection table is cheap and always useful (process attribution,
        # devices that the sniffer cannot see because of a switched network).
        netstat = ConnectionTableCapture(self.engine)
        netstat.start()
        self.sources.append(netstat)
        started.append('netstat')

        # Pi-hole is only started when it is actually reachable.
        try:
            from src.pihole_tap import PiHoleTap
            tap = PiHoleTap()
            if tap.enabled:
                pihole = PiHoleDnsCapture(self.engine, pihole=tap)
                pihole.start()
                self.sources.append(pihole)
                started.append('pihole')
        except Exception:
            pass

        self.mode = '+'.join(started)
        self.engine.health.note('capture', status='healthy',
                                detail={'mode': self.mode, 'interface': self.interface})
        return self.mode

    def stop(self):
        for source in self.sources:
            try:
                source.stop()
            except Exception:
                pass
        self.sources = []

    def status(self):
        detail = []
        for source in self.sources:
            detail.append({
                'name': getattr(source, 'name', source.__class__.__name__),
                'alive': source.is_alive() if hasattr(source, 'is_alive') else None,
                'error': getattr(source, 'error', None),
                'packets': getattr(source, 'packets', None),
                'dropped': getattr(source, 'dropped', None),
            })
        return {'mode': self.mode, 'interface': self.interface, 'sources': detail}
