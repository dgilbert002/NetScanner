"""
VPN / proxy / DNS-bypass detection.

Ten independent signals are combined into a 0-100 score.  Every signal records
its evidence so the UI can explain *why* something was flagged, and the scoring
deliberately refuses to call plain datacentre traffic a VPN without at least one
corroborating signal (or a sustained single-destination tunnel), because most
household traffic now goes to hosting ASNs.

Signals
-------
1. ``provider_domain``   hostname belongs to a known VPN/proxy brand
2. ``asn_vpn_brand``     destination ASN organisation is a VPN brand
3. ``asn_hosting``       destination ASN is a hosting/datacentre provider
4. ``tunnel_port``       port used by OpenVPN / WireGuard / IPsec / SOCKS / Tor…
5. ``tunnel_protocol``   IP protocol 4/41/47/50/51 (GRE, ESP, 6in4, L2TP…)
6. ``private_relay``     Apple iCloud Private Relay / Cloudflare WARP endpoints
7. ``doh_domain``        DNS-over-HTTPS domain (DNS bypass)
8. ``public_dns``        plain DNS to a public resolver, bypassing the router
9. ``dns_bypass``        DNS over TLS (853)
10. ``tor``              Tor ports/domains
11. ``sustained_tunnel`` one remote endpoint, long-lived, high volume, unnamed
12. ``nonstandard_tls``  TLS to unusual ports without SNI (often custom VPNs)

Free data only: the ASN lookup uses the bundled ``ip2asn.tsv`` and the brand
lists live in :mod:`src.intel.catalog_data`.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta

from src.models.user import db
from src.intel.catalog import DEFAULT_CATALOG, root_domain
from src.intel.catalog_data import (
    PUBLIC_DNS_IPS,
    SCORE_WEIGHTS,
    TUNNEL_IP_PROTOS,
    TUNNEL_PORTS,
    VPN_ASN_HOSTING,
    VPN_ASN_STRONG,
    VPN_HOST_HINTS,
    VPN_PROVIDER_DOMAINS,
)
from src.intel.models import IntelFlow, IntelVpnFinding
from src.intel import store as intel_store

LABELS = ((80, 'critical'), (60, 'high'), (40, 'medium'), (20, 'low'), (0, 'none'))


def label_for(score):
    for threshold, name in LABELS:
        if score >= threshold:
            return name
    return 'none'


class _Ip2Asn:
    """Lazy singleton around the bundled offline ASN database."""

    _instance = None
    _attempted = False

    def __init__(self):
        self.db = None
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'data', 'ip2asn.tsv')
        if os.path.exists(path):
            try:
                from src.ip2asn_lookup import Ip2AsnDB
                self.db = Ip2AsnDB(path)
            except Exception:
                self.db = None

    @classmethod
    def get(cls):
        if cls._instance is None and not cls._attempted:
            cls._attempted = True
            cls._instance = cls()
        return cls._instance

    def lookup(self, ip):
        info = None
        if self.db is not None:
            try:
                info = self.db.lookup(ip)
            except Exception:
                info = None
        if not info:
            try:
                from src.models.network import EnrichedData
                row = EnrichedData.query.filter_by(ip_address=ip).first()
                if row:
                    info = {'asn': row.asn, 'organization': row.organization,
                            'country': row.country_code}
            except Exception:
                info = None
        return info or {}


class VpnWatch:
    def __init__(self, health=None):
        self.health = health
        self._asn = _Ip2Asn.get()

    # ------------------------------------------------------------------
    # signal extraction
    # ------------------------------------------------------------------
    def asn_signals(self, ip):
        """Return ``(asn, org, country, signals)`` for a destination IP."""
        signals = []
        info = self._asn.lookup(ip) if ip else {}
        org = (info.get('organization') or '').lower()
        asn = info.get('asn')
        country = info.get('country')
        if org:
            for brand in VPN_ASN_STRONG:
                if brand in org:
                    signals.append({
                        'signal': 'asn_vpn_brand', 'weight': SCORE_WEIGHTS['asn_vpn_brand'],
                        'detail': f'ASN organisation is a VPN brand: {org} (AS{asn})'})
                    return asn, org, country, signals
            for hosting in VPN_ASN_HOSTING:
                if hosting in org:
                    signals.append({
                        'signal': 'asn_hosting', 'weight': SCORE_WEIGHTS['asn_hosting'],
                        'detail': f'Hosting/datacentre ASN: {org} (AS{asn})'})
                    break
        return asn, org, country, signals

    def evaluate(self, device_mac=None, dst_ip=None, dst_port=None, hostname=None,
                 protocol='TCP', ip_proto=None, source='live', when=None):
        """Score one destination.  Returns a finding dict or ``None``."""
        signals = []
        provider = None
        kind = 'vpn'

        host = (hostname or '').strip('.').lower() or None
        if host:
            provider = DEFAULT_CATALOG.vpn_provider_for(host)
            if provider:
                signals.append({
                    'signal': 'provider_domain', 'weight': SCORE_WEIGHTS['provider_domain'],
                    'detail': f'Known VPN/proxy domain: {host} ({provider})'})
            if 'apple-relay' in host or 'mask.icloud.com' in host or 'icloud-private-relay' in host:
                signals.append({
                    'signal': 'private_relay', 'weight': SCORE_WEIGHTS['private_relay'],
                    'detail': f'Apple iCloud Private Relay endpoint: {host}'})
                provider = provider or 'Apple iCloud Private Relay'
                kind = 'proxy'
            if DEFAULT_CATALOG.is_doh_domain(host):
                signals.append({
                    'signal': 'doh_domain', 'weight': SCORE_WEIGHTS['doh_domain'],
                    'detail': f'DNS-over-HTTPS endpoint: {host}'})
                kind = 'dns_bypass'
            elif any(hint in host for hint in VPN_HOST_HINTS) and not provider:
                signals.append({
                    'signal': 'host_hint', 'weight': SCORE_WEIGHTS['host_hint'],
                    'detail': f'Hostname looks like an encrypted tunnel endpoint: {host}'})

        # destination port / protocol
        try:
            port = int(dst_port) if dst_port else None
        except Exception:
            port = None
        if port and port in TUNNEL_PORTS:
            name, weight = TUNNEL_PORTS[port]
            if name == 'DNS' and port == 53:
                provider_dns = DEFAULT_CATALOG.public_dns_provider(dst_ip or '')
                if provider_dns:
                    signals.append({
                        'signal': 'public_dns', 'weight': SCORE_WEIGHTS['public_dns'],
                        'detail': f'DNS query to public resolver {dst_ip} ({provider_dns}) bypasses the router'})
                    kind = 'dns_bypass'
            elif name == 'DNS over TLS':
                signals.append({
                    'signal': 'dns_bypass', 'weight': SCORE_WEIGHTS['dns_bypass'],
                    'detail': 'DNS-over-TLS (port 853) bypasses local filtering'})
                kind = 'dns_bypass'
            elif name in ('Tor SOCKS', 'Tor Browser SOCKS', 'Tor relay', 'Tor directory'):
                signals.append({
                    'signal': 'tor', 'weight': SCORE_WEIGHTS['tor'],
                    'detail': f'Tor traffic ({name}, port {port})'})
                kind = 'tor'
            elif name == 'HTTPS':
                if host and any(hint in host for hint in VPN_HOST_HINTS):
                    signals.append({
                        'signal': 'host_hint', 'weight': SCORE_WEIGHTS['host_hint'],
                        'detail': f'Tunnel-looking hostname over 443: {host}'})
            else:
                weight_scale = min(1.0, weight / 26.0)
                signals.append({
                    'signal': 'tunnel_port',
                    'weight': round(SCORE_WEIGHTS['tunnel_port'] * weight_scale, 1),
                    'detail': f'{name} on port {port}'})
                if name in ('SOCKS proxy', 'HTTP proxy', 'Privoxy', 'Various proxy'):
                    kind = 'proxy'

        if ip_proto and int(ip_proto) in TUNNEL_IP_PROTOS:
            tname, tweight = TUNNEL_IP_PROTOS[int(ip_proto)]
            signals.append({
                'signal': 'tunnel_protocol',
                'weight': round(SCORE_WEIGHTS['tunnel_protocol'] * min(1.0, tweight / 24.0), 1),
                'detail': f'IP protocol {ip_proto}: {tname}'})
            if kind == 'vpn':
                kind = 'tunnel'

        # ASN evidence (only when we have a public destination)
        asn = org = country = None
        if dst_ip and not dst_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                                             '172.19.', '172.2', '172.30.', '172.31.', '127.', '169.254.')):
            asn, org, country, asn_signals = self.asn_signals(dst_ip)
            signals.extend(asn_signals)

        # DATACENTER ALONE IS NOT A VPN.  Require corroboration.
        strong = {'provider_domain', 'asn_vpn_brand', 'tunnel_port', 'tunnel_protocol',
                  'tor', 'private_relay', 'dns_bypass', 'doh_domain'}
        names = {s['signal'] for s in signals}
        if not (names & strong):
            if 'asn_hosting' in names:
                return None
            if not signals:
                return None

        if 'asn_hosting' in names and not (names & (strong - {'doh_domain'})):
            # hosting + dial-a-tunnel: keep it, but the score is capped below.
            pass

        score = min(100.0, sum(s['weight'] for s in signals))
        if names == {'asn_hosting'}:
            score = min(score, 35.0)
        label = label_for(score)

        # confidence grows with corroboration, not raw score
        confidence = min(0.95, 0.35 + 0.15 * len(signals))
        return {
            'device_mac': device_mac,
            'dst_ip': dst_ip,
            'dst_host': host,
            'provider': provider or (org.title() if org and 'asn_vpn_brand' in names else None),
            'kind': 'tor' if 'tor' in names else ('dns_bypass' if
                    (names & {'doh_domain', 'public_dns', 'dns_bypass'}) == names or
                    (names & {'doh_domain', 'public_dns', 'dns_bypass'} and not (names - {'doh_domain', 'public_dns', 'dns_bypass', 'asn_hosting'}))
                    else kind),
            'score': round(score, 1),
            'label': label,
            'evidence': signals,
            'asn': asn, 'org': org, 'country': country,
            'confidence': round(confidence, 2),
            'when': when or datetime.utcnow(),
            'source': source,
        }

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def record(self, finding):
        """Upsert a finding; returns the row."""
        if not finding:
            return None
        key_ip = finding.get('dst_ip') or ''
        row = intel_store.equery(IntelVpnFinding).filter_by(
            device_mac=finding.get('device_mac'), dst_ip=key_ip,
            kind=finding.get('kind')).first()
        if row is None:
            row = IntelVpnFinding(
                device_mac=finding.get('device_mac'), dst_ip=key_ip,
                dst_host=finding.get('dst_host'), provider=finding.get('provider'),
                kind=finding.get('kind'), score=finding.get('score'),
                label=finding.get('label'), asn=finding.get('asn'),
                org=finding.get('org'), country=finding.get('country'),
                first_seen=finding.get('when') or datetime.utcnow(),
                last_seen=finding.get('when') or datetime.utcnow(),
                evidence=json.dumps(finding.get('evidence') or [], default=str),
                confidence=finding.get('confidence', 0.5), hits=1)
            intel_store.engine_session().add(row)
        else:
            row.last_seen = finding.get('when') or datetime.utcnow()
            row.hits = int((row.hits or 0) + 1)
            if finding.get('score', 0) > (row.score or 0):
                row.score = finding['score']
                row.label = finding['label']
                row.evidence = json.dumps(finding.get('evidence') or [], default=str)
            if finding.get('dst_host') and not row.dst_host:
                row.dst_host = finding['dst_host']
            if finding.get('provider') and not row.provider:
                row.provider = finding['provider']
        return row

    # ------------------------------------------------------------------
    # scheduled scan
    # ------------------------------------------------------------------
    def scan_flows(self, hours=24, min_duration=1800, min_bytes=5 * 1024 * 1024, min_packets=500):
        """Look for sustained single-destination tunnels in stored flows."""
        since = datetime.utcnow() - timedelta(hours=hours)
        findings = 0
        try:
            flows = intel_store.equery(IntelFlow).filter(IntelFlow.last_seen >= since).all()
            grouped = defaultdict(lambda: {'bytes': 0, 'packets': 0, 'first': None,
                                           'last': None, 'hosts': set(), 'ports': set(),
                                           'src_ip': None, 'protocols': set()})
            for flow in flows:
                key = (flow.device_mac, flow.dst_ip)
                if not flow.dst_ip:
                    continue
                entry = grouped[key]
                entry['bytes'] += int((flow.bytes_up or 0) + (flow.bytes_down or 0))
                entry['packets'] += int(flow.packets or 0)
                entry['first'] = min(entry['first'] or flow.first_seen, flow.first_seen)
                entry['last'] = max(entry['last'] or flow.last_seen, flow.last_seen)
                if flow.hostname:
                    entry['hosts'].add(root_domain(flow.hostname))
                if flow.service_port:
                    entry['ports'].add(flow.service_port)
                entry['src_ip'] = entry['src_ip'] or flow.src_ip
                entry['protocols'].add(flow.protocol)

            for (mac, dst_ip), entry in grouped.items():
                if not entry['first'] or not entry['last']:
                    continue
                duration = (entry['last'] - entry['first']).total_seconds()
                if duration < min_duration or entry['bytes'] < min_bytes or entry['packets'] < min_packets:
                    continue
                if entry['hosts']:
                    continue                      # named traffic: probably not a tunnel
                named_ports = {p for p in entry['ports'] if p in (80, 443)}
                finding = self.evaluate(device_mac=mac, dst_ip=dst_ip,
                                        dst_port=sorted(entry['ports'])[0] if entry['ports'] else None,
                                        hostname=None, protocol='TCP', source='scan')
                if not finding:
                    finding = {'device_mac': mac, 'dst_ip': dst_ip, 'dst_host': None,
                               'provider': None, 'kind': 'tunnel', 'score': 0.0,
                               'label': 'none', 'evidence': [], 'asn': None, 'org': None,
                               'country': None, 'confidence': 0.3}
                finding['score'] = min(100.0, finding['score'] + SCORE_WEIGHTS['sustained_tunnel'])
                finding['label'] = label_for(finding['score'])
                finding['evidence'] = list(finding.get('evidence') or []) + [{
                    'signal': 'sustained_tunnel',
                    'weight': SCORE_WEIGHTS['sustained_tunnel'],
                    'detail': (f'{duration/3600:.1f} h to a single unnamed endpoint '
                               f'{dst_ip}, {entry["bytes"]/1e6:.1f} MB, '
                               f'{entry["packets"]} packets'),
                }]
                if finding['label'] in ('low', 'medium', 'high', 'critical'):
                    self.record(finding)
                    findings += 1
            intel_store.engine_session().commit()
        except Exception as exc:
            intel_store.engine_session().rollback()
            if self.health:
                self.health.note('vpnwatch', error=exc)
        return findings

    def scan_dns_bypass(self, hours=24):
        """Find devices talking to public resolvers instead of the local one."""
        since = datetime.utcnow() - timedelta(hours=hours)
        count = 0
        try:
            from src.intel.models import IntelObservation
            rows = intel_store.equery(IntelObservation).filter(
                IntelObservation.observed_at >= since,
                IntelObservation.dst_port == 53).limit(5000).all()
            seen = set()
            for row in rows:
                if not row.dst_ip or row.dst_ip in seen:
                    continue
                provider = PUBLIC_DNS_IPS.get(row.dst_ip)
                if not provider:
                    continue
                seen.add(row.dst_ip)
                finding = self.evaluate(device_mac=row.device_mac, dst_ip=row.dst_ip,
                                        dst_port=53, hostname=None, protocol='UDP',
                                        source=row.source)
                if finding:
                    self.record(finding)
                    count += 1
            intel_store.engine_session().commit()
        except Exception as exc:
            intel_store.engine_session().rollback()
            if self.health:
                self.health.note('vpnwatch', error=exc)
        return count

    # ------------------------------------------------------------------
    # reporting
    # ------------------------------------------------------------------
    def device_scores(self, hours=24, include_seen=False):
        """Aggregate findings per device: max score + signal summary."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = intel_store.equery(IntelVpnFinding).filter(IntelVpnFinding.last_seen >= since)
        if not include_seen:
            query = query
        rows = query.order_by(IntelVpnFinding.score.desc()).all()
        out = {}
        for row in rows:
            key = row.device_mac or 'unknown'
            entry = out.setdefault(key, {
                'device_mac': key, 'score': 0.0, 'label': 'none', 'findings': 0,
                'kinds': set(), 'providers': set(), 'signals': defaultdict(int),
                'first_seen': row.first_seen, 'last_seen': row.last_seen,
                'top': None,
            })
            entry['findings'] += 1
            entry['kinds'].add(row.kind)
            if row.provider:
                entry['providers'].add(row.provider)
            try:
                for ev in json.loads(row.evidence or '[]'):
                    entry['signals'][ev.get('signal')] += 1
            except Exception:
                pass
            if (row.score or 0) > entry['score']:
                entry['score'] = row.score or 0
                entry['label'] = row.label or label_for(row.score or 0)
                entry['top'] = row.to_dict()
            entry['last_seen'] = max(entry['last_seen'], row.last_seen)
        results = []
        for entry in out.values():
            entry['kinds'] = sorted(entry['kinds'])
            entry['providers'] = sorted(entry['providers'])
            entry['signals'] = dict(entry['signals'])
            results.append(entry)
        results.sort(key=lambda x: -x['score'])
        return results
