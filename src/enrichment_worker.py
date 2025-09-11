import threading
import time
from datetime import datetime, timedelta
from queue import PriorityQueue
import socket
import ssl
import ipaddress
import os

try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None

try:
    import dns.resolver as dns_resolver
    import dns.reversename as dns_reversename
except Exception:
    dns_resolver = None
    dns_reversename = None

from src.models.network import EnrichedData, db
from src.ip2asn_lookup import Ip2AsnDB


class EnrichmentJob:
    def __init__(self, ip: str, priority: int = 0):
        self.ip = ip
        self.priority = priority
        self.enqueued_at = time.time()

    def __lt__(self, other):
        # Lower priority number runs sooner; tie-breaker by time
        if self.priority == other.priority:
            return self.enqueued_at < other.enqueued_at
        return self.priority < other.priority


class EnrichmentWorker:
    """Background worker that enriches IPs via reverse DNS and RDAP (ipwhois).
    - Immediate enrichment for brand-new IPs
    - Backoff retries on failure: 60s -> 5m -> 30m
    - Successful lookups cached and refreshed after TTL (default 24h)
    """

    def __init__(self, app=None, ttl_hours: int = 24):
        self.app = app
        self.queue: PriorityQueue[EnrichmentJob] = PriorityQueue()
        self.thread = None
        self.running = False
        self.ttl = timedelta(hours=ttl_hours)
        self.failures = {}  # ip -> backoff_seconds
        # Optional offline ip2asn database
        self.ip2asn = None
        db_path = os.path.join(os.path.dirname(__file__), 'data', 'ip2asn.tsv')
        if os.path.exists(db_path):
            try:
                self.ip2asn = Ip2AsnDB(db_path)
            except Exception:
                self.ip2asn = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def enqueue_ip(self, ip: str, immediate: bool = False):
        if not ip or ip.startswith('127.'):
            return
        # If we already have fresh enrichment, skip
        with self.app.app_context() if self.app else _nullcontext():
            enr = EnrichedData.query.filter_by(ip_address=ip).first()
            if enr and enr.updated_at and (datetime.utcnow() - enr.updated_at) < self.ttl:
                return
        priority = 0 if immediate else 5
        self.queue.put(EnrichmentJob(ip, priority))

    def _loop(self):
        with self.app.app_context() if self.app else _nullcontext():
            while self.running:
                try:
                    try:
                        job: EnrichmentJob = self.queue.get(timeout=1)
                    except Exception:
                        time.sleep(0.25)
                        continue

                    ip = job.ip
                    backoff = self.failures.get(ip, 0)
                    if backoff > 0:
                        # Re-queue after backoff
                        time.sleep(min(backoff, 5))
                        self.queue.put(EnrichmentJob(ip, job.priority + 1))
                        self.failures[ip] = max(0, backoff - 5)
                        continue

                    success = self._enrich_ip(ip)
                    if not success:
                        # Exponential backoff: 60s -> 300s -> 1800s (cap)
                        next_backoff = 60 if backoff == 0 else min(int(backoff * 5), 1800)
                        self.failures[ip] = next_backoff
                    else:
                        self.failures.pop(ip, None)
                except Exception:
                    time.sleep(1)

    def _enrich_ip(self, ip: str) -> bool:
        try:
            hostname = self._reverse_dns(ip)
            if not hostname:
                # Try DNS PTR via public resolvers
                hostname = self._ptr_dns(ip)
            if not hostname and self._is_public_ip(ip):
                # As a last resort, try TLS cert SAN/CN on 443
                hostname = self._tls_cert_hostname(ip)
            org = None
            asn = None
            isp = None

            if IPWhois is not None:
                try:
                    obj = IPWhois(ip)
                    rdap = obj.lookup_rdap(asn_methods=["whois", "http"])
                    asn_raw = rdap.get('asn')
                    asn = self._normalize_asn(asn_raw)
                    org = (rdap.get('asn_description') or '').strip() or None
                    # Try network name
                    nets = rdap.get('network') or {}
                    name = nets.get('name') if isinstance(nets, dict) else None
                    if name and not org:
                        org = name
                except Exception:
                    pass
            # Offline fallback via ip2asn
            if (asn is None or org is None) and self.ip2asn and self._is_public_ip(ip):
                info = self.ip2asn.lookup(ip)
                if info:
                    if asn is None and info.get('asn') is not None:
                        asn = info.get('asn')
                    if org is None and info.get('organization'):
                        org = info.get('organization')
                    # Country is available
                    ip2asn_country = info.get('country')

            enr = EnrichedData.query.filter_by(ip_address=ip).first()
            now = datetime.utcnow()
            if not enr:
                enr = EnrichedData(ip_address=ip, updated_at=now)
                db.session.add(enr)
            # Update fields if found
            if hostname:
                enr.hostname = hostname
            if org:
                enr.organization = org
            if asn is not None:
                try:
                    enr.asn = int(asn)
                except Exception:
                    pass
            if isp and hasattr(enr, 'isp'):
                enr.isp = isp
            # Persist country code if we found one and model supports it
            try:
                if 'ip2asn_country' in locals() and ip2asn_country and hasattr(enr, 'country_code'):
                    enr.country_code = ip2asn_country
            except Exception:
                pass
            enr.updated_at = now
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False

    def _reverse_dns(self, ip: str):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _ptr_dns(self, ip: str):
        try:
            if not dns_resolver or not dns_reversename:
                return None
            # Try system resolver first
            name = dns_reversename.from_address(ip)
            for servers in [None, ["1.1.1.1"], ["8.8.8.8"]]:
                try:
                    resolver = dns_resolver.Resolver(configure=(servers is None))
                    if servers:
                        resolver.nameservers = servers
                    resolver.lifetime = 2.0
                    resolver.timeout = 1.5
                    answer = resolver.resolve(name, 'PTR')
                    for rdata in answer:
                        host = str(rdata.target).rstrip('.')
                        if host:
                            return host
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def _tls_cert_hostname(self, ip: str):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, 443), timeout=2.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                    cert = ssock.getpeercert()
                    # Prefer SAN DNS names
                    san = cert.get('subjectAltName', []) or []
                    for typ, val in san:
                        if typ.lower() == 'dns' and val:
                            return val.lower()
                    # Fallback to subject CN
                    subject = cert.get('subject', [])
                    for entry in subject:
                        for key, val in entry:
                            if key.lower() == 'commonname' and val:
                                return str(val).lower()
            return None
        except Exception:
            return None

    def _normalize_asn(self, asn_value):
        try:
            if asn_value is None:
                return None
            s = str(asn_value).strip().upper()
            if s.startswith('AS'):
                s = s[2:]
            digits = ''.join(ch for ch in s if ch.isdigit())
            return int(digits) if digits else None
        except Exception:
            return None

    def _is_public_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback or addr.is_link_local)
        except Exception:
            return False


class _nullcontext:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass


