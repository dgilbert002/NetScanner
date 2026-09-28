"""
Free naming and classification service.

Resolution order (first hit wins, confidence attached to every hit):

1. User rules from the Rules tab (``hn_rules`` / ``hn_apps`` / ``hn_categories``).
2. ``config/app_domains.json`` (the project's existing mapping file).
3. The curated built-in catalog in :mod:`src.intel.catalog_data`.
4. Community feed lists imported by :mod:`src.intel.extdata` (adult/gambling/
   tracking) - optional, offline, cached in the ``intel_names`` table.
5. Structural fallbacks: registrable root domain (``tldextract``), then the
   TLD, then the raw host.

Every answer is cached in ``intel_names`` with its source and confidence, and
late corrections are recorded in ``intel_revisions`` so the UI can show that a
name was refined after the fact (the "delayed data" concept).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime

from src.intel.catalog_data import (
    CATEGORIES,
    DOH_DOMAINS,
    DOMAIN_CATALOG,
    PUBLIC_DNS_IPS,
    VPN_PROVIDER_DOMAINS,
)
from src.intel import store as intel_store

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover
    _TLD_EXTRACT = None

_CATALOG = {}
for _domain, _app, _category, _owner in DOMAIN_CATALOG:
    entry = {'app': _app, 'category': _category, 'owner': _owner}
    _CATALOG.setdefault(_domain.lower(), entry)

_CATEGORY_SET = set(CATEGORIES)


def app_categories():
    """{app name (lower): category} for every curated app name.

    App names - not domains - are what the daily rollups store, so the history
    API uses this to label an app with its category and to answer "show me the
    games" without guessing from a domain lookup.
    """
    mapping = {}
    for _domain, app, cat, _owner in DOMAIN_CATALOG:
        if app and cat:
            mapping.setdefault(app.lower(), cat)
    return mapping


def apps_in_category(category):
    """App/service names whose catalogue entries are in ``category``.

    Used by the 'games' view: the daily rollups store *app names* (``Roblox``),
    not domains, so a category filter has to be answered from the catalogue.
    """
    wanted = (category or '').lower()
    names = set()
    for _domain, app, cat, _owner in DOMAIN_CATALOG:
        if (cat or '').lower() == wanted and app:
            names.add(app)
    return names


def root_domain(host):
    """Registrable domain (``r4---sn-x.googlevideo.com`` -> ``googlevideo.com``)."""
    if not host:
        return ''
    host = host.strip().strip('.').lower()
    if _TLD_EXTRACT is not None:
        try:
            ext = _TLD_EXTRACT(host)
            if ext.domain and ext.suffix:
                return f'{ext.domain}.{ext.suffix}'.lower()
            if ext.domain and not ext.suffix:
                return ext.domain.lower()
        except Exception:
            pass
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def suffix_candidates(host):
    """Yield suffixes of ``host`` from most specific to least specific."""
    host = (host or '').strip('.').lower()
    if not host:
        return
    parts = host.split('.')
    for i in range(len(parts) - 1):
        yield '.'.join(parts[i:])


class Catalog:
    """Loads and merges all free naming sources, with a small in-process cache."""

    def __init__(self):
        self._json_map = {}
        self._rules = {}
        self._rule_cache_ts = None
        self._feed_domains = {}
        self._memo = {}
        self._load_json_mappings()

    # -- sources ---------------------------------------------------------
    def _load_json_mappings(self):
        roots = [
            os.path.join(os.getcwd(), 'config', 'app_domains.json'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), 'config', 'app_domains.json'),
        ]
        for path in roots:
            try:
                if not os.path.exists(path):
                    continue
                with open(path, 'r', encoding='utf-8-sig') as fh:
                    raw = json.load(fh)
                for app, domains in (raw or {}).items():
                    if not isinstance(domains, (list, tuple)):
                        continue
                    for dom in domains:
                        self._json_map[str(dom).lower()] = {
                            'app': app, 'category': self._default_category(app), 'owner': None,
                        }
                break
            except Exception:
                continue

    @staticmethod
    def _default_category(app):
        hints = {
            'google': 'Search', 'youtube': 'Video', 'facebook': 'Social',
            'instagram': 'Social', 'tiktok': 'Social', 'netflix': 'Streaming',
            'spotify': 'Music', 'steam': 'Gaming', 'microsoft': 'Work',
            'amazon': 'Shopping', 'whatsapp': 'Messaging', 'discord': 'Messaging',
            'zoom': 'Communication', 'slack': 'Communication', 'github': 'Development',
            'apple': 'Shopping', 'cloudflare': 'Cloud', 'linkedin': 'Work',
            'twitter': 'Social', 'twitch': 'Streaming', 'reddit': 'Forums',
        }
        return hints.get(str(app).lower(), 'Unknown')

    def load_user_rules(self, force=False):
        """Pull the user's own rules from the Rules tab (cheap; cached 60 s)."""
        now = datetime.utcnow()
        if not force and self._rule_cache_ts is not None and \
                (now - self._rule_cache_ts).total_seconds() < 60:
            return
        try:
            from src.models.hostnames import HnApp, HnCategory, HnRule
            rules = HnRule.query.all()
            mapping = {}
            for rule in rules:
                # Auto-learned rules are hints, not user intent: the curated
                # catalog outranks them so a wrong guess cannot become sticky.
                if (rule.source or 'manual') == 'auto':
                    continue
                app = HnApp.query.get(rule.app_id) if rule.app_id else None
                cat = HnCategory.query.get(app.category_id) if app else None
                mapping[(rule.type or 'domain').lower(), (rule.value or '').lower()] = {
                    'app': app.name if app else 'Unknown',
                    'category': cat.name if cat else 'Uncategorized',
                    'owner': None,
                    'source': 'user_rule',
                    'confidence': float(rule.confidence or 1.0),
                }
            self._rules = mapping
            self._rule_cache_ts = now
        except Exception:
            # No app context / table missing - ignore, the catalog still works.
            self._rule_cache_ts = now

    # -- lookups ---------------------------------------------------------
    def lookup_host(self, host, use_cache=True):
        """Return ``dict(app, category, owner, source, confidence, display_name)``.

        Never raises, never does network I/O.
        """
        host = (host or '').strip().strip('.').lower()
        if not host:
            return None
        if use_cache and host in self._memo:
            return self._memo[host]

        result = None
        self.load_user_rules()

        # 1) user rules (exact, then suffix)
        for candidate in list(suffix_candidates(host)) + [host]:
            hit = self._rules.get(('domain', candidate))
            if hit:
                result = dict(hit)
                result['display_name'] = host
                break
        # 2) curated built-in catalog (best names and categories)
        if not result:
            for candidate in suffix_candidates(host):
                hit = _CATALOG.get(candidate)
                if hit:
                    result = dict(hit, source='catalog', confidence=0.9)
                    result['display_name'] = host
                    break
        # 3) project JSON mapping (config/app_domains.json)
        if not result:
            for candidate in suffix_candidates(host):
                hit = self._json_map.get(candidate)
                if hit:
                    result = dict(hit, source='app_domains.json', confidence=0.75)
                    result['display_name'] = host
                    break
        # 4) community feeds (only categorise; do not claim an app)
        if not result:
            feed = self.lookup_feed(host)
            if feed:
                result = {
                    'app': 'Blocked list: ' + feed['list'],
                    'category': feed['category'],
                    'owner': None, 'source': 'feed',
                    'confidence': 0.8, 'display_name': host,
                }
        # 5) structural fallback
        if not result:
            root = root_domain(host)
            result = {
                'app': root or host,
                'category': 'Unknown',
                'owner': None,
                'source': 'root_domain',
                'confidence': 0.25,
                'display_name': host,
            }

        result['root_domain'] = root_domain(host)
        result.setdefault('owner', None)
        result.setdefault('confidence', 0.5)
        if use_cache:
            self._memo[host] = result
            if len(self._memo) > 20000:
                self._memo.clear()
        return result

    def lookup_ip(self, ip):
        """Best-effort name for an IP using the existing enrichment tables."""
        if not ip:
            return None
        try:
            from src.models.network import EnrichedData
            row = EnrichedData.query.filter_by(ip_address=ip).first()
            if row and row.hostname:
                return {
                    'display_name': row.hostname,
                    'app': None, 'category': None, 'owner': row.organization,
                    'source': 'enrichment', 'confidence': 0.6,
                    'root_domain': root_domain(row.hostname),
                    'asn': row.asn, 'country': row.country_code,
                    'org': row.organization, 'hostname': row.hostname,
                }
        except Exception:
            return None
        return None

    def lookup_feed(self, host):
        """Match against imported community lists (adult/gambling/tracking)."""
        for candidate in suffix_candidates(host):
            hit = _FEED_CACHE.get(candidate)
            if hit:
                return hit
        return None

    # -- VPN / DNS helpers ----------------------------------------------
    @staticmethod
    def vpn_provider_for(host):
        """Return the VPN/proxy brand for a hostname, or ``None``."""
        if not host:
            return None
        host = host.lower()
        for domain, provider in VPN_PROVIDER_DOMAINS.items():
            if domain in host:
                return provider
        return None

    @staticmethod
    def is_doh_domain(host):
        if not host:
            return False
        host = host.lower()
        return any(d == host or host.endswith('.' + d) for d in DOH_DOMAINS)

    @staticmethod
    def public_dns_provider(ip):
        return PUBLIC_DNS_IPS.get(ip)

    @staticmethod
    def is_category(name):
        return name in _CATEGORY_SET


# Module-level cache of imported feed domains: domain -> {list, category}
_FEED_CACHE = {}


def load_feed_cache():
    """Populate ``_FEED_CACHE`` from the ``intel_names`` table (feed rows only)."""
    global _FEED_CACHE
    try:
        from src.intel.models import IntelNameCache
        rows = intel_store.equery(IntelNameCache).filter_by(key_type='feed_domain').all()
        _FEED_CACHE = {
            r.key: {'list': (r.owner or 'list'), 'category': r.category or 'Unknown'}
            for r in rows
        }
    except Exception:
        _FEED_CACHE = {}
    return len(_FEED_CACHE)


def remember_name(key, key_type='domain', display_name=None, app=None, category=None,
                  owner=None, source='catalog', confidence=0.5):
    """Upsert the name cache; returns ``(row, changed_field)``."""
    try:
        from src.models.user import db
        from src.intel.models import IntelNameCache, IntelRevision
        row = intel_store.equery(IntelNameCache).filter_by(key=key).first()
        changed = None
        if row is None:
            row = IntelNameCache(key=key, key_type=key_type, display_name=display_name,
                                 app=app, category=category, owner=owner,
                                 name_source=source, confidence=confidence)
            intel_store.engine_session().add(row)
            intel_store.engine_session().flush()
            return row, None
        updates = {
            'display_name': (display_name, 0.6),
            'app': (app, 0.9),
            'category': (category, 0.9),
            'owner': (owner, 0.5),
        }
        for field, (value, weight) in updates.items():
            if not value:
                continue
            current = getattr(row, field)
            if current == value:
                continue
            if current is None or (confidence or 0) >= (row.confidence or 0) * weight:
                setattr(row, field, value)
                if current:
                    intel_store.engine_session().add(IntelRevision(
                        entity='name', entity_id=row.id, field=field,
                        old_value=str(current), new_value=str(value),
                        source=source, confidence=confidence))
                    row.revisions = int((row.revisions or 0) + 1)
                changed = field
        row.name_source = source or row.name_source
        row.confidence = max(row.confidence or 0, confidence or 0)
        return row, changed
    except Exception:
        return None, None


def catalog_summary():
    return {
        'catalog_domains': len(_CATALOG),
        'app_domains_json': len(Catalog()._json_map),
        'vpn_domains': len(VPN_PROVIDER_DOMAINS),
        'doh_domains': len(DOH_DOMAINS),
        'public_dns_ips': len(PUBLIC_DNS_IPS),
        'categories': len(CATEGORIES),
    }


DEFAULT_CATALOG = Catalog()
