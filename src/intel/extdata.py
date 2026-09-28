"""
Optional free community-list importer.

Nothing here is required for the app to work, and nothing here costs money.
When enabled (Settings → community feeds), it mirrors a handful of well-known
open domain lists into the local ``intel_names`` table so that adult, gambling,
tracking and social domains are categorised even when the app has never seen
them before.  The lists are cached locally and can be re-synced on demand:

    python -m src.intel.extdata --list
    python -m src.intel.extdata --sync porn gambling tracking
    python -m src.intel.extdata --sync all --limit 50000

Everything is opt-in, offline-cacheable and removable (``--purge``).
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import time
import urllib.request
from datetime import datetime

from src.models.user import db
from src.intel.models import IntelNameCache
from src.intel import store as intel_store

FEEDS = {
    'porn': {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
        'category': 'Adult',
        'description': 'StevenBlack porn-only hosts list (adult domains)',
        'format': 'hosts',
    },
    'gambling': {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts',
        'category': 'Gambling',
        'description': 'StevenBlack gambling hosts list',
        'format': 'hosts',
    },
    'fakenews': {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts',
        'category': 'News',
        'description': 'StevenBlack fake-news hosts list (flagged, not blocked)',
        'format': 'hosts',
    },
    'social': {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts',
        'category': 'Social',
        'description': 'StevenBlack social-media hosts list',
        'format': 'hosts',
    },
    'tracking': {
        'url': 'https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/tracking/domains',
        'category': 'Ads & Tracking',
        'description': 'UT1 tracker blocklist',
        'format': 'domains',
    },
    'ads': {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt',
        'category': 'Ads & Tracking',
        'description': 'HaGeZi Pro DNS blocklist (ads + trackers)',
        'format': 'domains',
    },
}

CACHE_DIR_ENV = 'NETSCANNER_FEED_CACHE'


def cache_dir():
    path = os.getenv(CACHE_DIR_ENV) or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'feeds')
    os.makedirs(path, exist_ok=True)
    return path


def fetch_feed(name, timeout=60, use_cache=True, max_age_hours=168):
    """Download (or read from cache) a feed. Returns the decoded text."""
    meta = FEEDS.get(name)
    if not meta:
        raise KeyError(f'unknown feed: {name}')
    path = os.path.join(cache_dir(), f'{name}.txt.gz')
    if use_cache and os.path.exists(path):
        age = time.time() - os.path.getmtime(path)
        if age < max_age_hours * 3600:
            try:
                with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as fh:
                    return fh.read()
            except Exception:
                pass
    request = urllib.request.Request(meta['url'], headers={'User-Agent': 'NetScanner/1.0 (local)'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    try:
        text = raw.decode('utf-8', 'ignore')
    except Exception:
        text = raw.decode('latin-1', 'ignore')
    try:
        with gzip.open(path, 'wt', encoding='utf-8') as fh:
            fh.write(text)
    except Exception:
        pass
    return text


def parse_feed(text, fmt='hosts'):
    """Yield domains from a hosts file or a plain domain list."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!', ';', '[')):
            continue
        if fmt == 'hosts':
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'):
                domain = parts[1].strip('.').lower()
            elif len(parts) == 1:
                domain = parts[0].strip('.').lower()
            else:
                continue
        else:
            domain = line.split()[0].strip('.').lower()
        if not domain or domain in ('localhost', 'localhost.localdomain', 'broadcasthost'):
            continue
        if domain.startswith(('0.0.0.0', '127.', '::')):
            continue
        if len(domain) > 253 or ' ' in domain:
            continue
        yield domain


def import_feed(name, limit=None, batch=5000, purge_first=False, progress=None):
    """Import one feed into ``intel_names``. Returns a stats dict."""
    meta = FEEDS[name]
    text = fetch_feed(name)
    started = datetime.utcnow()
    if purge_first:
        purge_feed(name)
    seen = 0
    inserted = 0
    updated = 0
    existing = {
        row.key: row for row in intel_store.equery(IntelNameCache).filter_by(
            key_type='feed_domain', owner=name).all()
    }
    pending = []
    for domain in parse_feed(text, meta.get('format', 'hosts')):
        seen += 1
        if limit and seen > limit:
            break
        row = existing.get(domain)
        if row is None:
            pending.append(IntelNameCache(
                key=domain[:255], key_type='feed_domain', display_name=domain[:255],
                category=meta['category'], owner=name, name_source='feed', confidence=0.8))
            inserted += 1
        elif row.category != meta['category']:
            row.category = meta['category']
            updated += 1
        if len(pending) >= batch:
            intel_store.engine_session().bulk_save_objects(pending)
            intel_store.engine_session().commit()
            pending = []
            if progress:
                progress(seen, inserted)
    if pending:
        intel_store.engine_session().bulk_save_objects(pending)
        intel_store.engine_session().commit()
    _write_feed_meta(name, {'rows': seen, 'inserted': inserted, 'updated': updated,
                            'imported_at': started.isoformat()})
    from src.intel.catalog import load_feed_cache
    load_feed_cache()
    return {'feed': name, 'category': meta['category'], 'rows': seen,
            'inserted': inserted, 'updated': updated,
            'seconds': round((datetime.utcnow() - started).total_seconds(), 1)}


def purge_feed(name):
    removed = intel_store.equery(IntelNameCache).filter_by(key_type='feed_domain', owner=name).delete()
    intel_store.engine_session().commit()
    _write_feed_meta(name, {'purged_at': datetime.utcnow().isoformat()})
    from src.intel.catalog import load_feed_cache
    load_feed_cache()
    return removed


def _meta_path():
    return os.path.join(cache_dir(), 'feeds.json')


def _write_feed_meta(name, payload):
    try:
        data = {}
        if os.path.exists(_meta_path()):
            with open(_meta_path(), 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        data.setdefault(name, {}).update(payload)
        with open(_meta_path(), 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def feed_status():
    """Report which feeds are imported, cached and how big they are."""
    meta = {}
    try:
        if os.path.exists(_meta_path()):
            with open(_meta_path(), 'r', encoding='utf-8') as fh:
                meta = json.load(fh)
    except Exception:
        meta = {}
    out = []
    for name, definition in FEEDS.items():
        cached = os.path.exists(os.path.join(cache_dir(), f'{name}.txt.gz'))
        rows = 0
        try:
            rows = intel_store.equery(IntelNameCache).filter_by(key_type='feed_domain', owner=name).count()
        except Exception:
            rows = 0
        out.append({
            'name': name, 'category': definition['category'],
            'description': definition['description'], 'url': definition['url'],
            'cached': cached, 'domains': rows, 'meta': meta.get(name, {}),
        })
    return out


def sync(feeds=None, limit=None, purge_first=False):
    names = list(FEEDS.keys()) if not feeds or feeds == ['all'] else feeds
    results = []
    for name in names:
        if name not in FEEDS:
            results.append({'feed': name, 'error': 'unknown feed'})
            continue
        try:
            results.append(import_feed(name, limit=limit, purge_first=purge_first))
        except Exception as exc:
            results.append({'feed': name, 'error': str(exc)})
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description='Import free community domain lists')
    parser.add_argument('--list', action='store_true', help='show feed status')
    parser.add_argument('--sync', nargs='*', default=None, help='import feeds (names or "all")')
    parser.add_argument('--limit', type=int, default=None, help='max domains per feed')
    parser.add_argument('--purge', nargs='*', default=None, help='remove imported domains')
    args = parser.parse_args(argv)

    from src.main import app
    with app.app_context():
        if args.list:
            print(json.dumps(feed_status(), indent=2))
        if args.sync is not None:
            for row in sync(args.sync or ['all'], limit=args.limit):
                print(json.dumps(row))
        if args.purge is not None:
            for name in (args.purge or list(FEEDS.keys())):
                print(f'purged {name}: {purge_feed(name)} domains')


if __name__ == '__main__':
    main()
