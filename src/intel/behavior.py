"""
Behavioural fingerprinting and identity probability.

The maths, stated plainly so it can be argued with:

1. **Fingerprint** - a device (or a person, aggregated over their bound devices)
   is described by a normalised feature vector:

   * ``hours``      24 bins, share of activity seconds per hour of day
   * ``days``        7 bins, share per day of week
   * ``categories``  share per content category (fixed vocabulary)
   * ``apps``        share per application (free-form, top-N)
   * ``sites``       share per root domain (free-form, top-N)
   * ``dwell``       6 log-buckets of session-length distribution
   * ``stats``       sessions/day, mean dwell, night ratio, domain diversity

2. **Entropy / distinctiveness** - ``H = -Σ p log2 p`` over the hour and
   category distributions.  ``distinctiveness = 1 - H/Hmax``.  A person who only
   browses between 07:00-08:00 has a very distinctive schedule; a device that is
   on 24/7 with random traffic does not, so its fingerprint is worth less.

3. **Similarity** - weighted blend of
   ``0.30 * cosine(full vector) + 0.30 * (1 - JS(hours)) + 0.20 * (1 - JS(categories))
   + 0.10 * jaccard(sites) + 0.10 * (1 - |dwell-cdf distance|)``.
   Jensen-Shannon is symmetric and bounded, which makes the blend defensible.

4. **Probability** - a softmax over candidates on log-odds
   ``s_i = w_prior * ln(prior_i) + w_sim * similarity_i * distinctiveness_i``
   with ``w_prior = 1.0`` and ``w_sim = 2.2`` (so behaviour can beat a weak
   prior, but a user-confirmed binding cannot be overridden).  The prior comes
   from (in order) a user-confirmed binding, the person's profile device
   assignment, a matching ``device_key``/hostname, or 1/#candidates.

   Each score keeps Beta counters (``alpha``/``beta``) that accumulate evidence
   over time, so repeated consistent observations raise confidence and a single
   ambiguous day does not flip an identity.

5. **Rotation** - when a MAC we have never seen before (a) shares a
   ``device_key`` with a known device that went quiet recently, or (b) matches a
   person's fingerprint above ``ROTATION_THRESHOLD`` while that person's known
   devices are quiet, we raise a ``mac_rotation`` event.  The UI renders those
   with a star.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import datetime, timedelta

from src.models.user import db
from src.intel.catalog_data import CATEGORIES
from src.intel.models import (
    IntelBehaviorProfile,
    IntelDailyUsage,
    IntelDeviceEvent,
    IntelDeviceMac,
    IntelFlow,
    IntelIdentityScore,
    IntelOnlineDay,
    IntelPerson,
    IntelUsageBucket,
)
from src.intel import store as intel_store

ROTATION_THRESHOLD = 0.62          # similarity needed to call a rotation
MIN_SECONDS_FOR_FINGERPRINT = 300  # 5 minutes of data before we trust a vector
MIN_SAMPLES_FOR_IDENTITY = 3
NIGHT_HOURS = set(list(range(0, 6)) + [23])


# ---------------------------------------------------------------------------
# Small maths helpers (pure, unit-testable)
# ---------------------------------------------------------------------------

def shannon_entropy(weights):
    total = sum(weights)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for w in weights:
        if w <= 0:
            continue
        p = w / total
        entropy -= p * math.log2(p)
    return entropy


def normalized_entropy(weights):
    n = len([w for w in weights if w > 0])
    if n <= 1:
        return 0.0
    return shannon_entropy(weights) / math.log2(n)


def distinctiveness(weights):
    return max(0.0, min(1.0, 1.0 - normalized_entropy(weights)))


def cosine(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def jensen_shannon(p, q):
    """Jensen-Shannon divergence (base 2) between two weight vectors; 0..1."""
    n = max(len(p), len(q))
    if n == 0:
        return 1.0
    p = list(p) + [0.0] * (n - len(p))
    q = list(q) + [0.0] * (n - len(q))
    sp, sq = sum(p), sum(q)
    if sp <= 0 and sq <= 0:
        return 1.0
    p = [x / sp for x in p] if sp > 0 else [0.0] * n
    q = [x / sq for x in q] if sq > 0 else [0.0] * n
    m = [(pi + qi) / 2 for pi, qi in zip(p, q)]

    def kl(a, b):
        total = 0.0
        for ai, bi in zip(a, b):
            if ai > 0 and bi > 0:
                total += ai * math.log2(ai / bi)
        return total

    return max(0.0, min(1.0, 0.5 * kl(p, m) + 0.5 * kl(q, m)))


def jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / max(1, len(sa | sb))


def dwell_buckets(seconds_list):
    """6 log-ish buckets: <10s, <30s, <2m, <10m, <1h, >=1h."""
    buckets = [0.0] * 6
    for s in seconds_list:
        if s <= 0:
            continue
        if s < 10:
            buckets[0] += 1
        elif s < 30:
            buckets[1] += 1
        elif s < 120:
            buckets[2] += 1
        elif s < 600:
            buckets[3] += 1
        elif s < 3600:
            buckets[4] += 1
        else:
            buckets[5] += 1
    return buckets


def vector_from_features(features):
    """Flatten a fingerprint dict into a fixed-length numeric vector."""
    vec = []
    vec.extend(features.get('hours', [0.0] * 24))
    vec.extend(features.get('days', [0.0] * 7))
    vec.extend([features.get('categories', {}).get(cat, 0.0) for cat in CATEGORIES])
    vec.extend([
        features.get('stats', {}).get('sessions_per_day', 0.0),
        features.get('stats', {}).get('mean_dwell', 0.0),
        features.get('stats', {}).get('night_ratio', 0.0),
        features.get('stats', {}).get('domain_diversity', 0.0),
        features.get('stats', {}).get('bytes_per_day', 0.0),
    ])
    vec.extend(features.get('dwell', [0.0] * 6))
    return vec


def features_similarity(a, b):
    if not a or not b:
        return 0.0, {}
    parts = {}
    parts['vector'] = cosine(vector_from_features(a), vector_from_features(b))
    parts['hours'] = 1.0 - jensen_shannon(a.get('hours', []), b.get('hours', []))
    parts['categories'] = 1.0 - jensen_shannon(
        [a.get('categories', {}).get(c, 0.0) for c in CATEGORIES],
        [b.get('categories', {}).get(c, 0.0) for c in CATEGORIES])
    parts['sites'] = jaccard(list(a.get('sites', {}).keys()), list(b.get('sites', {}).keys()))
    parts['apps'] = jaccard(list(a.get('apps', {}).keys()), list(b.get('apps', {}).keys()))
    parts['dwell'] = 1.0 - jensen_shannon(a.get('dwell', []), b.get('dwell', []))
    weights = {'vector': 0.28, 'hours': 0.26, 'categories': 0.16,
               'sites': 0.10, 'apps': 0.10, 'dwell': 0.10}
    score = sum(parts[k] * weights[k] for k in weights)
    return max(0.0, min(1.0, score)), parts


def softmax(scores):
    if not scores:
        return []
    top = max(scores)
    exps = [math.exp(s - top) for s in scores]
    total = sum(exps)
    if total <= 0:
        return [0.0] * len(scores)
    return [e / total for e in exps]


# ---------------------------------------------------------------------------
# Fingerprint construction
# ---------------------------------------------------------------------------

class BehaviorEngine:
    def __init__(self, idle_seconds=90, days=30):
        self.idle_seconds = idle_seconds
        self.days = days
        self._cache = {}

    # -- raw aggregation ------------------------------------------------
    def _window_start(self, days=None):
        return datetime.utcnow() - timedelta(days=days or self.days)

    def fingerprint_for_device(self, device_mac, days=None):
        """Build a fingerprint dict for a MAC from stored buckets/usage."""
        device_mac = (device_mac or '').lower()
        if not device_mac:
            return None
        start = self._window_start(days)
        hours = [0.0] * 24
        days_hist = [0.0] * 7
        categories = defaultdict(float)
        apps = defaultdict(float)
        sites = defaultdict(float)
        bytes_total = 0.0

        rows = intel_store.equery(IntelUsageBucket).filter(
            IntelUsageBucket.device_mac == device_mac,
            IntelUsageBucket.bucket_start >= start).all()
        bucket_online = 0.0
        for row in rows:
            if row.dimension == 'device':
                seconds = float(row.online_seconds or row.seconds or 0)
                hours[row.bucket_start.hour] += seconds
                days_hist[row.bucket_start.weekday()] += seconds
                bytes_total += float(row.bytes_total or 0)
                bucket_online += seconds
            elif row.dimension == 'category':
                categories[row.key] += float(row.seconds or 0)
            elif row.dimension == 'app':
                apps[row.key] += float(row.seconds or 0)
            elif row.dimension in ('site', 'flow-site'):
                sites[row.key] += float(row.seconds or 0)

        sessions = intel_store.equery(IntelFlow).filter(
            IntelFlow.device_mac == device_mac,
            IntelFlow.first_seen >= start).all()
        dwell_sources = [f.duration_seconds or 0 for f in sessions]
        dwell = dwell_buckets(dwell_sources)
        online_rows = intel_store.equery(IntelOnlineDay).filter(
            IntelOnlineDay.device_mac == device_mac,
            IntelOnlineDay.day >= start.strftime('%Y-%m-%d')).all()
        # Pretend the day-total table is authoritative and the bucket table is
        # the fallback: imported/backfilled buckets may never produce a day row,
        # so take whichever source saw more time.  Overlapping windows mean the
        # per-hour histogram is still taken only from the buckets above.
        total_online = max(bucket_online, sum(r.online_seconds or 0 for r in online_rows))
        active_days = len({r.day for r in online_rows if (r.online_seconds or 0) > 0}) or 1
        night = sum(hours[h] for h in NIGHT_HOURS)
        total_hours = sum(hours) or 1.0
        mean_dwell = (sum(dwell_sources) / len(dwell_sources)) if dwell_sources else 0.0

        if total_online < MIN_SECONDS_FOR_FINGERPRINT and not sessions:
            return None

        def norm(mapping):
            total = sum(mapping.values()) or 1.0
            return {k: v / total for k, v in mapping.items()}

        features = {
            'hours': [h / total_hours for h in hours],
            'days': [d / (sum(days_hist) or 1.0) for d in days_hist],
            'categories': norm(categories),
            'apps': dict(sorted(norm(apps).items(), key=lambda x: -x[1])[:20]),
            'sites': dict(sorted(norm(sites).items(), key=lambda x: -x[1])[:25]),
            'dwell': [(d / (sum(dwell) or 1.0)) for d in dwell],
            'stats': {
                'sessions_per_day': round(len(sessions) / max(1, active_days), 3),
                'mean_dwell': round(mean_dwell, 1),
                'night_ratio': round(night / total_hours, 4),
                'domain_diversity': len(sites),
                'bytes_per_day': round(bytes_total / max(1, active_days), 1),
                'total_online_seconds': int(total_online),
                'days_observed': active_days,
            },
            'meta': {
                'sessions': len(sessions),
                'bytes': int(bytes_total),
                'window_days': days or self.days,
                'built_at': datetime.utcnow().isoformat(),
            },
        }
        features['entropy'] = round(shannon_entropy(hours), 4)
        features['distinctiveness'] = round(distinctiveness(hours), 4)
        features['category_distinctiveness'] = round(distinctiveness(list(categories.values())), 4)
        features['top_apps'] = list(features['apps'].items())[:6]
        return features

    def fingerprint_for_person(self, person, device_macs=None, days=None):
        """Aggregate the fingerprints of all MACs bound to a person."""
        macs = device_macs if device_macs is not None else bound_macs_for_person(person)
        collected = []
        for mac in macs:
            fp = self.fingerprint_for_device(mac, days=days)
            if fp:
                collected.append(fp)
        if not collected:
            return None
        hours = [0.0] * 24
        days_hist = [0.0] * 7
        categories = defaultdict(float)
        apps = defaultdict(float)
        sites = defaultdict(float)
        dwell = [0.0] * 6
        stats = defaultdict(float)
        for fp in collected:
            for i, v in enumerate(fp.get('hours', [])):
                hours[i] += v
            for i, v in enumerate(fp.get('days', [])):
                days_hist[i] += v
            for k, v in fp.get('categories', {}).items():
                categories[k] += v
            for k, v in fp.get('apps', {}).items():
                apps[k] += v
            for k, v in fp.get('sites', {}).items():
                sites[k] += v
            for i, v in enumerate(fp.get('dwell', [])):
                dwell[i] += v
            for k, v in (fp.get('stats') or {}).items():
                stats[k] += v
        n = len(collected)
        total_hours = sum(hours) or 1.0
        features = {
            'hours': [h / total_hours for h in hours],
            'days': [d / (sum(days_hist) or 1.0) for d in days_hist],
            'categories': norm_map(categories),
            'apps': dict(sorted(norm_map(apps).items(), key=lambda x: -x[1])[:20]),
            'sites': dict(sorted(norm_map(sites).items(), key=lambda x: -x[1])[:25]),
            'dwell': [d / (sum(dwell) or 1.0) for d in dwell],
            'stats': {k: round(v / n, 3) for k, v in stats.items()},
            'meta': {'devices': len(collected), 'window_days': days or self.days,
                     'built_at': datetime.utcnow().isoformat()},
        }
        features['entropy'] = round(shannon_entropy(features['hours']), 4)
        features['distinctiveness'] = round(distinctiveness(features['hours']), 4)
        features['category_distinctiveness'] = round(distinctiveness(list(categories.values())), 4)
        features['top_apps'] = list(features['apps'].items())[:6]
        return features

    # -- persistence ----------------------------------------------------
    def update_profiles(self, days=None):
        """Recompute and store fingerprints for every device and person."""
        updated = {'devices': 0, 'persons': 0}
        try:
            macs = [r.normalized or r.mac for r in intel_store.equery(IntelDeviceMac).all()]
            for mac in macs:
                fp = self.fingerprint_for_device(mac, days=days)
                if not fp:
                    continue
                self._store_profile('device', mac, fp)
                updated['devices'] += 1
            for person in intel_store.equery(IntelPerson).all():
                fp = self.fingerprint_for_person(person, days=days)
                if not fp:
                    continue
                self._store_profile('person', person.name, fp, label=person.display_name or person.name)
                updated['persons'] += 1
            intel_store.engine_session().commit()
        except Exception:
            intel_store.engine_session().rollback()
        return updated

    def _store_profile(self, subject_type, subject_key, features, label=None):
        row = intel_store.equery(IntelBehaviorProfile).filter_by(
            subject_type=subject_type, subject_key=subject_key).first()
        stability = None
        if row and row.features:
            try:
                old = json.loads(row.features)
                sim, _parts = features_similarity(old, features)
                stability = round(sim, 4)
            except Exception:
                stability = None
        if row is None:
            row = IntelBehaviorProfile(subject_type=subject_type, subject_key=subject_key)
            intel_store.engine_session().add(row)
        row.label = label or row.label or subject_key
        row.features = json.dumps(features, default=str)
        row.sample_sessions = int((features.get('meta') or {}).get('sessions') or 0)
        row.sample_seconds = int((features.get('stats') or {}).get('total_online_seconds') or 0)
        row.entropy = float(features.get('entropy') or 0)
        row.distinctiveness = float(features.get('distinctiveness') or 0)
        row.stability = stability
        row.top_signature = json.dumps(features.get('top_apps') or [], default=str)
        row.observed_from = row.observed_from or (datetime.utcnow() - timedelta(days=self.days))
        row.observed_to = datetime.utcnow()
        return row

    # -- identity -------------------------------------------------------
    def candidates_for_device(self, device_mac, days=None, top_n=3):
        """Return ranked identity candidates for a MAC with probabilities."""
        device_mac = (device_mac or '').lower()
        fp = self.fingerprint_for_device(device_mac, days=days)
        prior_sources = self._priors_for_device(device_mac)
        if fp is None and not prior_sources:
            return []

        persons = intel_store.equery(IntelPerson).all()
        if not persons:
            return []

        rows = intel_store.equery(IntelBehaviorProfile).filter_by(subject_type='person').all()
        profiles = {r.subject_key: (json.loads(r.features) if r.features else None) for r in rows}

        candidates = []
        for person in persons:
            person_fp = profiles.get(person.name)
            if person_fp is None:
                person_fp = self.fingerprint_for_person(person, days=days)
                if person_fp:
                    self._store_profile('person', person.name, person_fp,
                                        label=person.display_name or person.name)
            prior, prior_reason = self._prior_for(device_mac, person, prior_sources)
            sim, parts = (0.0, {})
            if fp and person_fp:
                sim, parts = features_similarity(fp, person_fp)
            dist = float(person_fp.get('distinctiveness') or 0.3) if person_fp else 0.3
            if prior_reason == 'confirmed':
                logit = 3.2 + 1.5 * sim
            else:
                logit = math.log(max(prior, 0.02)) + 2.2 * sim * (0.35 + 0.65 * dist)
            candidates.append({
                'person': person, 'prior': prior, 'prior_reason': prior_reason,
                'similarity': sim, 'parts': parts, 'distinctiveness': dist, 'logit': logit,
            })

        probs = softmax([c['logit'] for c in candidates])
        out = []
        for cand, prob in zip(candidates, probs):
            cand['probability'] = prob
            out.append({
                'person_id': cand['person'].id,
                'person_name': cand['person'].display_name or cand['person'].name,
                'probability': round(prob, 4),
                'prior': round(cand['prior'], 3),
                'prior_reason': cand['prior_reason'],
                'similarity': round(cand['similarity'], 4),
                'distinctiveness': round(cand['distinctiveness'], 4),
                'parts': {k: round(v, 3) for k, v in (cand['parts'] or {}).items()},
                'explanation': self._explain(cand, fp),
            })
        out.sort(key=lambda x: -x['probability'])
        return out[:top_n]

    def _priors_for_device(self, mac):
        """Collect non-behavioural evidence for which person owns a MAC."""
        sources = {}
        row = intel_store.equery(IntelDeviceMac).filter_by(normalized=mac).first()
        if row is None:
            row = intel_store.equery(IntelDeviceMac).filter_by(mac=mac).first()
        if row is not None:
            if row.device_key:
                sources['device_key'] = row.device_key
            if row.hostname:
                sources['hostname'] = row.hostname.lower()
            sources['is_randomized'] = bool(row.is_randomized)
        # user-confirmed bindings
        confirmed = intel_store.equery(IntelIdentityScore).filter_by(device_mac=mac).filter(
            (IntelIdentityScore.is_binding == True) | (IntelIdentityScore.locked == True)).all()  # noqa: E712
        sources['confirmed'] = [c.person_name for c in confirmed if c.person_name]
        # profile assignments from the legacy profile system
        profile_names = []
        try:
            person_profile = {p.name: p.profile_id for p in intel_store.equery(IntelPerson).all() if p.profile_id}
            if row is not None:
                from src.models.network import Device
                # engine-session query: this runs on the worker thread, where
                # Flask-SQLAlchemy's scoped session may have no app context.
                dev = intel_store.equery(Device).filter_by(mac_address=mac).first()
                if dev is not None:
                    import sqlite3
                    import os
                    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                        'database', 'enhanced_network_monitor.db')
                    conn = sqlite3.connect(path)
                    cur = conn.cursor()
                    cur.execute('SELECT profile_id FROM profile_device_assignments WHERE device_id = ?',
                                (dev.id,))
                    for (pid,) in cur.fetchall():
                        for name, person_pid in person_profile.items():
                            if person_pid == pid:
                                profile_names.append(name)
                    conn.close()
        except Exception:
            pass
        sources['profile'] = profile_names
        return sources

    def _prior_for(self, mac, person, sources):
        name = (person.display_name or person.name).lower()
        if any((n or '').lower() == name for n in sources.get('confirmed') or []):
            return 0.97, 'confirmed'
        if any((n or '').lower() == name for n in sources.get('profile') or []):
            return 0.9, 'profile'
        key = sources.get('device_key') or ''
        host = sources.get('hostname') or ''
        for token in (name, name.split()[0] if name else ''):
            if token and len(token) >= 3 and (token in key or token in host):
                return 0.75, 'hostname'
        # fingerprints of the person's other devices that carry the name
        try:
            for row in intel_store.equery(IntelDeviceMac).filter(IntelDeviceMac.device_key.contains(name)).all():
                if row.normalized != mac:
                    return 0.7, 'device_key'
        except Exception:
            pass
        total = max(1, intel_store.equery(IntelPerson).count())
        return 1.0 / total, 'uniform'

    def _explain(self, cand, fp):
        parts = cand.get('parts') or {}
        ordered = sorted(parts.items(), key=lambda x: -x[1])
        explanation = {
            'top_signals': [{'signal': k, 'score': round(v, 3)} for k, v in ordered[:4]],
            'prior_reason': cand['prior_reason'],
            'top_apps': (fp or {}).get('top_apps', [])[:4] if fp else [],
            'night_ratio': ((fp or {}).get('stats') or {}).get('night_ratio'),
            'mean_dwell': ((fp or {}).get('stats') or {}).get('mean_dwell'),
        }
        return explanation

    def score_all(self, days=None, only_unscored=False):
        """Recompute identity scores for every known MAC. Returns a summary."""
        summary = {'scored': 0, 'rotations': 0, 'unallocated': 0}
        try:
            mac_rows = intel_store.equery(IntelDeviceMac).all()
            for row in mac_rows:
                mac = row.normalized or row.mac
                cands = self.candidates_for_device(mac, days=days)
                if not cands:
                    summary['unallocated'] += 1
                    continue
                self._store_scores(mac, cands)
                summary['scored'] += 1
            summary['rotations'] = self.detect_rotations()
            intel_store.engine_session().commit()
        except Exception:
            intel_store.engine_session().rollback()
            raise
        return summary

    def _store_scores(self, mac, candidates):
        for cand in candidates:
            row = intel_store.equery(IntelIdentityScore).filter_by(device_mac=mac,
                                                     person_id=cand['person_id']).first()
            if row is None:
                row = IntelIdentityScore(device_mac=mac, person_id=cand['person_id'],
                                         person_name=cand['person_name'])
                intel_store.engine_session().add(row)
            if row.locked:
                # user pin wins; refresh metadata only
                row.probability = max(row.probability or 0, cand['probability'])
                continue
            row.person_name = cand['person_name']
            row.probability = cand['probability']
            row.prior = cand['prior']
            row.similarity = cand['similarity']
            row.method = 'behavioral+prior'
            row.is_binding = cand['prior_reason'] in ('confirmed', 'profile')
            row.explanation = json.dumps(cand['explanation'], default=str)
            row.samples = int((row.samples or 0) + 1)
            # Beta posterior update: consistent high similarity raises confidence
            alpha = row.alpha if row.alpha is not None else 1.0
            beta = row.beta if row.beta is not None else 1.0
            if cand['probability'] >= 0.5:
                row.alpha = alpha + min(1.0, cand['probability'])
            else:
                row.beta = beta + (1.0 - cand['probability'])
            row.updated_at = datetime.utcnow()

    # -- rotation / movement detection ----------------------------------
    def detect_rotations(self, window_hours=8):
        """Raise starred events when a MAC looks like a rotated identity."""
        created = 0
        now = datetime.utcnow()
        window = timedelta(hours=window_hours)
        recent_macs = intel_store.equery(IntelDeviceMac).filter(
            IntelDeviceMac.first_seen >= now - timedelta(hours=48)).all()
        for row in recent_macs:
            mac = row.normalized or row.mac
            if not mac:
                continue
            existing = intel_store.equery(IntelDeviceEvent).filter_by(device_mac=mac).filter(
                IntelDeviceEvent.kind.in_(('mac_rotation', 'mac_handoff',
                                           'identity_recovered'))).first()
            if existing:
                continue
            if not row.is_randomized and not row.device_key:
                continue
            candidates = self.candidates_for_device(mac)
            best = candidates[0] if candidates else None
            # Find a sibling that went quiet recently
            quiet_sibling = None
            if row.device_key:
                for sib in intel_store.equery(IntelDeviceMac).filter(
                        IntelDeviceMac.device_key == row.device_key,
                        IntelDeviceMac.normalized != mac).all():
                    if sib.last_seen and (now - sib.last_seen) <= window and \
                            (row.first_seen or now) >= (sib.last_seen or now) - window:
                        quiet_sibling = sib
                        break

            if quiet_sibling is not None:
                self._raise_event(
                    kind='mac_rotation' if row.is_randomized else 'mac_handoff',
                    severity='notice',
                    device_mac=mac, related_mac=quiet_sibling.normalized,
                    person_id=(best or {}).get('person_id'),
                    title=(f"{row.hostname or quiet_sibling.hostname or 'Device'} moved to a new MAC "
                           f"{quiet_sibling.normalized} → {mac}"),
                    detail={'reason': 'device_key_match', 'device_key': row.device_key,
                            'quiet_seconds': int((now - quiet_sibling.last_seen).total_seconds())
                            if quiet_sibling.last_seen else None,
                            'randomized': bool(row.is_randomized)},
                    confidence=0.72)
                created += 1
                continue

            if best and best['probability'] >= 0.5 and best['similarity'] >= ROTATION_THRESHOLD:
                quiet = self._person_quiet_for(best['person_id'], mac, window, now)
                self._raise_event(
                    kind='identity_recovered' if quiet else 'identity_switch',
                    severity='notice' if quiet else 'warning',
                    device_mac=mac, person_id=best['person_id'],
                    title=(f"{best['person_name']} is probably using {row.hostname or mac} "
                           f"({int(best['probability'] * 100)}%)"),
                    detail={'probability': best['probability'], 'similarity': best['similarity'],
                            'prior_reason': best['prior_reason'],
                            'previous_device_quiet': quiet,
                            'randomized_mac': bool(row.is_randomized),
                            'explanation': best.get('explanation')},
                    confidence=float(best['probability']))
                created += 1
        return created

    def _person_quiet_for(self, person_id, new_mac, window, now):
        """True when the person's known device went quiet before the new MAC appeared."""
        try:
            rows = intel_store.equery(IntelIdentityScore).filter_by(person_id=person_id).all()
            for row in rows:
                if (row.device_mac or '') == new_mac or (row.probability or 0) < 0.35:
                    continue
                mac_row = intel_store.equery(IntelDeviceMac).filter_by(normalized=row.device_mac).first()
                if mac_row and mac_row.last_seen and (now - mac_row.last_seen) <= window:
                    return row.device_mac
        except Exception:
            return None
        return None

    def _raise_event(self, kind, severity, device_mac, title, detail, confidence=0.5,
                     related_mac=None, person_id=None):
        event = IntelDeviceEvent(
            event_at=datetime.utcnow(), kind=kind, severity=severity,
            device_mac=device_mac, related_mac=related_mac, person_id=person_id,
            title=title, detail=json.dumps(detail, default=str),
            confidence=float(confidence), is_estimated=True)
        intel_store.engine_session().add(event)
        return event

    # -- reporting ------------------------------------------------------
    def person_daily_usage(self, person_id, day=None, dimension='app', limit=25):
        """Usage for a person on a day, aggregated over all associated devices."""
        macs = bound_macs_for_person_id(person_id)
        day = day or datetime.utcnow().strftime('%Y-%m-%d')
        totals = defaultdict(lambda: {'seconds': 0, 'bytes': 0, 'sessions': 0})
        if not macs:
            return []
        rows = intel_store.equery(IntelDailyUsage).filter(
            IntelDailyUsage.day == day,
            IntelDailyUsage.dimension == dimension,
            IntelDailyUsage.device_mac.in_(list(macs))).all()
        for row in rows:
            entry = totals[row.key]
            entry['seconds'] += row.seconds or 0
            entry['bytes'] += row.bytes_total or 0
            entry['sessions'] += row.sessions or 0
            entry['is_estimated'] = bool(row.is_estimated)
        out = [dict(key=k, **v) for k, v in totals.items()]
        out.sort(key=lambda x: -x['seconds'])
        return out[:limit]


# ---------------------------------------------------------------------------
# Person <-> device binding helpers
# ---------------------------------------------------------------------------

def norm_map(mapping):
    total = sum(mapping.values()) or 1.0
    return {k: v / total for k, v in mapping.items()}


def bound_macs_for_person_id(person_id):
    """MACs we associate with a person: confirmed bindings first, then likely ones."""
    macs = set()
    try:
        rows = intel_store.equery(IntelIdentityScore).filter_by(person_id=person_id).all()
        for row in rows:
            if row.locked or row.is_binding or (row.probability or 0) >= 0.6:
                macs.add((row.device_mac or '').lower())
        person = intel_store.equery(IntelPerson).get(person_id)
        if person and person.profile_id:
            macs.update(_macs_for_profile(person.profile_id))
    except Exception:
        pass
    return {m for m in macs if m}


def bound_macs_for_person(person):
    return bound_macs_for_person_id(person.id) if person else set()


def _macs_for_profile(profile_id):
    """Devices assigned to a legacy profile, resolved to MACs."""
    macs = set()
    try:
        import os
        import sqlite3
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'database', 'enhanced_network_monitor.db')
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute('SELECT device_id FROM profile_device_assignments WHERE profile_id = ?',
                    (profile_id,))
        device_ids = [r[0] for r in cur.fetchall()]
        for device_id in device_ids:
            cur.execute('SELECT mac_address FROM devices WHERE id = ?', (device_id,))
            row = cur.fetchone()
            if row and row[0]:
                macs.add(str(row[0]).lower())
        conn.close()
    except Exception:
        pass
    return macs
