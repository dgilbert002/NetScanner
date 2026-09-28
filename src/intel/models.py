"""
Additive database schema for the intelligence layer.

Design rules
------------
* Every table is new; nothing existing is altered or dropped.
* Timestamps are UTC (naive) to match the rest of the project.
* Every row that represents *derived* data carries provenance
  (``source``, ``is_estimated``, ``confidence``) so the UI can separate
  "actual, observed" data from "delayed / inferred / estimated" data.
"""

from __future__ import annotations

import json
from datetime import datetime

from src.models.user import db


def _iso(value):
    return value.isoformat() if value else None


def _loads(raw, default):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Evidence layer
# ---------------------------------------------------------------------------

class IntelObservation(db.Model):
    """A single piece of observed network evidence (one packet or one DNS answer).

    This is the "actual data" table.  Rows are written in batches by
    :mod:`src.intel.store` to keep SQLite happy at high packet rates.
    """

    __tablename__ = 'intel_observations'

    id = db.Column(db.Integer, primary_key=True)
    observed_at = db.Column(db.DateTime, nullable=False, index=True)   # when it happened on the wire
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)      # when we stored it
    latency_ms = db.Column(db.Integer, default=0)                      # ingested - observed (delayed data marker)

    # Provenance: live | dns | pihole | probe | backfill | import | synthetic
    source = db.Column(db.String(16), nullable=False, default='live', index=True)
    collector = db.Column(db.String(32))                               # scapy | pyshark | netstat | pihole | api

    device_mac = db.Column(db.String(32), index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(12))
    direction = db.Column(db.String(8), default='out')                 # out | in | local

    # Evidence extracted from the wire (the identification chain)
    dns_qname = db.Column(db.String(255))
    sni = db.Column(db.String(255))
    http_host = db.Column(db.String(255))
    http_path = db.Column(db.Text)
    quic_sni = db.Column(db.String(255))
    tls_fingerprint = db.Column(db.String(64))                         # JA3-ish hash
    dhcp_hostname = db.Column(db.String(255))
    mdns_name = db.Column(db.String(255))
    user_agent = db.Column(db.String(300))

    bytes_up = db.Column(db.Integer, default=0)
    bytes_down = db.Column(db.Integer, default=0)
    packets = db.Column(db.Integer, default=1)
    is_estimated = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.5)
    detail = db.Column(db.Text)                                        # JSON blob, optional

    def to_dict(self):
        return {
            'id': self.id,
            'observed_at': _iso(self.observed_at),
            'ingested_at': _iso(self.ingested_at),
            'latency_ms': self.latency_ms,
            'source': self.source,
            'collector': self.collector,
            'device_mac': self.device_mac,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'direction': self.direction,
            'dns_qname': self.dns_qname,
            'sni': self.sni,
            'http_host': self.http_host,
            'http_path': self.http_path,
            'quic_sni': self.quic_sni,
            'tls_fingerprint': self.tls_fingerprint,
            'dhcp_hostname': self.dhcp_hostname,
            'mdns_name': self.mdns_name,
            'user_agent': self.user_agent,
            'bytes_up': self.bytes_up,
            'bytes_down': self.bytes_down,
            'packets': self.packets,
            'is_estimated': bool(self.is_estimated),
            'confidence': self.confidence,
            'detail': _loads(self.detail, {}),
        }


# ---------------------------------------------------------------------------
# Flow sessions (correct 5-tuple key, idle closed)
# ---------------------------------------------------------------------------

class IntelFlow(db.Model):
    """A network flow/session with a *real* key: (device, src_port, dst_ip, dst_port, proto).

    ``last_seen`` is the last-activity marker (always).  ``closed_at`` /
    ``close_reason`` describe how the session ended.  ``state`` is one of
    ``live`` (activity within the idle window), ``idle`` (open but quiet),
    ``closed`` (closed by the sweeper / FIN).
    """

    __tablename__ = 'intel_flows'
    __table_args__ = (
        db.Index('ix_intel_flows_key', 'device_mac', 'dst_ip', 'dst_port', 'protocol', 'src_port'),
        db.Index('ix_intel_flows_last_seen', 'last_seen'),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(32), index=True)
    src_ip = db.Column(db.String(45), index=True)
    dst_ip = db.Column(db.String(45), index=True)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(12))
    service_port = db.Column(db.Integer)         # canonical port used for classification

    hostname = db.Column(db.String(255))         # best evidence name (SNI > host > DNS > PTR)
    root_domain = db.Column(db.String(255), index=True)
    url_sample = db.Column(db.Text)
    app = db.Column(db.String(80), index=True)
    category = db.Column(db.String(60), index=True)
    name_source = db.Column(db.String(24))       # sni | http | dns | catalouge | ptr | port
    name_confidence = db.Column(db.Float, default=0.3)

    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at = db.Column(db.DateTime)
    close_reason = db.Column(db.String(24))      # idle_timeout | fin | shutdown | superseded
    state = db.Column(db.String(10), default='live', index=True)
    duration_seconds = db.Column(db.Integer, default=0)

    bytes_up = db.Column(db.BigInteger, default=0)
    bytes_down = db.Column(db.BigInteger, default=0)
    packets = db.Column(db.Integer, default=0)
    obs_count = db.Column(db.Integer, default=0)

    source = db.Column(db.String(16), default='live')
    is_estimated = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.5)
    last_accrued = db.Column(db.DateTime)        # restart-safe bucket accrual marker

    def total_bytes(self):
        return int((self.bytes_up or 0) + (self.bytes_down or 0))

    def to_dict(self):
        return {
            'id': self.id,
            'device_mac': self.device_mac,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'hostname': self.hostname,
            'root_domain': self.root_domain,
            'url': self.url_sample,
            'app': self.app,
            'category': self.category,
            'name_source': self.name_source,
            'name_confidence': self.name_confidence,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'closed_at': _iso(self.closed_at),
            'close_reason': self.close_reason,
            'state': self.state,
            'duration_seconds': self.duration_seconds,
            'bytes_up': self.bytes_up,
            'bytes_down': self.bytes_down,
            'bytes_total': self.total_bytes(),
            'packets': self.packets,
            'obs_count': self.obs_count,
            'source': self.source,
            'is_estimated': bool(self.is_estimated),
            'confidence': self.confidence,
        }


# ---------------------------------------------------------------------------
# Site visits (per device + site, with merged dwell time)
# ---------------------------------------------------------------------------

class IntelSiteSession(db.Model):
    """Time-on-site for one device, with merged (non-double-counted) dwell.

    ``dwell_seconds`` is the sum of activity bursts separated by less than the
    idle window.  ``pageviews`` counts distinct evidence hits.  ``url_last`` is
    the last full URL we could evidence (plain HTTP, or host+SNI for HTTPS).
    """

    __tablename__ = 'intel_site_sessions'
    __table_args__ = (
        db.Index('ix_intel_site_key', 'device_mac', 'root_domain', 'last_seen'),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(32), index=True)
    root_domain = db.Column(db.String(255), index=True)
    hostname = db.Column(db.String(255))
    app = db.Column(db.String(80))
    category = db.Column(db.String(60), index=True)
    url_last = db.Column(db.Text)

    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    closed_at = db.Column(db.DateTime)
    state = db.Column(db.String(10), default='live', index=True)
    dwell_seconds = db.Column(db.Integer, default=0)
    active_seconds = db.Column(db.Integer, default=0)     # within the idle window of last_seen
    pageviews = db.Column(db.Integer, default=0)
    bytes_total = db.Column(db.BigInteger, default=0)
    packets = db.Column(db.Integer, default=0)
    last_accrued = db.Column(db.DateTime)

    source = db.Column(db.String(16), default='live')
    is_estimated = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.5)

    def to_dict(self):
        return {
            'id': self.id,
            'device_mac': self.device_mac,
            'root_domain': self.root_domain,
            'hostname': self.hostname,
            'app': self.app,
            'category': self.category,
            'url': self.url_last,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'closed_at': _iso(self.closed_at),
            'state': self.state,
            'dwell_seconds': self.dwell_seconds,
            'active_seconds': self.active_seconds,
            'pageviews': self.pageviews,
            'bytes_total': self.bytes_total,
            'packets': self.packets,
            'source': self.source,
            'is_estimated': bool(self.is_estimated),
            'confidence': self.confidence,
        }


# ---------------------------------------------------------------------------
# Usage rollups (5-minute buckets; daily aggregation via SQL)
# ---------------------------------------------------------------------------

class IntelUsageBucket(db.Model):
    """Incremental 5-minute usage bucket.

    ``dimension`` is ``app`` / ``site`` / ``category`` / ``device`` and ``key`` is
    the value inside that dimension.  ``seconds`` is *attributed* time (sum of
    per-key intervals, so it can exceed wall-clock when things overlap);
    ``online_seconds`` is only written for ``dimension='device'`` and holds the
    merged-interval union (true time online).
    """

    __tablename__ = 'intel_usage_buckets'
    __table_args__ = (
        db.UniqueConstraint('bucket_start', 'dimension', 'key', 'device_mac', name='uq_intel_bucket'),
        db.Index('ix_intel_bucket_lookup', 'dimension', 'key', 'bucket_start'),
    )

    id = db.Column(db.Integer, primary_key=True)
    bucket_start = db.Column(db.DateTime, nullable=False, index=True)
    dimension = db.Column(db.String(16), nullable=False)
    key = db.Column(db.String(255), nullable=False)
    device_mac = db.Column(db.String(32), nullable=False, default='')

    seconds = db.Column(db.Integer, default=0)
    online_seconds = db.Column(db.Integer, default=0)
    bytes_total = db.Column(db.BigInteger, default=0)
    sessions = db.Column(db.Integer, default=0)
    source = db.Column(db.String(16), default='live')
    is_estimated = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'bucket_start': _iso(self.bucket_start),
            'dimension': self.dimension,
            'key': self.key,
            'device_mac': self.device_mac,
            'seconds': self.seconds,
            'online_seconds': self.online_seconds,
            'bytes_total': self.bytes_total,
            'sessions': self.sessions,
            'source': self.source,
            'is_estimated': bool(self.is_estimated),
        }


class IntelDailyUsage(db.Model):
    """Daily rollup used by "what was used today / this week" screens."""

    __tablename__ = 'intel_daily_usage'
    __table_args__ = (
        db.UniqueConstraint('day', 'dimension', 'key', 'device_mac', name='uq_intel_daily'),
        db.Index('ix_intel_daily_lookup', 'dimension', 'key', 'day'),
    )

    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False, index=True)   # YYYY-MM-DD (local day)
    dimension = db.Column(db.String(16), nullable=False)         # app | site | category
    key = db.Column(db.String(255), nullable=False)
    device_mac = db.Column(db.String(32), nullable=False, default='')

    seconds = db.Column(db.Integer, default=0)
    bytes_total = db.Column(db.BigInteger, default=0)
    sessions = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    is_estimated = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'day': self.day,
            'dimension': self.dimension,
            'key': self.key,
            'device_mac': self.device_mac,
            'seconds': self.seconds,
            'bytes_total': self.bytes_total,
            'sessions': self.sessions,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'is_estimated': bool(self.is_estimated),
        }


class IntelOnlineDay(db.Model):
    """True time-online per device per day (union of activity intervals)."""

    __tablename__ = 'intel_online_days'
    __table_args__ = (db.UniqueConstraint('day', 'device_mac', name='uq_intel_online_day'),)

    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(10), nullable=False, index=True)
    device_mac = db.Column(db.String(32), nullable=False, index=True)
    online_seconds = db.Column(db.Integer, default=0)
    active_seconds = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    is_estimated = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'day': self.day,
            'device_mac': self.device_mac,
            'online_seconds': self.online_seconds,
            'active_seconds': self.active_seconds,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'is_estimated': bool(self.is_estimated),
        }


# ---------------------------------------------------------------------------
# Device / MAC identity
# ---------------------------------------------------------------------------

class IntelDeviceMac(db.Model):
    """MAC registry: one row per MAC ever seen, with vendor + randomness info."""

    __tablename__ = 'intel_device_macs'

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String(32), unique=True, nullable=False, index=True)
    normalized = db.Column(db.String(17), index=True)      # aa:bb:cc:dd:ee:ff
    vendor = db.Column(db.String(120))
    oui = db.Column(db.String(8))
    is_randomized = db.Column(db.Boolean, default=False, index=True)
    random_kind = db.Column(db.String(32))                 # locally_administered | apple_private | android_random
    device_class = db.Column(db.String(32))                # phone | laptop | iot | router | unknown
    hostname = db.Column(db.String(255))
    ip_addresses = db.Column(db.Text)                      # JSON list
    device_key = db.Column(db.String(120), index=True)     # stable grouping key (hostname/fingerprint)
    mac_rotations = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    observed_seconds = db.Column(db.Integer, default=0)
    bytes_total = db.Column(db.BigInteger, default=0)
    evidence = db.Column(db.Text)                          # JSON
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'mac': self.mac,
            'normalized': self.normalized,
            'vendor': self.vendor,
            'oui': self.oui,
            'is_randomized': bool(self.is_randomized),
            'random_kind': self.random_kind,
            'device_class': self.device_class,
            'hostname': self.hostname,
            'ip_addresses': _loads(self.ip_addresses, []),
            'device_key': self.device_key,
            'mac_rotations': self.mac_rotations,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'observed_seconds': self.observed_seconds,
            'bytes_total': self.bytes_total,
            'evidence': _loads(self.evidence, {}),
            'is_active': bool(self.is_active),
        }


class IntelDeviceEvent(db.Model):
    """Notable device/identity events (drives the stars and the alert feed)."""

    __tablename__ = 'intel_device_events'

    id = db.Column(db.Integer, primary_key=True)
    event_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    kind = db.Column(db.String(40), nullable=False, index=True)
    severity = db.Column(db.String(16), default='info')     # info | notice | warning | critical
    device_mac = db.Column(db.String(32), index=True)
    related_mac = db.Column(db.String(32))
    person_id = db.Column(db.Integer)
    title = db.Column(db.String(200))
    detail = db.Column(db.Text)
    confidence = db.Column(db.Float, default=0.5)
    is_estimated = db.Column(db.Boolean, default=False)
    seen = db.Column(db.Boolean, default=False, index=True)

    STARRED = {'mac_rotation', 'mac_handoff', 'identity_recovered', 'identity_switch'}

    def to_dict(self):
        return {
            'id': self.id,
            'event_at': _iso(self.event_at),
            'kind': self.kind,
            'severity': self.severity,
            'device_mac': self.device_mac,
            'related_mac': self.related_mac,
            'person_id': self.person_id,
            'title': self.title,
            'detail': _loads(self.detail, {}),
            'confidence': self.confidence,
            'is_estimated': bool(self.is_estimated),
            'seen': bool(self.seen),
            'star': self.kind in self.STARRED,
        }


class IntelPerson(db.Model):
    """A human being we are tracking across devices."""

    __tablename__ = 'intel_persons'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(120))
    profile_id = db.Column(db.Integer)                     # links to user_profiles.id when present
    color = db.Column(db.String(16), default='#3498db')
    is_child = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'display_name': self.display_name or self.name,
            'profile_id': self.profile_id,
            'color': self.color,
            'is_child': bool(self.is_child),
            'notes': self.notes,
        }


class IntelBehaviorProfile(db.Model):
    """Stored behavioural fingerprint (heuristic + entropy summary).

    ``subject_type`` is ``device`` or ``person``; ``subject_key`` is the MAC or
    the person name.  ``features`` holds the JSON feature vector described in
    :mod:`src.intel.behavior`.
    """

    __tablename__ = 'intel_behavior_profiles'
    __table_args__ = (
        db.UniqueConstraint('subject_type', 'subject_key', name='uq_intel_behavior_subject'),
    )

    id = db.Column(db.Integer, primary_key=True)
    subject_type = db.Column(db.String(16), nullable=False)
    subject_key = db.Column(db.String(120), nullable=False, index=True)
    label = db.Column(db.String(120))
    features = db.Column(db.Text)                 # JSON: normalised feature vector + metadata
    sample_sessions = db.Column(db.Integer, default=0)
    sample_seconds = db.Column(db.Integer, default=0)
    entropy = db.Column(db.Float)                 # Shannon entropy of hour distribution (bits)
    distinctiveness = db.Column(db.Float)         # 1 - H/Hmax
    stability = db.Column(db.Float)               # re-estimation drift (1 = stable)
    top_signature = db.Column(db.Text)            # JSON list of (feature, weight)
    observed_from = db.Column(db.DateTime)
    observed_to = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'subject_type': self.subject_type,
            'subject_key': self.subject_key,
            'label': self.label,
            'features': _loads(self.features, {}),
            'sample_sessions': self.sample_sessions,
            'sample_seconds': self.sample_seconds,
            'entropy': self.entropy,
            'distinctiveness': self.distinctiveness,
            'stability': self.stability,
            'top_signature': _loads(self.top_signature, []),
            'observed_from': _iso(self.observed_from),
            'observed_to': _iso(self.observed_to),
            'updated_at': _iso(self.updated_at),
        }


class IntelIdentityScore(db.Model):
    """Probability that a MAC currently belongs to a given person."""

    __tablename__ = 'intel_identity_scores'
    __table_args__ = (
        db.Index('ix_intel_identity_lookup', 'device_mac', 'probability'),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(32), nullable=False, index=True)
    person_id = db.Column(db.Integer)
    person_name = db.Column(db.String(120))
    probability = db.Column(db.Float, default=0.0)
    prior = db.Column(db.Float, default=0.0)
    similarity = db.Column(db.Float, default=0.0)
    method = db.Column(db.String(40), default='behavioral')
    is_binding = db.Column(db.Boolean, default=False)      # user confirmed / assigned
    explanation = db.Column(db.Text)                       # JSON feature contributions
    alpha = db.Column(db.Float, default=1.0)               # Beta posterior counters
    beta = db.Column(db.Float, default=1.0)
    samples = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_estimated = db.Column(db.Boolean, default=True)
    locked = db.Column(db.Boolean, default=False)          # user pinned this mapping

    def to_dict(self):
        return {
            'device_mac': self.device_mac,
            'person_id': self.person_id,
            'person_name': self.person_name,
            'probability': self.probability,
            'prior': self.prior,
            'similarity': self.similarity,
            'method': self.method,
            'is_binding': bool(self.is_binding),
            # Hoisted for the UI: the reason the prior exists ('hostname',
            # 'device_key', 'confirmed', ...), otherwise only inside explanation.
            'prior_reason': (_loads(self.explanation, {}) or {}).get('prior_reason'),
            'explanation': _loads(self.explanation, {}),
            'samples': self.samples,
            'updated_at': _iso(self.updated_at),
            'is_estimated': bool(self.is_estimated),
            'locked': bool(self.locked),
        }


# ---------------------------------------------------------------------------
# Naming / classification cache
# ---------------------------------------------------------------------------

class IntelNameCache(db.Model):
    """Cache of resolved names for domains / IPs / apps (free lookups only)."""

    __tablename__ = 'intel_names'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), unique=True, nullable=False, index=True)
    key_type = db.Column(db.String(16), default='domain')     # domain | ip | app
    display_name = db.Column(db.String(255))
    app = db.Column(db.String(80))
    category = db.Column(db.String(60))
    owner = db.Column(db.String(120))
    name_source = db.Column(db.String(24), default='catalog')
    confidence = db.Column(db.Float, default=0.5)
    revisions = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'key': self.key,
            'key_type': self.key_type,
            'display_name': self.display_name,
            'app': self.app,
            'category': self.category,
            'owner': self.owner,
            'name_source': self.name_source,
            'confidence': self.confidence,
            'revisions': self.revisions,
            'updated_at': _iso(self.updated_at),
        }


class IntelRevision(db.Model):
    """Audit trail for late-arriving corrections (delayed data vs actual data)."""

    __tablename__ = 'intel_revisions'

    id = db.Column(db.Integer, primary_key=True)
    entity = db.Column(db.String(40), nullable=False)      # flow | site | device | name
    entity_id = db.Column(db.Integer)
    field = db.Column(db.String(40))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    source = db.Column(db.String(24))
    confidence = db.Column(db.Float, default=0.5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'entity': self.entity,
            'entity_id': self.entity_id,
            'field': self.field,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'source': self.source,
            'confidence': self.confidence,
            'created_at': _iso(self.created_at),
        }


# ---------------------------------------------------------------------------
# Bypass detection (VPN / proxy / DNS bypass)
# ---------------------------------------------------------------------------

class IntelVpnFinding(db.Model):
    """A VPN / proxy / DNS-bypass signal with its evidence and score."""

    __tablename__ = 'intel_vpn_findings'
    __table_args__ = (
        db.Index('ix_intel_vpn_lookup', 'device_mac', 'score'),
    )

    id = db.Column(db.Integer, primary_key=True)
    device_mac = db.Column(db.String(32), index=True)
    dst_ip = db.Column(db.String(45))
    dst_host = db.Column(db.String(255))
    provider = db.Column(db.String(120))
    kind = db.Column(db.String(24), nullable=False)     # vpn | proxy | dns_bypass | tor | tunnel | datacenter
    score = db.Column(db.Float, default=0.0)            # 0..100 aggregate for this row
    label = db.Column(db.String(16))                    # none|low|medium|high|critical
    evidence = db.Column(db.Text)                       # JSON list of {signal, weight, detail}
    asn = db.Column(db.Integer)
    org = db.Column(db.String(160))
    country = db.Column(db.String(4))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    hits = db.Column(db.Integer, default=1)
    is_estimated = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.5)
    seen = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'device_mac': self.device_mac,
            'dst_ip': self.dst_ip,
            'dst_host': self.dst_host,
            'provider': self.provider,
            'kind': self.kind,
            'score': self.score,
            'label': self.label,
            'evidence': _loads(self.evidence, []),
            'asn': self.asn,
            'org': self.org,
            'country': self.country,
            'first_seen': _iso(self.first_seen),
            'last_seen': _iso(self.last_seen),
            'hits': self.hits,
            'is_estimated': bool(self.is_estimated),
            'confidence': self.confidence,
            'seen': bool(self.seen),
        }


# ---------------------------------------------------------------------------
# Source health (data quality dashboard)
# ---------------------------------------------------------------------------

class IntelSourceHealth(db.Model):
    """Per-collector health so the UI can show whether data is live or stale."""

    __tablename__ = 'intel_source_health'

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(32), unique=True, nullable=False)
    status = db.Column(db.String(16), default='idle')     # idle | healthy | degraded | error | disabled
    last_event_at = db.Column(db.DateTime)
    last_success_at = db.Column(db.DateTime)
    last_error = db.Column(db.Text)
    events = db.Column(db.BigInteger, default=0)
    dropped = db.Column(db.BigInteger, default=0)
    lag_seconds = db.Column(db.Float, default=0.0)
    detail = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'source': self.source,
            'status': self.status,
            'last_event_at': _iso(self.last_event_at),
            'last_success_at': _iso(self.last_success_at),
            'last_error': self.last_error,
            'events': self.events,
            'dropped': self.dropped,
            'lag_seconds': self.lag_seconds,
            'detail': _loads(self.detail, {}),
            'updated_at': _iso(self.updated_at),
        }


class IntelRuntimeState(db.Model):
    """Tiny key/value store for restart-safe engine bookkeeping."""

    __tablename__ = 'intel_runtime_state'

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def intel_tables_ready():
    """Return True when the intelligence tables exist in the database."""
    from sqlalchemy import inspect
    try:
        insp = inspect(db.engine)
        return insp.has_table('intel_observations') and insp.has_table('intel_flows')
    except Exception:
        return False
