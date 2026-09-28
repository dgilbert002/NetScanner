"""
NetScanner Intelligence Layer
=============================

Evidence-based network intelligence built on top of the existing NetScanner
database.  Everything in this package is additive: it never mutates or drops
existing tables, and it never requires a paid API.

Modules
-------
``models``      SQLAlchemy tables for evidence, sessions, rollups, behaviour,
                identity scores, MAC history, VPN findings and source health.
``maclab``      MAC normalisation, randomised-MAC detection, OUI vendor lookup,
                MAC registry and movement (star) detection.
``catalog``     Free domain/app/category catalog + name resolution service.
``flow``        Packet -> evidence extraction (DNS, TLS SNI, HTTP, QUIC, DHCP,
                mDNS, ARP) and local process attribution.
``store``       Batched, crash-safe writer (WAL, busy_timeout, indexes).
``sessionizer`` Idle-aware flow/site session building with merged-interval
                duration maths and incremental 5-minute bucket accrual.
``behavior``    Behavioural fingerprints, entropy/distinctiveness, identity
                probability, rotation detection.
``vpnwatch``    VPN / proxy / DNS-bypass detection scoring.
``engine``      Orchestrator that owns the single background worker thread.
``extdata``     Optional importers for free community feed lists.

Import order matters: ``src.intel.models`` must be imported before
``db.create_all()`` runs so the new tables exist.
"""

__all__ = [
    'models',
    'maclab',
    'catalog',
    'flow',
    'store',
    'sessionizer',
    'behavior',
    'vpnwatch',
    'engine',
    'extdata',
]

INTEL_VERSION = '1.0.0'
