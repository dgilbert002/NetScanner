# NetScanner — Deep Assessment (source-level audit)

Audit performed against commit `aae7345` (branch `arena/01a0e967-netscanner`).
Every claim below is traceable to a file and line reference.

---

## 1. What the system is

A Flask + SQLite home-network monitor with a single-page HTML dashboard.

| Layer | Files | Lines |
|---|---|---|
| Entry point | `src/main.py` | 533 |
| Capture engines (6 competing implementations) | `cross_platform_capture.py` (856), `realtime_capture.py` (341), `packet_capture.py` (350), `enhanced_packet_capture.py` (567), `windows_packet_capture.py` (220), `real_packet_capture.py` (291) | 2 625 |
| Analytics (3 competing services) | `analytics_service.py` (715), `comprehensive_analytics.py` (569), `traffic_analyzer.py` (658) | 1 942 |
| Classification | `traffic_classifier.py` (355), `models/hostnames.py` (93), `config/app_domains.json` | 448 |
| Routes | 11 blueprints, 60+ endpoints | 3 084 |
| UI | `index.html` (5 419), `group_management.html` (1 107), `enhanced_dashboard.html` (1 187), `dashboard.html` (1 039) | 8 752 |
| Data assets | `src/data/ip2asn.tsv` (28 MB, real), `ip2asn-combined.tsv.gz` (8 MB) | — |

---

## 2. Strengths (keep these)

1. **Real, offline ASN/country data is already bundled.** `src/data/ip2asn.tsv` is a genuine
   iptoasn-style dataset (28 MB, `start end ASN country org`). `ip2asn_lookup.py` reads it
   with bisect, so IP → ASN/country/org costs nothing and needs no paid API. This is the
   single most valuable asset in the repo and is currently under-used.
2. **Domain classification is already rule-based and offline.** `traffic_classifier.py`
   ships ~80 regex domain rules, ~90 port mappings and IP-prefix hints. No API keys needed.
3. **Ticket-queue enrichment design is sound.** `enrichment_worker.py` uses a priority queue,
   TTL cache (24 h), exponential backoff (60 s → 300 s → 1800 s) and offline ip2asn fallback —
   a correct pattern for slow network lookups.
4. **Evidence-attached enrichment.** `EnrichedData` (`models/network.py:70`) already carries
   hostname, org, ASN, country, plus `is_vpn`/`is_proxy`/`is_tor` columns — unused, but the
   schema is ready for the detection work.
5. **Vendor lookup is offline** via `manuf` (`cross_platform_capture.py:135`), with a cache.
6. **Uptime-minded launcher.** `start.bat`/`setup.sh` handle dependency install, interface
   selection, Pi-hole/nDPI auto-detection and systemd service creation.
7. **Cross-platform intent is explicit and mostly correct**: scapy+Npcap on Windows,
   pyshark+tshark or scapy on the Pi, netstat fallback everywhere.
8. **Additive-migration philosophy** is documented in `ROADMAP.md` ("never destructive").

---

## 3. Weaknesses — correctness and reliability

### 3.1 Session identity is wrong (data corruption, not a bug)

`cross_platform_capture.py:565-571` matches an existing session on
`(src_mac, dst_ip, dst_port, protocol)` — **`src_port` is not part of the key**, and neither is
the source IP. Consequences:

* Every parallel connection from the same device to the same server:port (e.g. the dozen
  HTTP/2 sockets a browser opens to a CDN) collapses into one ever-growing "session".
* `bytes_sent` is incremented for both directions (`:589`, `:604`) — `bytes_received` is
  never written, so per-direction accounting is impossible.
* `end_time` is deliberately overloaded as a *last-activity marker* (`:578`, `:590`, `:597`)
  while other code (`main.py:329`) treats `end_time IS NULL` as "live session". Two
  contradictory meanings for one column.

### 3.2 Session time is not time

* Sessions are never closed by an idle timer anywhere in the capture path. The only "close"
  logic is the 90 s *display* heuristic in `routes/network.py:264`. `end_time` therefore either
  equals `start_time` (one packet) or keeps sliding forever.
* `duration_minutes` = `(last_seen - start_time) // 60` (`routes/network.py:264`) — an open
  browser tab to a CDN produces a 7-hour "session" with 3 packets.
* Nothing merges overlapping intervals, so "time online" per device double-counts whenever two
  apps are open at once.

### 3.3 Website/URL evidence is lost

* The dashboard shows *domains* only. Paths are only ever seen for plain HTTP
  (`cross_platform_capture.py:634` writes `url = scheme://domain`), which is <2 % of traffic today.
* **No TLS SNI extraction in the scapy path.** `_process_scapy_packet` only reads DNS questions
  (`:317`) and `HTTPRequest.Host` (`:344`). The moment a site is HTTPS (all of them) the only
  remaining evidence is DNS — and the DNS cache is a single-IP→name map that is overwritten by
  every lookup (`:301`, `:343`), so shared CDN IPs get the *wrong* name.
* `_resolve_domain()` does a **blocking reverse-DNS call inside the packet callback**
  (`:358` → `socket.gethostbyaddr`). On a busy LAN this stalls the capture loop.
* PTR lookups succeed for almost no public IP, and the fallback name is then reused for
  unrelated flows to the same CDN address.
* DNS answer parsing handles only the *first* answer RR (`:326-341`), and only A records —
  no AAAA, no CNAME chain.

### 3.4 Device identity is fragile

* Devices are created from synthetic MAC strings (`device-192.168.1.5`, `remote-1.2.3.4`) in
  the pyshark and netstat paths (`cross_platform_capture.py:427`, `:481`). Those strings are
  15–17 chars by luck and get inserted into `devices.mac_address` (UNIQUE) — the table fills
  with fake "devices" that will never match a real NIC.
* `_guess_device_type()` (`:723`) is `ip.endswith('.1') → router`, else `192.168.* → computer`.
  Every phone on the LAN is labelled "computer".
* MAC randomization (iOS/Android "private Wi-Fi address") is not detected at all: the
  locally-administered bit is never examined, and each new MAC becomes a brand-new device with
  no history. Same for MAC/IP changes: there is no movement event, no star, no notification.

### 3.5 Capture performance and robustness

* **One SQLite transaction per packet** (`_store_packet_data` → `db.session.commit()` at `:668`,
  plus a `Device` commit at `:698` and another at `:702`). At 1 kpkt/s this is not viable;
  SQLite will lock and the capture thread will fall behind.
* `TrafficSession.src_mac` has a FK to `devices.mac_address` (`models/network.py:52`); inserting
  a session for an unknown MAC raises IntegrityError, which is swallowed at `:670` — silent data loss.
* No `PRAGMA journal_mode=WAL`, no `busy_timeout`, no indexes on `traffic_sessions.start_time`
  or `website_visits.timestamp`; every dashboard query is a full table scan.
* `db.session` is a **scoped session shared between threads** (capture thread, session-logger
  thread, Flask request threads) with no locking and no per-thread session. This is the most
  likely cause of intermittent `database is locked` / stale-object errors.
* No retention job: tables grow without bound (90-day retention is only a roadmap bullet).
* `main.py:180-332` runs a daemon thread that loops every 3 s and *queries the model inside the
  loop* — including `AppSettings.get_or_create_defaults()` per session row (`:300`, `:310`).

### 3.6 Duplicated / dead code

* Six capture engines, three analytics services, four dashboards. `main.py` imports
  `EnhancedPacketCapture` only under `ENABLE_ENHANCED=1`, which also switches the *models* —
  two different `Device`/`TrafficSession` classes with the same `__tablename__`; importing both
  in one process raises `InvalidRequestError` (they are guarded, but the fallback path in
  `cross_platform_capture.py:46-56` defines empty `ContentAnalysis`/`UserSession` stubs, so
  `ENABLE_ENHANCED=1` silently loses features instead of failing loudly).
* `routes/profile_management.py:362` calls `analytics.get_profile_analytics(...)`, a method that
  does not exist on `ComprehensiveAnalytics` → guaranteed HTTP 500 on every profile analytics view.
* `models/network.py` `Device.to_dict()` raises `AttributeError` on a `None` `last_seen`
  (no guard, unlike every other dict method).
* `comprehensive_analytics.py:314` indexes `hourly_pattern.index(max(...))` on an all-zero list →
  returns 0, harmless but wrong; `_get_top_items` relies on `desc('visit_count')` string labels.
* `pihole_remote.py:34` shells out to `ping` in the constructor, on the request path, with
  Windows-only flags; on Linux the connection test always fails.
* `main.py:11` `SECRET_KEY` is a hard-coded literal; `CORS(app)` is wide open on a service that
  binds `0.0.0.0:5002`; `debug=True` in `app.run` for a production-ish tool.
* `enhanced_packet_capture.py` requires paid APIs (`KLAZIFY_API_KEY`, `IPINFO_TOKEN`,
  `MAXMIND_LICENSE_KEY`) — contrary to the "free only" requirement; `traffic_analyzer.py:441`
  likewise. These paths must be treated as optional and never required.

### 3.7 UI

* `index.html` is a 5 419-line single file with ~120 inline handlers and 8 large mock-data
  generators (`generateSampleSessions`, `getRandomStatus`, `getRandomTimeOnline`,
  `loadProfileAlerts`, `loadProfileDevices`, `loadProfileActivity`, `loadProfileDevices`, …).
  Real data from `/api/live/sessions` is mapped into `liveData.sessions`, but **Devices,
  Profiles, Alerts, Active-Today and Dashboard tiles are still random** (`:3581`, `:3828`,
  `:3892`, `:4111`), so the "parental" view silently lies whenever the API is thin.
* No visual distinction between live, recent, historical or estimated figures; no MAC-movement
  indicator; no per-app/per-site time-online view; VPN/proxy is not surfaced anywhere.

---

## 4. Data-source audit (what we actually have, free)

| Source | Status | Used today | Value |
|---|---|---|---|
| `src/data/ip2asn.tsv` (28 MB) | ✅ real, offline | partially (`enrichment_worker`) | ASN, org, country — the backbone for hosting/VPN detection |
| DNS packets (scapy/pyshark) | ✅ free | yes, weakly | domain evidence (no path) |
| TLS SNI (ClientHello) | ✅ free, on the wire | ❌ **not extracted** | the highest-value identifier for HTTPS |
| HTTP Host + path | ✅ free (plain HTTP) | partially | full URLs when unencrypted |
| QUIC Initial SNI | ✅ free, parseable | ❌ | dominates mobile/Chrome traffic |
| ARP / DHCP hostnames | ✅ free, on the wire | ❌ | phone names (`iPhone-de-Marie`), DHCP fingerprint |
| mDNS / LLMNR | ✅ free | ❌ | Apple/Windows device names |
| Pi-hole FTL DB | ✅ free (optional) | partially (`pihole_tap`) | exact client-IP→domain mapping |
| RDAP/WHOIS + PTR | ✅ free | yes (`ipwhois`) | org, netname |
| TLS certificate SAN (port 443 probe) | ✅ free | yes (`enrichment_worker`) | hostname for CDN IPs |
| `manuf` OUI database | ✅ free, bundled | yes | NIC vendor |
| psutil local socket→PID map | ✅ free | ❌ | **real app names** (chrome.exe, Discord…) |
| StevenBlack / OISD / UT1 hosts lists | ✅ free | ❌ | porn/gambling/tracker/fakenews categories |
| Klazify / IPInfo / MaxMind | 💰 paid | code references them | must be removed from any required path |

---

## 5. Gap analysis vs. the requested capability

| Requirement | Where we are | What to build |
|---|---|---|
| See websites **and URLs** visited | domains only, DNS-only evidence, broken DNS cache | SNI/DNS/HTTP/QUIC evidence chain + per-site session table + URL sample |
| Separate **delayed** from **actual** data | no provenance at all | `source`, `observed_at`, `ingested_at`, `latency_ms`, `is_estimated`, revision log, source-health table, UI badges |
| Apps in use now / during the day | `applications` dict counted per packet | per-app dwell buckets (5-min), today + history, local process attribution |
| Name of URLs / apps / websites | regex rules, ~80 domains | larger free catalog + name-resolution service (catalog → rules → SNI → cert → PTR) |
| Consistent MAC tracking incl. phones | unique-MAC rows, no history, fake MACs | MAC registry with first/last seen, IP set, vendor, randomized-MAC detection, movement events |
| Behaviour detection + probability of who | nothing | behavioural fingerprints, entropy/distinctiveness, Bayesian/softmax probability, star on MAC rotation |
| Time per app / per site, session durations | wrong (no idle close, double counting) | idle-aware sessionizer, merged-interval union for "online", attributed time per app/site |
| Idle detection and accurate roll-up | display-only heuristic | server-side idle sweeper, incremental bucket accrual, restart-safe |
| Parental look & feel | mock-driven cards | live Intelligence page, star/probability badges, real aggregates |
| Robust / reliable | per-packet commits, thread-shared session, no indexes/WAL | batch writer, WAL + busy_timeout, indexes, retention, health endpoint |
| VPN / proxy bypass detection | `EnrichedData.is_vpn` never set | multi-signal detector (ASN keywords, tunnel ports/protocols, provider SNI, DNS bypass, datacenter heuristics) |

---

## 6. Prioritised remediation plan

**P0 — data integrity (done in this change-set)**
1. New evidence layer with provenance + freshness (`intel_observations`).
2. Correct flow key incl. `src_port`; never overload `end_time`.
3. Batched writer, WAL, `busy_timeout`, indexes, retention.
4. Server-side idle sweeper; merged-interval duration math.

**P1 — identification (done)**
5. SNI / DNS / HTTP / QUIC extraction; per-site and per-app sessions; URL samples.
6. MAC registry, randomized-MAC detection, movement events and stars.
7. Free catalog + name resolution with confidence and source.
8. App attribution for the capture host via psutil (optional, free).

**P2 — behaviour & bypass (done)**
9. Behavioural fingerprints with entropy and distinctiveness.
10. Identity probability (similarity + Bayesian posterior), star = rotation/handoff.
11. VPN/proxy/DNS-bypass scoring with evidence.

**P3 — progress since this assessment**
12. *(open)* Retire the five legacy capture engines behind one interface. The
    intelligence capture manager now owns scapy → pyshark → connection-table →
    Pi-hole when it is available; the legacy engines are disabled in that case
    but their code is still in the tree.
13. *(done)* Mock generators deleted from `index.html` (`generateSampleSessions`,
    `getRandom*`, `#demo-banner`); the dashboard now shows real collector state,
    live/delayed/estimated provenance and ★ markers from `/api/intel/*`, and
    says "no data" instead of inventing rows. The full intelligence UI lives at
    `/intel` (`src/static/intel.html`); `index.html` is still one large file and
    could be split per page.
14. *(done)* Community feed importer in `src/intel/extdata.py`
    (`python -m src.intel.extdata --sync`, gzip cache in `src/data/feeds/`).
15. *(open)* Auth + CSRF on the API before it is exposed beyond the LAN; the
    development server still runs with the debug reloader off but with CORS open.

---

See `docs/INTELLIGENCE.md` for the new architecture and API surface.
