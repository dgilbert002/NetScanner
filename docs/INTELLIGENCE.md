# NetScanner Intelligence Layer

A second, additive pipeline beside the legacy capture code. It answers the
questions the old pipeline could not: **what is being used right now**, **what
was used today**, **for how long**, **on which device**, **by whom**, **under
which URL**, and **whether anything is trying to bypass the home network**.

Nothing in the legacy path was deleted. The intelligence layer owns capture when
it is available (`main.py`), and everything it produces lands in new tables, so
the old dashboard keeps working from the old tables while the new ones fill up.

---

## 1. Run it

```bash
# Windows (collecting machine)
setup.bat && start.bat

# any platform
python src/main.py                     # serves 0.0.0.0:5002
```

| URL | What it is |
| --- | --- |
| `http://<host>:5002/` | existing dashboard (mocks removed, now shows live/delayed/star provenance) |
| `http://<host>:5002/intel` | full intelligence dashboard (`src/static/intel.html`) |
| `http://<host>:5002/api/intel/*` | JSON API (below) |

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `NETSCANNER_PORT` | `5002` | listen port |
| `NETSCANNER_HOST` | `0.0.0.0` | bind address |
| `NETSCANNER_DEBUG` | off | debug + reloader |
| `NETSCANNER_DB_URI` | `sqlite:///src/database/enhanced_network_monitor.db` | database |
| `NETSCANNER_INTEL` | `1` | master switch for the intelligence layer |
| `NETSCANNER_INTEL_CAPTURE` | `1` | start packet/connection capture |
| `NETSCANNER_SECRET_KEY` | dev fallback | Flask session key (set it in production) |

Tests (48 of them, throwaway database, capture off):

```bash
python -m pytest tests/ -q
```

---

## 2. Data pipeline

```
capture  ─┬─ ScapyCapture ............ packets: DNS, TLS ClientHello+JA3, QUIC, HTTP, DHCP
          ├─ PysharkCapture .......... same, when tshark + pyshark are installed
          ├─ ConnectionTableCapture .. ss/netstat fallback, + reverse-DNS naming
          └─ PiHoleDnsCapture ........ query log from local or remote Pi-hole
                        │
                  Evidence  (one fused observation: device, endpoints, name, bytes, estimate flag)
                        │
                  IntelEngine.process_evidence()
                        ├─ MAC registry (maclab) ........ randomisation, rotations, hand-off
                        ├─ Catalogue naming ............. host -> app / category / owner
                        ├─ Sessionizer (v2) ............. flows, site visits, union time buckets
                        ├─ VpnWatch ..................... provider/ASN/port/DoH/Tor scoring
                        └─ BatchWriter .................. observations, at most once per 5 s
                        │
        SQLite (WAL) ─── 5-minute buckets, daily rollups, online days, MAC registry,
                         events, identity scores, behaviour profiles, VPN findings
                        │
        /api/intel/* ─── /intel dashboard, legacy dashboard strip, exports
```

### Delayed vs actual data

Every row carries `freshness`:

* `state` – `live` (≤ 60 s), `idle` (≤ idle window), `recent` (≤ 15 min),
  `today`, `historic`
* `is_estimated` – derived from a connection table or a poll, not from a packet
* `is_delayed` – estimated, or reported by a slow source (`pihole`, `netstat`,
  `backfill`, `import`, `scan`), or older than 15 minutes
* `source` – which collector produced it

`IntelObservation.latency_ms` records how far behind reality each observation
was when it was ingested; the Data-quality screen shows the average per window.

### Time accounting (the maths)

For every dimension (device / app / site / category) the sessionizer keeps the
**union of intervals**, so:

* 12 sockets to YouTube in the same minute count once, not twelve times;
* Netflix + YouTube running together each get their own time, while the device
  gets the union of the two windows;
* a gap longer than the idle window (90 s default) closes the session with
  `close_reason = 'idle_timeout'`;
* buckets accrue **only newly covered** pieces, so restarts, replays and late
  packets can never double count;
* a single packet proves presence, never duration.

---

## 3. Naming: websites, apps and full URLs

`src/intel/catalog.py` resolves a host through, in order:

1. user rules (the existing Hostnames screen),
2. the built-in catalogue (`catalog_data.py`, ~494 domains / 32 categories),
3. `config/app_domains.json`,
4. imported community feeds (StevenBlack, UT1, HaGeZi),
5. the registrable domain, at low confidence.

Every result carries `source` and `confidence`, and the UI shows them, so a
guess never looks like a fact. Names are revised when better evidence arrives
(`intel_revisions` keeps the history).

Full URLs come from the HTTP parser (`Host` + request path). HTTPS normally
reveals only the hostname via SNI/QUIC — the dashboard shows the URL when it has
one and says "(no path seen)" when it does not, instead of inventing a path.

---

## 4. MAC addresses and "Hide My MAC"

`src/intel/maclab.py`

* normalises and validates MACs (the legacy synthetic `device-192.168.1.5`
  identifiers are rejected, not silently accepted);
* flags locally-administered addresses (iOS/Android private Wi-Fi) with
  `is_randomized`, keeping the vendor blank because a random MAC has no vendor;
* keeps a `device_key` derived from hostname/DHCP/mDNS, so rotation does not
  create a new device;
* links a new random MAC to a known device when the hostname, DHCP fingerprint
  or behaviour matches, emitting `mac_rotation` / `mac_handoff` events;
* the dashboard marks those devices with a ★ and lists the sibling MACs under
  **also seen as**.

Identity probability (`behavior.py`) is a softmax over

```
logit = ln(prior) + 2.2 · similarity · (0.35 + 0.65 · distinctiveness)
logit = 3.2 + 1.5 · similarity                      (user-confirmed binding)
```

where `similarity` blends cosine over the feature vector, Jensen-Shannon on the
hour-of-day and category distributions, Jaccard on sites, and a session-length
distribution distance. Priors come from a confirmed binding, a profile
assignment, a hostname/device-key match, or a uniform prior. Scores keep Beta
counters so evidence accumulates; user confirmations are locked and preserved.
`POST /api/intel/people/<id>/bind` confirms or rejects a match.

---

## 5. VPN / proxy detection

`src/intel/vpnwatch.py` scores independent signals:

| Signal | Weight |
| --- | --- |
| Tor exit/socks port (9050/9051/9150/9001/9030) | 60 |
| VPN provider domain (58 brands) | 45 |
| VPN/relay ASN | 35 |
| iCloud Private Relay | 40 |
| Tunnel protocol on a non-standard port | 30 |
| DoH endpoint | 30 |
| Public resolver used directly (DNS bypass) | 25 |
| Known tunnel port (1194, 51820, 1723, …) | 22 |
| Datacentre ASN (hosting) | 20 |
| Non-standard TLS/JA3 | 12 |

Labels: `low` ≥ 20, `medium` ≥ 40, `high` ≥ 60, `critical` ≥ 80. A datacentre
ASN **on its own is not reported** — hosting the app is not evidence of a
bypass. High/critical findings raise a `vpn_detected` event (deduplicated per
device for 6 hours) and appear on the Bypass screen with their signal breakdown.

---

## 6. API (`/api/intel`)

| Endpoint | Method | Returns |
| --- | --- | --- |
| `/status` | GET | engine state, capture mode, row counts, writer/sessionizer counters, source health, recent errors |
| `/settings` | GET/POST | idle window, retention, behaviour/scan intervals, mirror flag, interface |
| `/quality` | GET | live-vs-delayed observation counts, naming coverage, latency, DB size, retention |
| `/live` | GET | site sessions inside the idle window, with app, URL, duration, identity, star, freshness |
| `/sessions` | GET | unified flow list (`?state=live|idle|closed&hours=&limit=`) |
| `/apps` `/sites` `/categories` | GET | time per dimension (`?day=YYYY-MM-DD` for rollups, `?hours=` for buckets, `?mac=`) |
| `/timeline` | GET | 5-minute buckets for a day (`?dimension=app\|site\|category\|device&mac=`) |
| `/devices` `/device/<mac>` | GET | MAC registry with randomisation, rotations, siblings, identity, online-today |
| `/identity` `/identity/rescore` | GET/POST | per-device candidates with probability, similarity, prior, explanation |
| `/people` `/people/<id>/bind` | GET/POST | people and confirmed/rejected bindings |
| `/vpn` `/vpn/scan` `/vpn/<id>/seen` | GET/POST | findings, device risk ranking, rescan |
| `/events` `/events/seen` `/events/<id>/seen` `/events/clear` | GET/POST | ★ rotation/hand-over/recovery and bypass events |
| `/name` | GET | identify a URL/hostname/IP (`?host=`, `?url=`, `?ip=`) |
| `/lookup` | GET | search sites/apps already seen |
| `/observe` | POST | ingest up to 2000 evidence records (external collectors, tests) |
| `/maintenance` | POST | flush, rebuild profiles, re-scan VPN, indexes, retention (dry-run supported) |
| `/export/<entity>` | GET | sessions / devices / events / vpn as JSON or CSV |

---

## 7. Screens (`/intel`)

* **Happening now** – cards for each active site session: device, app, category,
  duration, URL, freshness chip, identity %, ★, plus open flows and the last
  hour's app mix.
* **Today** – per-app and per-site totals, category share, online-vs-attributed
  totals, 5-minute activity sparkline.
* **URLs visited** – full URL / hostname, app, device, which signal named it
  (`sni`, `http`, `quic`, `dns`, `ptr`), freshness, filterable.
* **Devices & MACs** – vendor, device key, randomisation, rotation count,
  online-today, sibling MACs, identity, ★.
* **Identity** – ranked candidates with probability, similarity, prior reason and
  the signals behind them; Confirm / Reject buttons; add people.
* **VPN / bypass** – findings with score, provider and signal list, plus a device
  risk ranking.
* **Data quality** – what is live vs delayed, per-source health, naming coverage,
  average lag, DB size, and safe maintenance actions (including retention
  dry-run).
* **Events** – the ★ timeline: rotations, hand-overs, recovered identities,
  bypass attempts.

The dashboard has a **preview data** switch for machines that are not yet on the
target network. It renders sample rows in the browser only, marks every one
`SAMPLE`, and never writes to the database. With it off, an idle network shows
empty screens that say why.

---

## 8. Verification performed

* 48 automated tests (`tests/`): protocol parsers, interval/union maths, idle
  handling, MAC randomisation and hand-off, identity scoring, VPN signals,
  catalogue naming, and persistence across request/worker-thread boundaries.
* End-to-end run with synthetic evidence through `POST /api/intel/observe`:
  YouTube/Discord/NordVPN sessions named, 5 m 30 s attributed to YouTube while
  3 m 30 s of Discord overlapped it, device online time 330 s (union, not 480 s),
  full HTTP URL captured, NordVPN scored `critical`, `vpn_detected` event raised,
  daily rollups and online days written.
* Live launch on a machine with no target LAN: capture degrades to the
  connection-table source (`netstat on eth0`), records what little it can see,
  and the dashboards show it as `estimated` rather than pretending it is a
  packet-level observation.

---

## 9. Known limits

* **HTTPS paths** are not visible without TLS interception (deliberately not
  implemented). URLs are exact for plain HTTP; for TLS the hostname is shown.
* **Random MAC hand-off** is probabilistic. A rotation is only claimed when the
  hostname/DHCP fingerprint or behaviour matches; otherwise the device stays a
  separate row and the identity screen asks for review.
* **Behaviour scoring needs history** — a few days of traffic per person before
  probabilities separate cleanly. Locked bindings work immediately.
* **DoH is invisible to DNS inspection**; it is detected as a bypass signal, but
  the tunnelled names are not recoverable.
* **netstat/ss fallback** gives connections and PTR names, not URLs, and its
  bytes are zero because the OS table does not report them.

## Parental / history surface (added in this round)

Endpoints (all `GET` unless noted), served by `src/routes/intel_history.py`:

| Endpoint | What it answers |
|---|---|
| `/api/intel/usage?range=day|week|month|6months|year|all&dimension=app|site|category|device|game|vpn&person=&mac=` | totals (`human`, `online_human`, sessions, bytes, active days) plus one row per app/site/category/device with a per-day map |
| `/api/intel/calendar?dimension=&key=&range=&person=` | gap-filled day list for one app/site/category (a calendar heat map), totals (best day, average per active day) and the session drill-down (`human` = active time, `span_human` = first→last activity, `idle_human` = quiet time) |
| `/api/intel/people/overview` | one row per person: today, week, online week, gaming time, top categories/apps, games, adult seconds, alert counts |
| `/api/intel/people/<id>/summary?range=` | everything about one person: devices, categories/apps/sites/devices usage, games, alerts, searches |
| `/api/intel/alerts?hours=&kind=&limit=` | alert rows + summary (per kind, per device, unseen, critical) + the active rules |
| `/api/intel/alerts/rules` (GET/POST) | read/update the parental rules (persisted in settings as `alert_*`) |
| `/api/intel/alerts/evaluate` (POST) | run every rule now over the last N hours |
| `/api/intel/searches?hours=&term=&person=` | observed search terms, with the HTTPS caveat in the response |

### Time maths: active vs span

A site session records three numbers, and the UI shows all three:

* `dwell_seconds` — union of active intervals (never double counts parallel sockets).
* `span_seconds` — first evidence → last evidence (how long the session lasted).
* `idle_seconds` — `span - dwell`: proven quiet time inside the session.

A browser opens a fresh socket for nearly every request, so the interval marker is
taken from the **site session** (and a per-device marker for the online dimension)
rather than from the flow: otherwise a multi-connection visit would total zero.

Connection-table capture (netstat) samples an established socket every N seconds.
A gap between two samples of the *same* socket is real usage, so it is credited —
but only up to `estimated_gap_seconds` (900 s) and only as estimated evidence.

### Alerts

`src/intel/alerts.py` evaluates the rules on a timer (`alerts_interval_seconds`,
default 300 s) and on demand. Kinds: `adult_content`, `gambling`, `bypass`,
`unknown_bypass`, `gaming_session`, `late_night`, `daily_limit`, `new_app`,
`new_device`, `vpn_detected`. Every alert is an `intel_device_events` row, so it
inherits severity, the ★ marker, the seen/unseen flag and retention. Alerts are
deduped per (kind, device) — 24 h by default, tighter for bypass (12 h), gaming
(6 h), bedtime (14 h) and limits (20 h) — so a five-minute sweep cannot spam.
"First use of an app" is scoped **per device**, so each child's own first game is
reported.

### Search terms

Search terms are recovered from the URL for ~30 engines
(`src/intel/flow.py: SEARCH_ENGINES`, `search_term_from_url`). This only ever
fires for plain HTTP: `https://www.google.com/search?q=…` is encrypted from the
browser, and no local monitor can read it without a TLS-intercepting proxy. The
dashboard states this next to the list instead of implying the data is complete.

### Games

`dimension=game` is the Gaming slice of the app dimension, resolved through the
catalogue's app names (`catalog.apps_in_category`) because the rollups store app
names (`Roblox`), not domains.

### Schema updates

New columns (`intel_site_sessions.span_seconds/idle_seconds`,
`intel_flows.span_seconds`) and the `intel_searches` table are created by
`ensure_columns()` / `create_all` at startup, so an existing database with months
of history keeps working; no reset is needed.
