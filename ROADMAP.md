## NetScanner Roadmap

This roadmap drives the app from the current demo-perfect GUI to a real-time, 90‑day history system with capture, classification, rules, and settings.

### Principles
- Additive migrations only (never destructive); safe on Windows and Raspberry Pi.
- Group by features (Home, Live, Devices, Rules, Settings).
- Logging for every function: name, inputs, outputs.
- Feature flags via Settings; single source of truth in DB.

---

### Phase A — Settings & Schema Safety (now)
Deliverables:
- Settings tab in UI: Session idle window (seconds), nDPI mode (Off / Fallback / On).
- Settings backend: `settings` table and `/api/settings` GET/POST.
- Schema ensure script: scans SQLAlchemy models and creates missing tables/columns.

Rollback:
- Remove Settings nav; keep defaults hard-coded (idle=90s, nDPI=Fallback).

---

### Phase B — Capture → Sessionization → Classification
Deliverables:
- Capture via pyshark/tshark; scapy fallback.
- Sessionizer with idle close threshold from Settings (default 90s).
- Classification order: Rules → root-domain → nDPI (per Settings mode) → Unknown/Uncategorized.
- Persist sessions with app_id/category_id, rule_source, confidence.

Rollback:
- Disable capture worker; UI continues with demo data.

---

### Phase C — Endpoints that mirror demo JSON
Deliverables:
- `/api/live/sessions`, `/api/devices`, `/api/home/summary`, `/api/profiles/:id/detail` returning the exact shape the UI expects.
- Keep client-side filters; add server-side filtering later.

Rollback:
- Repoint UI to demo adapters; endpoints remain additive.

---

### Phase D — Aggregations & Alerts
Deliverables:
- 5‑minute rollups for Live table and counters.
- Accurate “time online” via merged session intervals per profile.
- Alerts table + badge updates; toggle seen/clear wired.

Rollback:
- Turn off the aggregator job; real-time still shows live sessions.

---

### Phase E — Retention (90 days)
Deliverables:
- Nightly retention job: delete sessions/rollups older than 90 days; vacuum.
- Index maintenance.

Rollback:
- Disable the retention job; manual clean supported.

---

### Phase F — Optional nDPI Integration
Deliverables:
- ndpiReader JSON adapter; consult based on Settings (Off/Fallback/On).
- Confidence tagging; manual rules always override.

Rollback:
- Set Settings → nDPI=Off; code paths short‑circuit.

---

### Phase G — Documentation & Ops
Deliverables:
- Functionality.md kept in lock‑step with behavior.
- Raspberry Pi setup appendix (tshark, pyshark, scapy, optional nDPI build steps).
- Export/import of rules JSON.

Rollback:
- Docs remain; features can be toggled in Settings.

---

### Tracking
- Each phase is atomic and reversible via feature flags or job toggles.
- We will commit after each milestone and update Functionality.md and this roadmap.


