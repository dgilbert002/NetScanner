## NetScanner Family Profiles Roadmap

This roadmap captures the plan to evolve NetScanner into a family monitoring and safety system with Profiles (users), Devices, Live view, and Application/URL intelligence, while keeping the code robust, modular, and cross‑platform.

### Principles
- Keep existing DB schemas stable; prefer feature toggles and additive tables.
- Group by features (profiles, devices, analytics), keep files tidy.
- Logging for every function: name, inputs, outputs.
- Cross‑platform (Windows + Raspberry Pi) and low overhead.

### Phase 1 — UI Shell (left nav + right detail)
Deliver static HTML prototypes (no backend wiring yet) to confirm UX.
- Left nav items: Dashboard, Live, Profiles, Devices, Applications.
- Right detail shows section header, time range filters (30d, 7d, 24h, 15m, Live), and placeholder cards.

Artifacts to add under `src/static/prototypes/`:
- `dashboard.html` — KPIs, charts placeholders.
- `live.html` — live table layout, connection rows.
- `profiles.html` — profiles list at left, profile detail at right.
- `devices.html` — device grid/table with bulk actions and rename flow.

Roll back: delete the four prototype files and remove any links pointing to them.

### Phase 2 — Profiles (a.k.a. Groups)
Backend APIs: Use SQLite direct tables to avoid ORM collisions.
- Tables: `device_groups` and `device_group_memberships` (already added from `group_management`).
- CRUD for profiles; assign/unassign devices.
- Friendly device names via updating `Device.hostname` (alias support later).

Wire UI pages:
- Profiles: list, create, edit, delete; show devices; add/remove devices; live and analytics tabs.

Roll back: drop the 2 SQLite tables or leave empty; remove routes in `group_management` and `device_admin`.

### Phase 3 — DNS/URL/Application Intelligence
- Improve DNS resolution: cache DNS answers (A records) and reverse DNS fallback (done in `cross_platform_capture`).
- Maintain `config/app_domains.json` mappings; add editor UI for Apps/Categories.
- Enrich flows with domain → app category; guard with `ENABLE_ENHANCED` to avoid base model conflicts.

Roll back: disable mapping reads; revert `_categorize_domain` to port‑based fallback.

### Phase 4 — Time‑range Analytics
- Endpoints for summaries: per profile, per device, per app, per domain.
- Filters: 30d, 7d, 24h, 15m, Live. Return bytes, session counts, top domains/apps.
- Live tab auto‑refresh.

Roll back: keep old endpoints; new ones are additive under `/api/v2`.

### Phase 5 — Applications Manager
- UI to add/edit Application → Domains list and Category; bulk import.
- Drill‑down per app/category across profiles and devices.

Roll back: disable the UI routes; keep config file.

### Phase 6 — Polishing & Export
- Export CSV/JSON of profile/device usage by period.
- On‑device caching; background workers.
- Access control (pin or simple auth) for admin actions.

Roll back: remove export endpoints; keep capture untouched.

### Notes for Developers
- If `ENABLE_ENHANCED=0`, never access enhanced-only columns.
- Use `hasattr` checks when touching model attributes that differ.
- Prefer additive SQLite tables over altering existing ones.

### Quick Links (dev only)
- Profiles API: `/api/v2/groups/*`
- Device admin: `/api/v2/devices`, `PUT /api/v2/devices/<id>/rename`
- Prototypes: `/prototypes/dashboard`, `/prototypes/live`, `/prototypes/profiles`, `/prototypes/devices`


