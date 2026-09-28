# UI check

Runs both dashboards in a real DOM (jsdom), with real API responses, and fails
if any page throws JavaScript errors or renders empty where it should not.

This exists because a load-order bug (`LOADERS` referencing a function defined
in a script that had not been fetched yet) silently killed the entire
intelligence dashboard, and because static-looking pages can hide the fact that
their JavaScript never ran. Syntax checks do not catch either.

    # 1. serve the app (seeded preview database is fine)
    bash scripts/preview.sh

    # 2. capture real API responses
    python tools/ui_check/capture_fixtures.py

    # 3. drive both pages and report
    node tools/ui_check/verify.mjs /tmp/vt/fixtures.json

Requires `node` and `npm install jsdom` in the directory you run it from.

What it asserts:

| Dashboard | Checks |
|---|---|
| `/intel` | every tab click loads without error, the Analytics tab renders 7 heat rows x 24 hour cells, at least one SVG chart, populated "most frequent" and per-person tables |
| `/` (classic) | History and People sections exist in the nav, History renders day groups + timeline entries with 12-hour times and URLs, the most-used tab renders bars, the People panel renders assignment dropdowns, and the strip pills appear |
