#!/usr/bin/env bash
#
# Start the dashboard with a simulated household, so the parental views
# (People & calendar, Alerts, Searches, Games) render with content even when
# the collector is not on a network.  Safe to run on any machine: it uses a
# throwaway database and never touches src/database/enhanced_network_monitor.db.
#
#   ./scripts/preview.sh            # set up + serve on 0.0.0.0:5002
#   ./scripts/preview.sh --seed     # only (re)build the preview database
#   PORT=5003 ./scripts/preview.sh  # serve somewhere else
#
# On the collector you do NOT want this - run `python -m src.main` instead, so
# real capture and the real database are used.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
VENV="${VENV:-$ROOT/.venv}"
PY="$VENV/bin/python"
DB_URI="sqlite:///$ROOT/src/database/preview.db"
PORT="${PORT:-5002}"

packages=(
  "Flask==3.1.1" "Flask-SQLAlchemy==3.1.1" "flask-cors" "tldextract"
  "manuf" "dnspython" "requests" "scapy"
)

if [ ! -x "$PY" ]; then
  echo "== creating virtualenv in $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --disable-pip-version-check "${packages[@]}"
  echo "   installed: ${packages[*]}"
fi

echo "== building preview database ($DB_URI)"
rm -f "$ROOT/src/database/preview.db"
NETSCANNER_DB_URI="$DB_URI" NETSCANNER_INTEL_CAPTURE=0 \
  "$PY" scripts/demo_scenario.py > /dev/null

if [ "${1:-}" = "--seed" ]; then
  echo "== seeded; not starting the server (--seed)"
  exit 0
fi

echo "== serving on http://0.0.0.0:$PORT   (dashboard: /intel)"
exec env NETSCANNER_DB_URI="$DB_URI" NETSCANNER_INTEL_CAPTURE=0 \
     HOST=0.0.0.0 PORT="$PORT" "$PY" -m src.main
