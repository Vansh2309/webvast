#!/usr/bin/env bash
# Convenience launcher for WebVAST (development).
# Starts: the bundled vulnerable demo target (:5001), the API (:8000),
# and the React dashboard (:5173). Ctrl-C stops all three.
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

cd "$ROOT/backend"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  . .venv/bin/activate
  pip install -q -r requirements.txt
else
  . .venv/bin/activate
fi

echo "→ starting vulnerable demo target on http://localhost:5001"
python demo_target/app.py >/tmp/webvast_demo.log 2>&1 &
DEMO=$!

echo "→ starting API on http://localhost:8000"
uvicorn app.main:app --port 8000 >/tmp/webvast_api.log 2>&1 &
API=$!

cd "$ROOT/frontend"
[ -d node_modules ] || npm install
echo "→ starting dashboard on http://localhost:5173"
npm run dev &
WEB=$!

trap 'echo; echo "stopping…"; kill $DEMO $API $WEB 2>/dev/null; exit 0' INT TERM
echo
echo "WebVAST is up. Open http://localhost:5173  (Ctrl-C to stop everything)"
wait
