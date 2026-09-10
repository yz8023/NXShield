#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[NXShield] root: ${ROOT}"

if ! python3 -c "import fastapi" >/dev/null 2>&1; then
  echo "[NXShield] installing backend dependencies..."
  pip install --break-system-packages -q -r "${ROOT}/backend/requirements.txt"
fi

if [ ! -d "${ROOT}/frontend/node_modules" ]; then
  echo "[NXShield] installing frontend dependencies..."
  (cd "${ROOT}/frontend" && npm install)
fi

cleanup() {
  if [ -n "${BACKEND_PID:-}" ]; then
    kill "${BACKEND_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[NXShield] starting backend on :8000"
(cd "${ROOT}/backend" && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000) &
BACKEND_PID=$!

sleep 2
echo "[NXShield] starting frontend on :5173"
(cd "${ROOT}/frontend" && npm run dev)
