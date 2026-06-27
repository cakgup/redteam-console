#!/usr/bin/env bash
set -euo pipefail

# Stopper backend untuk repo redteam-console di WSL.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.runtime/console.pid"
PORT="${PORT:-4080}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Tidak ada PID file. Mencoba menghentikan proses uvicorn pada port $PORT."
  pkill -f "uvicorn backend.main:app --host 0.0.0.0 --port $PORT" 2>/dev/null || true
  exit 0
fi

PID="$(cat "$PID_FILE")"
if [[ -z "$PID" ]]; then
  rm -f "$PID_FILE"
  echo "PID file kosong dan sudah dibersihkan."
  exit 0
fi

if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  for _ in 1 2 3 4 5; do
    if ! kill -0 "$PID" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if kill -0 "$PID" 2>/dev/null; then
    kill -9 "$PID" 2>/dev/null || true
  fi
  echo "Menghentikan console dengan PID $PID"
else
  echo "Proses PID $PID tidak aktif."
fi

pkill -f "uvicorn backend.main:app --host 0.0.0.0 --port $PORT" 2>/dev/null || true
rm -f "$PID_FILE"
sync || true
sleep 1
