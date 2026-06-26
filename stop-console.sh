#!/usr/bin/env bash
set -euo pipefail

# Stopper backend untuk repo redteam-console di WSL.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$ROOT_DIR/.runtime/console.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "Tidak ada PID file. Console kemungkinan sudah berhenti."
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
  sleep 1
  echo "Menghentikan console dengan PID $PID"
else
  echo "Proses PID $PID tidak aktif."
fi

rm -f "$PID_FILE"
