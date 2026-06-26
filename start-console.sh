#!/usr/bin/env bash
set -euo pipefail

# Launcher backend untuk repo redteam-console di WSL.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
RUNTIME_DIR="$ROOT_DIR/.runtime"
PID_FILE="$RUNTIME_DIR/console.pid"
LOG_FILE="$RUNTIME_DIR/console.log"
PORT="${PORT:-4080}"
HOST="${HOST:-0.0.0.0}"

mkdir -p "$RUNTIME_DIR"

if [[ -f "$PID_FILE" ]]; then
  EXISTING_PID="$(cat "$PID_FILE")"
  if [[ -n "$EXISTING_PID" ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
    echo "Console sudah berjalan dengan PID $EXISTING_PID"
    echo "Buka http://localhost:$PORT"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 tidak ditemukan di Kali WSL."
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  pip install -r "$ROOT_DIR/requirements.txt"
fi

cd "$ROOT_DIR"
nohup python -m uvicorn backend.main:app --host "$HOST" --port "$PORT" --reload >>"$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" >"$PID_FILE"

sleep 2

if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Console berhasil dijalankan."
  echo "PID   : $SERVER_PID"
  echo "Log   : $LOG_FILE"
  echo "URL   : http://localhost:$PORT"
  exit 0
fi

echo "Gagal menjalankan console. Cek log di $LOG_FILE"
exit 1
