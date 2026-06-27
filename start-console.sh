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
PYTHON_BIN="$VENV_DIR/bin/python"

mkdir -p "$RUNTIME_DIR"
touch "$LOG_FILE"

cleanup_stale_pid() {
  if [[ -f "$PID_FILE" ]]; then
    local existing_pid
    existing_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "Console sudah berjalan dengan PID $existing_pid"
      echo "Buka http://localhost:$PORT"
      exit 0
    fi
    rm -f "$PID_FILE"
  fi
}

port_in_use_by_other_process() {
  ss -ltnp 2>/dev/null | grep -q ":$PORT "
}

resolve_server_pid() {
  pgrep -n -f "$PYTHON_BIN -m uvicorn backend.main:app --host $HOST --port $PORT" 2>/dev/null || true
}

cleanup_stale_pid
sleep 1
cleanup_stale_pid

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 tidak ditemukan di Kali WSL."
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Virtual environment tidak valid. Hapus .venv lalu jalankan ulang."
  exit 1
fi

if ! "$PYTHON_BIN" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  "$PYTHON_BIN" -m pip install -r "$ROOT_DIR/requirements.txt"
fi

if port_in_use_by_other_process; then
  echo "Port $PORT sudah dipakai proses lain."
  echo "Jalankan stop-console terlebih dahulu atau hentikan proses yang memakai port tersebut."
  ss -ltnp 2>/dev/null | grep ":$PORT " || true
  exit 1
fi

cd "$ROOT_DIR"
# Jalankan uvicorn dalam session baru agar tetap hidup setelah shell WSL selesai.
setsid "$PYTHON_BIN" -m uvicorn backend.main:app --host "$HOST" --port "$PORT" >>"$LOG_FILE" 2>&1 < /dev/null &
LAUNCH_PID=$!
disown "$LAUNCH_PID" 2>/dev/null || true
sync || true

SERVER_PID=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if port_in_use_by_other_process; then
    SERVER_PID="$(resolve_server_pid)"
    if [[ -z "$SERVER_PID" ]] && kill -0 "$LAUNCH_PID" 2>/dev/null; then
      SERVER_PID="$LAUNCH_PID"
    fi
    if [[ -n "$SERVER_PID" ]]; then
      echo "$SERVER_PID" >"$PID_FILE"
      break
    fi
  fi
  sleep 1
done

if [[ -n "$SERVER_PID" ]] && port_in_use_by_other_process; then
  echo "Console berhasil dijalankan."
  echo "PID   : $SERVER_PID"
  echo "Log   : $LOG_FILE"
  echo "URL   : http://localhost:$PORT"
  exit 0
fi

rm -f "$PID_FILE"
echo "Gagal menjalankan console. Cek log di $LOG_FILE"
exit 1
