@echo off
setlocal

set "DISTRO=kali-linux"
set "PROJECT_DIR=/mnt/c/Users/gufroni/Documents/GitHub/redteam-console"

wsl -d %DISTRO% bash -lc "cd %PROJECT_DIR% && chmod +x start-console.sh stop-console.sh && ./start-console.sh"

if errorlevel 1 (
  echo.
  echo Console gagal dijalankan. Cek output di atas.
  exit /b 1
)

echo.
echo Console siap di http://localhost:4080
exit /b 0
