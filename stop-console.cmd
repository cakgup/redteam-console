@echo off
setlocal

set "DISTRO=kali-linux"
set "PROJECT_DIR=/mnt/c/Users/gufroni/Documents/GitHub/redteam-console"

wsl -d %DISTRO% bash -lc "cd %PROJECT_DIR% && ./stop-console.sh"
