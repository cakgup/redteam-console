from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import ssl
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.assets import ASSETS, asset_map, serialize_asset
from backend.catalog import MODULES, module_map, module_playbook
from backend.lab_config import load_lab_config, save_lab_config
from backend.store import JobStore
from backend.workflow import ENGAGEMENTS, FINDINGS, parse_import


BASE_DIR = Path(__file__).resolve().parent.parent
APP_DB = BASE_DIR / "backend" / "data" / "console.db"
LAB_CONFIG = load_lab_config()
ALLOWED_SUBNET_STRINGS = tuple(LAB_CONFIG["allowed_subnets"])
LAB_PROFILES = tuple(LAB_CONFIG["lab_profiles"])
LAB_CONFIG_SOURCE = str(LAB_CONFIG["source"])
LAB_CONFIG_PATH = str(LAB_CONFIG["path"])
ALLOWED_SUBNETS = tuple(ipaddress.ip_network(cidr) for cidr in ALLOWED_SUBNET_STRINGS)
EXECUTION_MODE = "simulation-only"
JOB_HEARTBEAT_TIMEOUT_SECONDS = 30
LIVE_SAFE_MODULE_IDS = {
    "recon-service-scan",
    "recon-host-discovery",
    "recon-dns-enumeration",
    "baseline-web-fingerprint",
    "baseline-content-discovery",
    "baseline-tls-dns-review",
}
JOB_STORE = JobStore(APP_DB)
MODULE_BY_ID = module_map()
ASSET_BY_IP = asset_map()
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

app = FastAPI(title="Authorized Lab Emulation Console")
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")


class JobRequest(BaseModel):
    target: str = Field(..., examples=["10.10.10.20"])
    note: str = Field(default="", max_length=160)


class ModuleJobRequest(JobRequest):
    module_id: str


class ImportRequest(BaseModel):
    tool_name: str = Field(default="generic")
    target: str = Field(..., examples=["10.10.10.20"])
    content: str = Field(default="")


class ConfigUpdateRequest(BaseModel):
    allowed_subnets: list[str] = Field(default_factory=list)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def apply_lab_config(config: dict[str, Any]) -> None:
    global LAB_CONFIG, ALLOWED_SUBNET_STRINGS, LAB_PROFILES, LAB_CONFIG_SOURCE, LAB_CONFIG_PATH, ALLOWED_SUBNETS
    subnet_strings = tuple(str(item).strip() for item in config["allowed_subnets"])
    subnet_networks: list[ipaddress._BaseNetwork] = []
    for cidr in subnet_strings:
        try:
            subnet_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as error:
            raise HTTPException(status_code=400, detail=f"Subnet tidak valid: {cidr}") from error

    LAB_CONFIG = config
    ALLOWED_SUBNET_STRINGS = subnet_strings
    LAB_PROFILES = tuple(config["lab_profiles"])
    LAB_CONFIG_SOURCE = str(config["source"])
    LAB_CONFIG_PATH = str(config["path"])
    ALLOWED_SUBNETS = tuple(subnet_networks)


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


def module_execution_profile(module_id: str) -> str:
    return "live-safe-adapter" if module_id in LIVE_SAFE_MODULE_IDS else "simulation-only"


TOOL_COMMAND_ALIASES: dict[str, list[str] | None] = {
    "nmap": ["nmap"],
    "dnsx": ["dnsx"],
    "httpx": ["httpx"],
    "nuclei": ["nuclei"],
    "whatweb": ["whatweb"],
    "curl": ["curl"],
    "ffuf-safe": ["ffuf"],
    "sqlmap-safe": ["sqlmap"],
    "sha256sum": ["sha256sum"],
    "file": ["file"],
    "yara": ["yara"],
    "swaks": ["swaks"],
    "mailparser": ["mailparser", "eml-parser", "eml_parser"],
    "urlscan": ["urlscan"],
    "mitmproxy": ["mitmproxy"],
    "burpsuite": ["burpsuite"],
    "jq": ["jq"],
    "hydra-lab": ["hydra"],
    "autoruns": ["autoruns"],
    "schtasks": ["schtasks"],
    "crontab": ["crontab"],
    "systemctl": ["systemctl"],
    "zeek": ["zeek"],
    "tcpdump": ["tcpdump"],
    "suricata": ["suricata"],
    "proxychains": ["proxychains4", "proxychains"],
    "bloodhound-lab": ["bloodhound"],
    "graphviz": ["dot"],
    "pandoc": ["pandoc"],
    "wireshark": ["wireshark"],
    "responder-lab": ["responder"],
    "openssl": ["openssl"],
    "dig": ["dig"],
    "sslyze": ["sslyze"],
    "chisel-lab": ["chisel"],
    "strings": ["strings"],
    "jwt-tool": ["jwt-tool", "jwt"],
    "ssh -D": ["ssh"],
    "sigma": None,
    "sysmon review": None,
    "markdown": None,
    "otp review": None,
}

UNMODELED_WSL_TOOLS: tuple[dict[str, str], ...] = (
    {
        "label": "amass",
        "command": "amass",
        "phase_id": "recon",
        "phase_label": "Reconnaissance",
        "rationale": "asset and subdomain expansion for lab scoping",
    },
    {
        "label": "nikto",
        "command": "nikto",
        "phase_id": "baseline",
        "phase_label": "Baseline Assessment",
        "rationale": "web misconfiguration and known exposure review",
    },
    {
        "label": "gobuster",
        "command": "gobuster",
        "phase_id": "baseline",
        "phase_label": "Baseline Assessment",
        "rationale": "content and route discovery on approved targets",
    },
    {
        "label": "hashcat",
        "command": "hashcat",
        "phase_id": "objective",
        "phase_label": "Actions on Objectives",
        "rationale": "offline credential exposure impact simulation",
    },
    {
        "label": "john",
        "command": "john",
        "phase_id": "objective",
        "phase_label": "Actions on Objectives",
        "rationale": "offline password review for credential impact workflows",
    },
)


def tool_status(label: str) -> dict[str, Any]:
    commands = TOOL_COMMAND_ALIASES.get(label, [label])
    if commands is None:
        return {"label": label, "kind": "conceptual", "installed": None, "command": None}

    for command in commands:
        if shutil.which(command):
            return {"label": label, "kind": "binary", "installed": True, "command": command}
    return {"label": label, "kind": "binary", "installed": False, "command": commands[0]}


def tooling_coverage_payload() -> dict[str, Any]:
    module_tools: dict[str, dict[str, Any]] = {}
    represented_commands: set[str] = set()

    for module in MODULES:
        for label in module_playbook(module).tooling:
            if label not in module_tools:
                status = tool_status(label)
                module_tools[label] = {**status, "modules": []}
                if status.get("command"):
                    represented_commands.add(str(status["command"]))
            module_tools[label]["modules"].append(module.title)

    uncovered_installed: list[dict[str, Any]] = []
    for item in UNMODELED_WSL_TOOLS:
        if shutil.which(item["command"]) and item["command"] not in represented_commands:
            uncovered_installed.append(dict(item))

    missing_module_tools = [
        item for item in module_tools.values()
        if item["kind"] == "binary" and item["installed"] is False
    ]

    return {
        "module_tools": sorted(module_tools.values(), key=lambda item: str(item["label"]).lower()),
        "missing_module_tools": sorted(missing_module_tools, key=lambda item: str(item["label"]).lower()),
        "uncovered_installed": uncovered_installed,
    }


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
    }


def normalize_command_target_backend(command: str, target: str) -> str:
    safe_target = str(target).strip()
    if not safe_target:
        return str(command)
    return (
        str(command)
        .replace("https://lab.local", f"https://{safe_target}")
        .replace("http://lab.local", f"http://{safe_target}")
        .replace("ssh://target", f"ssh://{safe_target}")
        .replace("target:443", f"{safe_target}:443")
        .replace("TARGET/page", f"{safe_target}/page")
        .replace("TARGET", safe_target)
        .replace(" lab.local ", f" {safe_target} ")
        .replace("-d lab.local", f"-d {safe_target}")
        .replace(" lab.local]", f" {safe_target}]")
        .replace(" lab.local", f" {safe_target}")
    )


def collect_module_commands(module, target: str, note: str) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for event in module_runtime_events(module, target, note):
        if event.get("kind") == "log":
            message = str(event.get("message") or "").strip()
            if message.startswith("$ "):
                normalized = normalize_command_target_backend(message, target)
                if normalized not in seen:
                    seen.add(normalized)
                    commands.append(normalized)
        elif event.get("kind") == "evidence":
            artifacts = event.get("artifacts") or {}
            refs: list[str] = []
            reference_cmd = artifacts.get("reference_cmd")
            if isinstance(reference_cmd, str) and reference_cmd.strip():
                refs.append(reference_cmd.strip())
            reference_cmds = artifacts.get("reference_cmds")
            if isinstance(reference_cmds, list):
                refs.extend(str(item).strip() for item in reference_cmds if str(item).strip())
            for ref in refs:
                normalized = normalize_command_target_backend(f"$ {ref}", target)
                if normalized not in seen:
                    seen.add(normalized)
                    commands.append(normalized)
    return commands


def module_dry_run_payload(module, target: str, note: str) -> dict[str, Any]:
    playbook = module_playbook(module)
    return {
        "module_id": module.id,
        "title": module.title,
        "phase_label": module.phase_label,
        "target": target,
        "execution_profile": module_execution_profile(module.id),
        "commands": collect_module_commands(module, target, note),
        "tooling": list(playbook.tooling),
        "allowed_checks": list(playbook.allowed_checks),
        "notes": list(module.preview),
    }


def lookup_asset(target: str) -> dict[str, str] | None:
    asset = ASSET_BY_IP.get(target)
    return serialize_asset(asset) if asset else None


def blank_severity_summary() -> dict[str, int]:
    return {"info": 0, "low": 0, "medium": 0, "high": 0}


def make_log(message: str, severity: str = "info", timestamp: str | None = None) -> dict[str, str]:
    return {
        "timestamp": timestamp or now_iso(),
        "severity": severity,
        "message": message,
    }


def create_job(scope_type: str, scope_label: str, target: str, note: str, module_ids: list[str]) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    created_at = now_iso()
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
            make_log(f"Scope          : {scope_label}"),
            make_log(f"Target         : {target}"),
            make_log(f"Execution mode : {EXECUTION_MODE}"),
            make_log("Guardrail      : no raw command input accepted."),
            make_log(f"Module count   : {len(module_ids)}"),
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
                "execution_profile": module_execution_profile(module_id),
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
    job = JOB_STORE.get_job(job_id)
    if not job:
        return

    logs = [*job["logs"], make_log(message, severity=severity)]
    JOB_STORE.update_job(
        job_id,
        status=status,
        progress=job["progress"] if progress is None else progress,
        logs=logs,
        updated_at=now_iso(),
    )


def update_module_run(job_id: str, module_id: str, **changes: Any) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return

    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        if run["module_id"] == module_id:
            updated_runs.append({**run, **changes})
        else:
            updated_runs.append(run)

    JOB_STORE.update_job(
        job_id,
        module_runs=updated_runs,
        updated_at=now_iso(),
    )


def add_evidence(job_id: str, item: dict[str, Any]) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return

    evidence = [*job["evidence"], item]
    severity_summary = {**job["severity_summary"]}
    severity = str(item.get("severity") or "info")
    severity_summary[severity] = int(severity_summary.get(severity, 0)) + 1

    JOB_STORE.update_job(
        job_id,
        severity_summary=severity_summary,
        evidence=evidence,
        updated_at=now_iso(),
    )


def update_progress(job_id: str, value: int) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return
    JOB_STORE.update_job(job_id, progress=max(0, min(100, value)), updated_at=now_iso())


def parse_iso_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def mark_job_stalled(job: dict[str, Any]) -> dict[str, Any]:
    if str(job.get("status")) not in {"pending", "running"}:
        return job

    updated_at = parse_iso_timestamp(str(job.get("updated_at", "")))
    if not updated_at:
        return job

    age_seconds = (datetime.now(timezone.utc) - updated_at.astimezone(timezone.utc)).total_seconds()
    if age_seconds < JOB_HEARTBEAT_TIMEOUT_SECONDS:
        return job

    logs = list(job.get("logs") or [])
    stall_message = "Worker heartbeat stale. Job marked as stalled; inspect latest command or rerun the assessment."
    if not any(str(entry.get("message", "")) == stall_message for entry in logs):
        logs.append(make_log(stall_message, severity="high"))

    updated_runs: list[dict[str, Any]] = []
    for run in job.get("module_runs") or []:
        if str(run.get("status")) == "running":
            updated_runs.append({**run, "status": "stalled"})
        else:
            updated_runs.append(run)

    JOB_STORE.update_job(
        job["id"],
        status="stalled",
        logs=logs,
        module_runs=updated_runs,
        updated_at=now_iso(),
    )
    return JOB_STORE.get_job(job["id"]) or {**job, "status": "stalled", "logs": logs, "module_runs": updated_runs}


def hydrate_job(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if not job:
        return None
    return mark_job_stalled(job)


def fail_job(job_id: str, reason: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return

    logs = [*job["logs"], make_log(reason, severity="high")]
    updated_runs: list[dict[str, Any]] = []
    for run in job["module_runs"]:
        if str(run.get("status")) == "running":
            updated_runs.append({**run, "status": "failed", "highest_severity": "high", "completed_at": now_iso()})
        else:
            updated_runs.append(run)

    JOB_STORE.update_job(
        job_id,
        status="failed",
        logs=logs,
        module_runs=updated_runs,
        updated_at=now_iso(),
    )


def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def request_url(url: str, *, timeout: float = 1.2, context: ssl.SSLContext | None = None) -> tuple[int | None, dict[str, str], str]:
    request = urllib.request.Request(url, headers={"User-Agent": "AuthorizedLabConsole/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2048).decode("utf-8", errors="ignore")
            return int(response.status), dict(response.headers.items()), body
    except urllib.error.HTTPError as error:
        body = error.read(1024).decode("utf-8", errors="ignore")
        return int(error.code), dict(error.headers.items()), body
    except Exception:
        return None, {}, ""


def title_from_html(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start >= 0 and end > start:
        return html[start + 7:end].strip()
    return ""


def port_service_label(port: int) -> str:
    return {
        21: "ftp",
        22: "ssh",
        53: "domain",
        80: "http",
        443: "https",
        3306: "mysql",
        8080: "http-proxy",
        8443: "https-alt",
    }.get(port, "unknown")


def port_version_hint(port: int) -> str:
    return {
        21: "vsftpd 3.0.x",
        22: "OpenSSH 8.x",
        53: "resolver",
        80: "Apache httpd 2.4.x",
        443: "nginx/Apache TLS endpoint",
        3306: "MySQL 8.x",
        8080: "Jetty/Tomcat alt-http",
        8443: "TLS admin portal",
    }.get(port, "unknown")


def simulated_nse_findings(target: str, open_ports: list[int]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if 22 in open_ports:
        findings.extend(
            [
                {"severity": "low", "script": "ssh-hostkey", "line": "| ssh-hostkey: "},
                {"severity": "low", "script": "ssh-hostkey", "line": "|   3072 3b:17:4d:91:aa:54:72:10:ab:4c:7f:12:4e:91:dc:10 (RSA)"},
                {"severity": "low", "script": "ssh-hostkey", "line": "|   256 7f:8b:2a:14:9e:2c:cb:82:e2:77:5f:11:44:9a:7c:02 (ECDSA)"},
                {"severity": "low", "script": "ssh-hostkey", "line": "|_  256 d4:1e:55:2a:80:21:c6:90:35:1d:ee:90:4f:0a:11:72 (ED25519)"},
                {"severity": "medium", "script": "ssh2-enum-algos", "finding": "Legacy MAC preference order still includes broad compatibility set", "line": "|_ssh2-enum-algos: diffie-hellman-group14-sha1 still accepted in staged profile"},
            ]
        )
    if 80 in open_ports:
        findings.extend(
            [
                {"severity": "low", "script": "http-title", "finding": "Login surface exposed on primary web root", "line": "| http-title: Admin Portal"},
                {"severity": "low", "script": "http-title", "line": "|_Requested resource was /login"},
                {"severity": "medium", "script": "http-headers", "finding": "Missing hardening headers on primary HTTP endpoint", "line": "| http-headers: "},
                {"severity": "low", "script": "http-server-header", "finding": "Verbose server banner discloses stack family", "line": "|   Server: Apache/2.4.x"},
                {"severity": "low", "script": "http-generator", "finding": "Framework metadata leaks implementation detail", "line": "|   X-Powered-By: PHP/8.x"},
                {"severity": "medium", "script": "http-security-headers", "finding": "Missing X-Frame-Options and X-Content-Type-Options", "line": "|_  Missing hardening headers: X-Frame-Options, X-Content-Type-Options"},
                {"severity": "medium", "script": "http-enum", "finding": "Interesting admin and backup routes observed in bounded wordlist set", "line": "|_http-enum: /admin, /backup, /uploads"},
            ]
        )
    if 443 in open_ports:
        findings.extend(
            [
                {"severity": "low", "script": "ssl-cert", "finding": "TLS certificate CN exposed for primary HTTPS endpoint", "line": "| ssl-cert: Subject: commonName=lab-web.internal"},
                {"severity": "low", "script": "ssl-cert", "line": "| Subject Alternative Name: DNS:lab-web.internal, DNS:app.lab.local"},
                {"severity": "medium", "script": "ssl-cert", "finding": "Certificate issuer indicates internal CA trust boundary", "line": "| Issuer: commonName=Lab-Internal-CA"},
                {"severity": "low", "script": "ssl-cert", "line": "| Not valid before: 2026-01-10T00:00:00"},
                {"severity": "low", "script": "ssl-cert", "line": "|_Not valid after:  2027-01-10T23:59:59"},
                {"severity": "low", "script": "tls-alpn", "finding": "HTTP/2 enabled on HTTPS service", "line": "| tls-alpn: "},
                {"severity": "low", "script": "tls-alpn", "line": "|   h2"},
                {"severity": "low", "script": "tls-alpn", "line": "|_  http/1.1"},
                {"severity": "medium", "script": "ssl-enum-ciphers", "finding": "TLS profile still allows mixed-strength compatibility posture", "line": "|_ssl-enum-ciphers: TLSv1.2 accepted; modern + compatibility cipher mix observed"},
            ]
        )
    if 8080 in open_ports:
        findings.extend(
            [
                {"severity": "medium", "script": "http-title", "finding": "Administrative application exposed on alternate HTTP port", "line": "| http-title: Jenkins"},
                {"severity": "high", "script": "http-auth-finder", "finding": "Administrative auth surface exposed on alternate port", "line": "|_http-auth-finder: /manage uses form-based authentication on alternate port"},
                {"severity": "medium", "script": "http-server-header", "finding": "Alternate port leaks Jetty/Tomcat style banner metadata", "line": "|_http-server-header: Jetty/Tomcat alt-http"},
            ]
        )
    if 8443 in open_ports:
        findings.extend(
            [
                {"severity": "high", "script": "ssl-cert", "finding": "Administrative TLS endpoint certificate mismatches observed vhost set", "line": "| ssl-cert: Subject: commonName=admin.lab.local"},
                {"severity": "high", "script": "ssl-cert", "finding": "SAN coverage gap may expose alternate admin/API naming", "line": "|_SAN coverage appears narrower than observed admin/api virtual host set"},
                {"severity": "medium", "script": "vulners", "finding": "Banner correlation suggests review candidate for admin stack patch posture", "line": "|_vulners: simulated review candidate mapped from Jetty/Tomcat + admin TLS exposure"},
            ]
        )
    if findings:
        findings.append({"severity": "info", "script": "nse-summary", "line": "NSE: simulated metadata scripts completed in bounded lab mode."})
    return findings


def safe_service_scan(target: str) -> list[dict[str, Any]]:
    ports = [22, 80, 443, 8080, 8443]
    open_ports: list[int] = []
    port_rows: list[str] = []
    for port in ports:
        try:
            with socket.create_connection((target, port), timeout=0.7):
                open_ports.append(port)
        except OSError:
            continue

    severity = "medium" if any(port in open_ports for port in (8080, 8443)) else "low" if open_ports else "info"
    for port in open_ports:
        port_rows.append(f"{str(port).ljust(8)}/tcp open  {port_service_label(port).ljust(11)} {port_version_hint(port)}")
    nse_lines = simulated_nse_findings(target, open_ports)
    active_scripts: list[str] = []
    if 22 in open_ports:
        active_scripts.extend(["ssh-hostkey", "ssh2-enum-algos"])
    if any(port in open_ports for port in (80, 8080)):
        active_scripts.extend(["http-title", "http-headers", "http-server-header", "http-enum", "http-auth-finder"])
    if any(port in open_ports for port in (443, 8443)):
        active_scripts.extend(["ssl-cert", "tls-alpn", "ssl-enum-ciphers", "vulners"])
    if not active_scripts:
        active_scripts = ["banner"]
    unique_scripts = list(dict.fromkeys(active_scripts))

    cli_lines = [
        "$ nmap -Pn -sV -T4 -p 22,80,443,8080,8443 --version-light "
        f"--script={','.join(unique_scripts)} "
        f"{target}",
        "Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-25 09:14 WIB",
        f"Nmap scan report for {target}",
        "Host is up (live-safe bounded connect probe).",
        "PORT     STATE SERVICE     VERSION",
    ]
    cli_lines.extend(port_rows or ["No open ports observed in bounded port set."])
    cli_lines.extend(item["line"] for item in nse_lines)
    cli_lines.append("Service detection performed in live-safe adapter mode.")

    nse_evidence_lines = [
        f"{item['severity'].upper()} · nmap/{item.get('script', 'nse')} · {item.get('finding', item['line'])}"
        for item in nse_lines
        if item.get("finding")
    ]

    return [
        {
            "kind": "log",
            "severity": "info",
            "message": f"Live-safe adapter active: bounded TCP connect on {ports}.",
        },
        *[
            {
                "kind": "log",
                "severity": (
                    "info"
                    if index < 5
                    else next((item["severity"] for item in nse_lines if item["line"] == line), severity)
                ),
                "message": line,
            }
            for index, line in enumerate(cli_lines)
        ],
        {
            "kind": "log",
            "severity": severity,
            "message": f"Observed open ports on {target}: {open_ports or ['none observed']}.",
        },
        {
            "kind": "evidence",
            "severity": severity,
            "summary": "Bounded service snapshot",
            "details": [
                f"Open ports detected: {', '.join(map(str, open_ports)) or 'none'}",
                f"Service hints: {', '.join(port_service_label(port) for port in open_ports) or 'none'}",
                *port_rows[:4],
                *nse_evidence_lines[:6],
            ],
            "artifacts": {
                "open_ports": open_ports,
                "checked_ports": ports,
                "nse_scripts": unique_scripts,
                "nse_findings": [item["line"] for item in nse_lines],
                "nse_findings_structured": nse_lines,
            },
        },
    ]


def safe_host_discovery(target: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "kind": "log",
            "severity": "info",
            "message": "Live-safe adapter active: reverse DNS and reachability hints for the selected target only.",
        },
        {
            "kind": "log",
            "severity": "info",
            "message": f"$ nmap -sn -n {target}",
        },
        {
            "kind": "log",
            "severity": "info",
            "message": "Starting Nmap 7.99 ( https://nmap.org ) host discovery replay.",
        },
        {
            "kind": "log",
            "severity": "info",
            "message": f"Nmap scan report for {target}",
        },
        {
            "kind": "log",
            "severity": "info",
            "message": "Host is up.",
        },
    ]
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(target)
        details = [f"Primary name={hostname}", f"Aliases={aliases or ['none']}", f"Addresses={addresses or [target]}"]
        events.append({"kind": "log", "severity": "low", "message": f"Reverse DNS resolved to {hostname}."})
        events.append(
            {
                "kind": "evidence",
                "severity": "low",
                "summary": "Reverse DNS and target identity snapshot",
                "details": details,
                "artifacts": {"hostname": hostname, "aliases": aliases, "addresses": addresses},
            }
        )
    except OSError:
        events.append({"kind": "log", "severity": "info", "message": "Reverse DNS did not return a hostname for this target."})
        events.append(
            {
                "kind": "evidence",
                "severity": "info",
                "summary": "Reverse DNS unavailable",
                "details": ["No PTR-style identity data available from bounded lookup."],
                "artifacts": {"hostname": None},
            }
        )
    return events


def safe_dns_enumeration(target: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "kind": "log",
            "severity": "info",
            "message": "Live-safe adapter active: bounded forward/reverse resolution hints for the target only.",
        }
    ]
    try:
        fqdn = socket.getfqdn(target)
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(target, None)})
        events.append({"kind": "log", "severity": "low", "message": f"FQDN hint resolved as {fqdn}."})
        events.append(
            {
                "kind": "evidence",
                "severity": "low",
                "summary": "DNS resolution hint set",
                "details": [f"FQDN={fqdn}", f"Address candidates={addresses or [target]}"],
                "artifacts": {"fqdn": fqdn, "addresses": addresses},
            }
        )
    except OSError:
        events.append({"kind": "log", "severity": "info", "message": "Forward lookup did not return additional DNS hints."})
        events.append(
            {
                "kind": "evidence",
                "severity": "info",
                "summary": "DNS resolution hints unavailable",
                "details": ["No additional bounded DNS data available from the current lab state."],
                "artifacts": {"fqdn": None},
            }
        )
    return events


def safe_web_fingerprint(target: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "kind": "log",
            "severity": "info",
            "message": "Live-safe adapter active: HTTP/HTTPS metadata probe with 2KB response cap.",
        }
    ]
    findings: list[str] = []
    missing_headers: set[str] = set()
    highest = "info"

    for scheme in ("http", "https"):
        context = ssl._create_unverified_context() if scheme == "https" else None
        status, headers, body = request_url(f"{scheme}://{target}", context=context)
        if status is None:
            events.append(
                {"kind": "log", "severity": "info", "message": f"{scheme.upper()} probe unavailable or timed out."}
            )
            continue
        server = headers.get("Server", "unknown")
        title = title_from_html(body) or "no-title"
        findings.append(f"{scheme.upper()} status={status}, server={server}, title={title}")
        for header_name in ("X-Frame-Options", "X-Content-Type-Options"):
            if header_name not in headers:
                missing_headers.add(header_name)
        sev = "low" if server != "unknown" else "info"
        if missing_headers:
            sev = severity_max(sev, "medium")
        highest = severity_max(highest, sev)
        events.append(
            {"kind": "log", "severity": sev, "message": f"{scheme.upper()} responded with status {status}; server={server}; title={title}."}
        )

    if findings:
        detail_lines = [*findings]
        if missing_headers:
            detail_lines.append(f"Missing hardening headers: {', '.join(sorted(missing_headers))}")
        events.append(
            {
                "kind": "evidence",
                "severity": highest,
                "summary": "Web metadata fingerprint",
                "details": detail_lines,
                "artifacts": {"findings": findings, "missing_headers": sorted(missing_headers)},
            }
        )
    return events


def safe_content_discovery(target: str) -> list[dict[str, Any]]:
    paths = ["/", "/login", "/admin", "/backup", "/uploads", "/health", "/robots.txt"]
    results: list[str] = []
    exposed_paths: list[str] = []
    highest = "info"
    events: list[dict[str, Any]] = [
        {
            "kind": "log",
            "severity": "info",
            "message": f"Live-safe adapter active: bounded path review on {len(paths)} paths.",
        }
    ]
    events.extend(
        [
            {"kind": "log", "severity": "info", "message": f"$ httpx -u http://{target} -path /,/login,/admin,/backup,/uploads,/health,/robots.txt -silent"},
            {"kind": "log", "severity": "info", "message": "httpx bounded path replay started."},
        ]
    )

    for path in paths:
        status, _, _ = request_url(f"http://{target}{path}")
        if status is None:
            results.append(f"{path} -> timeout/unreachable")
            events.append({"kind": "log", "severity": "info", "message": f"{path} did not respond."})
            continue

        sev = "medium" if path == "/admin" and status == 200 else "low" if status in (200, 302, 403) else "info"
        highest = severity_max(highest, sev)
        results.append(f"{path} -> {status}")
        if path in {"/admin", "/backup", "/uploads"} and status in (200, 302, 403):
            exposed_paths.append(path)
        events.append({"kind": "log", "severity": sev, "message": f"http://{target}{path} [{status}]"})
        events.append({"kind": "log", "severity": sev, "message": f"{path} returned HTTP {status}."})

    detail_lines = [f"Sensitive paths exposed: {', '.join(exposed_paths) if exposed_paths else 'none'}", *results]
    events.append(
        {
            "kind": "evidence",
            "severity": highest,
            "summary": "Bounded content discovery review",
            "details": detail_lines,
            "artifacts": {"path_results": results, "exposed_paths": exposed_paths},
        }
    )
    return events


def safe_tls_review(target: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "kind": "log",
            "severity": "info",
            "message": "Live-safe adapter active: TLS handshake metadata review on port 443.",
        }
    ]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=1.0) as sock:
            with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                cert = secure_sock.getpeercert()
                tls_version = secure_sock.version() or "unknown"
                cipher = secure_sock.cipher()[0] if secure_sock.cipher() else "unknown"
                subject = dict(item[0] for item in cert.get("subject", [])) if cert else {}
                issuer = dict(item[0] for item in cert.get("issuer", [])) if cert else {}
        cn = subject.get("commonName", "unknown")
        issuer_cn = issuer.get("commonName", "unknown")
        events.append({"kind": "log", "severity": "low", "message": f"TLS {tls_version} negotiated with cipher {cipher}."})
        events.append(
            {
                "kind": "evidence",
                "severity": "low",
                "summary": "TLS endpoint metadata",
                "details": [f"Version={tls_version}", f"Cipher={cipher}", f"Subject CN={cn}", f"Issuer CN={issuer_cn}"],
                "artifacts": {
                    "tls_version": tls_version,
                    "cipher": cipher,
                    "subject_common_name": cn,
                    "issuer_common_name": issuer_cn,
                },
            }
        )
    except Exception:
        events.append({"kind": "log", "severity": "info", "message": "TLS metadata could not be collected from port 443."})
        events.append(
            {
                "kind": "evidence",
                "severity": "info",
                "summary": "TLS endpoint metadata unavailable",
                "details": ["Port 443 unreachable or TLS handshake not available in current lab state."],
                "artifacts": {"tls_version": None},
            }
        )
    return events


LIVE_SAFE_ADAPTERS = {
    "recon-service-scan": safe_service_scan,
    "recon-host-discovery": safe_host_discovery,
    "recon-dns-enumeration": safe_dns_enumeration,
    "baseline-web-fingerprint": safe_web_fingerprint,
    "baseline-content-discovery": safe_content_discovery,
    "baseline-tls-dns-review": safe_tls_review,
}


def simulated_phase_lines(module, target: str) -> list[dict[str, Any]]:
    module_specific: dict[str, list[dict[str, Any]]] = {
        "recon-service-scan": [
            {"kind": "log", "severity": "medium", "message": "Aggressive lab simulation: staged metadata-script pass expands fingerprint confidence on approved services only."},
            {"kind": "log", "severity": "medium", "message": f"$ nmap -sC -sV -T4 -A -oA scan_result {target}  [SIMULATED/BOUNDED]"},
            {"kind": "log", "severity": "medium", "message": "Synthetic correlation highlights alternate HTTP title exposure, SSH banner drift, and TLS subject mismatch candidates."},
            {"kind": "evidence", "severity": "medium", "summary": "Enriched service metadata pass", "details": ["Reference profile aligned to nmap -sC -sV -T4 -A style assessment in bounded lab mode.", "Banner, title, and certificate hints correlated across the approved service set."], "artifacts": {"stance": "intrusive-lab", "profile": "nse-enriched-metadata", "reference_cmd": f"nmap -sC -sV -T4 -A -oA scan_result {target}"}},
        ],
        "recon-host-discovery": [
            {"kind": "log", "severity": "info", "message": "Discovery map: gateway, app, db, and monitor nodes staged for tabletop review."},
            {"kind": "evidence", "severity": "low", "summary": "Host discovery snapshot", "details": ["Approved nodes recorded for lab topology review."], "artifacts": {"target": target}},
        ],
        "recon-dns-enumeration": [
            {"kind": "log", "severity": "low", "message": "Synthetic DNS labels prepared: app, admin, api, wazuh."},
            {"kind": "log", "severity": "low", "message": f"$ dnsx -silent -resp -a -ptr -recon {target}"},
            {"kind": "log", "severity": "medium", "message": "$ dnsrecon -d lab.local -a -j evidence/dnsrecon.json  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": "$ dnsenum lab.local | tee evidence/dnsenum.txt  [SIMULATED]"},
            {"kind": "log", "severity": "low", "message": f"{target} [A] app.lab.local"},
            {"kind": "log", "severity": "medium", "message": f"{target} [PTR] admin.lab.local"},
            {"kind": "log", "severity": "low", "message": "api.lab.local [A] same edge as app.lab.local"},
            {"kind": "evidence", "severity": "medium", "summary": "DNS/vhost review", "details": ["Reference commands: dnsrecon -d lab.local -a and dnsenum lab.local", "A records observed: app.lab.local, api.lab.local", "PTR hint: admin.lab.local", "Shared edge observed between admin and api virtual hosts"], "artifacts": {"labels": ["app", "admin", "api", "wazuh"], "records": ["app.lab.local A", "api.lab.local A", "admin.lab.local PTR"], "reference_cmds": ["dnsrecon -d lab.local -a -j evidence/dnsrecon.json", "dnsenum lab.local | tee evidence/dnsenum.txt"]}},
        ],
        "recon-amass-expansion": [
            {"kind": "log", "severity": "medium", "message": "Asset expansion simulation clusters approved domains into app, auth, static, and admin exposure groups."},
            {"kind": "log", "severity": "medium", "message": "$ amass enum -passive -d lab.local"},
            {"kind": "log", "severity": "high", "message": "$ amass enum -d lab.local -o evidence/amass-active.txt  [SIMULATED ACTIVE LAB]"},
            {"kind": "log", "severity": "medium", "message": "amass: discovered app.lab.local, auth.lab.local, admin.lab.local, static.lab.local"},
            {"kind": "log", "severity": "medium", "message": "amass: ASN/edge correlation suggests shared ingress for auth and admin labels"},
            {"kind": "evidence", "severity": "medium", "summary": "Asset surface expansion", "details": ["Reference commands: amass enum -passive -d lab.local and amass enum -d lab.local", "Discovered labels: app.lab.local, auth.lab.local, admin.lab.local, static.lab.local", "Shared ingress cluster: auth.lab.local <-> admin.lab.local", "Candidate backlog labels: docs.lab.local, staging-app.lab.local"], "artifacts": {"labels": ["staging-app", "auth-gateway", "admin-portal", "docs"], "fqdn": ["app.lab.local", "auth.lab.local", "admin.lab.local", "static.lab.local"], "reference_cmds": ["amass enum -passive -d lab.local -o evidence/amass-passive.txt", "amass enum -d lab.local -o evidence/amass-active.txt"]}},
        ],
        "weapon-artifact-review": [
            {"kind": "log", "severity": "medium", "message": "Artifact approval workflow reviewed with chain-of-custody requirement."},
            {"kind": "evidence", "severity": "medium", "summary": "Artifact review checklist", "details": ["Owner, reviewer, and expiration metadata required."], "artifacts": {"workflow": "training-only"}},
        ],
        "weapon-dropper-safety": [
            {"kind": "log", "severity": "medium", "message": "Dropper safety controls remain isolated to lab-only storage boundary."},
            {"kind": "evidence", "severity": "medium", "summary": "Dropper safety notes", "details": ["Checksum registration and quarantine expectations reviewed."], "artifacts": {"storage": "isolated-lab"}},
        ],
        "weapon-defender-view": [
            {"kind": "log", "severity": "low", "message": "Defender telemetry expectations for artifact handling staged for SOC workshop."},
            {"kind": "evidence", "severity": "low", "summary": "Defender-view artifact notes", "details": ["File create, quarantine, and hash enrichment indicators listed."], "artifacts": {"signals": ["file_create", "quarantine", "hash_enrichment"]}},
        ],
        "delivery-email-tabletop": [
            {"kind": "log", "severity": "medium", "message": "Email delivery rehearsal constrained to approved exercise identities; no mail sent."},
            {"kind": "evidence", "severity": "medium", "summary": "Email tabletop", "details": ["Gateway and SOC alert expectations documented."], "artifacts": {"delivery": "tabletop-only"}},
        ],
        "delivery-web-hosting-review": [
            {"kind": "log", "severity": "low", "message": "Web hosting delivery review staged on isolated lab host with monitored teardown."},
            {"kind": "evidence", "severity": "low", "summary": "Hosted delivery notes", "details": ["Cleanup window and teardown checkpoints listed."], "artifacts": {"hosting": "isolated"}},
        ],
        "delivery-responder-awareness": [
            {"kind": "log", "severity": "medium", "message": "Name-resolution abuse awareness scenario mapped to DNS, switch, and EDR telemetry."},
            {"kind": "evidence", "severity": "medium", "summary": "Responder awareness", "details": ["Containment expectations captured for training."], "artifacts": {"focus": "detection"}},
        ],
        "baseline-web-fingerprint": [
            {"kind": "log", "severity": "medium", "message": "$ echo https://lab.local | httpx -status-code -title -tech-detect -tls-probe -o evidence/httpx.txt  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": "$ nuclei -u https://lab.local -severity info,low,medium,high,critical -rl 10 -o evidence/nuclei.txt  [SIMULATED]"},
            {"kind": "log", "severity": "low", "message": "httpx: 200 [Apache] [Admin Portal] [TLS enabled]"},
            {"kind": "log", "severity": "medium", "message": "[http/misconfig/missing-security-headers] [http] [medium] https://lab.local"},
            {"kind": "evidence", "severity": "medium", "summary": "HTTP stack and template fingerprint", "details": ["Reference commands: httpx -status-code -title -tech-detect -tls-probe and nuclei -severity info,low,medium,high,critical", "httpx indicates live title, stack, and TLS posture visibility", "nuclei-style template review highlights missing security headers"], "artifacts": {"reference_cmds": ["echo https://lab.local | httpx -status-code -title -tech-detect -tls-probe -o evidence/httpx.txt", "nuclei -u https://lab.local -severity info,low,medium,high,critical -rl 10 -o evidence/nuclei.txt"], "template_finding": "http/misconfig/missing-security-headers"}},
        ],
        "baseline-content-discovery": [
            {"kind": "log", "severity": "medium", "message": "Assertive lab simulation: bounded route matrix extends into alternate admin, backup, and health surfaces."},
            {"kind": "log", "severity": "medium", "message": "Synthetic path review correlates 200, 302, and 403 drift across primary and alternate ports for validation backlog."},
            {"kind": "log", "severity": "medium", "message": "$ ffuf -u http://lab.local/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -of html -o evidence/ffuf.html  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": f"[http/misconfig/exposed-panels] [http] [medium] http://{target}/admin"},
            {"kind": "evidence", "severity": "medium", "summary": "Expanded route exposure matrix", "details": ["Reference command: ffuf -u http://lab.local/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all", "GET /admin -> 200", "GET /backup -> 200", "GET /uploads -> 200", "[http/misconfig/exposed-panels] [http] [medium] http://target/admin"], "artifacts": {"profile": "approved-path-review", "status_map": ["GET /admin -> 200", "GET /backup -> 200", "GET /uploads -> 200"], "reference_cmd": "ffuf -u http://lab.local/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -of html -o evidence/ffuf.html"}},
        ],
        "baseline-nikto-review": [
            {"kind": "log", "severity": "medium", "message": "Nikto-style simulation highlights default files, weak headers, and verbose error responses on the approved web stack."},
            {"kind": "log", "severity": "medium", "message": "$ nikto -h http://lab.local -output evidence/nikto.txt  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": f"- Nikto v2.5.0/SAFE   Target: http://{target}"},
            {"kind": "log", "severity": "medium", "message": "+ No X-Frame-Options header found"},
            {"kind": "log", "severity": "medium", "message": "+ No X-Content-Type-Options header found"},
            {"kind": "log", "severity": "medium", "message": "+ /robots.txt reveals helper/admin path hints"},
            {"kind": "log", "severity": "low", "message": "+ Retrieved x-powered-by style fingerprint from response metadata"},
            {"kind": "evidence", "severity": "medium", "summary": "Web misconfiguration heuristic review", "details": ["Reference command: nikto -h http://lab.local -output evidence/nikto.txt", "+ No X-Frame-Options header found", "+ No X-Content-Type-Options header found", "+ /robots.txt reveals helper/admin path hints", "+ Banner metadata suggests hardening drift between primary and alternate vhost"], "artifacts": {"signals": ["robots", "headers", "helper-endpoints"], "missing_headers": ["X-Frame-Options", "X-Content-Type-Options"], "reference_cmd": "nikto -h http://lab.local -output evidence/nikto.txt"}},
        ],
        "baseline-gobuster-routes": [
            {"kind": "log", "severity": "medium", "message": "Route expansion simulation surfaces admin, backup, uploads, and legacy-api path families within approved scope."},
            {"kind": "log", "severity": "medium", "message": f"$ gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -k"},
            {"kind": "log", "severity": "medium", "message": "$ gobuster vhost -u http://lab.local -w subdomains.txt  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": f"/admin       (Status: 200) [Size: 1248] [Words: 116]"},
            {"kind": "log", "severity": "medium", "message": f"/backup      (Status: 200) [Size: 932] [Words: 84]"},
            {"kind": "log", "severity": "low", "message": f"/uploads     (Status: 403) [Size: 278] [Words: 24]"},
            {"kind": "log", "severity": "medium", "message": f"/legacy-api  (Status: 302) [Redirect: /api/v1/]"},
            {"kind": "evidence", "severity": "medium", "summary": "Route enumeration review", "details": ["Reference commands: gobuster dir and gobuster vhost", "GET /admin -> 200", "GET /backup -> 200", "GET /uploads -> 403", "GET /legacy-api -> 302", "Interesting status codes: 200=2, 302=1, 403=1"], "artifacts": {"paths": ["/backup", "/uploads", "/admin", "/legacy-api"], "status_map": ["GET /admin -> 200", "GET /backup -> 200", "GET /uploads -> 403", "GET /legacy-api -> 302"], "reference_cmds": ["gobuster dir -u http://lab.local -w /usr/share/wordlists/dirb/common.txt", "gobuster vhost -u http://lab.local -w subdomains.txt"]}},
        ],
        "baseline-tls-dns-review": [
            {"kind": "log", "severity": "low", "message": "TLS posture review enriches handshake data with protocol/cipher and certificate-hygiene hints."},
            {"kind": "log", "severity": "low", "message": f"$ openssl s_client -connect {target}:443 -servername {target}"},
            {"kind": "log", "severity": "low", "message": "Protocol  : TLSv1.2"},
            {"kind": "log", "severity": "low", "message": "Cipher    : ECDHE-RSA-AES256-GCM-SHA384"},
            {"kind": "log", "severity": "medium", "message": "Certificate SAN set appears narrower than observed virtual-host labels"},
            {"kind": "log", "severity": "medium", "message": "$ sslyze --regular target:443"},
            {"kind": "evidence", "severity": "medium", "summary": "TLS and DNS baseline review", "details": ["TLS version negotiated: TLSv1.2", "Cipher suite: ECDHE-RSA-AES256-GCM-SHA384", "Certificate coverage gap: admin/api virtual host not clearly represented in SAN list", "DNS hygiene note: shared ingress concentrates multiple labels behind one edge"], "artifacts": {"protocol": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "san_gap": True}},
        ],
        "exploit-sql-validation": [
            {"kind": "log", "severity": "medium", "message": "Malformed input handling diverges in staged app flow, suggesting validation debt."},
            {"kind": "log", "severity": "high", "message": "Intrusive lab simulation chains stacked parameters, nested encoding, and error-state drift into a single review stream."},
            {"kind": "log", "severity": "high", "message": f"$ sqlmap -u \"http://{target}/page?id=1\" --dbs  [REFERENCE PROFILE]"},
            {"kind": "log", "severity": "high", "message": f"$ sqlmap -u http://{target}/search?q=test --batch --level=2 --risk=1 --technique=BEU"},
            {"kind": "log", "severity": "medium", "message": "sqlmap: heuristic test indicates parameter 'q' may influence backend error branch"},
            {"kind": "log", "severity": "high", "message": "sqlmap: ORDER BY / quote-balance drift suggests injectable-style behavior in lab replay"},
            {"kind": "log", "severity": "info", "message": "Destructive SQLi paths skipped: no enumeration, no write, no stacked query execution."},
            {"kind": "evidence", "severity": "high", "summary": "Input validation drill", "details": ["Reference command adapted from guidance: sqlmap -u \"http://TARGET/page?id=1\" --dbs", "Potentially risky parameter: q", "Observed behavior: quote-balance drift and verbose backend error state", "Likely severity: HIGH if confirmed manually on authorized staging path", "Safety gate: exploitation, data extraction, and write operations intentionally skipped"], "artifacts": {"surface": "login/search", "stance": "intrusive-lab", "parameter": "q", "reference_cmd": "sqlmap -u \"http://TARGET/page?id=1\" --dbs"}},
        ],
        "exploit-auth-control-review": [
            {"kind": "log", "severity": "high", "message": "Synthetic failed-auth threshold would require lockout and SOC escalation."},
            {"kind": "log", "severity": "high", "message": "Intrusive lab simulation escalates through spray-like timing, reset-window abuse, and alternate realm checks without touching real credentials."},
            {"kind": "log", "severity": "high", "message": "$ hydra -L users.txt -P rockyou.txt ssh://target  [SIMULATED POLICY REPLAY ONLY]"},
            {"kind": "log", "severity": "medium", "message": "Observed policy gap: response timing differs between invalid-user and invalid-password states"},
            {"kind": "log", "severity": "high", "message": "Lockout model: warning at 5 attempts, hard lock at 8 attempts, reset window > 15m"},
            {"kind": "log", "severity": "info", "message": "Credential testing disabled: no real usernames, passwords, or login attempts issued from the console."},
            {"kind": "evidence", "severity": "high", "summary": "Auth control review", "details": ["Finding: username enumeration signal via response variance", "Finding: lockout threshold visible but reset window appears too permissive", "Severity: HIGH for auth policy hardening", "Simulation note: hydra-style replay was modeled, not executed against a live login form"], "artifacts": {"thresholds": {"warn": 5, "lockout": 8}, "stance": "intrusive-lab", "username_enum_signal": True}},
        ],
        "exploit-session-review": [
            {"kind": "log", "severity": "medium", "message": "Session workflow remains approval-gated before any future live validation."},
            {"kind": "log", "severity": "high", "message": "Intrusive lab simulation stresses token reuse, idle-timeout drift, and parallel-session collision handling for blue-team rehearsal."},
            {"kind": "log", "severity": "medium", "message": "$ burpsuite  [REFERENCE TOOLING]"},
            {"kind": "log", "severity": "medium", "message": f"$ jwt-tool http://{target}/api/token --analyze  [SIMULATED]"},
            {"kind": "log", "severity": "medium", "message": "jwt-tool: token header advertises alg=HS256 and verbose kid metadata"},
            {"kind": "log", "severity": "high", "message": "Burp-style session diff indicates missing rotation after privilege boundary transition"},
            {"kind": "log", "severity": "medium", "message": "Idle timeout drift observed between UI and API session layers"},
            {"kind": "evidence", "severity": "high", "summary": "Session governance", "details": ["Reference tooling: burpsuite and jwt-tool", "Finding: session token not rotated after privilege change", "Finding: JWT metadata exposes implementation hints via kid/header fields", "Finding: idle timeout drift between browser and API session contexts", "Severity: HIGH for session management review"], "artifacts": {"governance": "approval-gated", "stance": "intrusive-lab", "jwt_alg": "HS256", "rotation_gap": True, "reference_tools": ["burpsuite", "jwt-tool"]}},
        ],
        "install-persistence-checklist": [
            {"kind": "log", "severity": "high", "message": "Persistence families reviewed as conceptual audit items with cleanup obligations."},
            {"kind": "evidence", "severity": "high", "summary": "Persistence checklist", "details": ["Scheduled task, autorun, ssh key, and cron families listed."], "artifacts": {"families": ["scheduled_task", "autorun", "ssh_key", "cron"]}},
        ],
        "install-registry-cron-audit": [
            {"kind": "log", "severity": "high", "message": "Registry and cron audit bundle staged for endpoint/server validation."},
            {"kind": "evidence", "severity": "high", "summary": "Registry and cron audit", "details": ["Residual telemetry suppression must be verified after cleanup."], "artifacts": {"platforms": ["windows", "linux"]}},
        ],
        "install-defender-recovery": [
            {"kind": "log", "severity": "medium", "message": "Recovery readiness requires joint sign-off from defender and system owner."},
            {"kind": "evidence", "severity": "medium", "summary": "Recovery readiness", "details": ["Restart, verification, and user validation checkpoints documented."], "artifacts": {"signoff": "joint"}},
        ],
        "c2-telemetry-review": [
            {"kind": "log", "severity": "high", "message": "Beacon-style telemetry pattern staged for proxy, DNS, and EDR correlation."},
            {"kind": "evidence", "severity": "high", "summary": "C2 telemetry review", "details": ["90-second jittered callback pattern documented."], "artifacts": {"interval": "90s+jitter"}},
        ],
        "c2-tunnel-governance": [
            {"kind": "log", "severity": "high", "message": "Tunnel lifecycle review highlights teardown and residual route validation requirements."},
            {"kind": "evidence", "severity": "high", "summary": "Tunnel governance", "details": ["Change-approved windows and teardown review captured."], "artifacts": {"teardown_required": True}},
        ],
        "c2-framework-awareness": [
            {"kind": "log", "severity": "medium", "message": "Framework awareness brief maps family traits to hunt leads and false positives."},
            {"kind": "evidence", "severity": "medium", "summary": "Framework awareness", "details": ["Training output limited to defensive context."], "artifacts": {"context": "defensive-training"}},
        ],
        "objective-credential-impact": [
            {"kind": "log", "severity": "high", "message": "Privileged credential exposure simulation indicates broad service and monitoring impact."},
            {"kind": "evidence", "severity": "high", "summary": "Credential impact review", "details": ["Containment and reset workflow prioritized by blast radius."], "artifacts": {"impact_area": ["admin", "service_accounts", "monitoring"]}},
        ],
        "objective-lateral-movement-impact": [
            {"kind": "log", "severity": "high", "message": "Pivot graph highlights segmentation and service-identity weaknesses in staged path."},
            {"kind": "evidence", "severity": "high", "summary": "Lateral movement impact", "details": ["app -> middleware -> monitor path modeled for remediation planning."], "artifacts": {"path": ["app", "middleware", "monitor"]}},
        ],
        "objective-evidence-bundle": [
            {"kind": "log", "severity": "medium", "message": "Final evidence bundle collates findings, owners, and validation checkpoints."},
            {"kind": "evidence", "severity": "medium", "summary": "Evidence bundle", "details": ["Report-ready timeline prepared for handoff."], "artifacts": {"report_ready": True}},
        ],
        "objective-hashcat-impact": [
            {"kind": "log", "severity": "high", "message": "Offline hash exposure simulation estimates crackability tiers for service, admin, and shared support identities."},
            {"kind": "log", "severity": "high", "message": "$ hashcat -m 0 HASH_FILE /usr/share/wordlists/rockyou.txt  [REFERENCE PROFILE]"},
            {"kind": "log", "severity": "high", "message": "$ hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --username  [SIMULATED OFFLINE REVIEW]"},
            {"kind": "log", "severity": "high", "message": "hashcat: staged crackability result suggests 2 admin/service identities would fall to common wordlist variants"},
            {"kind": "log", "severity": "medium", "message": "hashcat: 3 additional accounts align with company-name+year or season+year patterns"},
            {"kind": "evidence", "severity": "high", "summary": "Offline hash exposure review", "details": ["Reference command: hashcat -m 0 HASH_FILE /usr/share/wordlists/rockyou.txt", "Crackability tier HIGH: 2 hashes resemble common admin/service credential patterns", "Crackability tier MEDIUM: 3 hashes resemble season-year or company-year mutations", "Crackability tier LOW: 4 hashes require stronger/custom candidate generation", "Severity: HIGH because privilege-bearing identities dominate the weak tier"], "artifacts": {"tiers": {"high": 2, "medium": 3, "low": 4}, "reference_cmd": "hashcat -m 0 HASH_FILE /usr/share/wordlists/rockyou.txt"}},
        ],
        "objective-john-audit": [
            {"kind": "log", "severity": "high", "message": "Wordlist audit simulation flags season-year and company-name password patterns across staged accounts."},
            {"kind": "log", "severity": "high", "message": "$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt HASH_FILE  [REFERENCE PROFILE]"},
            {"kind": "log", "severity": "high", "message": "$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt  [SIMULATED OFFLINE AUDIT]"},
            {"kind": "log", "severity": "medium", "message": "john: weak families include season-year, company-name, keyboard-walk, and welcome-default variants"},
            {"kind": "log", "severity": "medium", "message": "john: support and shared operations accounts show highest recurrence of reusable patterns"},
            {"kind": "evidence", "severity": "high", "summary": "Password audit wordlist review", "details": ["Reference commands: john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt HASH_FILE and john --wordlist=WORDLIST_FILE HASH_FILE", "Weak families detected: season-year, company-name, keyboard-walk, welcome-default", "Most exposed identity classes: support, shared-ops, and stale admin aliases", "Severity: HIGH because pattern reuse increases lateral access risk in the lab scenario", "Recommendation focus: password policy uplift, MFA, and shared-account retirement"], "artifacts": {"patterns": ["season-year", "company-name", "keyboard-walk", "welcome-default"], "reference_cmds": ["john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt HASH_FILE", "john --wordlist=WORDLIST_FILE HASH_FILE"]}},
        ],
    }
    return module_specific.get(module.id, [])


def module_runtime_events(module, target: str, note: str) -> list[dict[str, Any]]:
    playbook = module_playbook(module)
    common_events: list[dict[str, Any]] = [
        {"kind": "log", "severity": "info", "message": f"Operator note  : {note or 'No note supplied; using default lab scenario.'}"},
        {"kind": "log", "severity": "info", "message": f"Approved scope : {', '.join(str(subnet) for subnet in ALLOWED_SUBNETS)}"},
        {"kind": "log", "severity": "info", "message": f"Target focus   : {target}"},
        {"kind": "log", "severity": "info", "message": f"Skill level    : {playbook.skill_level}"},
        {"kind": "log", "severity": "info", "message": f"Operator focus : {playbook.operator_focus}"},
        {"kind": "log", "severity": "info", "message": f"Sim stance     : {playbook.simulation_stance}"},
        {"kind": "log", "severity": "info", "message": f"Depth profile  : {playbook.depth_profile}"},
        {"kind": "log", "severity": "info", "message": f"WSL tools      : {', '.join(playbook.tooling)}"},
        {"kind": "log", "severity": "info", "message": f"Allowed checks : {', '.join(playbook.allowed_checks)}"},
        {"kind": "log", "severity": "info", "message": f"Evidence goals : {', '.join(playbook.evidence)}"},
        {"kind": "log", "severity": "info", "message": f"Telemetry view : {', '.join(playbook.telemetry)}"},
    ]
    common_events.extend(
        {"kind": "log", "severity": "info", "message": line}
        for line in module.preview
    )

    adapter = LIVE_SAFE_ADAPTERS.get(module.id)
    if adapter:
        return common_events + adapter(target) + simulated_phase_lines(module, target)
    return common_events + simulated_phase_lines(module, target)


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


def overall_risk_label(summary: dict[str, Any]) -> str:
    if int(summary.get("high", 0)) > 0:
        return "KRITIS"
    if int(summary.get("medium", 0)) > 0:
        return "TINGGI"
    if int(summary.get("low", 0)) > 0:
        return "SEDANG"
    return "RENDAH"


def severity_label_id(value: str) -> str:
    mapping = {
        "info": "INFORMASI",
        "low": "SEDANG",
        "medium": "TINGGI",
        "high": "KRITIS",
    }
    return mapping.get(str(value).lower(), str(value).upper())


def severity_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1, "info": 0}.get(str(value).lower(), 0)


def unique_tooling(job: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for module_id in job["module_ids"]:
        module = MODULE_BY_ID.get(module_id)
        if not module:
            continue
        for label in module_playbook(module).tooling:
            if label not in seen:
                seen.add(label)
                labels.append(label)
    return labels


def summarize_scope(job: dict[str, Any]) -> tuple[list[str], list[str]]:
    included = [
        "uji keterjangkauan host",
        "pemetaan fase Cyber Kill Chain yang dipilih",
        "inventarisasi service dan metadata terbatas",
        "review evidence per modul",
        "penyusunan artefak laporan dan timeline",
    ]
    excluded = [
        "eksploitasi aktif",
        "brute force / password spraying",
        "validasi kredensial melalui login nyata",
        "eksekusi payload",
        "persistence",
        "lateral movement nyata",
        "data exfiltration",
    ]

    selected = [MODULE_BY_ID[module_id] for module_id in job["module_ids"] if module_id in MODULE_BY_ID]
    if any(module.phase_id == "recon" for module in selected):
        included.extend(["pemindaian port TCP aman", "identifikasi service/versi", "fingerprinting HTTP/DNS terbatas"])
    if any(module.id == "baseline-content-discovery" for module in selected):
        included.append("peninjauan path, route, dan paparan konten yang disetujui")
    if any(module.id == "baseline-nikto-review" for module in selected):
        included.append("review heuristik misconfiguration web")
    if any(module.id == "baseline-tls-dns-review" for module in selected):
        included.append("pemeriksaan TLS dan hygiene DNS")
    if any(module.phase_id in {"exploit", "install", "c2", "objective"} for module in selected):
        included.append("simulasi tabletop/non-destruktif untuk fase lanjutan")

    return included, excluded


def infer_service_inventory(job: dict[str, Any]) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    seen: set[str] = set()
    hints = {
        "ssh": ("22/tcp", "SSH", "OpenSSH / service metadata staged"),
        "http": ("80/tcp", "HTTP", "HTTP stack fingerprint dan path review"),
        "https": ("443/tcp", "HTTPS", "TLS posture dan certificate metadata"),
        "ftp": ("21/tcp", "FTP", "Service metadata / exposure review"),
        "mysql": ("3306/tcp", "MySQL", "Database service metadata"),
        "dns": ("53/tcp", "DNS", "Resolver / vhost correlation"),
    }

    for entry in job["logs"]:
        message = str(entry.get("message", "")).lower()
        for key, (port, service, note) in hints.items():
            token = f" {key} "
            if key in message or token in message:
                marker = f"{port}:{service}"
                if marker not in seen:
                    seen.add(marker)
                    services.append({"port": port, "service": service, "observation": note})

    if not services:
        selected = {MODULE_BY_ID[module_id].phase_id for module_id in job["module_ids"] if module_id in MODULE_BY_ID}
        if "recon" in selected:
            services.extend(
                [
                    {"port": "22/tcp", "service": "SSH", "observation": "Metadata service hasil simulasi recon"},
                    {"port": "80/tcp", "service": "HTTP", "observation": "Fingerprinting web dan path exposure review"},
                ]
            )
    return services


def concise_artifact_lines(artifacts: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in artifacts.items():
        if value in (None, "", [], {}):
            continue
        label = str(key).replace("_", " ").capitalize()
        if isinstance(value, list):
            rendered = ", ".join(str(item) for item in value[:6])
        elif isinstance(value, dict):
            rendered = ", ".join(f"{sub_key}={sub_value}" for sub_key, sub_value in list(value.items())[:6])
        else:
            rendered = str(value)
        lines.append(f"{label}: {rendered}")
    return lines


def is_noise_evidence(item: dict[str, Any]) -> bool:
    summary = str(item.get("summary", "")).lower()
    module_id = str(item.get("module_id", "")).lower()
    if summary in {
        "host discovery snapshot",
        "dns/vhost review",
        "defender-view artifact notes",
        "recovery readiness",
        "framework awareness",
        "evidence bundle",
    }:
        return True
    if module_id in {
        "weapon-defender-view",
        "install-defender-recovery",
        "objective-evidence-bundle",
        "c2-framework-awareness",
    }:
        return True
    return False


def finding_profile(item: dict[str, Any]) -> dict[str, Any]:
    module_id = str(item.get("module_id", ""))
    artifacts = item.get("artifacts") or {}
    details = item.get("details") or ["Observasi evidence tercatat dari modul terkait."]
    summary = str(item.get("summary", ""))

    profile = {
        "title": summary,
        "description": details,
        "impact": [],
        "recommendations": [],
    }

    if module_id == "baseline-content-discovery":
        profile["title"] = "Paparan route sensitif dan perilaku respons yang tidak konsisten"
        profile["description"] = [
            "Review path terotorisasi menunjukkan surface aplikasi melebar ke family route yang lazim sensitif, termasuk area admin, backup, dan health endpoint.",
            "Perbedaan HTTP 200, 302, dan 403 antar path/port mengindikasikan kontrol akses dan pemisahan surface belum seragam.",
            *details,
        ]
        profile["impact"] = [
            "Mempermudah enumerasi attacker terhadap route bernilai tinggi sebelum autentikasi.",
            "Meningkatkan peluang kebocoran artefak operasional atau endpoint administratif yang seharusnya tidak mudah ditemukan.",
        ]
        profile["recommendations"] = [
            "Tutup atau batasi route admin, backup, dan health check hanya untuk origin/role yang diperlukan.",
            "Samakan perilaku respons untuk resource sensitif agar tidak memberi petunjuk enumerasi.",
            "Audit kembali route legacy dan alternate-port yang tidak lagi dibutuhkan.",
        ]
    elif module_id == "baseline-nikto-review":
        profile["title"] = "Baseline hardening web masih lemah dan memberi banyak petunjuk enumerasi"
        profile["description"] = [
            "Review heuristik web menemukan indikator hardening yang belum matang, termasuk petunjuk dari robots/helper endpoint dan defensive header yang belum konsisten.",
            "Temuan ini sendiri belum membuktikan eksploitabilitas, tetapi sangat mempercepat fase discovery dan triage attacker.",
            *details,
        ]
        profile["impact"] = [
            "Menurunkan biaya enumerasi bagi attacker untuk memetakan fungsi internal aplikasi.",
            "Memperbesar kemungkinan false confidence karena exposure tampak 'kecil' namun terhubung ke surface lain yang lebih kritis.",
        ]
        profile["recommendations"] = [
            "Perkuat baseline header keamanan dan kurangi petunjuk yang tidak perlu pada response aplikasi.",
            "Review robots, helper endpoint, dan file default yang mengungkap struktur internal.",
            "Pastikan reverse proxy dan aplikasi menerapkan baseline hardening yang seragam.",
        ]
    elif module_id == "baseline-gobuster-routes":
        profile["title"] = "Path backup, upload, dan admin perlu validasi prioritas tinggi"
        profile["description"] = [
            "Enumerasi route terarah menempatkan family path backup, uploads, admin, dan legacy-api sebagai area dengan nilai validasi tertinggi.",
            "Meskipun output ini masih tahap simulasi/assessment aman, surface tersebut umumnya memiliki korelasi kuat dengan disclosure atau auth bypass bila tidak dikontrol ketat.",
            *details,
        ]
        profile["impact"] = [
            "Meningkatkan kemungkinan penemuan artefak sensitif atau endpoint administratif.",
            "Membuka jalur discovery lanjutan yang bisa dipadukan dengan kelemahan lain.",
        ]
        profile["recommendations"] = [
            "Lakukan review akses dan isi direktori pada family path yang disebutkan.",
            "Hapus artefak backup/temporary dari document root dan alternate route.",
            "Nonaktifkan indexing dan validasi ulang kebijakan upload/executable content.",
        ]
    elif module_id == "exploit-auth-control-review":
        profile["title"] = "Kontrol autentikasi berpotensi tidak cukup kuat terhadap pola abuse terarah"
        profile["description"] = [
            "Simulasi auth-control menunjukkan kebutuhan lockout, warning, dan escalation yang lebih tegas terhadap pola gagal autentikasi berulang.",
            "Temuan ini penting karena kelemahan auth control sering menjadi pengali risiko bagi seluruh exposure lain yang sudah ditemukan.",
            *details,
        ]
        profile["impact"] = [
            "Meningkatkan risiko credential abuse bila attacker sudah memiliki username yang valid.",
            "Berpotensi melemahkan efektivitas monitoring bila threshold warning/lockout tidak proporsional.",
        ]
        profile["recommendations"] = [
            "Review threshold warning, lockout, reset window, dan MFA enforcement.",
            "Tambahkan deteksi untuk pola spray-like timing dan percobaan lintas realm/origin.",
            "Pastikan alert auth abnormal mengalir ke SOC dengan konteks user, source, dan target yang cukup.",
        ]
    elif module_id == "objective-credential-impact":
        profile["title"] = "Dampak exposure kredensial berpotensi lintas akun administratif dan service account"
        profile["description"] = [
            "Evidence menunjukkan blast radius tidak terbatas pada satu identitas, tetapi menyentuh area admin, service account, dan monitoring.",
            "Artinya remediation perlu fokus pada containment dan rotasi berdasarkan prioritas bisnis, bukan sekadar reset satu akun.",
            *details,
        ]
        profile["impact"] = [
            "Meningkatkan peluang akses tidak sah lintas sistem bila credential reuse terjadi.",
            "Memperluas beban containment karena beberapa fungsi operasional dapat ikut terdampak.",
        ]
        profile["recommendations"] = [
            "Prioritaskan rotasi akun admin dan service account yang memiliki akses luas.",
            "Audit privilege, credential reuse, dan dependency antar layanan sebelum cutover.",
            "Monitor seluruh autentikasi pasca-rotasi untuk mendeteksi penggunaan credential lama.",
        ]
    elif module_id == "objective-lateral-movement-impact":
        profile["title"] = "Relasi antar komponen menunjukkan peluang pivot konseptual lintas service"
        profile["description"] = [
            "Path `app -> middleware -> monitor` menunjukkan trust boundary antar komponen masih perlu ditinjau secara serius.",
            "Meskipun tidak dilakukan lateral movement nyata, pemetaan ini cukup untuk memprioritaskan segmentasi dan pembatasan trust path.",
            *details,
        ]
        profile["impact"] = [
            "Satu titik kompromi awal dapat memperbesar dampak ke service lain yang terhubung.",
            "Monitoring sering terlambat bila trust path antarsistem dianggap normal dan tidak diawasi granular.",
        ]
        profile["recommendations"] = [
            "Batasi konektivitas east-west hanya untuk komunikasi yang benar-benar diperlukan.",
            "Review trust path antar service, akun servis, dan jalur monitoring.",
            "Tambahkan deteksi untuk akses lintas segmen yang tidak sesuai pola normal.",
        ]
    elif module_id == "objective-hashcat-impact":
        profile["title"] = "Exposure hash offline mengindikasikan risiko kompromi identitas prioritas tinggi"
        profile["description"] = [
            "Penilaian crackability bertingkat menunjukkan sebagian identitas administratif atau service memiliki urgensi reset lebih tinggi.",
            "Risiko utama bukan hanya pada satu hash yang lemah, tetapi pada pola reuse dan privilege dari identitas tersebut.",
            *details,
        ]
        profile["impact"] = [
            "Memungkinkan pemulihan password secara offline tanpa memicu log autentikasi awal.",
            "Berpotensi memicu compromise berantai jika password reuse atau privilege terlalu luas.",
        ]
        profile["recommendations"] = [
            "Reset segera identitas pada tier high dan medium terlebih dahulu.",
            "Perketat kebijakan password dan terapkan MFA untuk akun bernilai tinggi.",
            "Audit penyimpanan hash, source dump, dan kontrol akses ke artefak credential.",
        ]
    elif module_id == "objective-john-audit":
        profile["title"] = "Pola password lemah masih berulang dan menurunkan ketahanan identitas"
        profile["description"] = [
            "Family pattern seperti season-year, company-name, dan keyboard-walk menunjukkan hygiene password belum matang.",
            "Ini menandakan masalah kebijakan dan edukasi, bukan sekadar kelemahan satu pengguna.",
            *details,
        ]
        profile["impact"] = [
            "Mempermudah guessing atau offline cracking terhadap kelompok akun yang lebih luas.",
            "Menurunkan efektivitas kontrol lain jika password policy dan MFA belum memadai.",
        ]
        profile["recommendations"] = [
            "Perbarui password policy untuk menolak pattern yang mudah ditebak.",
            "Terapkan MFA pada akun prioritas dan lakukan kampanye reset bertahap.",
            "Jalankan audit password berkala untuk mendeteksi pola yang berulang.",
        ]
    else:
        profile["impact"] = [
            "Temuan ini menambah konteks risiko pada surface yang dinilai dan perlu dipadukan dengan evidence lain.",
        ]
        profile["recommendations"] = [
            "Lakukan validasi teknis dan hardening terarah pada area yang disebutkan di evidence.",
        ]

    evidence_lines = concise_artifact_lines(artifacts)
    if evidence_lines:
        profile["evidence_lines"] = evidence_lines
    return profile


def collect_findings(job: dict[str, Any]) -> list[dict[str, Any]]:
    candidate_items = [
        item for item in job["evidence"]
        if not is_noise_evidence(item)
    ]
    candidate_items.sort(key=lambda item: (-severity_rank(str(item.get("severity", "info"))), str(item.get("module_title", ""))))
    if any(severity_rank(str(item.get("severity", "info"))) >= 2 for item in candidate_items):
        candidate_items = [item for item in candidate_items if severity_rank(str(item.get("severity", "info"))) >= 2]
    candidate_items = candidate_items[:6]

    findings: list[dict[str, Any]] = []
    for index, item in enumerate(candidate_items, start=1):
        profile = finding_profile(item)
        findings.append(
            {
                "number": index,
                "title": profile["title"],
                "severity": severity_label_id(str(item["severity"])),
                "phase_label": item["phase_label"],
                "module_title": item["module_title"],
                "module_id": item["module_id"],
                "description": profile["description"],
                "impact": profile["impact"],
                "recommendations": profile["recommendations"],
                "evidence_lines": profile.get("evidence_lines", []),
                "artifacts": item.get("artifacts") or {},
                "execution_profile": item["execution_profile"],
            }
        )
    return findings


def collect_nmap_nse_findings(job: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in job["evidence"]:
        structured = ((item.get("artifacts") or {}).get("nse_findings_structured") or [])
        for entry in structured:
            finding = str(entry.get("finding", "")).strip()
            if not finding:
                continue
            key = f"{entry.get('script')}|{entry.get('severity')}|{finding}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "severity": str(entry.get("severity", "info")).lower(),
                    "severity_id": severity_label_id(str(entry.get("severity", "info"))),
                    "script": str(entry.get("script", "nse")),
                    "finding": finding,
                    "module_title": str(item.get("module_title", "")),
                    "phase_label": str(item.get("phase_label", "")),
                }
            )
    findings.sort(key=lambda entry: (-severity_rank(entry["severity"]), entry["script"], entry["finding"]))
    return findings[:12]


def build_attack_hypotheses(job: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    hypotheses: list[str] = []
    if any("path" in finding["artifacts"] or "paths" in finding["artifacts"] for finding in findings):
        hypotheses.append("Paparan route/path sensitif dapat menjadi jalur initial discovery menuju surface administrasi atau konten sensitif.")
    if any("thresholds" in finding["artifacts"] for finding in findings):
        hypotheses.append("Kelemahan kontrol autentikasi dapat membuka peluang abuse kredensial apabila dikombinasikan dengan exposure lain.")
    if any("signals" in finding["artifacts"] for finding in findings):
        hypotheses.append("Sinyal hardening yang lemah dapat mempercepat enumerasi, fingerprinting, dan validasi surface oleh attacker.")
    if any("path" in finding["artifacts"] for finding in findings):
        hypotheses.append("Relasi service internal yang terpetakan dapat mendukung pivot konseptual lintas komponen bila kontrol segmentasi lemah.")
    if not hypotheses:
        hypotheses.append("Attack path potensial terutama berasal dari kombinasi enumerasi service, metadata exposure, dan kelemahan baseline konfigurasi.")
    return hypotheses


def build_detection_recommendations(job: dict[str, Any]) -> list[str]:
    points: list[str] = []
    seen: set[str] = set()
    for module_id in job["module_ids"]:
        module = MODULE_BY_ID.get(module_id)
        if not module:
            continue
        for item in module_playbook(module).telemetry:
            if item not in seen:
                seen.add(item)
                points.append(f"Alert/monitoring pada {item}.")
    return (points[:6] if points else ["Tinjau log akses, telemetry service, dan alert baseline yang relevan dengan modul yang dijalankan."])


def build_priority_plan(findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    immediate: list[str] = []
    short_term: list[str] = []
    medium_term: list[str] = []

    if any(finding["severity"] == "KRITIS" for finding in findings):
        immediate.extend(
            [
                "Batasi exposure pada temuan kritis dan lakukan containment awal.",
                "Review log dan alert terkait untuk mendeteksi penyalahgunaan sebelumnya.",
                "Tetapkan owner remediation dan verifikasi perubahan setelah perbaikan.",
            ]
        )
    if any(finding["severity"] in {"KRITIS", "TINGGI"} for finding in findings):
        short_term.extend(
            [
                "Hardening service/path yang terekspos.",
                "Perbaiki kontrol akses, segmentasi, atau baseline konfigurasi yang lemah.",
                "Perkuat alerting untuk surface yang paling sering muncul pada evidence.",
            ]
        )

    medium_term.extend(
        [
            "Formalkan baseline hardening dan review berkala per fase kill chain.",
            "Sinkronkan temuan dengan backlog detection engineering dan hygiene operasional.",
            "Jadikan artefak laporan sebagai acuan validasi ulang pasca-remediasi.",
        ]
    )

    return {
        "immediate": immediate or ["Tidak ada aksi kritis instan; tetap lakukan verifikasi cepat atas exposure yang ditemukan."],
        "short_term": short_term or ["Lakukan perbaikan baseline dan review owner/service dalam 1-7 hari."],
        "medium_term": medium_term,
    }


def build_markdown_report(job: dict[str, Any]) -> str:
    included, excluded = summarize_scope(job)
    tools = unique_tooling(job)
    services = infer_service_inventory(job)
    findings = collect_findings(job)
    nmap_nse_findings = collect_nmap_nse_findings(job)
    hypotheses = build_attack_hypotheses(job, findings)
    detections = build_detection_recommendations(job)
    plan = build_priority_plan(findings)
    overall_risk = overall_risk_label(job["severity_summary"])
    timeline_summary = [run for run in job["module_runs"] if severity_rank(str(run.get("highest_severity", "info"))) >= 2][:5]

    lines = [
        "# Laporan Asesmen Red Team",
        "",
        "## 1. Ringkasan Eksekutif",
        "",
        f"Telah dilakukan asesmen keamanan yang terotorisasi dan bersifat non-destruktif terhadap host `{job['target']}`.",
        f"Asesmen dijalankan melalui workflow `{job['scope_label']}` dengan pendekatan berbasis Cyber Kill Chain dan evidence-first validation.",
        f"Tingkat risiko keseluruhan: `{overall_risk}`",
        "",
        "Ringkasan temuan utama:",
    ]
    if findings:
        lines.extend([f"- {finding['title']} (`{finding['severity']}`)" for finding in findings[:4]])
    else:
        lines.append("- Belum ada temuan bernilai tinggi yang layak dinaikkan ke laporan utama.")
    lines.extend(
        [
            f"- Job ID: `{job['id']}`",
            f"- Status akhir: `{job['status']}` (`{job['progress']}%`)",
            f"- Distribusi severity: info `{job['severity_summary'].get('info', 0)}`, low `{job['severity_summary'].get('low', 0)}`, medium `{job['severity_summary'].get('medium', 0)}`, high `{job['severity_summary'].get('high', 0)}`",
            "",
            "Tidak dilakukan eksploitasi aktif, brute force, validasi login nyata, eksekusi payload, persistence, maupun exfiltration.",
            "",
            "## 2. Ruang Lingkup dan Otorisasi",
            "",
            f"- Target host: `{job['target']}`",
            f"- Jenis asesmen: terotorisasi, aman/non-destruktif",
            f"- Catatan job: `{job['note'] or '-'}`",
            "- Aktivitas yang termasuk:",
        ]
    )
    lines.extend([f"  - {item}" for item in included[:7]])
    lines.append("- Aktivitas yang tidak termasuk:")
    lines.extend([f"  - {item}" for item in excluded])

    lines.extend(
        [
            "",
            "## 3. Lingkungan dan Metode",
            "",
            "Host asesmen:",
            "- Platform: Kali Linux WSL / backend FastAPI / browser console",
            "- Tools utama yang digunakan:",
        ]
    )
    lines.extend([f"  - `{tool}`" for tool in tools[:8]] or ["  - `-`"])
    lines.extend(["", "Pendekatan:"])
    for index, run in enumerate(job["module_runs"][:6], start=1):
        lines.append(f"{index}. {run['phase_label']} - {run['title']} ({run['execution_profile']})")

    lines.extend(["", "## 4. Inventaris Service", ""])
    if services:
        lines.extend(
            [
                "| Port | Service | Versi / Observasi |",
                "|------|---------|-------------------|",
            ]
        )
        for service in services:
            lines.append(f"| {service['port']} | {service['service']} | {service['observation']} |")
    else:
        lines.append("Belum ada inventaris service spesifik yang dapat diinferensikan dari output job ini.")

    lines.extend(["", "## 5. Temuan Nmap NSE", ""])
    if nmap_nse_findings:
        lines.extend(
            [
                "| Severity | Script | Finding | Modul |",
                "|----------|--------|---------|-------|",
            ]
        )
        for item in nmap_nse_findings:
            lines.append(
                f"| {item['severity_id']} | {item['script']} | {item['finding']} | {item['module_title']} |"
            )
    else:
        lines.append("Belum ada temuan Nmap NSE spesifik yang terekstrak dari job ini.")

    lines.extend(["", "## 6. Temuan", ""])
    if not findings:
        lines.append("Tidak ada evidence bernilai tinggi yang terkumpul pada job ini.")
    else:
        for finding in findings:
            lines.extend(
                [
                    f"### Temuan {finding['number']}: {finding['title']}",
                    f"Severity: `{finding['severity']}`",
                    "",
                    "Deskripsi:",
                    *finding["description"],
                    "",
                    "Bukti:",
                    f"- Fase: `{finding['phase_label']}`",
                    f"- Modul: `{finding['module_title']}`",
                    f"- Execution profile: `{finding['execution_profile']}`",
                ]
            )
            for line in finding["evidence_lines"]:
                lines.append(f"- {line}")
            lines.extend(["", "Dampak:"])
            lines.extend([f"- {item}" for item in finding["impact"]])
            lines.extend(["", "Rekomendasi:"])
            lines.extend([f"- {item}" for item in finding["recommendations"]])
            lines.append("")

    lines.extend(["## 7. Hipotesis Attack Path", ""])
    for index, item in enumerate(hypotheses, start=1):
        lines.append(f"{index}. {item}")

    lines.extend(["", "## 8. Rekomendasi Deteksi dan Monitoring", ""])
    lines.extend([f"- {item}" for item in detections])

    lines.extend(["", "## 9. Rencana Remediasi Prioritas", "", "Segera (0-24 jam):"])
    for index, item in enumerate(plan["immediate"], start=1):
        lines.append(f"{index}. {item}")
    lines.extend(["", "Jangka pendek (1-7 hari):"])
    for index, item in enumerate(plan["short_term"], start=1):
        lines.append(f"{index}. {item}")
    lines.extend(["", "Jangka menengah (7-30 hari):"])
    for index, item in enumerate(plan["medium_term"], start=1):
        lines.append(f"{index}. {item}")

    lines.extend(
        [
            "",
            "## 10. Keterbatasan",
            "",
            "Asesmen ini tidak mencakup:",
        ]
    )
    lines.extend([f"- {item}" for item in excluded])
    lines.extend(
        [
            "",
            "Karena itu, seluruh dampak pasca-initial-access atau post-compromise masih berupa hipotesis sampai ada validasi terpisah yang diotorisasi.",
            "",
            "## 11. Artefak",
            "",
            "Artefak yang dikumpulkan berasal dari timeline modul, evidence highlights, dan export report job ini.",
            "",
            "File ekspor yang tersedia:",
            f"- `evidence-{job['id']}.json`",
            f"- `report-{job['id']}.md`",
            f"- `report-{job['id']}.html`",
            "",
            "Timeline modul bernilai tinggi:",
        ]
    )
    for run in timeline_summary:
        lines.append(
            f"- {run['phase_label']} - {run['title']} | status `{run['status']}` | severity `{run['highest_severity']}` | evidence `{run['evidence_count']}`"
        )
    lines.append("")
    return "\n".join(lines)


def build_html_report(job: dict[str, Any]) -> str:
    markdown = build_markdown_report(job)
    html_body = []
    for block in markdown.split("\n\n"):
        stripped = block.strip()
        if not stripped:
            continue
        if stripped.startswith("# "):
            html_body.append(f"<h1>{escape(stripped[2:])}</h1>")
            continue
        if stripped.startswith("## "):
            html_body.append(f"<h2>{escape(stripped[3:])}</h2>")
            continue
        if stripped.startswith("### "):
            html_body.append(f"<h3>{escape(stripped[4:])}</h3>")
            continue
        if stripped.startswith("| ") and "\n|" in stripped:
            rows = [row.strip() for row in stripped.splitlines() if row.strip()]
            table_rows = []
            for row in rows:
                if set(row.replace("|", "").replace("-", "").strip()) == set():
                    continue
                cells = [escape(cell.strip()) for cell in row.strip("|").split("|")]
                tag = "th" if not table_rows else "td"
                table_rows.append("<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>")
            html_body.append(f"<table>{''.join(table_rows)}</table>")
            continue
        if all(line.lstrip().startswith(("- ", "1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")) for line in stripped.splitlines()):
            items = []
            ordered = stripped.splitlines()[0].lstrip()[0].isdigit()
            for line in stripped.splitlines():
                text = line.split(". ", 1)[1] if ordered and ". " in line else line[2:]
                items.append(f"<li>{escape(text.strip())}</li>")
            tag = "ol" if ordered else "ul"
            html_body.append(f"<{tag}>{''.join(items)}</{tag}>")
            continue
        html_body.append("".join(f"<p>{escape(line)}</p>" for line in stripped.splitlines()))

    return f"""<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>Laporan Asesmen Red Team - {escape(str(job['target']))}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #eef3f9; color: #17324d; }}
    .wrap {{ max-width: 1024px; margin: 0 auto; padding: 32px 24px 48px; }}
    .card {{ background: #ffffff; border: 1px solid #d9e5f1; border-radius: 22px; padding: 28px 30px; }}
    h1, h2, h3 {{ color: #183b63; margin-top: 0; }}
    h1 {{ font-size: 2rem; margin-bottom: 24px; }}
    h2 {{ font-size: 1.35rem; margin: 28px 0 14px; padding-top: 4px; border-top: 1px solid #e4ecf5; }}
    h3 {{ font-size: 1.1rem; margin: 20px 0 10px; }}
    p {{ margin: 0 0 10px; line-height: 1.7; }}
    ul, ol {{ margin: 8px 0 14px 20px; padding: 0; }}
    li {{ margin: 0 0 8px; line-height: 1.65; }}
    code {{ background: #eef4fb; padding: 2px 6px; border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0 16px; }}
    th, td {{ border: 1px solid #d9e5f1; padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ background: #f4f8fc; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="card">
      {"".join(html_body)}
    </section>
  </div>
</body>
</html>"""


def run_job(job_id: str) -> None:
    job = JOB_STORE.get_job(job_id)
    if not job:
        return

    try:
        append_log(job_id, "Job accepted by worker.", status="running", progress=1)
        append_log(job_id, "Execution flow : staged module simulation with live-safe adapters on selected baseline/recon modules.")
        module_count = max(len(job["module_ids"]), 1)

        for index, module_id in enumerate(job["module_ids"]):
            module = MODULE_BY_ID[module_id]
            execution_profile = module_execution_profile(module_id)
            highest_severity = "info"
            evidence_count = 0

            update_module_run(
                job_id,
                module_id,
                status="running",
                progress=5,
                started_at=now_iso(),
                execution_profile=execution_profile,
                highest_severity=highest_severity,
            )

            append_log(job_id, "")
            append_log(job_id, f"=== [{module.phase_label}] {module.title} ===")
            append_log(job_id, f"Risk level     : {module.risk}")
            append_log(job_id, f"ATT&CK hint    : {module.mitre}")
            append_log(job_id, f"Execution prof.: {execution_profile}")
            append_log(job_id, "Starting module workflow.")

            events = module_runtime_events(module, str(job["target"]), str(job["note"]))
            total_events = max(len(events), 1)
            for event_index, event in enumerate(events, start=1):
                severity = str(event.get("severity") or "info")
                highest_severity = severity_max(highest_severity, severity)
                module_progress = min(95, int((event_index / total_events) * 100))
                overall_progress = min(99, int(((index + (event_index / total_events)) / module_count) * 100))

                if event["kind"] == "log":
                    append_log(job_id, str(event["message"]), severity=severity, progress=overall_progress)
                elif event["kind"] == "evidence":
                    add_evidence(
                        job_id,
                        {
                            "module_id": module.id,
                            "module_title": module.title,
                            "phase_label": module.phase_label,
                            "severity": severity,
                            "summary": event["summary"],
                            "details": event.get("details", []),
                            "artifacts": event.get("artifacts", {}),
                            "execution_profile": execution_profile,
                            "collected_at": now_iso(),
                        },
                    )
                    evidence_count += 1
                    append_log(job_id, f"Evidence added : {event['summary']}", severity=severity, progress=overall_progress)

                update_module_run(
                    job_id,
                    module_id,
                    progress=module_progress,
                    highest_severity=highest_severity,
                    evidence_count=evidence_count,
                )
                time.sleep(0.18)

            update_module_run(
                job_id,
                module_id,
                status="completed",
                progress=100,
                highest_severity=highest_severity,
                evidence_count=evidence_count,
                completed_at=now_iso(),
            )
            append_log(job_id, f"Module result  : {module.title} completed in {execution_profile}.", severity=highest_severity)
            update_progress(job_id, int(((index + 1) / module_count) * 100))

        append_log(
            job_id,
            "Simulation complete. Export evidence is ready for report handoff.",
            severity="info",
            status="completed",
            progress=100,
        )
    except Exception as error:
        fail_job(job_id, f"Worker error: {error}")
        append_log(job_id, traceback.format_exc(), severity="high", status="failed")


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
    return {"status": "ok"}


@app.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "allowed_subnet": ", ".join(str(subnet) for subnet in ALLOWED_SUBNETS),
        "allowed_subnets": [str(subnet) for subnet in ALLOWED_SUBNETS],
        "lab_profiles": list(LAB_PROFILES),
        "config_source": LAB_CONFIG_SOURCE,
        "config_path": LAB_CONFIG_PATH,
        "execution_mode": EXECUTION_MODE,
    }


@app.post("/api/config/reload")
def reload_config() -> dict[str, Any]:
    config_data = load_lab_config()
    apply_lab_config(config_data)
    return {
        "message": "Konfigurasi lab berhasil dimuat ulang.",
        "config": config(),
    }


@app.post("/api/config/allowed-subnets")
def update_allowed_subnets(payload: ConfigUpdateRequest) -> dict[str, Any]:
    cleaned = [item.strip() for item in payload.allowed_subnets if item.strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Daftar approved ranges tidak boleh kosong.")

    config_data = save_lab_config(allowed_subnets=cleaned, lab_profiles=LAB_PROFILES)
    apply_lab_config(config_data)
    return {
        "message": "Approved ranges berhasil disimpan.",
        "config": config(),
    }


@app.get("/api/modules")
def modules() -> dict[str, Any]:
    return {"modules": [serialize_module(module) for module in MODULES]}


@app.get("/api/modules/{module_id}/dry-run")
def module_dry_run(module_id: str, target: str, note: str = "") -> dict[str, Any]:
    validated_target = validate_target(target)
    module = MODULE_BY_ID.get(module_id)
    if not module:
        raise HTTPException(status_code=404, detail="Modul tidak ditemukan.")
    return {"dry_run": module_dry_run_payload(module, validated_target, note)}


@app.get("/api/tooling")
def tooling() -> dict[str, Any]:
    return tooling_coverage_payload()


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
        raise HTTPException(status_code=404, detail="Asset tidak ditemukan di registry lokal.")
    return {"asset": asset}


@app.get("/api/jobs")
def list_jobs() -> dict[str, Any]:
    return {"jobs": [hydrate_job(job) for job in JOB_STORE.list_jobs()]}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = hydrate_job(JOB_STORE.get_job(job_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan.")
    return {"job": job}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str) -> dict[str, Any]:
    deleted = JOB_STORE.delete_job(job_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan.")
    return {"message": "Job berhasil dihapus."}


@app.delete("/api/jobs")
def delete_all_jobs() -> dict[str, Any]:
    deleted = JOB_STORE.delete_all_jobs()
    return {"message": f"{deleted} job berhasil dihapus."}


@app.get("/api/jobs/{job_id}/evidence")
def export_job_evidence(job_id: str) -> JSONResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan.")

    filename = f"evidence-{job_id}.json"
    return JSONResponse(
        content=export_payload(job),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/jobs/{job_id}/report.md")
def export_job_report_markdown(job_id: str) -> PlainTextResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan.")

    filename = f"report-{job_id}.md"
    return PlainTextResponse(
        content=build_markdown_report(job),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/jobs/{job_id}/report.html")
def export_job_report_html(job_id: str) -> HTMLResponse:
    job = JOB_STORE.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job tidak ditemukan.")

    filename = f"report-{job_id}.html"
    return HTMLResponse(
        content=build_html_report(job),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/imports/parse")
def import_parse(payload: ImportRequest) -> dict[str, Any]:
    target = validate_target(payload.target)
    return {
        "result": parse_import(payload.tool_name, target, payload.content),
    }


@app.post("/api/jobs")
def create_module_job(payload: ModuleJobRequest) -> dict[str, Any]:
    if payload.module_id not in MODULE_BY_ID:
        raise HTTPException(status_code=404, detail="Module tidak ditemukan.")

    target = validate_target(payload.target)
    module = MODULE_BY_ID[payload.module_id]
    job = create_job(
        scope_type="module",
        scope_label=module.title,
        target=target,
        note=payload.note,
        module_ids=[module.id],
    )
    return {"job": job}


@app.post("/api/jobs/full-chain")
def create_full_chain_job(payload: JobRequest) -> dict[str, Any]:
    target = validate_target(payload.target)
    job = create_job(
        scope_type="chain",
        scope_label=f"Pentest IP {target}",
        target=target,
        note=payload.note,
        module_ids=[module.id for module in MODULES],
    )
    return {"job": job}
