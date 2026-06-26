from __future__ import annotations


ENGAGEMENTS = [
    {
        "id": "eng-2026-001",
        "name": "POC Internal Web Lab",
        "client": "SOC / IRM Proof of Concept",
        "scope": ["10.10.10.20", "10.10.10.30", "10.10.10.40"],
        "status": "active",
        "start_date": "2026-06-24",
        "methodology": "Cyber Kill Chain + evidence-first validation",
    },
    {
        "id": "eng-2026-002",
        "name": "Baseline Validation Sprint",
        "client": "Monitoring & Detection Lab",
        "scope": ["10.10.10.40"],
        "status": "planned",
        "start_date": "2026-06-28",
        "methodology": "Safe recon + defensive telemetry review",
    },
]


FINDINGS = [
    {
        "id": "finding-001",
        "engagement_id": "eng-2026-001",
        "target": "10.10.10.20",
        "title": "Admin path responds on alternate port",
        "severity": "medium",
        "status": "open",
        "evidence_source": "baseline-content-discovery",
        "remediation": "Review access control and reverse-proxy exposure for admin routes.",
    },
    {
        "id": "finding-002",
        "engagement_id": "eng-2026-001",
        "target": "10.10.10.20",
        "title": "Service metadata still exposes banner hints",
        "severity": "low",
        "status": "triaged",
        "evidence_source": "baseline-web-fingerprint",
        "remediation": "Reduce unnecessary banner/header disclosure where possible.",
    },
]


def parse_import(tool_name: str, target: str, content: str) -> dict[str, object]:
    normalized_tool = (tool_name or "").strip().lower()
    lines = [line.strip() for line in (content or "").splitlines() if line.strip()]
    findings: list[dict[str, str]] = []
    summary: list[str] = []

    if normalized_tool == "nmap":
        for line in lines:
            if "/tcp" in line or "/udp" in line:
                findings.append(
                    {
                        "title": f"Observed service line on {target}",
                        "severity": "low",
                        "detail": line,
                        "source": "nmap-import",
                    }
                )
        summary.append(f"Imported {len(findings)} port/service lines from pasted nmap output.")
    elif normalized_tool == "nikto":
        for line in lines:
            if "+ " in line or "OSVDB" in line or "Server:" in line:
                findings.append(
                    {
                        "title": f"Nikto observation for {target}",
                        "severity": "medium" if "OSVDB" in line else "low",
                        "detail": line,
                        "source": "nikto-import",
                    }
                )
        summary.append(f"Imported {len(findings)} Nikto observations from pasted output.")
    elif normalized_tool == "httpx":
        for line in lines:
            findings.append(
                {
                    "title": f"HTTPX host metadata for {target}",
                    "severity": "info",
                    "detail": line,
                    "source": "httpx-import",
                }
            )
        summary.append(f"Imported {len(findings)} HTTPX lines from pasted output.")
    else:
        findings.append(
            {
                "title": f"Generic imported output for {target}",
                "severity": "info",
                "detail": "\n".join(lines[:8]) or "No content supplied.",
                "source": "generic-import",
            }
        )
        summary.append("Tool type not recognized specifically; stored as generic pasted evidence.")

    return {
        "tool_name": normalized_tool or "generic",
        "target": target,
        "line_count": len(lines),
        "summary": summary,
        "findings": findings,
    }
