#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ssl
import urllib.error
import urllib.request
from typing import Any

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "function": "Restricts resource loading to prevent XSS and data injection",
        "risk": "High",
        "impact": "Attacker can inject malicious JavaScript or load external resources",
        "recommendation": "default-src 'self';",
    },
    "Strict-Transport-Security": {
        "function": "Forces browser to use HTTPS only",
        "risk": "High",
        "impact": "Vulnerable to SSL stripping and MITM attacks",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
    },
    "X-Frame-Options": {
        "function": "Prevents clickjacking via iframe embedding",
        "risk": "Medium",
        "impact": "User actions can be hijacked via hidden frames",
        "recommendation": "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "function": "Prevents MIME type sniffing",
        "risk": "Medium",
        "impact": "Browser may execute malicious content as script",
        "recommendation": "nosniff",
    },
    "Referrer-Policy": {
        "function": "Controls referrer information sent to other domains",
        "risk": "Low",
        "impact": "Sensitive URL data may leak to third-party sites",
        "recommendation": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "function": "Restricts access to browser features",
        "risk": "Low",
        "impact": "Browser features like camera or mic may be misused",
        "recommendation": "geolocation=(), camera=(), microphone=()",
    },
    "X-XSS-Protection": {
        "function": "Legacy XSS protection for old browsers",
        "risk": "Low",
        "impact": "Limited protection against reflected XSS",
        "recommendation": "1; mode=block",
    },
}

RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def risk_to_severity(risk: str) -> str:
    return RISK_TO_SEVERITY.get(str(risk or "").lower(), "info")


def fetch_response(url: str, timeout: int) -> tuple[int, str, dict[str, str]]:
    context = ssl._create_unverified_context()
    request = urllib.request.Request(url, headers={"User-Agent": "AuthorizedLabConsole/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return int(response.status), str(response.geturl()), dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return int(error.code), str(error.geturl()), dict(error.headers.items())


def check_headers(url: str, timeout: int = 10) -> dict[str, Any]:
    normalized_url = normalize_url(url)
    status_code, final_url, headers = fetch_response(normalized_url, timeout)

    present_headers: list[dict[str, str]] = []
    missing_headers: list[dict[str, str]] = []
    score = 0

    for header, info in SECURITY_HEADERS.items():
        if header in headers:
            present_headers.append(
                {
                    "name": header,
                    "value": str(headers.get(header, "")),
                    "function": str(info["function"]),
                }
            )
            score += 1
        else:
            missing_headers.append(
                {
                    "name": header,
                    "risk": str(info["risk"]),
                    "impact": str(info["impact"]),
                    "recommendation": str(info["recommendation"]),
                    "severity": risk_to_severity(str(info["risk"])),
                }
            )

    if score <= 2:
        overall_risk = "HIGH RISK"
        overall_severity = "high"
    elif score <= 4:
        overall_risk = "MEDIUM RISK"
        overall_severity = "medium"
    elif score <= 6:
        overall_risk = "LOW RISK"
        overall_severity = "low"
    else:
        overall_risk = "GOOD"
        overall_severity = "info"

    highest_missing = "info"
    for item in missing_headers:
        severity = str(item.get("severity", "info")).lower()
        if severity == "high":
            highest_missing = "high"
            break
        if severity == "medium" and highest_missing not in {"high", "medium"}:
            highest_missing = "medium"
        elif severity == "low" and highest_missing == "info":
            highest_missing = "low"

    return {
        "target_url": normalized_url,
        "final_url": final_url,
        "status_code": status_code,
        "headers": headers,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
        "score": score,
        "total_headers": len(SECURITY_HEADERS),
        "overall_risk": overall_risk,
        "overall_severity": highest_missing if missing_headers else overall_severity,
    }


def format_report(result: dict[str, Any]) -> str:
    lines = [
        "=" * 60,
        f"[+] Target        : {result['target_url']}",
        f"[+] Final URL     : {result['final_url']}",
        f"[+] Status Code   : {result['status_code']}",
        "=" * 60,
    ]

    for header, info in SECURITY_HEADERS.items():
        lines.append("")
        lines.append(f"[>] Checking: {header}")
        header_value = next((item["value"] for item in result["present_headers"] if item["name"] == header), None)
        if header_value is not None:
            lines.append("    Status        : FOUND")
            lines.append(f"    Value         : {header_value}")
            lines.append(f"    Function      : {info['function']}")
            continue

        missing = next((item for item in result["missing_headers"] if item["name"] == header), None)
        lines.append("    Status        : MISSING")
        if missing:
            lines.append(f"    Risk Level    : {missing['risk']}")
            lines.append(f"    Impact        : {missing['impact']}")
            lines.append(f"    Recommendation: {missing['recommendation']}")

    lines.extend(
        [
            "",
            "=" * 60,
            f"[+] Security Score: {result['score']}/{result['total_headers']}",
            f"[+] Overall Risk  : {result['overall_risk']}",
            "=" * 60,
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Advanced Security Headers Checker CLI")
    parser.add_argument("url", help="Target domain or URL")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()
    print(format_report(check_headers(args.url, args.timeout)))


if __name__ == "__main__":
    main()
