from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_ALLOWED_SUBNETS = (
    "10.10.10.0/24",
    "192.168.56.0/24",
    "192.168.122.0/24",
    "172.16.56.0/24",
)


DEFAULT_LAB_PROFILES = (
    {
        "id": "isolated-poc",
        "name": "Isolated POC Lab",
        "subnets": ["10.10.10.0/24"],
        "note": "Range untuk POC internal yang dipantau Wazuh.",
    },
    {
        "id": "virtualbox-hostonly",
        "name": "VirtualBox Host-Only",
        "subnets": ["192.168.56.0/24"],
        "note": "Range host-only yang umum dipakai VM simulasi di laptop.",
    },
    {
        "id": "libvirt-default",
        "name": "libvirt Default NAT",
        "subnets": ["192.168.122.0/24"],
        "note": "Range default pada banyak VM Linux/libvirt.",
    },
    {
        "id": "custom-lab",
        "name": "Custom Internal Lab",
        "subnets": ["172.16.56.0/24"],
        "note": "Contoh range lain untuk segment simulasi internal.",
    },
)


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = BASE_DIR / "lab-ranges.json"


def _normalize_subnets(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return DEFAULT_ALLOWED_SUBNETS
    subnets = tuple(str(item).strip() for item in values if str(item).strip())
    return subnets or DEFAULT_ALLOWED_SUBNETS


def _normalize_profiles(values: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(values, list):
        return DEFAULT_LAB_PROFILES

    profiles: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        subnets = [str(subnet).strip() for subnet in item.get("subnets", []) if str(subnet).strip()]
        if not subnets:
            continue
        profiles.append(
            {
                "id": str(item.get("id") or f"profile-{len(profiles) + 1}"),
                "name": str(item.get("name") or f"Profile {len(profiles) + 1}"),
                "subnets": subnets,
                "note": str(item.get("note") or ""),
            }
        )
    return tuple(profiles) or DEFAULT_LAB_PROFILES


def load_lab_config() -> dict[str, Any]:
    config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return {
            "allowed_subnets": DEFAULT_ALLOWED_SUBNETS,
            "lab_profiles": DEFAULT_LAB_PROFILES,
            "source": "defaults",
            "path": str(config_path),
        }

    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "allowed_subnets": DEFAULT_ALLOWED_SUBNETS,
            "lab_profiles": DEFAULT_LAB_PROFILES,
            "source": "defaults",
            "path": str(config_path),
        }

    return {
        "allowed_subnets": _normalize_subnets(payload.get("allowed_subnets")),
        "lab_profiles": _normalize_profiles(payload.get("lab_profiles")),
        "source": "file",
        "path": str(config_path),
    }


def save_lab_config(*, allowed_subnets: list[str] | tuple[str, ...], lab_profiles: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None) -> dict[str, Any]:
    normalized_subnets = _normalize_subnets(list(allowed_subnets))
    normalized_profiles = _normalize_profiles(list(lab_profiles) if lab_profiles is not None else list(DEFAULT_LAB_PROFILES))
    payload = {
        "allowed_subnets": list(normalized_subnets),
        "lab_profiles": list(normalized_profiles),
    }
    DEFAULT_CONFIG_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return {
        "allowed_subnets": normalized_subnets,
        "lab_profiles": normalized_profiles,
        "source": "file",
        "path": str(DEFAULT_CONFIG_PATH),
    }
