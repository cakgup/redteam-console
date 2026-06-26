from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class AssetRecord:
    ip: str
    hostname: str
    application: str
    owner_unit: str
    owner_name: str
    environment: str
    criticality: str
    monitoring: str
    note: str


ASSETS: tuple[AssetRecord, ...] = (
    AssetRecord(
        ip="10.10.10.20",
        hostname="poc-nginx-vulnshop.lab.local",
        application="POC NGINX / VulnShop",
        owner_unit="SOC / IRM Proof of Concept",
        owner_name="Tim Lab Internal",
        environment="Isolated Lab",
        criticality="Medium",
        monitoring="Wazuh",
        note="Aset contoh untuk emulasi terotorisasi pada subnet lab 10.10.10.0/24.",
    ),
    AssetRecord(
        ip="10.10.10.30",
        hostname="poc-db.lab.local",
        application="POC Database Service",
        owner_unit="SOC / IRM Proof of Concept",
        owner_name="Tim Database Lab",
        environment="Isolated Lab",
        criticality="High",
        monitoring="Wazuh + Syslog",
        note="Node database lab untuk validasi alert dan evidence chain.",
    ),
    AssetRecord(
        ip="10.10.10.40",
        hostname="wazuh-monitor.lab.local",
        application="Monitoring / Alert Aggregation",
        owner_unit="Monitoring & Detection Lab",
        owner_name="Tim SOC Engineering",
        environment="Isolated Lab",
        criticality="High",
        monitoring="Wazuh Manager",
        note="Dipakai untuk memonitor aliran alert selama exercise.",
    ),
)


def asset_map() -> dict[str, AssetRecord]:
    return {asset.ip: asset for asset in ASSETS}


def serialize_asset(asset: AssetRecord) -> dict[str, str]:
    return asdict(asset)
