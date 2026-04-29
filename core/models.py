from dataclasses import dataclass, field
from typing import Any

@dataclass(slots=True)
class StandardCVEAlert:
    """Neutrally formatted Data Transfer Object for CVE Alerts."""
    cve_id: str
    cvss_score: float | None
    severity: str
    risk_tag: str
    vendor: str
    product: str
    description: str
    url: str
    date: str
    impacted_clients: list[str] = field(default_factory=list)
    epss_score: float | None = None
    in_cisa_kev: bool = False
    has_exploit_db: bool = False
    headline: str = ""
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class StandardCTINews:
    """Neutrally formatted Data Transfer Object for CTI News."""
    title: str
    url: str
    source: str
    layer: int
    summary: str
    date: str
    matched_assets: list[str] = field(default_factory=list)
