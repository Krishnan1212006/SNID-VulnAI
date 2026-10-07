"""
Unified Security Finding Model for VulnAI DevSecOps.

Semantic verification states:
- CONFIRMED: Evidence is sufficiently validated.
- POTENTIAL: A scanner detected a security issue, but it has not been independently confirmed.
- INFORMATIONAL: Useful reconnaissance/technology/configuration information that is not itself a confirmed vulnerability.
- INCOMPLETE: The scanner did not complete sufficiently to make a reliable conclusion.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field


class FindingVerification:
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"
    INCOMPLETE = "INCOMPLETE"


class UnifiedFinding(BaseModel):
    id: str = Field(..., description="Unique finding identifier, e.g. VULNAI-001")
    scan_id: str = Field(..., description="Associated scan identifier")
    tool: Optional[str] = Field(default="nikto", description="Primary scanner tool name")
    title: str = Field(..., description="Human-readable finding title")
    category: str = Field(default="Security Misconfiguration", description="Risk category")
    severity: str = Field(default="LOW", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence: Union[int, float, str] = Field(default=85, description="Evidence confidence score (0-100)")
    status: str = Field(default="potential", description="potential, confirmed, informational, incomplete")
    target: str = Field(..., description="Target hostname or URL")
    endpoint: Optional[str] = Field(default="/", description="Affected path or endpoint")
    parameter: Optional[str] = Field(default=None, description="Affected request parameter")
    evidence: Any = Field(default_factory=dict, description="Raw evidence, response headers, matched patterns")
    description: str = Field(default="", description="Technical description of the observation")
    recommendation: str = Field(default="", description="Remediation steps")
    cve: Optional[str] = Field(default=None, description="CVE identifier or null")
    cwe: Optional[str] = Field(default=None, description="CWE identifier or null")
    source: Optional[str] = Field(default="nikto", description="Scanner source identifier")
    raw_reference: Optional[str] = Field(default=None, description="Raw scanner line reference")
    timestamp: Optional[str] = None

    # Extended assessment fields
    verification_status: str = Field(default=FindingVerification.POTENTIAL, description="CONFIRMED, POTENTIAL, INFORMATIONAL, INCOMPLETE")
    owasp_category: str = Field(default="A05:2021 - Security Misconfiguration", description="OWASP Top 10 category")
    wstg: str = Field(default="Not mapped", description="OWASP WSTG identifier, e.g. WSTG-CONF-07")
    detected_by: List[str] = Field(default_factory=list, description="Scanners that observed this finding")
    impact: str = Field(default="", description="Security impact explanation")
    references: List[str] = Field(default_factory=list, description="Authoritative reference URLs")
    raw_evidence_files: List[str] = Field(default_factory=list, description="Paths to scanner output files")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    asset_id: Optional[str] = None
    owner_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        sev_upper = self.severity.upper()
        conf_val = self.confidence
        if isinstance(conf_val, str):
            try:
                conf_num = int(float(conf_val))
            except ValueError:
                conf_map = {"CONFIRMED": 95, "HIGH": 85, "POTENTIAL": 75, "MEDIUM": 70, "LOW": 50, "INFORMATIONAL": 20}
                conf_num = conf_map.get(conf_val.upper(), 75)
        else:
            conf_num = int(conf_val) if conf_val <= 100 else 85
            if 0 < conf_num <= 1:  # converted from 0.0-1.0 float scale
                conf_num = int(conf_num * 100)

        ev_str = self.evidence if isinstance(self.evidence, str) else (
            self.evidence.get("raw") or self.evidence.get("nikto_finding") or self.evidence.get("raw_line") or str(self.evidence)
        )

        detected_list = self.detected_by if self.detected_by else ([self.tool.capitalize()] if self.tool else ["Nikto"])
        ts = self.timestamp or self.first_seen.isoformat()

        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "tool": self.tool or (detected_list[0].lower() if detected_list else "nikto"),
            "title": self.title,
            "category": self.category,
            "severity": sev_upper,
            "confidence": conf_num,
            "status": self.status.lower() if self.status in ("potential", "confirmed", "informational", "incomplete") else (
                self.verification_status.lower() if self.verification_status in ("POTENTIAL", "CONFIRMED", "INFORMATIONAL", "INCOMPLETE") else "potential"
            ),
            "target": self.target,
            "target_url": self.target,
            "endpoint": self.endpoint or "/",
            "parameter": self.parameter,
            "evidence": ev_str,
            "raw_evidence": self.evidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "cve": self.cve if self.cve not in ("Not mapped", "None", "") else None,
            "cwe": self.cwe if self.cwe not in ("Not mapped", "None", "") else None,
            "source": self.source or self.tool or "nikto",
            "raw_reference": self.raw_reference or (self.raw_evidence_files[0] if self.raw_evidence_files else f"scan-results/{self.scan_id}/"),
            "timestamp": ts,
            "created_at": self.first_seen,

            # Backwards-compatibility mappings for existing UI & routes
            "verification_status": self.verification_status,
            "owasp_id": self.owasp_category.split(" ")[0] if self.owasp_category else "Not mapped",
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe or "Not mapped",
            "wstg": self.wstg,
            "detected_by": detected_list,
            "scanner": ", ".join(detected_list),
            "impact": self.impact,
            "references": self.references,
            "raw_evidence_files": self.raw_evidence_files,
            "asset_id": self.asset_id,
            "owner_id": self.owner_id,
            "ai_analysis": {
                "priority": sev_upper.lower(),
                "problem": self.description or self.title,
                "impact": self.impact,
                "recommendation": self.recommendation,
                "verification_steps": [
                    f"Inspect endpoint {self.endpoint} on {self.target}.",
                    f"Verify using {', '.join(detected_list)} evidence: {ev_str[:80]}",
                    "Validate remediation using targeted test request."
                ]
            }
        }
