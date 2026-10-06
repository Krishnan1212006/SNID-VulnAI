"""
Unified Security Finding Model for VulnAI DevSecOps.

Semantic verification states:
- CONFIRMED: Evidence is sufficiently validated.
- POTENTIAL: A scanner detected a security issue, but it has not been independently confirmed.
- INFORMATIONAL: Useful reconnaissance/technology/configuration information that is not itself a confirmed vulnerability.
- INCOMPLETE: The scanner did not complete sufficiently to make a reliable conclusion.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class FindingVerification:
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFORMATIONAL = "INFORMATIONAL"
    INCOMPLETE = "INCOMPLETE"

class UnifiedFinding(BaseModel):
    id: str = Field(..., description="Unique finding identifier, e.g. VULNAI-001")
    title: str = Field(..., description="Human-readable finding title")
    description: str = Field(..., description="Technical description of the observation")
    target: str = Field(..., description="Target hostname or URL")
    endpoint: Optional[str] = Field(default="/", description="Affected path or endpoint")
    parameter: Optional[str] = Field(default=None, description="Affected request parameter")
    severity: str = Field(default="info", description="critical, high, medium, low, info")
    confidence: str = Field(default="MEDIUM", description="HIGH, MEDIUM, LOW")
    verification_status: str = Field(default=FindingVerification.POTENTIAL, description="CONFIRMED, POTENTIAL, INFORMATIONAL, INCOMPLETE")
    category: str = Field(default="Security Misconfiguration", description="Risk category")
    owasp_category: str = Field(default="A05:2021 - Security Misconfiguration", description="OWASP Top 10 category")
    cwe: str = Field(default="Not mapped", description="CWE identifier, e.g. CWE-1021")
    wstg: str = Field(default="Not mapped", description="OWASP WSTG identifier, e.g. WSTG-CONF-07")
    detected_by: List[str] = Field(default_factory=list, description="Scanners that observed this finding, e.g. ['Nikto', 'Wapiti']")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw evidence, response headers, matched patterns")
    impact: str = Field(default="", description="Security impact explanation")
    recommendation: str = Field(default="", description="Remediation steps")
    references: List[str] = Field(default_factory=list, description="Authoritative reference URLs")
    raw_evidence_files: List[str] = Field(default_factory=list, description="Paths to scanner output files")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = Field(...)
    asset_id: Optional[str] = None
    owner_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "target_url": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "severity": self.severity.lower(),
            "confidence": self.confidence,
            "verification_status": self.verification_status,
            "category": self.category,
            "owasp_id": self.owasp_category.split(" ")[0] if self.owasp_category else "Not mapped",
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe,
            "cwe": self.cwe,
            "wstg": self.wstg,
            "detected_by": self.detected_by,
            "scanner": ", ".join(self.detected_by) if self.detected_by else "unknown",
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "references": self.references,
            "raw_evidence_files": self.raw_evidence_files,
            "first_seen": self.first_seen.isoformat(),
            "created_at": self.first_seen,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "owner_id": self.owner_id,
            "status": "open",
            "ai_analysis": {
                "problem": self.description,
                "impact": self.impact,
                "recommendation": self.recommendation,
                "verification_steps": [
                    f"Inspect endpoint {self.endpoint} on {self.target}.",
                    f"Verify using {', '.join(self.detected_by)} evidence.",
                    "Validate remediation using targeted request."
                ]
            }
        }
