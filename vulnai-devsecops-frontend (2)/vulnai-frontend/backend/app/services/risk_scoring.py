"""
VulnAI Project Risk Scoring Engine.

Transparent, project-defined risk assessment model.
Does not claim to be CVSS or an industry-standard score.
Clearly labeled as 'VulnAI Project Risk Score'.

Never awards 100/100 simply because there are zero CONFIRMED vulnerabilities
if POTENTIAL findings exist.
"""

from typing import List, Dict, Any, Optional

# Configurable deduction weights
RISK_WEIGHTS = {
    # Confirmed vulnerabilities (validated evidence)
    "confirmed": {
        "critical": 25.0,
        "high": 18.0,
        "medium": 10.0,
        "low": 4.0,
        "info": 0.0,
    },
    # Potential findings (unverified scanner observations)
    "potential": {
        "critical": 12.0,
        "high": 8.0,
        "medium": 4.0,
        "low": 1.5,
        "info": 0.0,
    },
    # Informational observations
    "informational": {
        "critical": 0.0,
        "high": 0.0,
        "medium": 0.0,
        "low": 0.0,
        "info": 0.0,
    },
    # Incomplete scanner jobs (uncertainty penalty)
    "incomplete": {
        "penalty_per_incomplete": 3.0,
    }
}


class ProjectRiskScoreEngine:
    def __init__(
        self,
        findings: List[Dict[str, Any]],
        scanner_status: Optional[Dict[str, str]] = None,
        is_public: bool = True,
    ):
        self.findings = findings
        self.scanner_status = scanner_status or {}
        self.is_public = is_public

    def calculate(self) -> Dict[str, Any]:
        """
        Calculates the transparent VulnAI Project Risk Score.
        Base Score: 100.
        """
        # If all scanners failed or no scanners ran, score cannot be determined
        terminal_states = list(self.scanner_status.values())
        if terminal_states and all(s in ("failed", "unavailable") for s in terminal_states):
            return {
                "score": None,
                "score_display": "Not Fully Determined",
                "rating": "UNDETERMINED",
                "model_name": "VulnAI Project Risk Score (Project-Defined)",
                "base_score": 100,
                "total_deductions": 0,
                "explanation": ["All security scanners failed or were unavailable. Evidence is insufficient to calculate a risk score."],
                "is_indeterminate": True,
            }

        base_score = 100.0
        total_deductions = 0.0
        deduction_items = []

        confirmed_count = 0
        potential_count = 0
        info_count = 0

        for f in self.findings:
            title = f.get("title", "Unknown Observation")
            sev = str(f.get("severity", "info")).lower()
            raw_verif = f.get("verification_status")
            if raw_verif:
                verif = str(raw_verif).lower()
            else:
                conf = f.get("confidence")
                if conf in (1.0, "1.0", "confirmed"):
                    verif = "confirmed"
                elif sev == "info" or conf in ("informational",):
                    verif = "informational"
                else:
                    verif = "potential"

            if verif == "confirmed":
                confirmed_count += 1
                deduction = RISK_WEIGHTS["confirmed"].get(sev, 0.0)
            elif verif == "informational" or sev == "info":
                info_count += 1
                deduction = RISK_WEIGHTS["informational"].get(sev, 0.0)
            else:
                potential_count += 1
                deduction = RISK_WEIGHTS["potential"].get(sev, 0.0)

            if deduction > 0:
                total_deductions += deduction
                deduction_items.append({
                    "finding": title,
                    "verification": verif.upper(),
                    "verification_status": verif.upper(),
                    "severity": sev.upper(),
                    "deduction": round(deduction, 1),
                    "reason": f"{verif.capitalize()} {sev.capitalize()} observation (-{round(deduction, 1)} pts)"
                })

        # Check for incomplete / timed out scanner jobs
        incomplete_scanners = [
            scanner for scanner, st in self.scanner_status.items()
            if st in ("timed_out", "incomplete", "cancelled")
        ]
        if incomplete_scanners:
            penalty = len(incomplete_scanners) * RISK_WEIGHTS["incomplete"]["penalty_per_incomplete"]
            total_deductions += penalty
            deduction_items.append({
                "finding": f"Incomplete Assessment ({', '.join(incomplete_scanners)})",
                "verification": "INCOMPLETE",
                "verification_status": "INCOMPLETE",
                "severity": "UNCERTAINTY",
                "deduction": round(penalty, 1),
                "reason": f"{len(incomplete_scanners)} scanner(s) did not finish cleanly; uncertainty deduction applied"
            })

        final_score = max(0, min(100, round(base_score - total_deductions)))

        if final_score >= 85:
            rating = "Low"
        elif final_score >= 65:
            rating = "Medium"
        elif final_score >= 45:
            rating = "High"
        else:
            rating = "Critical"

        return {
            "score": final_score,
            "score_display": f"{final_score} / 100",
            "rating": rating,
            "model": "VulnAI Project Risk Score (Project-Defined)",
            "model_name": "VulnAI Project Risk Score (Project-Defined)",
            "base_score": 100,
            "total_deductions": round(total_deductions, 1),
            "deductions": deduction_items,
            "explanation": deduction_items,
            "counts": {
                "confirmed": confirmed_count,
                "potential": potential_count,
                "informational": info_count,
                "incomplete": len(incomplete_scanners),
            },
            "is_indeterminate": False,
        }


def compute_scan_risk(
    findings: List[Dict[str, Any]],
    scanner_status: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    engine = ProjectRiskScoreEngine(findings, scanner_status=scanner_status)
    return engine.calculate()


class RiskScore:
    """Compatibility wrapper for tests and legacy callers."""
    def __init__(self, findings: List[Dict[str, Any]], active_incidents: int = 0):
        self.findings = findings
        self.active_incidents = active_incidents

    def calculate_score(self) -> Dict[str, Any]:
        engine = ProjectRiskScoreEngine(self.findings)
        res = engine.calculate()
        compat_res = dict(res)
        # Ensure 'deductions' is numeric for test assertion: assert res['deductions'] > 0.0
        compat_res["deductions"] = res.get("total_deductions", 0.0)
        return compat_res

