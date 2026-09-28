from typing import List, Dict, Any

class RiskScore:
    def __init__(self, findings: List[Dict[str, Any]], asset_criticality: float = 1.0, is_public: bool = True):
        self.findings = findings
        self.asset_criticality = asset_criticality
        self.is_public = is_public
        
    def calculate_score(self) -> Dict[str, Any]:
        """
        Explainable Risk Scoring Engine
        Base score is 100.
        finding_risk = severity_weight * confidence * exposure_factor * asset_criticality_factor
        Weights:
        - Critical: 10
        - High: 7
        - Medium: 4
        - Low: 1
        """
        weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0
        }
        
        exposure_factor = 1.2 if self.is_public else 0.8
        
        total_deductions = 0
        explanations = []
        
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            conf_val = f.get("confidence", 1.0)
            if isinstance(conf_val, str):
                conf_map = {
                    "confirmed": 1.0,
                    "potential": 0.75,
                    "informational": 0.3,
                    "incomplete": 0.2
                }
                confidence = conf_map.get(conf_val.lower(), 0.75)
            else:
                try:
                    confidence = float(conf_val)
                except (ValueError, TypeError):
                    confidence = 1.0
            weight = weights.get(sev, 0)
            finding_risk = weight * confidence * exposure_factor * self.asset_criticality
            
            if finding_risk > 0:
                total_deductions += finding_risk
                explanations.append({
                    "finding": f.get("title", "Unknown Finding"),
                    "deduction": round(finding_risk, 2),
                    "reason": f"Severity {sev} (wt: {weight}) x Conf {confidence} x Exp Fact {exposure_factor} x Crit {self.asset_criticality}"
                })
                
        # Deduct active incident risk (stub for now, suppose 0)
        incident_risk = 0
        
        final_score = 100 - total_deductions - incident_risk
        
        final_score = max(0, min(100, final_score))
        final_score = round(final_score)
        
        if final_score >= 80:
            rating = "Low"
        elif final_score >= 60:
            rating = "Medium"
        elif final_score >= 40:
            rating = "High"
        else:
            rating = "Critical"
            
        return {
            "score": final_score,
            "rating": rating,
            "deductions": round(total_deductions, 2),
            "explanation": explanations
        }

def compute_scan_risk(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    engine = RiskScore(scan_results)
    return engine.calculate_score()
