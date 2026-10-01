import json
from typing import Dict, Any, List
from app.core.paths import APP_ROOT

RULES_PATH = APP_ROOT / "rules" / "policies.json"

class RuleEngine:
    def __init__(self):
        try:
            with open(RULES_PATH, 'r') as f:
                data = json.load(f)
                self.rules = {r["rule_id"]: r for r in data.get("rules", [])}
        except Exception as e:
            print(f"Failed to load rules: {e}")
            self.rules = {}

    def evaluate(self, rule_id: str, target_url: str, evidence: Dict[str, Any], confidence: float = 1.0) -> Dict[str, Any]:
        rule = self.rules.get(rule_id)
        if not rule:
            # Fallback if rule not defined
            return {
                "title": f"Unknown finding: {rule_id}",
                "severity": "info",
                "confidence": confidence,
                "category": "unknown",
                "owasp_id": "Unknown",
                "cwe_id": "Unknown",
                "target_url": target_url,
                "evidence": evidence,
                "status": "open",
                "ai_analysis": {
                    "priority": "low",
                    "problem": "Undocumented scanner finding.",
                    "impact": "Unknown impact.",
                    "recommendation": "Review manually.",
                    "verification_steps": ["Review evidence."]
                }
            }
            
        return {
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": confidence,
            "category": rule["category"],
            "owasp_id": rule["owasp_id"],
            "cwe_id": rule["cwe_id"],
            "target_url": target_url,
            "evidence": evidence,
            "status": "open",
            "ai_analysis": {
                "priority": rule["severity"],
                "problem": rule["description"],
                "impact": "Misconfiguration exposes the application or its users to potential attacks.",
                "recommendation": rule.get("remediation_template", ""),
                "verification_steps": [
                    "Verify the configuration change in a staging environment.",
                    "Deploy the mitigation.",
                    "Re-run an automated scan to confirm the fix."
                ]
            }
        }
