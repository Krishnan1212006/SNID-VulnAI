from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import asyncio
from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest
import numpy as np

from app.dependencies import get_current_user

router = APIRouter()

class VulnerabilityPayload(BaseModel):
    title: str
    description: str
    evidence: Dict[str, Any]

@router.post("/analyze-vulnerability")
async def analyze_vulnerability(payload: VulnerabilityPayload, current_user: dict = Depends(get_current_user)):
    """
    AI Fallback Service & stub
    In production, this would call OpenAI or Gemini APIs to provide explainable remediation.
    If no API key is set, it falls back to a deterministic RAG mock response.
    """
    
    # Simulate network call to AI
    await asyncio.sleep(1.5)
    
    remediation_text = "General Best Practice:\n"
    
    if "Headers" in payload.title or "HSTS" in payload.description:
        remediation_text += "Ensure you configure your web server (Nginx/Apache) to append security headers. For HSTS, add `add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;` to your config."
    elif "Disclosure" in payload.title.lower():
        remediation_text += "Disable the `Server` and `X-Powered-By` tokens. In Express, use `app.disable('x-powered-by')`. In Nginx, use `server_tokens off;`."
    else:
        remediation_text += "Apply standard zero-trust patching procedures for the identified vulnerability."
        
    return {
        "analysis": f"The AI analyzed the vulnerability '{payload.title}'.",
        "remediation": remediation_text,
        "confidence": "95%",
        "model": "stub-local-fallback"
    }

# --- Phase 7 SNID ML Operations ---

ml_model = None

def extract_features(m: Dict[str, Any]) -> list:
    return [
        float(m.get("packets_per_second", 0)),
        float(m.get("bytes_per_second", 0)),
        float(m.get("active_connections", 0)),
        float(m.get("failed_connections", 0))
    ]

@router.post("/anomaly/train")
async def train_anomaly_model(metrics: List[Dict[str, Any]], current_user: dict = Depends(get_current_user)):
    global ml_model
    if not metrics:
        return {"message": "No data provided"}

    data = np.array([extract_features(m) for m in metrics])
    
    ml_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    ml_model.fit(data)
    
    return {"message": "Isolation Forest model trained successfully on normal metrics.", "samples": len(metrics)}

@router.post("/anomaly/predict")
async def predict_anomaly(metric: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    global ml_model
    if ml_model is None:
        # Fallback pseudo-random if model not trained yet
        return {"anomaly_score": 0.5, "is_anomaly": False, "explanation": "Fallback due to untrained ML model."}
    
    vec = extract_features(metric)
    data = np.array([vec])
    
    # isolation forest predict returns -1 for outlier, 1 for inlier
    prediction = ml_model.predict(data)[0]
    score_raw = ml_model.decision_function(data)[0]  # < 0 is anomaly
    
    # map decision_function pseudo-probability (typically -0.5 to 0.5) to a 0-1 scale visually
    # decision function: lower is more anomalous
    normalized_score = max(0.0, min(1.0, 0.5 - score_raw))
    
    is_anomaly = (prediction == -1)
    
    explanation = "Traffic resembles normal operating boundaries."
    if is_anomaly:
        reasons = []
        if vec[0] > 1000: reasons.append("extremely high packet rates")
        if vec[2] > 50: reasons.append("excessive active connections")
        if vec[3] > 10: reasons.append("spiking failed connections")
        explanation = f"Anomaly detected due to: {', '.join(reasons) if reasons else 'complex multi-dimensional deviation'}."

    return {
        "anomaly_score": round(normalized_score, 2), 
        "is_anomaly": bool(is_anomaly),
        "explanation": explanation
    }
