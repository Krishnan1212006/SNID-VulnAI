from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import List, Optional, Any, Dict

class ScanCreate(BaseModel):
    asset_id: Optional[str] = None
    target_urls: Optional[List[str]] = None  # If not provided, will scan all URLs from asset
    authorized: bool = Field(..., description="Must confirm authorization")
    lab_mode: bool = False
    kali_mode: bool = False
    unified_mode: bool = False

class ScanResponse(BaseModel):
    id: str
    asset_id: str
    owner_id: str
    status: str
    progress: int
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    target_url: Optional[str] = None
    target_urls: Optional[List[str]] = None   # Alias for Reports page compatibility
    security_score: Optional[int] = None
    risk_score: Optional[Dict[str, Any]] = None  # Full nested risk score object
    total_findings: Optional[int] = 0
    severity_summary: Optional[Dict[str, int]] = {}
    kali_mode: Optional[bool] = False
    unified_mode: Optional[bool] = False
    lab_mode: Optional[bool] = False
    scanner_status: Optional[Dict[str, str]] = {}
    scanner_details: Optional[Dict[str, Any]] = {}
    runtime_status: Optional[Dict[str, Any]] = None
    evidence_files: Optional[Dict[str, str]] = {}
    report_html_path: Optional[str] = None
    report_md_path: Optional[str] = None

    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    tool_summaries: Optional[Dict[str, Any]] = {}

    model_config = ConfigDict(extra='ignore')

class ScanResultResponse(BaseModel):
    scan_id: str
    status: str
    results: List[Dict[str, Any]] = []
    issues_found: int = 0
    confirmed: Optional[List[Dict[str, Any]]] = []
    potential: Optional[List[Dict[str, Any]]] = []
    informational: Optional[List[Dict[str, Any]]] = []
    incomplete: Optional[List[Dict[str, Any]]] = []
    unverified: Optional[List[Dict[str, Any]]] = []
    technology_detection: Optional[Dict[str, Any]] = None
    tool_summaries: Optional[Dict[str, Any]] = {}

    model_config = ConfigDict(extra='ignore')
