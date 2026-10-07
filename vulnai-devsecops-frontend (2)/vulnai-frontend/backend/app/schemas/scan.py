from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import List, Optional, Any, Dict

class ScanCreate(BaseModel):
    target: Optional[str] = None
    asset_id: Optional[str] = None
    target_urls: Optional[List[str]] = None  # If not provided, will scan all URLs from asset
    authorized: bool = Field(..., description="Must confirm authorization")
    lab_mode: bool = False
    kali_mode: bool = False
    unified_mode: bool = False

    model_config = ConfigDict(extra='ignore')

class ToolExecutionStatus(BaseModel):
    status: str = Field(default="pending", description="pending|running|completed|timeout|failed")
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    raw_output: str = ""
    error: Optional[str] = None

    model_config = ConfigDict(extra='ignore')

class ScanResponse(BaseModel):
    id: str
    scan_id: Optional[str] = None
    target: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    asset_id: Optional[str] = None
    owner_id: Optional[str] = None
    status: str = "running"
    progress: int = 0
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    target_url: Optional[str] = None
    target_urls: Optional[List[str]] = None   # Alias for Reports page compatibility
    tools: Optional[Dict[str, Any]] = None
    findings: Optional[List[Dict[str, Any]]] = None
    score: Optional[int] = None
    risk_level: Optional[str] = None
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
