"""
Domain Security Assessment Router.
Provides endpoints for initiating, monitoring, and retrieving domain security assessments.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.database import get_database
from app.dependencies import get_current_user
from app.services.domain_assessment import (
    DomainAssessmentEngine,
    ACTIVE_DOMAIN_JOBS,
)

router = APIRouter()


class DomainAssessRequest(BaseModel):
    target: str = Field(..., description="Target domain or authorized URL, e.g. scanme.nmap.org")
    authorized: bool = Field(..., description="Confirmation that the requester has explicit authorization to assess this target")
    active_sqli: bool = Field(False, description="Whether to perform authorized active SQLMap test")
    allow_internal: bool = Field(False, description="Explicit authorization for internal network evaluation")


@router.post("/assess")
async def start_domain_assessment(
    req: DomainAssessRequest,
    current_user: dict = Depends(get_current_user),
):
    """Initiate a domain security assessment job."""
    if not req.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must confirm you have authorization to assess this target.",
        )

    clean_target = req.target.strip()
    if not clean_target or len(clean_target) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid domain name or URL is required.",
        )

    db = get_database()
    owner_id = str(current_user["_id"])
    job_id = f"dom-{uuid.uuid4().hex[:10]}"

    engine = DomainAssessmentEngine(db, owner_id)
    try:
        report = await engine.run_assessment(
            job_id=job_id,
            target_input=clean_target,
            active_sqli=req.active_sqli,
            allow_internal=req.allow_internal,
        )
        return report
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Assessment failed: {exc}")


@router.get("/assess/{job_id}")
async def get_assessment_status(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Retrieve status and live progress of a domain assessment job."""
    db = get_database()
    owner_id = str(current_user["_id"])

    if job_id in ACTIVE_DOMAIN_JOBS:
        return ACTIVE_DOMAIN_JOBS[job_id]

    doc = await db.domain_assessments.find_one({"job_id": job_id, "owner_id": owner_id})
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    doc["id"] = str(doc["_id"])
    doc.pop("_id", None)
    return doc


@router.post("/assess/{job_id}/cancel")
async def cancel_assessment(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Cancel a running domain assessment."""
    if job_id in ACTIVE_DOMAIN_JOBS:
        ACTIVE_DOMAIN_JOBS[job_id]["cancelled"] = True
        ACTIVE_DOMAIN_JOBS[job_id]["status"] = "CANCELLED"
        return {"message": "Assessment cancelled", "job_id": job_id}
    return {"message": "Job not active or already finished", "job_id": job_id}


@router.get("/history")
async def list_assessment_history(
    limit: int = Query(25, le=100),
    current_user: dict = Depends(get_current_user),
):
    """List historical domain assessments for the current user."""
    db = get_database()
    owner_id = str(current_user["_id"])

    cursor = db.domain_assessments.find({"owner_id": owner_id}).sort("start_time", -1)
    items = await cursor.to_list(limit)

    summary_list = []
    for it in items:
        it["id"] = str(it["_id"])
        it.pop("_id", None)
        summary_list.append({
            "id": it["id"],
            "job_id": it.get("job_id"),
            "domain": it.get("domain"),
            "target_url": it.get("target_url"),
            "status": it.get("status"),
            "start_time": it.get("start_time"),
            "duration_seconds": it.get("duration_seconds"),
            "architecture_label": it.get("technology", {}).get("architecture_label", "N/A"),
            "resolved_ips": it.get("resolved_ips", []),
            "open_ports_count": len(it.get("nmap", {}).get("open_ports", [])),
        })

    return summary_list


@router.delete("/history/{job_id}")
async def delete_assessment(
    job_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Remove a historical assessment record."""
    db = get_database()
    owner_id = str(current_user["_id"])

    res = await db.domain_assessments.delete_one({"job_id": job_id, "owner_id": owner_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    return {"message": "Assessment record removed"}
