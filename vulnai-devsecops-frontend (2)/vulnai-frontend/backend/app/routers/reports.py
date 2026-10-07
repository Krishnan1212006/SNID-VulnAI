from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from app.core.ids import ObjectId
from app.database import get_database
from app.dependencies import get_current_user
from app.routers.audit import log_audit_action
from app.services.reports import generate_pdf, generate_csv, generate_json
from app.services.unified_scan import compile_scan_results_from_disk

router = APIRouter()

@router.get("/{scan_id}/pdf")
async def get_report_pdf(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    scan = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(length=1000)
    if not scan.get("combined_results") or not vulns:
        compiled_scan, compiled_vulns = await compile_scan_results_from_disk(scan_id, db=db)
        if compiled_scan:
            scan = compiled_scan
            vulns = compiled_vulns
    
    pdf_buffer = generate_pdf(scan, vulns)
    
    await log_audit_action(current_user["_id"], "Downloaded PDF Report", {"scan_id": scan_id})
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"}
    )

@router.get("/{scan_id}/csv")
async def get_report_csv(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    scan = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(length=1000)
    if not scan.get("combined_results") or not vulns:
        compiled_scan, compiled_vulns = await compile_scan_results_from_disk(scan_id, db=db)
        if compiled_scan:
            scan = compiled_scan
            vulns = compiled_vulns
    
    csv_buffer = generate_csv(vulns, scan)
    
    await log_audit_action(current_user["_id"], "Downloaded CSV Report", {"scan_id": scan_id})
    return StreamingResponse(
        csv_buffer, 
        media_type="text/csv", 
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.csv"}
    )
    
@router.get("/{scan_id}/json")
async def get_report_json(scan_id: str, current_user: dict = Depends(get_current_user)):
    db = get_database()
    try:
        obj_id = ObjectId(scan_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid scan ID")
        
    scan = await db.scans.find_one({"_id": obj_id, "owner_id": str(current_user["_id"])})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(length=1000)
    if not scan.get("combined_results") or not vulns:
        compiled_scan, compiled_vulns = await compile_scan_results_from_disk(scan_id, db=db)
        if compiled_scan:
            scan = compiled_scan
            vulns = compiled_vulns
    
    json_buffer = generate_json(scan, vulns)
    
    await log_audit_action(current_user["_id"], "Downloaded JSON Report", {"scan_id": scan_id})
    return StreamingResponse(
        json_buffer, 
        media_type="application/json", 
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
    )
