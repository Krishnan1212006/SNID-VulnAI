import io
import json
import csv
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf(scan_data: dict, vulns_data: list) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = styles['Heading1']
    h2_style = styles['Heading2']
    h3_style = styles['Heading3']
    normal_style = styles['Normal']
    
    elements = []
    
    # Base Metadata
    elements.append(Paragraph("VulnAI DevSecOps - Security Assessment Report", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Notice:</b> Automated security assessment report. Scanner output represents indicators that must be manually validated before being treated as confirmed vulnerabilities. This assessment records observed evidence and does not claim or certify that the target is completely secure.", normal_style))
    elements.append(Spacer(1, 12))
    
    target_display = scan_data.get('target_url') or (scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown')
    elements.append(Paragraph(f"<b>Target URL:</b> {target_display}", normal_style))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan_data.get('_id')}", normal_style))
    started = scan_data.get('started_at')
    date_str = started.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(started, datetime) else str(started)
    elements.append(Paragraph(f"<b>Scan Date:</b> {date_str}", normal_style))
    
    risk_score = scan_data.get('risk_score', {})
    elements.append(Paragraph(f"<b>Security Score:</b> {risk_score.get('score', 'N/A')} / 100", normal_style))
    elements.append(Paragraph(f"<b>Risk Level:</b> {risk_score.get('rating', 'N/A')}", normal_style))
    elements.append(Spacer(1, 12))
    
    # Severity Summary
    elements.append(Paragraph("Severity Summary", h2_style))
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns_data:
        s = v.get("severity", "info").lower()
        if s in sev_counts:
            sev_counts[s] += 1
            
    sev_data = [["Critical", "High", "Medium", "Low", "Info"],
                [str(sev_counts['critical']), str(sev_counts['high']), str(sev_counts['medium']), str(sev_counts['low']), str(sev_counts['info'])]]
    t = Table(sev_data, colWidths=80)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))
    
    # Risk-score explanation
    elements.append(Paragraph("Risk-Score Explanation", h2_style))
    for exp in risk_score.get('explanation', []):
        elements.append(Paragraph(f"• {exp.get('finding', 'Finding')}: {exp.get('reason', '')} (Deduction: -{exp.get('deduction', 0)})", normal_style))
    if not risk_score.get('explanation'):
        elements.append(Paragraph("No deductions applied.", normal_style))
    elements.append(Spacer(1, 20))
    
    # Vulnerabilities
    elements.append(Paragraph("Vulnerability Findings", h2_style))
    if not vulns_data:
        elements.append(Paragraph("No vulnerabilities were discovered.", normal_style))
    for v in vulns_data:
        elements.append(Paragraph(f"{v.get('title', 'Unknown')}", h3_style))
        elements.append(Paragraph(f"<b>Severity:</b> {v.get('severity', 'info')} | <b>Status:</b> {v.get('status', 'open')} | <b>Confidence:</b> {v.get('confidence', 1.0)}", normal_style))
        elements.append(Paragraph(f"<b>OWASP ID:</b> {v.get('owasp_id', 'Unknown')} | <b>CWE ID:</b> {v.get('cwe_id', 'Unknown')}", normal_style))
        
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Description:</b> {v.get('description', '')}", normal_style))
        
        evidence = json.dumps(v.get('evidence', {}))[:200] + "..." if len(json.dumps(v.get('evidence', {}))) > 200 else json.dumps(v.get('evidence', {}))
        elements.append(Paragraph(f"<b>Evidence:</b> {evidence}", normal_style))
        
        ai = v.get('ai_analysis', {})
        if ai:
            elements.append(Paragraph(f"<b>AI Problem Analysis:</b> {ai.get('problem', '')}", normal_style))
            elements.append(Paragraph(f"<b>AI Impact Analysis:</b> {ai.get('impact', '')}", normal_style))
            elements.append(Paragraph(f"<b>Recommendation:</b> {ai.get('recommendation', '')}", normal_style))
            
            steps = ai.get('verification_steps', [])
            if steps:
                elements.append(Paragraph("<b>Verification Steps:</b>", normal_style))
                for i, step in enumerate(steps, 1):
                    elements.append(Paragraph(f"{i}. {step}", normal_style))
        
        elements.append(Spacer(1, 12))

    combined_results = scan_data.get("combined_results") or {}
    if combined_results:
        elements.append(Paragraph("Unified Scanner Results", h2_style))
        scanner_status = combined_results.get("scanner_status", {})
        scanner_details = combined_results.get("scanner_details", {})
        for scanner, scanner_state in scanner_status.items():
            detail = scanner_details.get(scanner, {})
            elements.append(Paragraph(
                escape(f"{scanner}: {scanner_state} (exit code: {detail.get('exit_code')})"),
                normal_style,
            ))

        for classification in ("confirmed", "potential", "informational", "incomplete"):
            observations = combined_results.get(classification, [])
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(f"{classification.title()} Observations ({len(observations)})", h3_style))
            if not observations:
                elements.append(Paragraph("None.", normal_style))
                continue
            for observation in observations:
                scanner = escape(str(observation.get("scanner", "unknown")))
                title = escape(str(observation.get("title") or observation.get("path") or observation.get("message") or "Scanner observation"))
                elements.append(Paragraph(f"<b>{scanner}:</b> {title}", normal_style))
                verification = escape(str(observation.get("verification_status", "unverified")))
                elements.append(Paragraph(f"<b>Classification:</b> {classification} | <b>Verification:</b> {verification}", normal_style))
                status_code = observation.get("status_code")
                if status_code is not None:
                    elements.append(Paragraph(
                        escape(f"HTTP {status_code}; {observation.get('response_size', 'unknown')} bytes"),
                        normal_style,
                    ))
                output_file = observation.get("evidence", {}).get("raw_output_file") if isinstance(observation.get("evidence"), dict) else None
                output_file = output_file or observation.get("raw_output_file")
                if output_file:
                    elements.append(Paragraph(f"<b>Evidence:</b> {escape(str(output_file))}", normal_style))
                description = observation.get("description") or observation.get("raw_line") or observation.get("message")
                if description:
                    elements.append(Paragraph(escape(str(description)[:1200]), normal_style))
                elements.append(Spacer(1, 6))
        
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_csv(vulns_data: list) -> io.StringIO:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Title", "Severity", "Target URL", "Status", "Confidence", "OWASP ID", "CWE ID", "Description", "Recommendation"])
    for v in vulns_data:
        writer.writerow([
            v.get('title'),
            v.get('severity'),
            v.get('target_url'),
            v.get('status'),
            v.get('confidence'),
            v.get('owasp_id'),
            v.get('cwe_id'),
            v.get('description'),
            v.get('ai_analysis', {}).get('recommendation', '')
        ])
    buffer.seek(0)
    return buffer

def generate_json(scan_data: dict, vulns_data: list) -> io.StringIO:
    buffer = io.StringIO()
    payload = {
        "scan_data": {
            "scan_id": str(scan_data.get("_id")),
            "target_urls": scan_data.get("target_urls", []),
            "started_at": str(scan_data.get("started_at")),
            "risk_score": scan_data.get("risk_score", {})
        },
        "combined_results": _json_safe(scan_data.get("combined_results", {})),
        "vulnerabilities": []
    }
    for v in vulns_data:
        vd = v.copy()
        vd["_id"] = str(vd.get("_id"))
        if "created_at" in vd:
            vd["created_at"] = str(vd["created_at"])
        if "updated_at" in vd:
            vd["updated_at"] = str(vd["updated_at"])
        payload["vulnerabilities"].append(vd)
        
    json.dump(payload, buffer, indent=2)
    buffer.seek(0)
    return buffer


def _json_safe(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "__str__") and value.__class__.__name__ == "ObjectId":
        return str(value)
    return value
