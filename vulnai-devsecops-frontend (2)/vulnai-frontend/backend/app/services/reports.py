import io
import json
import csv
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def _format_duration(duration) -> str:
    if duration is None:
        return "N/A"
    try:
        dur_val = float(duration)
        mins = int(dur_val // 60)
        secs = int(dur_val % 60)
        if mins > 0:
            return f"{mins}m {secs}s ({round(dur_val, 1)}s)"
        return f"{round(dur_val, 1)}s"
    except (ValueError, TypeError):
        return str(duration)

def _format_datetime(dt) -> str:
    if not dt:
        return "N/A"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(dt)

def generate_pdf(scan_data: dict, vulns_data: list) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    title_style = styles['Heading1']
    h2_style = styles['Heading2']
    h3_style = styles['Heading3']
    normal_style = styles['Normal']
    
    elements = []
    
    # Timing Metadata Preparation
    now_utc = datetime.now(timezone.utc)
    report_gen_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    started_str = _format_datetime(scan_data.get('started_at'))
    completed_str = _format_datetime(scan_data.get('completed_at') or scan_data.get('ended_at'))
    dur_str = _format_duration(scan_data.get('duration'))

    # Base Metadata
    elements.append(Paragraph("VulnAI DevSecOps - Security Assessment Report", title_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("<b>Notice:</b> Automated security assessment report. Scanner output represents indicators that must be manually validated before being treated as confirmed vulnerabilities. This assessment records observed evidence and does not claim or certify that the target is completely secure.", normal_style))
    elements.append(Spacer(1, 12))
    
    target_display = scan_data.get('target_url') or (scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown')
    elements.append(Paragraph(f"<b>Target URL:</b> {target_display}", normal_style))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan_data.get('_id')}", normal_style))
    elements.append(Paragraph(f"<b>Report Generated At:</b> {report_gen_str}", normal_style))
    elements.append(Paragraph(f"<b>Scan Started At:</b> {started_str}", normal_style))
    if completed_str != "N/A":
        elements.append(Paragraph(f"<b>Scan Completed At:</b> {completed_str}", normal_style))
    elements.append(Paragraph(f"<b>Total Execution Duration:</b> {dur_str}", normal_style))
    
    risk_score = scan_data.get('risk_score', {})
    elements.append(Paragraph(f"<b>Security Score:</b> {risk_score.get('score', 'N/A')} / 100", normal_style))
    elements.append(Paragraph(f"<b>Risk Level:</b> {risk_score.get('rating', 'N/A')}", normal_style))
    elements.append(Spacer(1, 14))

    # Dedicated Execution & Report Timeline Section
    elements.append(Paragraph("Report Generation & Execution Timeline", h2_style))
    timeline_data = [
        ["Report Generated At", report_gen_str],
        ["Scan Started At", started_str],
        ["Scan Completed At", completed_str],
        ["Total Scan Duration", dur_str],
    ]
    t_timeline = Table(timeline_data, colWidths=[150, 330])
    t_timeline.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#38bdf8")),
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BACKGROUND', (1,0), (1,-1), colors.HexColor("#f8fafc")),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor("#1e293b")),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
    ]))
    elements.append(t_timeline)
    elements.append(Spacer(1, 16))
    
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

def generate_csv(vulns_data: list, scan_data: dict = None) -> io.StringIO:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    now_utc = datetime.now(timezone.utc)
    report_gen_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    if scan_data:
        target_display = scan_data.get('target_url') or (scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown')
        started_str = _format_datetime(scan_data.get('started_at'))
        completed_str = _format_datetime(scan_data.get('completed_at') or scan_data.get('ended_at'))
        dur_str = _format_duration(scan_data.get('duration'))

        writer.writerow(["# VulnAI DevSecOps Assessment Report"])
        writer.writerow(["# Report Generated At", report_gen_str])
        writer.writerow(["# Target Host / URL", target_display])
        writer.writerow(["# Scan Started At", started_str])
        writer.writerow(["# Scan Completed At", completed_str])
        writer.writerow(["# Total Execution Duration", dur_str])
        writer.writerow([])

    writer.writerow([
        "Title", "Severity", "Target URL", "Status", "Confidence",
        "OWASP ID", "CWE ID", "Description", "Recommendation", "Report Generated At"
    ])
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
            v.get('ai_analysis', {}).get('recommendation', ''),
            report_gen_str
        ])
    buffer.seek(0)
    return buffer

def generate_json(scan_data: dict, vulns_data: list) -> io.StringIO:
    buffer = io.StringIO()
    now_utc = datetime.now(timezone.utc)
    report_gen_iso = now_utc.isoformat()
    duration = scan_data.get("duration")
    dur_str = _format_duration(duration)

    started = scan_data.get('started_at')
    started_iso = started.isoformat() if isinstance(started, datetime) else str(started or "")
    completed = scan_data.get('completed_at') or scan_data.get('ended_at')
    completed_iso = completed.isoformat() if isinstance(completed, datetime) else str(completed or "")

    target_display = scan_data.get('target_url') or (scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown')

    payload = {
        "report_metadata": {
            "report_generated_at": report_gen_iso,
            "scan_id": str(scan_data.get("_id")),
            "target": target_display,
            "scan_started_at": started_iso,
            "scan_completed_at": completed_iso,
            "duration_seconds": duration,
            "duration_formatted": dur_str,
        },
        "scan_data": {
            "scan_id": str(scan_data.get("_id")),
            "target_urls": scan_data.get("target_urls", []),
            "started_at": started_iso,
            "completed_at": completed_iso,
            "duration": duration,
            "duration_formatted": dur_str,
            "report_generated_at": report_gen_iso,
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
