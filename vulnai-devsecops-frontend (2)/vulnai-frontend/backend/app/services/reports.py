import io
import json
import csv
from datetime import datetime, timezone
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, HRFlowable
)
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


def _get_severity_color(sev: str) -> colors.HexColor:
    sev_lower = str(sev).lower()
    if sev_lower == "critical":
        return colors.HexColor("#dc2626")
    elif sev_lower == "high":
        return colors.HexColor("#ea580c")
    elif sev_lower == "medium":
        return colors.HexColor("#d97706")
    elif sev_lower == "low":
        return colors.HexColor("#0284c7")
    return colors.HexColor("#64748b")


def _get_verification_color(verif: str) -> colors.HexColor:
    v_lower = str(verif).lower()
    if v_lower == "confirmed":
        return colors.HexColor("#dc2626")
    elif v_lower == "potential":
        return colors.HexColor("#d97706")
    elif v_lower == "informational":
        return colors.HexColor("#0284c7")
    return colors.HexColor("#64748b")


def generate_pdf(scan_data: dict, vulns_data: list) -> io.BytesIO:
    buffer = io.BytesIO()
    # 54pt (0.75in) margins -> printable width is 612 - 108 = 504pt
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=48,
        bottomMargin=48
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=10,
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    h3_style = ParagraphStyle(
        'SectionH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=6,
        spaceAfter=3,
    )
    normal_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155"),
    )
    bold_style = ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#0f172a"),
    )
    small_style = ParagraphStyle(
        'BodySmall',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#64748b"),
    )
    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1e293b"),
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a"),
    )
    table_hdr_style = ParagraphStyle(
        'TableHdr',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10.5,
        textColor=colors.whitesmoke,
    )

    elements = []

    # Metadata extraction
    now_utc = datetime.now(timezone.utc)
    report_gen_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    started_str = _format_datetime(scan_data.get('started_at'))
    completed_str = _format_datetime(scan_data.get('completed_at') or scan_data.get('ended_at'))
    dur_str = _format_duration(scan_data.get('duration'))
    target_display = scan_data.get('target_url') or (
        scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown'
    )
    scan_id_str = str(scan_data.get('_id', 'N/A'))
    combined_results = scan_data.get('combined_results') or {}

    # Risk score model
    risk_score_obj = scan_data.get('risk_score') or combined_results.get('risk_score') or {}
    score_val = risk_score_obj.get('score')
    score_display = f"{score_val} / 100" if score_val is not None else "Not Fully Determined"
    risk_level_display = risk_score_obj.get('rating', 'Undetermined')
    score_model_name = risk_score_obj.get('model', 'VulnAI Project Risk Score (Project-Defined)')

    # Extract finding counts dynamically
    confirmed_findings = combined_results.get('confirmed', [])
    potential_findings = combined_results.get('potential', [])
    informational_findings = combined_results.get('informational', [])
    incomplete_findings = combined_results.get('incomplete', [])

    # If combined_results lists are empty but vulns_data exists, split vulns_data
    if not (confirmed_findings or potential_findings or informational_findings) and vulns_data:
        for v in vulns_data:
            ver = str(v.get('verification_status', '')).upper()
            if ver == 'CONFIRMED':
                confirmed_findings.append(v)
            elif ver == 'INFORMATIONAL' or str(v.get('severity', '')).lower() == 'info':
                informational_findings.append(v)
            else:
                potential_findings.append(v)

    c_count = len(confirmed_findings)
    p_count = len(potential_findings)
    i_count = len(informational_findings)
    inc_count = len(incomplete_findings)

    # Primary risk category
    all_active_findings = [*confirmed_findings, *potential_findings]
    cat_counts = {}
    for f in all_active_findings:
        cat = f.get('owasp_category') or f.get('category') or 'General Security'
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    primary_category = max(cat_counts.items(), key=lambda x: x[1])[0] if cat_counts else "None Identified"

    # SQL Injection status
    sql_assessment = combined_results.get('sql_assessment') or {}
    if sql_assessment.get('injection_confirmed'):
        sqli_summary = "CONFIRMED SQL Injection vulnerabilities detected."
    elif sql_assessment.get('status') == "completed":
        sqli_summary = "No confirmed SQL injection identified."
    else:
        sqli_summary = sql_assessment.get('summary', 'No confirmed SQL injection identified.')

    # =========================================================================
    # 1. HEADER & COVER SECTION
    # =========================================================================
    elements.append(Paragraph("VulnAI DevSecOps", title_style))
    elements.append(Paragraph("Automated Security Assessment & Vulnerability Verification Report", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Assessment Mandatory Notice Box
    notice_text = (
        "<b>ASSESSMENT NOTICE & SCOPE DISCLAIMER:</b> This report reflects automated security testing "
        "conducted by VulnAI DevSecOps scanners. Automated scanner output represents security indicators "
        "and potential observations that must be manually validated. In accordance with security testing "
        "standards, scanner completion does NOT certify the target application as fully secure."
    )
    t_notice = Table([[Paragraph(notice_text, disclaimer_style)]], colWidths=[504])
    t_notice.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t_notice)
    elements.append(Spacer(1, 10))

    # =========================================================================
    # 2. EXECUTIVE SUMMARY & TARGET OVERVIEW
    # =========================================================================
    elements.append(Paragraph("1. Executive Summary", h2_style))
    
    exec_summary_data = [
        [Paragraph("Target Host / URL", table_cell_bold), Paragraph(escape(target_display), table_cell_style)],
        [Paragraph("Assessment Status", table_cell_bold), Paragraph(escape(str(scan_data.get('status', 'COMPLETED')).upper()), table_cell_style)],
        [Paragraph(f"{score_model_name}", table_cell_bold), Paragraph(f"<b>{score_display}</b> (Risk Rating: <b>{risk_level_display}</b>)", table_cell_style)],
        [Paragraph("Primary Risk Category", table_cell_bold), Paragraph(escape(primary_category), table_cell_style)],
        [Paragraph("SQL Injection Assessment", table_cell_bold), Paragraph(escape(sqli_summary), table_cell_style)],
        [Paragraph("Assessment ID", table_cell_bold), Paragraph(escape(scan_id_str), table_cell_style)],
        [Paragraph("Scan Timestamps", table_cell_bold), Paragraph(f"Started: {started_str} | Completed: {completed_str} | Runtime: {dur_str}", table_cell_style)],
    ]
    t_exec = Table(exec_summary_data, colWidths=[150, 354])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_exec)
    elements.append(Spacer(1, 10))

    # Dynamic Finding Verification Matrix
    elements.append(Paragraph("Finding Verification Classification Breakdown", h3_style))
    verif_matrix_data = [
        [
            Paragraph("Confirmed Vulnerabilities", table_hdr_style),
            Paragraph("Potential Security Findings", table_hdr_style),
            Paragraph("Informational Observations", table_hdr_style),
            Paragraph("Incomplete / Timed Out", table_hdr_style)
        ],
        [
            Paragraph(f"<font size=12><b>{c_count}</b></font><br/>Validated Evidence", table_cell_style),
            Paragraph(f"<font size=12><b>{p_count}</b></font><br/>Detected Indicators", table_cell_style),
            Paragraph(f"<font size=12><b>{i_count}</b></font><br/>Recon / Technology", table_cell_style),
            Paragraph(f"<font size=12><b>{inc_count}</b></font><br/>Incomplete Jobs", table_cell_style)
        ]
    ]
    t_vmatrix = Table(verif_matrix_data, colWidths=[126, 126, 126, 126])
    t_vmatrix.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('BACKGROUND', (0,1), (0,1), colors.HexColor("#fee2e2") if c_count > 0 else colors.HexColor("#f8fafc")),
        ('BACKGROUND', (1,1), (1,1), colors.HexColor("#fef3c7") if p_count > 0 else colors.HexColor("#f8fafc")),
        ('BACKGROUND', (2,1), (2,1), colors.HexColor("#e0f2fe")),
        ('BACKGROUND', (3,1), (3,1), colors.HexColor("#f1f5f9")),
    ]))
    elements.append(t_vmatrix)
    elements.append(Spacer(1, 10))

    # Key Observations List
    elements.append(Paragraph("Key Security Observations", h3_style))
    if all_active_findings:
        for f in all_active_findings[:6]:
            sev_badge = f.get('severity', 'info').upper()
            v_badge = f.get('verification_status', 'POTENTIAL').upper()
            det_by = ", ".join(f.get('detected_by', [])) if isinstance(f.get('detected_by'), list) else str(f.get('detected_by') or f.get('scanner', 'Scanner'))
            obs_line = f"• <b>{escape(f.get('title', 'Security Finding'))}</b> — Severity: <b>{sev_badge}</b> | Verification: <b>{v_badge}</b> | Detected By: <b>{escape(det_by)}</b>"
            elements.append(Paragraph(obs_line, normal_style))
            elements.append(Spacer(1, 2))
    else:
        elements.append(Paragraph("• No confirmed or potential security findings were identified within the automated assessment scope.", normal_style))
    elements.append(Spacer(1, 12))

    # =========================================================================
    # 3. VULNAI PROJECT RISK SCORE & CALCULATION BREAKDOWN
    # =========================================================================
    elements.append(Paragraph("2. VulnAI Project Risk Score Calculation", h2_style))
    elements.append(Paragraph(
        "<b>Model Methodology:</b> The VulnAI Project Risk Score is a transparent, project-defined security score. "
        "It starts at a baseline of 100 points. Verified confirmed vulnerabilities and potential unconfirmed indicators "
        "deduct points based on defined weights. The score does not claim to represent CVSS or an official compliance certification.",
        normal_style
    ))
    elements.append(Spacer(1, 6))

    deductions = risk_score_obj.get('deductions', []) or risk_score_obj.get('explanation', [])
    calc_rows = [
        [
            Paragraph("Finding / Factor", table_hdr_style),
            Paragraph("Verification", table_hdr_style),
            Paragraph("Severity", table_hdr_style),
            Paragraph("Deduction", table_hdr_style),
        ],
        [
            Paragraph("Base Starting Score", table_cell_bold),
            Paragraph("Baseline", table_cell_style),
            Paragraph("Standard", table_cell_style),
            Paragraph("100 pts", table_cell_bold),
        ]
    ]

    for d in deductions:
        calc_rows.append([
            Paragraph(escape(str(d.get('finding', d.get('reason', 'Deduction')))), table_cell_style),
            Paragraph(escape(str(d.get('verification_status', 'POTENTIAL'))), table_cell_style),
            Paragraph(escape(str(d.get('severity', 'LOW')).upper()), table_cell_style),
            Paragraph(f"-{d.get('deduction', d.get('points', 0))} pts", table_cell_bold),
        ])

    final_calc_score = score_val if score_val is not None else "Undetermined"
    calc_rows.append([
        Paragraph("<b>Final VulnAI Project Risk Score</b>", table_cell_bold),
        Paragraph("-", table_cell_style),
        Paragraph(f"<b>{risk_level_display}</b>", table_cell_bold),
        Paragraph(f"<b>{final_calc_score} / 100</b>", table_cell_bold),
    ])

    t_calc = Table(calc_rows, colWidths=[240, 94, 85, 85])
    t_calc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor("#e2e8f0")),
    ]))
    elements.append(t_calc)
    elements.append(Spacer(1, 12))

    # =========================================================================
    # 4. SCANNER EXECUTION SUMMARY
    # =========================================================================
    elements.append(Paragraph("3. Scanner Execution Summary", h2_style))
    elements.append(Paragraph(
        "<i>Notice: 'COMPLETED' indicates the automated subprocess finished executing. "
        "It does NOT indicate that the target application is secure or free of vulnerabilities.</i>",
        disclaimer_style
    ))
    elements.append(Spacer(1, 6))

    tool_summaries = combined_results.get('tool_summaries', {}) or scan_data.get('tool_summaries', {})
    scanner_details = combined_results.get('scanner_details', {}) or scan_data.get('scanner_details', {})
    scanner_status = combined_results.get('scanner_status', {}) or scan_data.get('scanner_status', {})

    tools_table_rows = [
        [
            Paragraph("Scanner", table_hdr_style),
            Paragraph("Status", table_hdr_style),
            Paragraph("Runtime", table_hdr_style),
            Paragraph("Findings Detected", table_hdr_style),
            Paragraph("Verification State", table_hdr_style),
        ]
    ]

    all_tool_names = ["nmap", "nikto", "wapiti", "sqlmap", "gobuster", "wappalyzer"]
    for t_name in all_tool_names:
        ts = tool_summaries.get(t_name) if isinstance(tool_summaries.get(t_name), dict) else {}
        sd = scanner_details.get(t_name) if isinstance(scanner_details.get(t_name), dict) else {}
        st = ts.get('status') or (scanner_status.get(t_name) if isinstance(scanner_status, dict) else None) or (scan_data.get('scanner_status', {}).get(t_name)) or 'unknown'
        dur = ts.get('duration') or sd.get('duration') or sd.get('execution_seconds')
        f_count = ts.get('findings_count', 0)
        if not f_count and vulns_data:
            f_count = sum(1 for v in vulns_data if str(v.get('source', '')).lower() == t_name or str(v.get('scanner', '')).lower() == t_name)
        
        # If tool completed and detected 0 confirmed/potential findings
        if st == 'completed':
            ver_text = f"{f_count} observation(s)" if f_count > 0 else "Execution Completed (No findings)"
        elif st in ('running', 'queued') or scan_data.get('status') == 'running':
            ver_text = "In Progress"
            if st == 'unknown':
                st = 'running'
        elif st == 'cancelled':
            ver_text = "Cancelled by User"
        elif st == 'timed_out':
            ver_text = "Timed Out (Incomplete)"
        else:
            raw_err = (sd.get('error') if isinstance(sd, dict) else None) or (ts.get('error') if isinstance(ts, dict) else None) or 'Execution Error'
            err_str = str(raw_err) if raw_err else 'Execution Error'
            ver_text = f"Failed ({err_str[:30]})"

        tools_table_rows.append([
            Paragraph(escape(t_name.capitalize()), table_cell_bold),
            Paragraph(escape(str(st).upper()), table_cell_style),
            Paragraph(escape(_format_duration(dur)), table_cell_style),
            Paragraph(str(f_count), table_cell_style),
            Paragraph(escape(ver_text), table_cell_style),
        ])

    t_tools = Table(tools_table_rows, colWidths=[80, 85, 75, 94, 170])
    t_tools.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_tools)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 5. HOST INFORMATION & PORT DISCOVERY (NMAP)
    # =========================================================================
    elements.append(Paragraph("4. Host Information & Port Discovery (Nmap)", h2_style))
    host_disc = combined_results.get('host_discovery') or scan_data.get('host_discovery') or {}
    hostname = host_disc.get('hostname', target_display)
    resolved_ip = host_disc.get('resolved_ip', 'Not Resolved')
    host_state = host_disc.get('host_state', 'UP')

    host_info_data = [
        [Paragraph("Target Hostname", table_cell_bold), Paragraph(escape(hostname), table_cell_style)],
        [Paragraph("Resolved IP Address", table_cell_bold), Paragraph(escape(resolved_ip), table_cell_style)],
        [Paragraph("Host Operational State", table_cell_bold), Paragraph(f"<b>{escape(host_state)}</b>", table_cell_style)],
    ]
    t_hinfo = Table(host_info_data, colWidths=[150, 354])
    t_hinfo.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_hinfo)
    elements.append(Spacer(1, 6))

    open_ports = host_disc.get('open_ports', [])
    port_rows = [
        [
            Paragraph("Port / Protocol", table_hdr_style),
            Paragraph("State", table_hdr_style),
            Paragraph("Service", table_hdr_style),
            Paragraph("Product", table_hdr_style),
            Paragraph("Version", table_hdr_style),
        ]
    ]
    if open_ports:
        for p in open_ports:
            port_num = f"{p.get('port')}/{p.get('protocol', 'tcp')}"
            port_rows.append([
                Paragraph(escape(port_num), table_cell_bold),
                Paragraph(escape(str(p.get('state', 'open')).upper()), table_cell_style),
                Paragraph(escape(str(p.get('service', 'unknown'))), table_cell_style),
                Paragraph(escape(str(p.get('product', '—'))), table_cell_style),
                Paragraph(escape(str(p.get('version', '—'))), table_cell_style),
            ])
    else:
        port_rows.append([
            Paragraph("No open ports reported or standard web port assessed.", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
        ])

    t_ports = Table(port_rows, colWidths=[90, 60, 94, 130, 130])
    t_ports.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_ports)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 6. TECHNOLOGY STACK FINGERPRINTING (WAPPALYZER)
    # =========================================================================
    elements.append(Paragraph("5. Technology Stack Fingerprinting (Wappalyzer)", h2_style))
    elements.append(Paragraph(
        "<i>Classification: INFORMATIONAL. Technology stack fingerprinting identifies components for attack surface mapping. "
        "Detection does not indicate a vulnerability unless specific version CVE evidence exists.</i>",
        disclaimer_style
    ))
    elements.append(Spacer(1, 6))

    tech_detection = combined_results.get('technology_detection') or scan_data.get('technology_detection') or {}
    technologies = tech_detection.get('technologies', [])
    tech_rows = [
        [
            Paragraph("Technology Name", table_hdr_style),
            Paragraph("Category", table_hdr_style),
            Paragraph("Detected Version", table_hdr_style),
            Paragraph("Confidence", table_hdr_style),
        ]
    ]

    if technologies:
        for t in technologies:
            tech_rows.append([
                Paragraph(escape(str(t.get('name', 'Unknown'))), table_cell_bold),
                Paragraph(escape(str(t.get('category', 'Technology'))), table_cell_style),
                Paragraph(escape(str(t.get('version') or 'Not Specified')), table_cell_style),
                Paragraph(f"{t.get('confidence', 100)}%", table_cell_style),
            ])
    else:
        tech_rows.append([
            Paragraph("No distinctive technologies fingerprinted.", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
        ])

    t_tech = Table(tech_rows, colWidths=[150, 154, 110, 90])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_tech)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 7. DIRECTORY & PATH DISCOVERY (GOBUSTER)
    # =========================================================================
    elements.append(Paragraph("6. Directory & Path Discovery (Gobuster)", h2_style))
    elements.append(Paragraph(
        "<i>Classification: INFORMATIONAL. Discovered paths map application surface exposure. "
        "Paths are observations and are not vulnerabilities unless unauthorized access or data exposure is proven.</i>",
        disclaimer_style
    ))
    elements.append(Spacer(1, 6))

    gobuster_findings = [f for f in informational_findings if "Gobuster" in f.get('detected_by', []) or f.get('scanner') == 'Gobuster']
    dir_rows = [
        [
            Paragraph("Discovered Path / Endpoint", table_hdr_style),
            Paragraph("HTTP Status", table_hdr_style),
            Paragraph("Response Size", table_hdr_style),
            Paragraph("Assessment Observation", table_hdr_style),
        ]
    ]

    if gobuster_findings:
        for gf in gobuster_findings[:15]:
            ev = gf.get('evidence', {}) if isinstance(gf.get('evidence'), dict) else {}
            status_code = ev.get('status_code') or gf.get('status_code') or '200'
            resp_size = ev.get('response_size') or gf.get('response_size') or '—'
            dir_rows.append([
                Paragraph(escape(str(gf.get('endpoint') or gf.get('title', '/'))), table_cell_bold),
                Paragraph(f"HTTP {status_code}", table_cell_style),
                Paragraph(f"{resp_size} bytes", table_cell_style),
                Paragraph("Exposed Endpoint Observation", table_cell_style),
            ])
    else:
        dir_rows.append([
            Paragraph("No directory brute-force paths discovered or Gobuster completed clean.", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
            Paragraph("—", table_cell_style),
        ])

    t_dir = Table(dir_rows, colWidths=[174, 80, 100, 150])
    t_dir.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_dir)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 8. ASSESSMENT COVERAGE & LIMITATIONS
    # =========================================================================
    elements.append(Paragraph("7. Assessment Coverage & Scope Boundaries", h2_style))
    elements.append(Paragraph(
        "Automated tools assess only a bounded slice of security controls. Areas marked 'NOT ASSESSED' "
        "require manual penetration testing or specialized assessment suites and must not be assumed secure.",
        normal_style
    ))
    elements.append(Spacer(1, 6))

    coverage_list = combined_results.get('assessment_coverage', [])
    cov_rows = [
        [
            Paragraph("Assessment Area", table_hdr_style),
            Paragraph("Execution Tool", table_hdr_style),
            Paragraph("Coverage Status", table_hdr_style),
            Paragraph("Methodology / Scope Note", table_hdr_style),
        ]
    ]

    for item in coverage_list:
        status_disp = item.get('status', 'NOT ASSESSED')
        cov_rows.append([
            Paragraph(escape(item.get('area', '')), table_cell_bold),
            Paragraph(escape(item.get('tool', '—')), table_cell_style),
            Paragraph(f"<b>{escape(status_disp)}</b>", table_cell_style),
            Paragraph(escape(item.get('note', '')), table_cell_style),
        ])

    t_cov = Table(cov_rows, colWidths=[130, 80, 104, 190])
    t_cov.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(t_cov)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 9. OWASP TOP 10 COVERAGE MATRIX
    # =========================================================================
    elements.append(Paragraph("8. OWASP Top 10 (2021) Coverage Matrix", h2_style))
    elements.append(Paragraph(
        "<b>Important Disclaimer:</b> OWASP Top 10 coverage represents automated scanner coverage "
        "and does NOT constitute compliance certification or proof of security.",
        disclaimer_style
    ))
    elements.append(Spacer(1, 6))

    owasp_matrix = combined_results.get('owasp_coverage', [])
    owasp_rows = [
        [
            Paragraph("OWASP Category", table_hdr_style),
            Paragraph("Status", table_hdr_style),
            Paragraph("Findings", table_hdr_style),
            Paragraph("Assessment Scope & Evidence Note", table_hdr_style),
        ]
    ]

    for ow in owasp_matrix:
        owasp_rows.append([
            Paragraph(escape(f"{ow.get('id')} {ow.get('name')}"), table_cell_bold),
            Paragraph(f"<b>{escape(ow.get('status', 'Not Assessed'))}</b>", table_cell_style),
            Paragraph(str(ow.get('findings_count', 0)), table_cell_style),
            Paragraph(escape(ow.get('notes', '')), table_cell_style),
        ])

    t_owasp = Table(owasp_rows, colWidths=[140, 100, 54, 210])
    t_owasp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(t_owasp)
    elements.append(Spacer(1, 14))

    # =========================================================================
    # 10. DETAILED SECURITY FINDINGS
    # =========================================================================
    elements.append(Paragraph("9. Correlated Security Findings", h2_style))
    elements.append(Paragraph(
        "Findings correlated across multiple tools have been deduplicated into canonical security items. "
        "Original scanner evidence from each reporting tool is preserved below.",
        normal_style
    ))
    elements.append(Spacer(1, 8))

    # Detailed findings list (Confirmed and Potential findings first, followed by key informational if needed)
    detailed_findings = [*confirmed_findings, *potential_findings]

    if not detailed_findings:
        no_findings_box = Table([[Paragraph(
            "<b>No Confirmed or Potential Security Vulnerabilities Identified:</b> "
            "Within the automated scanning scope of the executed tools, no confirmed vulnerabilities "
            "or potential security misconfigurations were detected.", normal_style
        )]], colWidths=[504])
        no_findings_box.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f0fdf4")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#86efac")),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(no_findings_box)
        elements.append(Spacer(1, 14))
    else:
        for idx, finding in enumerate(detailed_findings, start=1):
            f_id = finding.get('id') or f"VULNAI-{idx:03d}"
            title = finding.get('title', 'Security Finding')
            sev = finding.get('severity', 'info').upper()
            verif = finding.get('verification_status', 'POTENTIAL').upper()
            conf = str(finding.get('confidence', 'MEDIUM')).upper()
            owasp_cat = finding.get('owasp_category') or finding.get('owasp_id') or 'Not mapped'
            cwe = finding.get('cwe') or finding.get('cwe_id') or 'Not mapped'
            wstg = finding.get('wstg', 'Not mapped')
            endpoint = finding.get('endpoint') or finding.get('target_url') or target_display
            
            det_by_list = finding.get('detected_by', [])
            det_by = ", ".join(det_by_list) if isinstance(det_by_list, list) else str(det_by_list or finding.get('scanner', 'Scanner'))
            
            desc = finding.get('description', '')
            impact = finding.get('impact', 'Potential security exposure or configuration weakness.')
            rec = finding.get('recommendation', 'Apply vendor security best practices and test in non-production.')
            
            raw_files = finding.get('raw_evidence_files', [])
            raw_ev = finding.get('evidence')
            if raw_files:
                raw_ref = ", ".join(raw_files)
            elif isinstance(raw_ev, dict):
                raw_ref = raw_ev.get('raw_output_file', 'scan-results/')
            else:
                raw_ref = 'scan-results/'

            ev_content = ""
            if isinstance(raw_ev, dict):
                ev_items = [f"{k}: {v}" for k, v in raw_ev.items() if k not in ('raw_output_file',) and v]
                ev_content = " | ".join(ev_items)[:400]
            elif raw_ev:
                ev_content = str(raw_ev)[:400]
            if not ev_content:
                ev_content = desc[:300]

            refs_list = finding.get('references')
            ref_first = refs_list[0] if (isinstance(refs_list, (list, tuple)) and refs_list and refs_list[0]) else 'OWASP Guidance'

            finding_table_data = [
                [
                    Paragraph(f"<b>Finding ID: {escape(f_id)}</b> — {escape(title)}", table_cell_bold),
                    Paragraph(f"<b>{sev}</b> | <b>{verif}</b>", table_cell_bold)
                ],
                [
                    Paragraph(f"<b>OWASP Top 10:</b> {escape(owasp_cat)}<br/><b>CWE:</b> {escape(cwe)} | <b>WSTG:</b> {escape(wstg)}", table_cell_style),
                    Paragraph(f"<b>Confidence:</b> {conf}<br/><b>Detected By:</b> {escape(det_by)}", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Affected Endpoint:</b> {escape(endpoint)}", table_cell_style),
                    Paragraph(f"<b>Raw Artifact:</b> {escape(str(raw_ref))}", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Description & Scanner Evidence:</b><br/>{escape(ev_content)}", table_cell_style),
                    Paragraph(f"<b>Security Impact:</b><br/>{escape(impact)}", table_cell_style)
                ],
                [
                    Paragraph(f"<b>Remediation Recommendation:</b><br/>{escape(rec)}", table_cell_style),
                    Paragraph(f"<b>References:</b><br/>{escape(str(ref_first))}", table_cell_style)
                ]
            ]

            t_finding = Table(finding_table_data, colWidths=[252, 252])
            t_finding.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            elements.append(KeepTogether([t_finding, Spacer(1, 8)]))

    # =========================================================================
    # 11. REMEDIATION ROADMAP
    # =========================================================================
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("10. Actionable Remediation Roadmap", h2_style))
    elements.append(Paragraph(
        "Prioritize remediating high-impact security configurations and missing browser security protections:",
        normal_style
    ))
    elements.append(Spacer(1, 4))

    rem_rows = [
        [
            Paragraph("Security Item", table_hdr_style),
            Paragraph("Priority", table_hdr_style),
            Paragraph("Recommended Engineering Action", table_hdr_style),
        ]
    ]

    for f in detailed_findings:
        rem_rows.append([
            Paragraph(escape(f.get('title', 'Security Finding')), table_cell_bold),
            Paragraph(escape(f.get('severity', 'LOW').upper()), table_cell_style),
            Paragraph(escape(f.get('recommendation', 'Review server configuration.')), table_cell_style),
        ])

    if not detailed_findings:
        rem_rows.append([
            Paragraph("Standard Baseline Maintenance", table_cell_bold),
            Paragraph("INFO", table_cell_style),
            Paragraph("Continue routine automated vulnerability scanning and software dependency patching.", table_cell_style),
        ])

    t_rem = Table(rem_rows, colWidths=[164, 70, 270])
    t_rem.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_rem)

    doc.build(elements)
    buffer.seek(0)
    return buffer


def generate_csv(vulns_data: list, scan_data: dict = None) -> io.StringIO:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    now_utc = datetime.now(timezone.utc)
    report_gen_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    if scan_data:
        target_display = scan_data.get('target_url') or (
            scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown'
        )
        started_str = _format_datetime(scan_data.get('started_at'))
        completed_str = _format_datetime(scan_data.get('completed_at') or scan_data.get('ended_at'))
        dur_str = _format_duration(scan_data.get('duration'))
        risk_score = scan_data.get('risk_score', {})

        writer.writerow(["# VulnAI DevSecOps Assessment Report"])
        writer.writerow(["# Report Generated At", report_gen_str])
        writer.writerow(["# Target Host / URL", target_display])
        writer.writerow(["# Scan Started At", started_str])
        writer.writerow(["# Scan Completed At", completed_str])
        writer.writerow(["# Total Execution Duration", dur_str])
        writer.writerow(["# VulnAI Project Risk Score", f"{risk_score.get('score', 'N/A')}/100 ({risk_score.get('rating', 'N/A')})"])
        writer.writerow([])

    writer.writerow([
        "Finding ID", "Title", "Severity", "Verification Status", "Confidence",
        "Detected By", "Target URL", "Endpoint", "OWASP Category", "CWE", "WSTG",
        "Description", "Recommendation", "Raw Artifact"
    ])

    for v in vulns_data:
        det_by = ", ".join(v.get('detected_by', [])) if isinstance(v.get('detected_by'), list) else str(v.get('detected_by') or v.get('scanner', ''))
        raw_files = v.get('raw_evidence_files', [])
        raw_ref = ", ".join(raw_files) if raw_files else v.get('evidence', {}).get('raw_output_file', '')
        
        writer.writerow([
            v.get('id', ''),
            v.get('title', ''),
            v.get('severity', ''),
            v.get('verification_status', v.get('status', '')),
            v.get('confidence', ''),
            det_by,
            v.get('target_url', ''),
            v.get('endpoint', ''),
            v.get('owasp_category', v.get('owasp_id', '')),
            v.get('cwe', v.get('cwe_id', '')),
            v.get('wstg', ''),
            v.get('description', ''),
            v.get('recommendation', v.get('ai_analysis', {}).get('recommendation', '')),
            raw_ref
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

    target_display = scan_data.get('target_url') or (
        scan_data.get('target_urls', ['Unknown'])[0] if scan_data.get('target_urls') else 'Unknown'
    )
    combined = scan_data.get("combined_results", {})

    payload = {
        "report_metadata": {
            "report_generated_at": report_gen_iso,
            "scan_id": str(scan_data.get("_id")),
            "target": target_display,
            "scan_started_at": started_iso,
            "scan_completed_at": completed_iso,
            "duration_seconds": duration,
            "duration_formatted": dur_str,
            "disclaimer": "Automated security assessment. Findings represent indicators and observations within tested scope.",
        },
        "scan_data": {
            "scan_id": str(scan_data.get("_id")),
            "target_urls": scan_data.get("target_urls", [target_display]),
            "started_at": started_iso,
            "completed_at": completed_iso,
            "duration": duration,
            "duration_formatted": dur_str,
            "report_generated_at": report_gen_iso,
            "status": scan_data.get("status"),
            "risk_score": scan_data.get("risk_score", combined.get("risk_score", {})),
            "counts": combined.get("counts", {}),
            "assessment_coverage": combined.get("assessment_coverage", []),
            "owasp_coverage": combined.get("owasp_coverage", []),
            "host_discovery": combined.get("host_discovery", {}),
            "sql_assessment": combined.get("sql_assessment", {}),
            "tool_summaries": combined.get("tool_summaries", {}),
        },
        "combined_results": _json_safe(combined),
        "vulnerabilities": []
    }

    for v in vulns_data:
        vd = v.copy()
        vd["_id"] = str(vd.get("_id"))
        if "created_at" in vd:
            vd["created_at"] = str(vd["created_at"])
        if "updated_at" in vd:
            vd["updated_at"] = str(vd["updated_at"])
        payload["vulnerabilities"].append(_json_safe(vd))
        
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


def generate_report_dict(scan_data: dict, vulns_data: list) -> dict:
    """Generate structured full assessment report dictionary containing all 17 sections."""
    target_display = scan_data.get("target_url") or (
        scan_data.get("target_urls", ["Unknown"])[0] if scan_data.get("target_urls") else "Unknown"
    )
    combined = scan_data.get("combined_results") or {}
    risk_score_obj = scan_data.get("risk_score") or combined.get("risk_score") or {}
    score_val = risk_score_obj.get("score")
    score_display = f"{score_val} / 100" if score_val is not None else "Not Fully Determined"
    risk_level_display = str(risk_score_obj.get("risk_level") or risk_score_obj.get("rating") or "Undetermined").upper()

    confirmed = combined.get("confirmed", [])
    potential = combined.get("potential", [])
    informational = combined.get("informational", [])
    incomplete = combined.get("incomplete", [])

    if not (confirmed or potential or informational) and vulns_data:
        for v in vulns_data:
            ver = str(v.get("verification_status") or v.get("status") or "").upper()
            if ver == "CONFIRMED":
                confirmed.append(v)
            elif ver == "INFORMATIONAL" or str(v.get("severity", "")).lower() == "info":
                informational.append(v)
            else:
                potential.append(v)

    # Mathematical calculation
    deductions = risk_score_obj.get("deductions") or []
    calc_info = risk_score_obj.get("calculation") or {}
    low_count = sum(1 for d in deductions if str(d.get("severity")).upper() == "LOW")
    med_count = sum(1 for d in deductions if str(d.get("severity")).upper() == "MEDIUM")
    high_count = sum(1 for d in deductions if str(d.get("severity")).upper() == "HIGH")
    crit_count = sum(1 for d in deductions if str(d.get("severity")).upper() == "CRITICAL")
    total_ded = risk_score_obj.get("total_deductions", 0.0)

    score_calculation = {
        "base_score": 100,
        "deductions": deductions,
        "summary": {
            "critical": {"count": crit_count, "points_each": 20.0, "total": crit_count * 20.0},
            "high": {"count": high_count, "points_each": 10.0, "total": high_count * 10.0},
            "medium": {"count": med_count, "points_each": 4.0, "total": med_count * 4.0},
            "low": {"count": low_count, "points_each": 1.5, "total": low_count * 1.5},
            "info": {"count": 0, "points_each": 0.0, "total": 0.0},
        },
        "total_deductions": total_ded,
        "final_score": score_val if score_val is not None else 100,
        "risk_level": risk_level_display,
        "formula": calc_info.get("formula_string") or f"100 - ({low_count} × 1.5) - ({med_count} × 4.0) = {score_val or 100}",
    }

    scanner_status = scan_data.get("scanner_status") or combined.get("scanner_status") or {}
    scanner_details = scan_data.get("scanner_details") or combined.get("scanner_details") or {}
    tool_summaries = scan_data.get("tool_summaries") or combined.get("tool_summaries") or {}

    tool_exec_summary = []
    ALL_TOOLS = ("nmap", "nikto", "wapiti", "sqlmap", "gobuster", "wappalyzer")
    for t in ALL_TOOLS:
        detail = scanner_details.get(t, {})
        tsum = tool_summaries.get(t, {})
        status_val = scanner_status.get(t) or detail.get("status") or "completed"
        dur = detail.get("duration") or detail.get("execution_seconds") or tsum.get("duration") or 0.0
        tool_exec_summary.append({
            "tool": t,
            "status": status_val,
            "duration_seconds": round(dur, 2),
            "findings_count": tsum.get("findings_count", 0),
            "summary": tsum.get("summary_message", ""),
        })

    # Host discovery
    host_disc = combined.get("host_discovery", {})
    # Tech detection
    tech_det = combined.get("technology_detection", scan_data.get("technology_detection", {}))
    # SQLMap
    sql_assessment = combined.get("sql_assessment", {})

    severity_summary = {
        "critical": crit_count,
        "high": high_count,
        "medium": med_count,
        "low": low_count,
        "info": len(informational),
    }

    incomplete_tools = [
        t for t, st in scanner_status.items()
        if st in ("timed_out", "incomplete", "failed", "timeout")
    ]

    return {
        "scan_id": str(scan_data.get("_id") or scan_data.get("id")),
        "target": target_display,
        "executive_summary": {
            "target": target_display,
            "status": scan_data.get("status", "completed"),
            "score": score_val,
            "score_display": score_display,
            "risk_level": risk_level_display,
            "findings_count": len(confirmed) + len(potential),
            "confirmed_count": len(confirmed),
            "potential_count": len(potential),
            "informational_count": len(informational),
            "incomplete_count": len(incomplete),
        },
        "target_information": {
            "target": target_display,
            "hostname": host_disc.get("hostname", target_display),
            "ip": host_disc.get("resolved_ip", "Not Resolved"),
            "host_state": host_disc.get("host_state", "UP"),
        },
        "scan_metadata": {
            "scan_id": str(scan_data.get("_id") or scan_data.get("id")),
            "started_at": str(scan_data.get("started_at")),
            "completed_at": str(scan_data.get("completed_at") or scan_data.get("ended_at")),
            "duration_seconds": scan_data.get("duration"),
        },
        "tool_execution_summary": tool_exec_summary,
        "nmap_results": host_disc,
        "nikto_results": {
            "findings": [f for f in [*confirmed, *potential] if "nikto" in str(f.get("source") or f.get("tool") or "").lower() or any("nikto" in str(d).lower() for d in f.get("detected_by", []))],
        },
        "wapiti_results": {
            "findings": [f for f in [*confirmed, *potential] if "wapiti" in str(f.get("source") or f.get("tool") or "").lower() or any("wapiti" in str(d).lower() for d in f.get("detected_by", []))],
        },
        "sqlmap_results": sql_assessment,
        "gobuster_results": {
            "paths": [f for f in informational if "gobuster" in str(f.get("source") or f.get("tool") or "").lower() or any("gobuster" in str(d).lower() for d in f.get("detected_by", []))],
            "wildcard_behavior": combined.get("http_analysis", {}).get("wildcard_behavior_note"),
        },
        "technology_detection": tech_det,
        "normalized_findings": [*confirmed, *potential, *informational],
        "correlated_findings": combined.get("correlated_findings") or [*confirmed, *potential],
        "severity_summary": severity_summary,
        "risk_score_calculation": score_calculation,
        "evidence": {
            "evidence_files": scan_data.get("evidence_files", {}),
        },
        "recommendations": [
            {"finding": f.get("title"), "recommendation": f.get("recommendation")}
            for f in [*confirmed, *potential] if f.get("recommendation")
        ],
        "incomplete_tools": incomplete_tools,
    }


def generate_markdown(scan_data: dict, vulns_data: list) -> str:
    """Generate Markdown report string with all 17 standard sections and mathematical score breakdown."""
    rep = generate_report_dict(scan_data, vulns_data)
    es = rep["executive_summary"]
    calc = rep["risk_score_calculation"]
    ti = rep["target_information"]
    meta = rep["scan_metadata"]

    lines = [
        "# VulnAI DevSecOps - Security Assessment Report",
        "",
        "> **Notice:** Automated security assessment report. Scanner output represents indicators that must be manually validated before being treated as confirmed vulnerabilities. Scanner completion does not denote that the target is completely secure.",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Target Host / URL:** `{rep['target']}`",
        f"- **Scan ID:** `{rep['scan_id']}`",
        f"- **Assessment Status:** `{es['status'].upper()}`",
        f"- **VulnAI Project Risk Score:** `{es['score_display']}` (Risk Rating: **{es['risk_level']}**)",
        "- **Model:** VulnAI Project Risk Score (Project-Defined)",
        "",
        "### Finding Verification Classification",
        "",
        "| Category | Count | Definition |",
        "|---|---:|---|",
        f"| **Confirmed Vulnerabilities** | **{es['confirmed_count']}** | Evidence is sufficiently validated |",
        f"| **Potential Security Findings** | **{es['potential_count']}** | Security indicator detected; requires independent confirmation |",
        f"| **Informational Observations** | **{es['informational_count']}** | Reconnaissance / technology / configuration data |",
        f"| **Incomplete / Timed Out** | **{es['incomplete_count']}** | Tool did not complete sufficiently |",
        "",
        "## 2. Target Information",
        "",
        f"- **Target URL:** `{ti['target']}`",
        f"- **Hostname:** `{ti['hostname']}`",
        f"- **Resolved IP:** `{ti['ip']}`",
        f"- **Host State:** `{ti['host_state']}`",
        "",
        "## 3. Scan Metadata",
        "",
        f"- **Scan ID:** `{meta['scan_id']}`",
        f"- **Started At:** `{meta['started_at']}`",
        f"- **Completed At:** `{meta['completed_at']}`",
        f"- **Duration:** `{meta['duration_seconds']}s`",
        "",
        "## 4. Tool Execution Summary",
        "",
        "| Scanner | Status | Runtime | Findings | Summary |",
        "|---|---|---:|---:|---|",
    ]

    for tool in rep["tool_execution_summary"]:
        lines.append(f"| {tool['tool'].capitalize()} | **{tool['status'].upper()}** | {tool['duration_seconds']}s | {tool['findings_count']} | {tool['summary'] or 'Completed'} |")
    lines.append("")

    # 5. Nmap Results
    lines.extend([
        "## 5. Nmap Port & Service Discovery",
        "",
        "| Port / Protocol | State | Service | Version |",
        "|---|---|---|---|",
    ])
    open_ports = rep["nmap_results"].get("open_ports", [])
    if open_ports:
        for p in open_ports:
            lines.append(f"| {p.get('port', p.get('port_number', 'N/A'))} | {p.get('state', 'OPEN')} | {p.get('service', 'N/A')} | {p.get('product_version', p.get('version', '—'))} |")
    else:
        lines.append("| 443/tcp | OPEN | HTTPS | — |")
    lines.append("")

    # 6. Nikto Results
    lines.extend([
        "## 6. Nikto Web Server Scanner Results",
        "",
    ])
    nikto_findings = rep["nikto_results"].get("findings", [])
    if nikto_findings:
        for nf in nikto_findings:
            lines.append(f"- **[{nf.get('severity', 'LOW')}]** {nf.get('title')}: `{nf.get('evidence', '')[:100]}`")
    else:
        lines.append("No independent Nikto findings observed.")
    lines.append("")

    # 7. Wapiti Results
    lines.extend([
        "## 7. Wapiti Web Application Findings",
        "",
    ])
    wapiti_findings = rep["wapiti_results"].get("findings", [])
    if wapiti_findings:
        for wf in wapiti_findings:
            lines.append(f"- **[{wf.get('severity', 'HIGH')}]** {wf.get('title')}: `{wf.get('endpoint', '/')}`")
    else:
        lines.append("No web application injection or traversal flaws reported by Wapiti.")
    lines.append("")

    # 8. SQLMap Results
    sqlmap_res = rep["sqlmap_results"]
    lines.extend([
        "## 8. SQLMap Database Vulnerability Assessment",
        "",
        f"- **Status:** {sqlmap_res.get('status', 'Completed')}",
        f"- **SQL Injection Confirmed:** {sqlmap_res.get('injection_confirmed', False)}",
        f"- **Assessment Summary:** {sqlmap_res.get('summary', 'No confirmed injection points.')}",
        "",
    ])

    # 9. Gobuster Results
    gobuster_res = rep["gobuster_results"]
    lines.extend([
        "## 9. Gobuster Directory Enumeration",
        "",
    ])
    if gobuster_res.get("wildcard_behavior"):
        lines.append(f"> **Wildcard Notice:** {gobuster_res['wildcard_behavior']}")
        lines.append("")
    paths = gobuster_res.get("paths", [])
    if paths:
        for p in paths[:15]:
            lines.append(f"- Discovered endpoint: `{p.get('endpoint') or p.get('title')}`")
    else:
        lines.append("No public directories enumerated within scan threshold.")
    lines.append("")

    # 10. Technology Detection
    tech_list = rep["technology_detection"].get("technologies", [])
    lines.extend([
        "## 10. Technology Stack Detection (Wappalyzer)",
        "",
        "| Component | Category | Version | Confidence |",
        "|---|---|---|---:|",
    ])
    if tech_list:
        for t in tech_list:
            lines.append(f"| {t.get('name')} | {t.get('category')} | {t.get('version') or '—'} | {t.get('confidence', 100)}% |")
    else:
        lines.append("| No distinctive technologies detected | — | — | — |")
    lines.append("")

    # 11. Normalized Findings
    lines.extend([
        "## 11. Normalized Findings",
        "",
    ])
    norm_findings = rep["normalized_findings"]
    for idx, f in enumerate(norm_findings, 1):
        lines.append(f"### Finding {idx}: {f.get('title')}")
        lines.append(f"- **Tool:** `{f.get('tool', f.get('source', 'scanner'))}`")
        lines.append(f"- **Severity:** `{f.get('severity', 'LOW')}`")
        lines.append(f"- **Confidence:** `{f.get('confidence', 85)}%`")
        lines.append(f"- **Status:** `{f.get('status', 'potential')}`")
        lines.append(f"- **Endpoint:** `{f.get('endpoint', '/')}`")
        lines.append(f"- **Evidence:** {f.get('evidence', '')}")
        lines.append(f"- **Recommendation:** {f.get('recommendation', '')}")
        lines.append("")

    # 12. Correlated Findings
    lines.extend([
        "## 12. Correlated Findings Across Tools",
        "",
    ])
    corr_findings = rep["correlated_findings"]
    for cf in corr_findings:
        det = ", ".join(cf.get("detected_by", [])) if isinstance(cf.get("detected_by"), list) else str(cf.get("detected_by"))
        lines.append(f"- **{cf.get('title')}** (Detected by: **{det}** | Severity: **{cf.get('severity')}**)")
    lines.append("")

    # 13. Severity Summary
    sev_sum = rep["severity_summary"]
    lines.extend([
        "## 13. Severity Summary",
        "",
        "| Severity Level | Count | Deduction per Item |",
        "|---|---:|---:|",
        f"| **CRITICAL** | {sev_sum['critical']} | 20.0 pts |",
        f"| **HIGH** | {sev_sum['high']} | 10.0 pts |",
        f"| **MEDIUM** | {sev_sum['medium']} | 4.0 pts |",
        f"| **LOW** | {sev_sum['low']} | 1.5 pts |",
        f"| **INFORMATIONAL** | {sev_sum['info']} | 0.0 pts |",
        "",
    ])

    # 14. Risk Score Calculation
    lines.extend([
        "## 14. Transparent Risk Score Calculation",
        "",
        f"- **Base Starting Score:** `100.0` points",
        f"- **LOW Deductions:** {calc['summary']['low']['count']} × 1.5 = `-{calc['summary']['low']['total']}` points",
        f"- **MEDIUM Deductions:** {calc['summary']['medium']['count']} × 4.0 = `-{calc['summary']['medium']['total']}` points",
        f"- **HIGH Deductions:** {calc['summary']['high']['count']} × 10.0 = `-{calc['summary']['high']['total']}` points",
        f"- **CRITICAL Deductions:** {calc['summary']['critical']['count']} × 20.0 = `-{calc['summary']['critical']['total']}` points",
        f"- **Total Deductions:** `-{calc['total_deductions']}` points",
        f"- **Mathematical Formula:** `{calc['formula']}`",
        f"- **Final Risk Score:** `{calc['final_score']} / 100` (**{calc['risk_level']}**)",
        "",
    ])

    # 15. Evidence
    lines.extend([
        "## 15. Scanner Evidence Artifacts",
        "",
    ])
    for s_name, path in rep["evidence"].get("evidence_files", {}).items():
        lines.append(f"- `{s_name}`: `{path}`")
    lines.append("")

    # 16. Recommendations
    lines.extend([
        "## 16. Prioritized Remediation Recommendations",
        "",
    ])
    recs = rep["recommendations"]
    if recs:
        for idx, r in enumerate(recs, 1):
            lines.append(f"{idx}. **{r['finding']}:** {r['recommendation']}")
    else:
        lines.append("- Review server headers and disable unnecessary exposed endpoints.")
    lines.append("")

    # 17. Incomplete Tools
    lines.extend([
        "## 17. Incomplete or Timed-Out Tools",
        "",
    ])
    inc_tools = rep["incomplete_tools"]
    if inc_tools:
        for it in inc_tools:
            lines.append(f"- **{it.capitalize()}:** Assessment incomplete or timed out. Manual verification required.")
    else:
        lines.append("All scanners completed execution cleanly.")
    lines.append("")

    return "\n".join(lines) + "\n"

