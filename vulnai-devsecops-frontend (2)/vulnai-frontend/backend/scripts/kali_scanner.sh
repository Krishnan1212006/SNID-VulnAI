#!/bin/bash

# ============================================================
# INTELLIGENT WEBSITE SECURITY ASSESSMENT
# VULNERABILITY ANALYZER
#
# Tools:
#   Nmap
#   Wapiti
#   SQLMap
#   Gobuster
#
# IMPORTANT:
# Run only against systems for which you have explicit
# authorization to perform security testing.
# ============================================================

set -u

# ============================================================
# COLORS
# ============================================================

RED='\033[0;31m'
GOLD='\033[1;33m'
GREEN='\033[0;32m'
WHITE='\033[1;37m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# UI FUNCTIONS
# ============================================================

banner() {
    [[ -t 1 ]] && clear

    echo -e "${GOLD}"
    echo "=============================================================="
    echo "       INTELLIGENT WEBSITE SECURITY ASSESSMENT"
    echo "             VULNERABILITY ANALYZER"
    echo "=============================================================="
    echo -e "${RED}"
    echo "   NMAP | NIKTO | WAPITI | SQLMAP | GOBUSTER"
    echo -e "${GOLD}"
    echo "=============================================================="
    echo -e "${NC}"
}

info() {
    echo -e "${GOLD}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[ OK ]${NC} $1"
}

warning() {
    echo -e "${GOLD}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

section() {
    echo
    echo -e "${RED}==============================================================${NC}"
    echo -e "${GOLD}$1${NC}"
    echo -e "${RED}==============================================================${NC}"
}

# ============================================================
# USAGE
# ============================================================

usage() {
    echo
    echo "Usage:"
    echo "  ./scannerpro <authorized-target-url> [wordlist] [output_dir]"
    echo
    echo "Example:"
    echo "  ./scannerpro https://example.com/"
    echo
    echo "Optional wordlist & output directory:"
    echo "  ./scannerpro https://example.com/ /path/to/wordlist.txt /path/to/output_dir"
    echo
}

# ============================================================
# ARGUMENT CHECK
# ============================================================

if [[ $# -lt 1 ]]; then
    usage
    exit 1
fi

TARGET="$1"

WORDLIST="${2:-/usr/share/wordlists/dirb/common.txt}"
CUSTOM_OUTPUT_DIR="${3:-}"

# ============================================================
# NORMALIZE TARGET
# ============================================================

if [[ "$TARGET" =~ ^https?:// ]]; then
    URL="${TARGET%/}"
else
    URL="https://${TARGET%/}"
fi

DOMAIN="$(printf '%s' "$URL" |
    sed -E 's#^https?://##' |
    cut -d/ -f1 |
    cut -d: -f1)"

if [[ -z "$DOMAIN" ]]; then
    error "Could not determine target hostname."
    exit 1
fi

# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

if [[ -n "$CUSTOM_OUTPUT_DIR" ]]; then
    REPORT_DIR="$CUSTOM_OUTPUT_DIR"
else
    TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
    SAFE_TARGET="$(printf '%s' "$DOMAIN" |
        sed 's#[/:?&=]#_#g')"
    REPORT_DIR="security_scan_${SAFE_TARGET}_${TIMESTAMP}"
fi

mkdir -p "$REPORT_DIR"

REPORT_MD="$REPORT_DIR/security_assessment_report.md"

# ============================================================
# START UI
# ============================================================

banner

info "Target : $URL"
info "Host   : $DOMAIN"
info "Output : $REPORT_DIR"

# ============================================================
# DEPENDENCY CHECK
# ============================================================

section "DEPENDENCY CHECK"

TOOLS=(
    "nmap"
    "nikto"
    "wapiti"
    "sqlmap"
    "gobuster"
    "timeout"
)

MISSING=()

for TOOL in "${TOOLS[@]}"; do

    if command -v "$TOOL" >/dev/null 2>&1; then
        success "$TOOL -> $(command -v "$TOOL")"
    else
        error "$TOOL is not installed"
        MISSING+=("$TOOL")
    fi

done

if (( ${#MISSING[@]} > 0 )); then

    error "Required tools are missing."

    echo
    echo "Install missing tools with:"
    echo

    printf 'sudo apt update && sudo apt install -y'

    for TOOL in "${MISSING[@]}"; do
        printf ' %s' "$TOOL"
    done

    echo
    exit 1
fi

success "All required tools are available."

# ============================================================
# WORDLIST CHECK
# ============================================================

section "WORDLIST CHECK"

if [[ ! -f "$WORDLIST" ]]; then

    error "Gobuster wordlist not found:"
    error "$WORDLIST"

    exit 1

fi

success "Wordlist found: $WORDLIST"

# ============================================================
# TARGET RESOLUTION
# ============================================================

section "TARGET RESOLUTION"

TARGET_IP="$(getent ahostsv4 "$DOMAIN" 2>/dev/null |
    awk 'NR==1 {print $1}')"

if [[ -z "$TARGET_IP" ]]; then

    error "Could not resolve $DOMAIN to an IPv4 address."

    exit 1

fi

success "Resolved IP: $TARGET_IP"

# ============================================================
# CREATE REPORT HEADER
# ============================================================

create_report() {

    cat > "$REPORT_MD" <<EOF
# Intelligent Website Security Assessment Report

## Assessment Information

| Field | Value |
|---|---|
| Target | $URL |
| Host | $DOMAIN |
| IP Address | $TARGET_IP |
| Assessment Date | $(date) |

---

## Authorization

This assessment is intended only for an authorized target.

---

## Scanner Configuration

| Scanner | Purpose |
|---|---|
| Nmap | Host, port and service discovery |
| Nikto | Web server and configuration assessment |
| Wapiti | Web application vulnerability assessment |
| SQLMap | Authorized SQL injection assessment |
| Gobuster | Directory and file discovery |

---

EOF

}

create_report

# ============================================================
# ADD RESULT TO REPORT
# ============================================================

add_result() {

    local TOOL="$1"
    local STATUS="$2"
    local FILE="$3"

    {
        echo
        echo "## $TOOL"
        echo
        echo "**Status:** $STATUS"
        echo
        echo '```text'

        if [[ -f "$FILE" ]]; then
            cat "$FILE"
        else
            echo "No output file was generated."
        fi

        echo '```'
        echo

    } >> "$REPORT_MD"

}

# ============================================================
# NMAP
# ============================================================

run_nmap() {

    section "NMAP - HOST / PORT / SERVICE DISCOVERY"

    local OUTPUT="$REPORT_DIR/nmap.txt"

    info "Starting Nmap..."
    info "Service and version discovery enabled."

    timeout 300s nmap \
        -sV \
        --version-light \
        "$DOMAIN" \
        > "$OUTPUT" 2>&1

    local CODE=$?

    if [[ $CODE -eq 0 ]]; then

        success "Nmap completed."

        add_result \
            "Nmap" \
            "Completed" \
            "$OUTPUT"

    elif [[ $CODE -eq 124 ]]; then

        warning "Nmap reached the 5-minute safety limit."

        add_result \
            "Nmap" \
            "Timed out - partial results preserved" \
            "$OUTPUT"

    else

        warning "Nmap returned exit code $CODE."

        add_result \
            "Nmap" \
            "Completed with warnings" \
            "$OUTPUT"

    fi
}

# ============================================================
# NIKTO
# ============================================================

run_nikto() {

    section "NIKTO - WEB SERVER VULNERABILITY SCAN"

    local OUTPUT="$REPORT_DIR/nikto.txt"

    info "Starting Nikto web server assessment..."
    info "Maximum scan time: 5 minutes."

    timeout 300s nikto \
        -h "$URL" \
        -Tuning 1 2 3 4 8 9 \
        -output "$OUTPUT" \
        -Format txt \
        > /dev/null 2>&1

    local CODE=$?

    if [[ $CODE -eq 0 ]]; then

        success "Nikto completed."

        add_result \
            "Nikto" \
            "Completed" \
            "$OUTPUT"

    elif [[ $CODE -eq 124 ]]; then

        warning "Nikto reached the 5-minute safety limit."

        add_result \
            "Nikto" \
            "Timed out - partial results preserved" \
            "$OUTPUT"

    else

        warning "Nikto returned exit code $CODE."

        add_result \
            "Nikto" \
            "Completed with warnings" \
            "$OUTPUT"

    fi
}


# ============================================================
# WAPITI
# ============================================================

run_wapiti() {

    section "WAPITI - WEB APPLICATION ASSESSMENT"

    local OUTPUT="$REPORT_DIR/wapiti.txt"

    info "Starting Wapiti."
    info "Maximum scan time: 5 minutes."

    timeout 300s wapiti \
        -u "$URL" \
        -f txt \
        -o "$OUTPUT" \
        > /dev/null 2>&1

    local CODE=$?

    if [[ $CODE -eq 0 ]]; then

        success "Wapiti completed."

        add_result \
            "Wapiti" \
            "Completed" \
            "$OUTPUT"

    elif [[ $CODE -eq 124 ]]; then

        warning "Wapiti reached the 5-minute safety limit."

        add_result \
            "Wapiti" \
            "Timed out - partial results preserved" \
            "$OUTPUT"

    else

        warning "Wapiti returned exit code $CODE."

        add_result \
            "Wapiti" \
            "Completed with warnings" \
            "$OUTPUT"

    fi
}

# ============================================================
# SQLMAP
# ============================================================

run_sqlmap() {

    section "SQLMAP - AUTHORIZED SQL INJECTION ASSESSMENT"

    local OUTPUT="$REPORT_DIR/sqlmap.txt"

    info "Starting controlled SQLMap assessment."
    warning "SQLMap must only be used against an explicitly authorized target."

    mkdir -p "$REPORT_DIR/sqlmap_data"

    timeout 180s sqlmap \
        -u "$URL" \
        --batch \
        --output-dir="$REPORT_DIR/sqlmap_data" \
        > "$OUTPUT" 2>&1

    local CODE=$?

    if [[ $CODE -eq 0 ]]; then

        success "SQLMap completed."

        add_result \
            "SQLMap" \
            "Completed" \
            "$OUTPUT"

    elif [[ $CODE -eq 124 ]]; then

        warning "SQLMap reached the 3-minute safety limit."

        add_result \
            "SQLMap" \
            "Timed out - partial results preserved" \
            "$OUTPUT"

    else

        warning "SQLMap returned exit code $CODE."

        add_result \
            "SQLMap" \
            "Completed with warnings" \
            "$OUTPUT"

    fi
}

# ============================================================
# GOBUSTER
# ============================================================

run_gobuster() {

    section "GOBUSTER - DIRECTORY / FILE DISCOVERY"

    local OUTPUT="$REPORT_DIR/gobuster.txt"

    info "Starting directory discovery."

    timeout 300s gobuster dir \
        -u "$URL" \
        -w "$WORDLIST" \
        --exclude-status 302 \
        -q \
        > "$OUTPUT" 2>&1

    local CODE=$?

    if [[ $CODE -eq 0 ]]; then

        success "Gobuster completed."

        add_result \
            "Gobuster" \
            "Completed" \
            "$OUTPUT"

    elif [[ $CODE -eq 124 ]]; then

        warning "Gobuster reached the 5-minute safety limit."

        add_result \
            "Gobuster" \
            "Timed out - partial results preserved" \
            "$OUTPUT"

    else

        warning "Gobuster returned exit code $CODE."

        add_result \
            "Gobuster" \
            "Completed with warnings" \
            "$OUTPUT"

    fi
}

# ============================================================
# SUMMARY
# ============================================================

generate_summary() {

    section "GENERATING SECURITY SUMMARY"

    cat >> "$REPORT_MD" <<EOF

# Assessment Summary

## Target

$URL

## Host

$DOMAIN

## IP Address

$TARGET_IP

## Assessment Date

$(date)

---

## Scanner Output

| Scanner | Output |
|---|---|
| Nmap | nmap.txt |
| Nikto | nikto.txt |
| Wapiti | wapiti.txt |
| SQLMap | sqlmap.txt |
| Gobuster | gobuster.txt |

---

## Interpretation Notice

Automated scanner output represents assessment indicators and
should be manually validated before being classified as a
confirmed vulnerability.

A missing security header, discovered endpoint, server banner,
or scanner warning does not by itself prove that a system is
exploitable.

---

## Assessment Status

Security assessment completed.

This report does not claim that the target is completely secure.

EOF

    success "Security summary generated."

}

# ============================================================
# PROFESSIONAL HTML REPORT UI/UX
# ============================================================

generate_html_report() {

    section "GENERATING PROFESSIONAL HTML REPORT"

    local HTML="$REPORT_DIR/security_assessment_report.html"

    # Escape scanner output before embedding it in HTML.
    html_escape_file() {
        if [[ -f "$1" ]]; then
            sed \
                -e 's/&/\&amp;/g' \
                -e 's/</\&lt;/g' \
                -e 's/>/\&gt;/g' \
                -e 's/"/\&quot;/g' \
                -e "s/'/\&#39;/g" "$1"
        else
            echo "No output available."
        fi
    }

    local NMAP_LINES=0
    local NIKTO_LINES=0
    local WAPITI_LINES=0
    local SQLMAP_LINES=0
    local GOBUSTER_LINES=0

    [[ -f "$REPORT_DIR/nmap.txt" ]] && NMAP_LINES=$(wc -l < "$REPORT_DIR/nmap.txt")
    [[ -f "$REPORT_DIR/nikto.txt" ]] && NIKTO_LINES=$(wc -l < "$REPORT_DIR/nikto.txt")
    [[ -f "$REPORT_DIR/wapiti.txt" ]] && WAPITI_LINES=$(wc -l < "$REPORT_DIR/wapiti.txt")
    [[ -f "$REPORT_DIR/sqlmap.txt" ]] && SQLMAP_LINES=$(wc -l < "$REPORT_DIR/sqlmap.txt")
    [[ -f "$REPORT_DIR/gobuster.txt" ]] && GOBUSTER_LINES=$(wc -l < "$REPORT_DIR/gobuster.txt")

    local NMAP_STATUS="NO DATA"
    local NIKTO_STATUS="NO DATA"
    local WAPITI_STATUS="NO DATA"
    local SQLMAP_STATUS="NO DATA"
    local GOBUSTER_STATUS="NO DATA"

    [[ -s "$REPORT_DIR/nmap.txt" ]] && NMAP_STATUS="AVAILABLE"
    [[ -s "$REPORT_DIR/nikto.txt" ]] && NIKTO_STATUS="AVAILABLE"
    [[ -s "$REPORT_DIR/wapiti.txt" ]] && WAPITI_STATUS="AVAILABLE"
    [[ -s "$REPORT_DIR/sqlmap.txt" ]] && SQLMAP_STATUS="AVAILABLE"
    [[ -s "$REPORT_DIR/gobuster.txt" ]] && GOBUSTER_STATUS="AVAILABLE"

    local TOTAL_BYTES=0
    for F in nmap.txt nikto.txt wapiti.txt sqlmap.txt gobuster.txt; do
        if [[ -f "$REPORT_DIR/$F" ]]; then
            TOTAL_BYTES=$((TOTAL_BYTES + $(wc -c < "$REPORT_DIR/$F")))
        fi
    done

    cat > "$HTML" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Intelligent Website Security Assessment</title>
<style>
:root{--bg:#050505;--panel:#0d0d0d;--panel2:#121212;--gold:#f5c542;--gold2:#ffd86a;--red:#e53935;--red2:#ff625d;--green:#3ddc84;--text:#eeeeee;--muted:#999;--line:#292929}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 12% 8%,rgba(245,197,66,.09),transparent 28%),radial-gradient(circle at 90% 18%,rgba(229,57,53,.08),transparent 30%),var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}.container{max-width:1450px;margin:auto;padding:30px}.header{border:1px solid #443716;background:linear-gradient(135deg,#090909,#171208);border-radius:24px;padding:34px;position:relative;overflow:hidden;box-shadow:0 18px 60px rgba(0,0,0,.5)}.header:after{content:"";position:absolute;right:-90px;top:-110px;width:330px;height:330px;border-radius:50%;border:1px solid rgba(245,197,66,.18);box-shadow:0 0 0 35px rgba(245,197,66,.03),0 0 0 70px rgba(245,197,66,.02)}.kicker{color:var(--red2);font-size:12px;font-weight:900;letter-spacing:3px}.header h1{margin:10px 0;color:var(--gold);font-size:36px}.subtitle{color:#c7c7c7}.badge{display:inline-flex;margin-top:18px;padding:9px 14px;border-radius:999px;background:rgba(61,220,132,.08);border:1px solid rgba(61,220,132,.3);color:var(--green);font-size:11px;font-weight:900}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:20px}.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:17px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.25)}.label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:1.6px}.value{margin-top:8px;font-size:17px;font-weight:750;word-break:break-word}.gold{color:var(--gold)}.red{color:var(--red2)}.green{color:var(--green)}.section{margin-top:26px;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:24px}.section-title{display:flex;align-items:center;gap:10px;margin:0 0 18px;color:var(--gold);font-size:20px}.section-title:before{content:"";width:4px;height:24px;background:var(--red);border-radius:4px}.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.tool{border:1px solid #292929;border-radius:15px;padding:18px;background:#0a0a0a;position:relative;overflow:hidden}.tool:before{content:"";position:absolute;left:0;top:0;width:3px;height:100%;background:var(--gold)}.tool h3{margin:0 0 9px}.tool p{margin:6px 0;color:var(--muted);font-size:12px}.status{display:inline-block;padding:5px 9px;border-radius:6px;font-size:10px;font-weight:900;background:rgba(61,220,132,.08);color:var(--green);border:1px solid rgba(61,220,132,.25)}.status.none{color:var(--red2);background:rgba(229,57,53,.08);border-color:rgba(229,57,53,.25)}.progress{height:7px;background:#202020;border-radius:10px;overflow:hidden;margin-top:13px}.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--red),var(--gold));width:100%}.evidence{margin-top:16px;border:1px solid #252525;border-radius:13px;overflow:hidden}.evidence-head{padding:11px 14px;background:#151515;color:var(--gold);font-size:12px;font-weight:900;display:flex;justify-content:space-between}pre{margin:0;padding:17px;background:#030303;color:#ddd;font:12px/1.55 "JetBrains Mono",Consolas,monospace;white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto}.notice{border-left:4px solid var(--red);background:#100909;padding:17px 18px;color:#d7d7d7;border-radius:8px;line-height:1.6}.footer{margin-top:25px;padding:25px;text-align:center;color:#777;border-top:1px solid #222;font-size:11px}@media(max-width:1000px){.grid,.tools{grid-template-columns:repeat(2,1fr)}}@media(max-width:600px){.container{padding:14px}.grid,.tools{grid-template-columns:1fr}.header h1{font-size:27px}}@media print{body{background:#fff;color:#111}.header,.card,.section{box-shadow:none}.section{break-inside:avoid}}
</style>
</head>
<body>
<div class="container">
<header class="header"><div class="kicker">SECURITY OPERATIONS • WEB ASSESSMENT</div><h1>Intelligent Website Security Assessment</h1><div class="subtitle">Unified vulnerability assessment dashboard</div><div class="badge">● ASSESSMENT COMPLETED</div></header>
<div class="grid">
<div class="card"><div class="label">Target</div><div class="value gold">$URL</div></div>
<div class="card"><div class="label">Hostname</div><div class="value">$DOMAIN</div></div>
<div class="card"><div class="label">Resolved IP</div><div class="value">$TARGET_IP</div></div>
<div class="card"><div class="label">Assessment Date</div><div class="value">$(date '+%d %b %Y, %H:%M:%S')</div></div>
</div>
<section class="section"><h2 class="section-title">Assessment Overview</h2><div class="tools">
<div class="tool"><h3>Nmap</h3><span class="status">$NMAP_STATUS</span><p>Host, port & service discovery</p><p>Evidence lines: $NMAP_LINES</p><div class="progress"><span></span></div></div>
<div class="tool"><h3>Nikto</h3><span class="status">$NIKTO_STATUS</span><p>Web server vulnerability assessment</p><p>Evidence lines: $NIKTO_LINES</p><div class="progress"><span></span></div></div>
<div class="tool"><h3>Wapiti</h3><span class="status">$WAPITI_STATUS</span><p>Web application assessment</p><p>Evidence lines: $WAPITI_LINES</p><div class="progress"><span></span></div></div>
<div class="tool"><h3>SQLMap</h3><span class="status">$SQLMAP_STATUS</span><p>Controlled SQL injection assessment</p><p>Evidence lines: $SQLMAP_LINES</p><div class="progress"><span></span></div></div>
<div class="tool"><h3>Gobuster</h3><span class="status">$GOBUSTER_STATUS</span><p>Directory & file discovery</p><p>Evidence lines: $GOBUSTER_LINES</p><div class="progress"><span></span></div></div>
</div></section>
<section class="section"><h2 class="section-title">Scan Evidence</h2>
<div class="evidence"><div class="evidence-head"><span>NMAP OUTPUT</span><span>$NMAP_LINES lines</span></div><pre>$(html_escape_file "$REPORT_DIR/nmap.txt")</pre></div>
<div class="evidence"><div class="evidence-head"><span>NIKTO OUTPUT</span><span>$NIKTO_LINES lines</span></div><pre>$(html_escape_file "$REPORT_DIR/nikto.txt")</pre></div>
<div class="evidence"><div class="evidence-head"><span>WAPITI OUTPUT</span><span>$WAPITI_LINES lines</span></div><pre>$(html_escape_file "$REPORT_DIR/wapiti.txt")</pre></div>
<div class="evidence"><div class="evidence-head"><span>SQLMAP OUTPUT</span><span>$SQLMAP_LINES lines</span></div><pre>$(html_escape_file "$REPORT_DIR/sqlmap.txt")</pre></div>
<div class="evidence"><div class="evidence-head"><span>GOBUSTER OUTPUT</span><span>$GOBUSTER_LINES lines</span></div><pre>$(html_escape_file "$REPORT_DIR/gobuster.txt")</pre></div>
</section>
<section class="section"><h2 class="section-title">Assessment Interpretation</h2><div class="notice">Automated scanner output represents assessment indicators and should be manually validated before being classified as a confirmed vulnerability. A discovered port, endpoint, banner, or scanner warning does not by itself prove exploitability. This report records assessment evidence and does not claim that the target is completely secure.</div></section>
<section class="section"><h2 class="section-title">Report Statistics</h2><div class="grid"><div class="card"><div class="label">Scanner Modules</div><div class="value gold">5</div></div><div class="card"><div class="label">Evidence Files</div><div class="value">5</div></div><div class="card"><div class="label">Collected Evidence</div><div class="value">$TOTAL_BYTES bytes</div></div><div class="card"><div class="label">Report Type</div><div class="value red">HTML Dashboard</div></div></div></section>
<div class="footer">INTELLIGENT WEBSITE SECURITY ASSESSMENT • VULNERABILITY ANALYZER<br>Authorized security assessment only • Generated automatically</div>
</div></body></html>
EOF

    success "Professional HTML report generated."
    echo -e "${CYAN}$HTML${NC}"
}

# ============================================================
# PDF GENERATION
# ============================================================

generate_pdf() {
    section "PDF REPORT"
    local HTML="$REPORT_DIR/security_assessment_report.html"
    local PDF="$REPORT_DIR/security_assessment_report.pdf"

    if command -v wkhtmltopdf >/dev/null 2>&1 && [[ -f "$HTML" ]]; then
        info "Generating styled PDF from HTML..."
        if wkhtmltopdf --enable-local-file-access --quiet "$HTML" "$PDF" > "$REPORT_DIR/pdf_generation.log" 2>&1; then
            success "Styled PDF generated: $PDF"
            return
        fi
        warning "wkhtmltopdf could not generate the PDF."
    fi

    if command -v pandoc >/dev/null 2>&1 && command -v xelatex >/dev/null 2>&1; then
        info "Generating fallback PDF from Markdown..."
        if pandoc "$REPORT_MD" -o "$PDF" --pdf-engine=xelatex > "$REPORT_DIR/pdf_generation.log" 2>&1; then
            success "Fallback PDF generated: $PDF"
            return
        fi
    fi

    warning "Styled PDF converter not installed."
    info "HTML report is available and can be printed to PDF from the browser."
}

# ============================================================
# RUN ALL SCANNERS
# ============================================================

run_nmap

run_nikto

run_wapiti

run_sqlmap

run_gobuster

# ============================================================
# GENERATE REPORT
# ============================================================

generate_summary

generate_html_report

generate_pdf

# ============================================================
# FINAL SCREEN
# ============================================================

section "ASSESSMENT COMPLETED"

echo -e "${GOLD}"
echo "Target:"
echo -e "${WHITE}$URL${NC}"

echo
echo -e "${GOLD}"
echo "Resolved IP:"
echo -e "${WHITE}$TARGET_IP${NC}"

echo
echo -e "${GOLD}"
echo "Results directory:"
echo -e "${WHITE}$REPORT_DIR${NC}"

echo
echo -e "${GOLD}"
echo "Main report:"
echo -e "${WHITE}$REPORT_MD${NC}"

echo -e "${GOLD}Designed HTML report:${NC}"
echo -e "${WHITE}$REPORT_DIR/security_assessment_report.html${NC}"

echo
echo -e "${RED}==============================================================${NC}"
echo -e "${GOLD}       INTELLIGENT SECURITY ASSESSMENT COMPLETE${NC}"
echo -e "${RED}==============================================================${NC}"
echo -e "${NC}"
