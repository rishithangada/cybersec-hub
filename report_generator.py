"""Generate a self-contained branded HTML audit report from scanner.scan() output."""
import os, secrets
from datetime import datetime

# Port risk levels — mirrors scanner.py RISKY
PORT_RISK = {23:"HIGH", 6379:"HIGH", 21:"MEDIUM", 3389:"MEDIUM"}

SEV_COLOR = {"CRITICAL":"#f85149","HIGH":"#e3824e","MEDIUM":"#e3b341","LOW":"#3fb950","INFO":"#8b949e"}

# (substring-in-issue-lower, remediation text)
REMEDIATIONS = [
    ("telnet",                  "Disable Telnet immediately. Use SSH (port 22) with key-based auth only."),
    ("redis",                   "Bind Redis to 127.0.0.1 in redis.conf. Enable requirepass."),
    ("rdp",                     "Move RDP behind VPN. Enable NLA authentication."),
    ("x-frame-options",         "Add: X-Frame-Options: DENY in your server config."),
    ("x-content-type-options",  "Add: X-Content-Type-Options: nosniff"),
    ("strict-transport-security","Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("ssl cert expires",        "Renew SSL certificate immediately. Consider Let's Encrypt for auto-renewal."),
    ("ssl cert invalid",        "Certificate validation failed. Check your certificate chain."),
]

def _remediation(issue):
    il = issue.lower()
    hits = [r for k, r in REMEDIATIONS if k in il]
    return "<br>".join(hits) if hits else "Review and remediate per security best practices."

def _sev_badge(sev):
    c = SEV_COLOR.get(sev, "#8b949e")
    return f'<span style="background:{c};color:#0d1117;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:700;">{sev}</span>'

def _port_rows(open_ports):
    if not open_ports:
        return '<tr><td colspan="3" style="color:#8b949e;text-align:center;">No open ports found</td></tr>'
    rows = []
    for p in open_ports:
        port, svc = p["port"], p["service"]
        risk = PORT_RISK.get(port, "INFO")
        c = SEV_COLOR.get(risk, "#8b949e")
        rows.append(
            f'<tr><td>{port}</td><td>{svc}</td>'
            f'<td><span style="color:{c};font-weight:700;">{risk}</span></td></tr>'
        )
    return "\n".join(rows)

def _ssl_section(ssl):
    if not ssl:
        return '<p style="color:#8b949e;">Port 443 not open — SSL not checked.</p>'
    if ssl.get("valid") is None:
        return f'<p style="color:#8b949e;">SSL check error: {ssl.get("error","unknown")}</p>'
    valid_str = '<span style="color:#3fb950;">YES</span>' if ssl.get("valid") else '<span style="color:#f85149;">NO</span>'
    expires = ssl.get("expires", "N/A")
    days = ssl.get("days_remaining")
    days_color = "#f85149" if (days is not None and days < 30) else "#3fb950"
    days_str = f'<span style="color:{days_color};">{days} days</span>' if days is not None else "N/A"
    err = f'<p style="color:#f85149;">Error: {ssl.get("error")}</p>' if ssl.get("error") else ""
    return f"""
    <table><tr><th>Valid</th><th>Expires</th><th>Days Remaining</th></tr>
    <tr><td>{valid_str}</td><td>{expires}</td><td>{days_str}</td></tr></table>{err}"""

def _headers_section(http_headers):
    if not http_headers:
        return '<p style="color:#8b949e;">No HTTP endpoint found — headers not checked.</p>'
    if "error" in http_headers:
        return f'<p style="color:#8b949e;">Header check error: {http_headers["error"]}</p>'
    all_headers = ["x-frame-options","x-content-type-options","strict-transport-security"]
    missing = set(http_headers.get("missing_headers", []))
    server = http_headers.get("server","?")
    rows = []
    for h in all_headers:
        if h in missing:
            status = '<span style="color:#f85149;font-weight:700;">FAIL</span>'
        else:
            status = '<span style="color:#3fb950;font-weight:700;">PASS</span>'
        rows.append(f"<tr><td>{h}</td><td>{status}</td></tr>")
    return f"""
    <p style="color:#8b949e;margin-bottom:8px;">Server: <span style="color:#e6edf3;">{server}</span></p>
    <table><tr><th>Header</th><th>Status</th></tr>{"".join(rows)}</table>"""

def _findings_cards(findings):
    if not findings:
        return '<p style="color:#3fb950;">No findings — looking clean.</p>'
    cards = []
    for f in findings:
        sev = f.get("severity","INFO")
        c = SEV_COLOR.get(sev, "#8b949e")
        rem = _remediation(f.get("issue",""))
        cards.append(f"""
        <div style="border-left:4px solid {c};background:#161b22;padding:16px 20px;margin-bottom:12px;border-radius:0 6px 6px 0;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
            {_sev_badge(sev)}
            <span style="font-weight:600;color:#e6edf3;">{f.get("issue","")}</span>
          </div>
          <div style="color:#8b949e;font-size:0.88em;">
            <span style="color:#3fb950;">Remediation:</span> {rem}
          </div>
        </div>""")
    return "\n".join(cards)

def _exec_summary(host, findings, scanned_at):
    counts = {}
    for f in findings:
        s = f.get("severity","INFO")
        counts[s] = counts.get(s, 0) + 1
    criticals = counts.get("CRITICAL", 0)
    highs = counts.get("HIGH", 0)
    mediums = counts.get("MEDIUM", 0)
    lows = counts.get("LOW", 0)
    total = sum(counts.values())

    if criticals > 0:
        urgency = f'<strong style="color:#f85149;">URGENT: {criticals} critical issue(s) require immediate remediation.</strong> '
    else:
        urgency = '<span style="color:#3fb950;">No critical vulnerabilities found.</span> '

    breakdown = f"{total} finding(s) total — {criticals} critical, {highs} high, {mediums} medium, {lows} low."
    return f"""<p style="line-height:1.7;color:#c9d1d9;">{urgency}
    Automated scan of <strong>{host}</strong> completed on {scanned_at}.
    {breakdown}
    Review all findings below and prioritize remediation by severity. Manual verification is recommended before drawing final conclusions.</p>"""

def generate(result):
    """Return a self-contained HTML string for the given scan result dict."""
    host = result.get("host","unknown")
    ip = result.get("ip","?")
    scanned_at = result.get("scanned_at","")[:10]
    report_id = secrets.token_hex(4).upper()
    findings = result.get("findings", [])

    CSS = """
      *{box-sizing:border-box;margin:0;padding:0}
      body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',Courier,monospace;padding:0}
      a{color:#3fb950}
      .container{max-width:900px;margin:0 auto;padding:40px 24px}
      .header{border-bottom:2px solid #21262d;padding-bottom:24px;margin-bottom:32px}
      .logo{color:#3fb950;font-size:1.5em;font-weight:700;letter-spacing:2px}
      .title{font-size:1.1em;color:#8b949e;margin-top:4px}
      .meta{display:flex;gap:32px;margin-top:16px;font-size:0.85em;color:#8b949e}
      .meta span{display:flex;flex-direction:column;gap:2px}
      .meta strong{color:#e6edf3}
      h2{color:#3fb950;font-size:1em;text-transform:uppercase;letter-spacing:2px;
         margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #21262d}
      table{width:100%;border-collapse:collapse;margin-top:8px}
      th{text-align:left;color:#8b949e;font-size:0.8em;text-transform:uppercase;
         letter-spacing:1px;padding:8px 12px;border-bottom:1px solid #21262d}
      td{padding:10px 12px;border-bottom:1px solid #161b22;color:#e6edf3}
      tr:last-child td{border-bottom:none}
      .section{margin-bottom:32px}
      .footer{margin-top:48px;padding-top:24px;border-top:1px solid #21262d;
              color:#484f58;font-size:0.8em;line-height:1.6}
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SPIRIT Security Audit — {host}</title>
  <style>{CSS}</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div class="logo">SPIRIT SECURITY</div>
    <div class="title">Web Application Audit Report</div>
    <div class="meta">
      <span><strong>{host}</strong>Target Domain</span>
      <span><strong>{ip}</strong>Resolved IP</span>
      <span><strong>{scanned_at}</strong>Scan Date</span>
      <span><strong>{report_id}</strong>Report ID</span>
    </div>
  </div>

  <div class="section">
    <h2>Executive Summary</h2>
    {_exec_summary(host, findings, scanned_at)}
  </div>

  <div class="section">
    <h2>Open Ports</h2>
    <table>
      <tr><th>Port</th><th>Service</th><th>Risk Level</th></tr>
      {_port_rows(result.get("open_ports",[]))}
    </table>
  </div>

  <div class="section">
    <h2>SSL / TLS</h2>
    {_ssl_section(result.get("ssl"))}
  </div>

  <div class="section">
    <h2>HTTP Security Headers</h2>
    {_headers_section(result.get("http_headers"))}
  </div>

  <div class="section">
    <h2>Findings</h2>
    {_findings_cards(findings)}
  </div>

  <div class="footer">
    This report was generated by D2D Spirit automated scanner.
    This audit covers the scope defined in your authorization agreement.
    It is not a substitute for a comprehensive penetration test by a certified security firm.
    <br>Report ID: {report_id} &nbsp;|&nbsp; Generated: {scanned_at} &nbsp;|&nbsp; Target: {host}
  </div>

</div>
</body>
</html>"""
    return html
