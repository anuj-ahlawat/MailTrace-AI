"""Generate professional HTML forensic reports from case/analysis data."""
from datetime import datetime, timezone


def generate_html_report(report: dict, case: dict, analysis: dict, analyst: dict) -> str:
    """Generate a self-contained HTML forensic report."""
    case = case or {}
    analysis = analysis or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_score = case.get("risk_score", 0)
    classification = case.get("classification", "Unknown")
    severity = case.get("severity", "UNKNOWN")
    case_id = case.get("case_id", report.get("case_id", "Unknown"))

    # Risk color
    if risk_score >= 80:
        risk_color = "#ef4444"
    elif risk_score >= 60:
        risk_color = "#f97316"
    elif risk_score >= 40:
        risk_color = "#eab308"
    else:
        risk_color = "#22c55e"

    # IOCs table
    iocs = analysis.get("iocs", [])
    ioc_rows = ""
    for ioc in iocs[:20]:
        ioc_rows += f"""
        <tr>
            <td>{ioc.get('type', '').upper()}</td>
            <td style="font-family:monospace">{ioc.get('indicator', '')[:60]}</td>
            <td>{ioc.get('reputation', 'unknown')}</td>
            <td>{ioc.get('risk_level', 'low')}</td>
        </tr>"""

    # Relay path
    relay = analysis.get("relay_path", [])
    relay_rows = ""
    for hop in relay:
        relay_rows += f"""
        <tr>
            <td>{hop.get('hop_number', '')}</td>
            <td>{hop.get('label', '')}</td>
            <td style="font-family:monospace">{hop.get('ip', '')}</td>
            <td>{hop.get('hostname', '')}</td>
            <td>{hop.get('location', '')}</td>
            <td>{hop.get('timestamp', '')}</td>
        </tr>"""

    # Auth
    auth = analysis.get("auth", {})
    spf_color = "#22c55e" if auth.get("spf") == "pass" else "#ef4444" if auth.get("spf") == "fail" else "#94a3b8"
    dkim_color = "#22c55e" if auth.get("dkim") == "pass" else "#ef4444" if auth.get("dkim") == "fail" else "#94a3b8"
    dmarc_color = "#22c55e" if auth.get("dmarc") == "pass" else "#ef4444" if auth.get("dmarc") == "fail" else "#94a3b8"

    meta = analysis.get("email_metadata", {})
    scoring = analysis.get("scoring_breakdown", {})
    explainable = analysis.get("explainable_ai", "No AI explanation available.")

    recommendations = """
    <ul>
        <li>Quarantine the email and block all extracted domains and IPs at perimeter firewall.</li>
        <li>Alert the intended recipient and advise against clicking any links or opening attachments.</li>
        <li>Conduct user awareness training if the recipient interacted with the email.</li>
        <li>Submit extracted IOCs to threat intelligence platforms.</li>
        <li>Review mail gateway rules to prevent similar emails from bypassing filters.</li>
        <li>Document findings and preserve all evidence per incident response policy.</li>
    </ul>
    """ if risk_score >= 60 else """
    <ul>
        <li>No immediate action required. Continue monitoring for related activity.</li>
        <li>Archive analysis results per data retention policy.</li>
    </ul>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MailTrace AI — Forensic Report {case_id}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px; color: #1e293b; background: #fff; }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 40px; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
  .header h1 {{ font-size: 22px; font-weight: 700; }}
  .header .subtitle {{ font-size: 13px; opacity: 0.7; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; color: white; }}
  .section {{ margin-bottom: 24px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }}
  .section-title {{ background: #f8fafc; padding: 12px 16px; font-weight: 700; font-size: 13px; border-bottom: 1px solid #e2e8f0; color: #0f172a; }}
  .section-body {{ padding: 16px; }}
  .kv-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  .kv-item label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 2px; }}
  .kv-item value {{ font-size: 13px; font-weight: 500; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: #f1f5f9; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; color: #64748b; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .auth-pill {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 700; color: white; margin-right: 8px; }}
  .risk-bar {{ background: #f1f5f9; border-radius: 4px; height: 8px; margin-top: 4px; }}
  .risk-fill {{ height: 8px; border-radius: 4px; }}
  .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }}
  .explainable {{ background: #f0f9ff; border-left: 4px solid #3b82f6; padding: 16px; border-radius: 4px; line-height: 1.7; white-space: pre-wrap; font-size: 12px; }}
  .disclaimer {{ background: #fef3c7; border: 1px solid #f59e0b; border-radius: 6px; padding: 12px; font-size: 12px; color: #92400e; margin-bottom: 16px; }}
  @media print {{ .page {{ padding: 20px; }} }}
</style>
</head>
<body>
<div class="page">

<!-- Header -->
<div class="header">
  <h1>🛡️ MailTrace AI — Forensic Investigation Report</h1>
  <div class="subtitle">AI-Powered Email Threat Detection &amp; Forensic Intelligence Platform</div>
  <div style="margin-top:16px; display:flex; gap:16px; flex-wrap:wrap">
    <div><span style="opacity:0.6;font-size:11px">Case ID</span><br><strong>{case_id}</strong></div>
    <div><span style="opacity:0.6;font-size:11px">Generated</span><br><strong>{now}</strong></div>
    <div><span style="opacity:0.6;font-size:11px">Analyst</span><br><strong>{analyst.get('name', 'Unknown')}</strong></div>
    <div><span style="opacity:0.6;font-size:11px">Risk Score</span><br>
      <span class="badge" style="background:{risk_color};font-size:14px">{risk_score}/100</span></div>
    <div><span style="opacity:0.6;font-size:11px">Classification</span><br>
      <span class="badge" style="background:{risk_color}">{classification}</span></div>
  </div>
</div>

<!-- Disclaimer -->
<div class="disclaimer">
  ⚠️ <strong>Disclaimer:</strong> IP geolocation represents <em>Probable Infrastructure Location</em> and may not represent the physical location of the threat actor. Always validate findings with additional corroborating intelligence before attribution.
</div>

<!-- Executive Summary -->
<div class="section">
  <div class="section-title">📋 Executive Summary</div>
  <div class="section-body">
    <div class="kv-grid">
      <div class="kv-item"><label>Classification</label><value>{classification}</value></div>
      <div class="kv-item"><label>Severity</label><value>{severity}</value></div>
      <div class="kv-item"><label>Risk Score</label><value style="color:{risk_color};font-weight:700">{risk_score}/100</value></div>
      <div class="kv-item"><label>Status</label><value>{case.get('status', 'NEW')}</value></div>
      <div class="kv-item"><label>Sender</label><value>{case.get('sender', 'Unknown')}</value></div>
      <div class="kv-item"><label>Subject</label><value>{case.get('subject', 'Unknown')}</value></div>
    </div>
  </div>
</div>

<!-- Email Metadata -->
<div class="section">
  <div class="section-title">📧 Email Metadata</div>
  <div class="section-body">
    <div class="kv-grid">
      <div class="kv-item"><label>From</label><value>{meta.get('from_address', 'N/A')}</value></div>
      <div class="kv-item"><label>Reply-To</label><value>{meta.get('reply_to', 'N/A')}</value></div>
      <div class="kv-item"><label>Return-Path</label><value>{meta.get('return_path', 'N/A')}</value></div>
      <div class="kv-item"><label>Date</label><value>{meta.get('date', 'N/A')}</value></div>
      <div class="kv-item"><label>Message-ID</label><value style="font-size:11px;font-family:monospace">{meta.get('message_id', 'N/A')}</value></div>
      <div class="kv-item"><label>X-Originating-IP</label><value style="font-family:monospace">{meta.get('x_originating_ip', 'N/A')}</value></div>
    </div>
  </div>
</div>

<!-- Authentication -->
<div class="section">
  <div class="section-title">🔐 Authentication Analysis (SPF / DKIM / DMARC)</div>
  <div class="section-body">
    <div style="margin-bottom:12px">
      <span class="auth-pill" style="background:{spf_color}">SPF: {auth.get('spf', 'unknown').upper()}</span>
      <span class="auth-pill" style="background:{dkim_color}">DKIM: {auth.get('dkim', 'unknown').upper()}</span>
      <span class="auth-pill" style="background:{dmarc_color}">DMARC: {auth.get('dmarc', 'unknown').upper()}</span>
    </div>
    <div style="font-size:12px;color:#475569;line-height:1.6">
      {auth.get('spf_detail', '')}<br>
      {auth.get('dkim_detail', '')}<br>
      {auth.get('dmarc_detail', '')}
      {'<br><strong style="color:#ef4444">⚠️ ' + auth.get('reply_to_mismatch_detail', '') + '</strong>' if auth.get('reply_to_mismatch') else ''}
    </div>
  </div>
</div>

<!-- Scoring Breakdown -->
<div class="section">
  <div class="section-title">📊 AI Scoring Breakdown</div>
  <div class="section-body">
    {"".join(f'''
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
        <span style="font-size:12px;font-weight:500">{k.replace("_", " ").title()}</span>
        <span style="font-size:12px;color:{risk_color if v >= 60 else "#94a3b8"}">{v:.0f}/100</span>
      </div>
      <div class="risk-bar"><div class="risk-fill" style="width:{v}%;background:{risk_color if v >= 60 else "#3b82f6" if v >= 30 else "#94a3b8"}"></div></div>
    </div>''' for k, v in scoring.items())}
  </div>
</div>

<!-- IOCs -->
<div class="section">
  <div class="section-title">🎯 Indicators of Compromise (IOCs)</div>
  <div class="section-body">
    {"<p style='color:#94a3b8'>No IOCs extracted.</p>" if not iocs else f'''
    <table>
      <thead><tr><th>Type</th><th>Indicator</th><th>Reputation</th><th>Risk</th></tr></thead>
      <tbody>{ioc_rows}</tbody>
    </table>'''}
  </div>
</div>

<!-- Relay Path -->
<div class="section">
  <div class="section-title">🌐 Probable Infrastructure Location & Email Relay Path</div>
  <div class="section-body">
    <div class="disclaimer" style="margin-bottom:12px">
      Probable Infrastructure Location — reflects observed relay infrastructure. This is NOT a confirmed attacker location.
    </div>
    {"<p style='color:#94a3b8'>No relay path data available.</p>" if not relay else f'''
    <table>
      <thead><tr><th>#</th><th>Label</th><th>IP</th><th>Hostname</th><th>Location</th><th>Timestamp</th></tr></thead>
      <tbody>{relay_rows}</tbody>
    </table>'''}
  </div>
</div>

<!-- AI Explanation -->
<div class="section">
  <div class="section-title">🤖 AI Threat Explanation</div>
  <div class="section-body">
    <div class="explainable">{explainable}</div>
  </div>
</div>

<!-- Recommendations -->
<div class="section">
  <div class="section-title">✅ Recommendations</div>
  <div class="section-body">{recommendations}</div>
</div>

<!-- Evidence -->
<div class="section">
  <div class="section-title">🔒 Evidence Integrity</div>
  <div class="section-body">
    <div class="kv-grid">
      <div class="kv-item"><label>Evidence Hash (SHA256)</label><value style="font-family:monospace;font-size:11px">{analysis.get('evidence_hash', 'N/A')}</value></div>
      <div class="kv-item"><label>Analysis Timestamp</label><value>{analysis.get('analysis_timestamp', 'N/A')}</value></div>
    </div>
    <div style="margin-top:12px;font-size:12px;color:#475569">
      Chain of custody: Email Uploaded → Analyzed → Case Created → Report Generated
    </div>
  </div>
</div>

<!-- Footer -->
<div class="footer">
  <strong>MailTrace AI</strong> — AI-Powered Email Threat Detection &amp; Forensic Intelligence Platform<br>
  Report generated: {now} | Analyst: {analyst.get('name', 'Unknown')} ({analyst.get('email', '')})<br>
  <em>This report is confidential and intended for authorized investigators only.</em>
</div>

</div>
</body>
</html>"""
