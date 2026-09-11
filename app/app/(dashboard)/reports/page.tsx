'use client';

import { useState, useEffect, useCallback } from 'react';
import { FileText, Download, Eye, Plus, Search, CheckCircle, AlertTriangle, Shield, Brain, Clock, Lock, X, RefreshCw, Printer } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { reportsAPI, casesAPI, type Report } from '@/lib/api';
import { mockCases } from '@/lib/mockData';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import { demoEmails } from '@/lib/demoEmails';

// ─── PDF/Print report generator ───────────────────────────────────────────────
// Generates a self-contained HTML page and opens it in a new tab for print-to-PDF

function generatePrintableHTML(report: ReportDisplay): string {
  const riskColor = report.risk >= 81 ? '#ef4444' : report.risk >= 61 ? '#f97316' : report.risk >= 41 ? '#eab308' : '#22c55e';
  const riskLabel = report.risk >= 81 ? 'CRITICAL' : report.risk >= 61 ? 'HIGH' : report.risk >= 41 ? 'SUSPICIOUS' : 'LOW';
  const now = new Date().toLocaleString();

  // Pull analysis data from mock if available
  const demoId = report.demoId;
  const result = demoId ? mockAnalysisResults[demoId] : null;
  const email = demoId ? demoEmails.find(d => d.id === demoId) : null;

  const authSection = result ? `
    <div class="section">
      <div class="section-title">🔐 Authentication Results (SPF / DKIM / DMARC)</div>
      <div class="section-body">
        <div class="auth-row">
          <span class="auth-pill" style="background:${result.auth.spf === 'pass' ? '#22c55e' : '#ef4444'}">SPF: ${result.auth.spf.toUpperCase()}</span>
          <span class="auth-pill" style="background:${result.auth.dkim === 'pass' ? '#22c55e' : '#ef4444'}">DKIM: ${result.auth.dkim.toUpperCase()}</span>
          <span class="auth-pill" style="background:${result.auth.dmarc === 'pass' ? '#22c55e' : '#ef4444'}">DMARC: ${result.auth.dmarc.toUpperCase()}</span>
        </div>
        <div class="auth-details">
          <p>${result.auth.spfDetail}</p>
          <p>${result.auth.dkimDetail}</p>
          <p>${result.auth.dmarcDetail}</p>
          ${result.auth.replyToMismatch ? `<p class="warning">⚠️ ${result.auth.replyToMismatchDetail}</p>` : ''}
        </div>
      </div>
    </div>
  ` : '';

  const iocRows = result ? result.iocs.map(ioc => `
    <tr>
      <td>${ioc.type.toUpperCase()}</td>
      <td class="mono">${ioc.indicator}</td>
      <td class="${ioc.reputation === 'malicious' ? 'danger' : ioc.reputation === 'suspicious' ? 'warn' : 'safe'}">${ioc.reputation}</td>
      <td>${ioc.riskLevel}</td>
    </tr>
  `).join('') : '';

  const iocSection = result && result.iocs.length > 0 ? `
    <div class="section">
      <div class="section-title">🎯 Indicators of Compromise (${result.iocs.length} IOCs)</div>
      <div class="section-body">
        <table><thead><tr><th>Type</th><th>Indicator</th><th>Reputation</th><th>Risk</th></tr></thead>
        <tbody>${iocRows}</tbody></table>
      </div>
    </div>
  ` : '';

  const relayRows = result ? result.relayPath.map((hop, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>${hop.label}</td>
      <td class="mono">${hop.ip || 'Private'}</td>
      <td>${hop.hostname}</td>
      <td>${hop.location}</td>
      <td>${hop.confidence}</td>
    </tr>
  `).join('') : '';

  const relaySection = result && result.relayPath.length > 0 ? `
    <div class="section">
      <div class="section-title">🌐 Email Relay Path & Probable Infrastructure Location</div>
      <div class="section-body">
        <div class="disclaimer">⚠️ IP geolocation reflects <em>Probable Infrastructure Location</em>, NOT confirmed attacker location.</div>
        <table><thead><tr><th>#</th><th>Label</th><th>IP</th><th>Hostname</th><th>Location</th><th>Confidence</th></tr></thead>
        <tbody>${relayRows}</tbody></table>
      </div>
    </div>
  ` : '';

  const aiSection = result ? `
    <div class="section">
      <div class="section-title">🤖 AI Threat Explanation</div>
      <div class="section-body"><div class="ai-box">${result.explainableAI}</div></div>
    </div>
  ` : '';

  const scoringSection = result ? `
    <div class="section">
      <div class="section-title">📊 AI Scoring Breakdown</div>
      <div class="section-body">
        ${Object.entries(result.scoringBreakdown).map(([k, v]) => {
          const label = k.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase());
          return `<div class="bar-row"><span class="bar-label">${label}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.min(100, (v as number) * 4)}%;background:${(v as number) > 18 ? '#ef4444' : (v as number) > 10 ? '#f97316' : '#3b82f6'}"></div></div><span class="bar-val">${v}/25</span></div>`;
        }).join('')}
      </div>
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MailTrace AI — Forensic Report ${report.caseId}</title>
<style>
  @page { size: A4; margin: 15mm; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 12px; color: #1e293b; background: #fff; line-height: 1.5; }
  .page { max-width: 900px; margin: 0 auto; padding: 20px; }
  .header { background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; padding: 24px; border-radius: 8px; margin-bottom: 20px; }
  .header h1 { font-size: 20px; margin-bottom: 4px; }
  .header .sub { font-size: 12px; opacity: 0.7; }
  .header .meta { display: flex; gap: 20px; margin-top: 12px; flex-wrap: wrap; }
  .header .meta-item { }
  .header .meta-label { font-size: 10px; opacity: 0.6; text-transform: uppercase; }
  .header .meta-value { font-weight: 700; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; color: white; }
  .section { margin-bottom: 16px; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden; page-break-inside: avoid; }
  .section-title { background: #f8fafc; padding: 10px 14px; font-weight: 700; font-size: 12px; border-bottom: 1px solid #e2e8f0; }
  .section-body { padding: 12px 14px; }
  .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .kv-item label { font-size: 10px; color: #64748b; text-transform: uppercase; display: block; margin-bottom: 1px; }
  .kv-item value { font-size: 12px; font-weight: 500; word-break: break-all; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; }
  th { background: #f1f5f9; padding: 6px 10px; text-align: left; font-weight: 600; font-size: 10px; text-transform: uppercase; color: #64748b; }
  td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; }
  .mono { font-family: monospace; font-size: 11px; }
  .danger { color: #ef4444; font-weight: 700; }
  .warn { color: #f97316; font-weight: 700; }
  .safe { color: #22c55e; font-weight: 700; }
  .warning { color: #ef4444; font-weight: 600; margin-top: 8px; }
  .auth-row { display: flex; gap: 8px; margin-bottom: 10px; }
  .auth-pill { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-size: 11px; font-weight: 700; }
  .auth-details p { font-size: 11px; color: #475569; margin-bottom: 4px; }
  .disclaimer { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 4px; padding: 8px; font-size: 11px; color: #92400e; margin-bottom: 10px; }
  .ai-box { background: #f0f9ff; border-left: 3px solid #3b82f6; padding: 12px; border-radius: 4px; font-size: 12px; line-height: 1.7; white-space: pre-wrap; }
  .bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .bar-label { font-size: 11px; width: 180px; flex-shrink: 0; }
  .bar-track { flex: 1; height: 6px; background: #f1f5f9; border-radius: 3px; overflow: hidden; }
  .bar-fill { height: 6px; border-radius: 3px; }
  .bar-val { font-size: 11px; width: 40px; text-align: right; color: #64748b; }
  .footer { margin-top: 20px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 10px; color: #94a3b8; text-align: center; }
  .rec-list { list-style: none; counter-reset: rec; }
  .rec-list li { counter-increment: rec; padding: 4px 0; font-size: 12px; }
  .rec-list li::before { content: counter(rec) ". "; font-weight: 700; color: #3b82f6; }
  .print-btn { position: fixed; top: 16px; right: 16px; padding: 10px 20px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer; z-index: 100; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
  .print-btn:hover { background: #2563eb; }
  @media print { .print-btn { display: none; } }
</style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
<div class="page">

<div class="header">
  <h1>🛡️ MailTrace AI — Forensic Investigation Report</h1>
  <div class="sub">AI-Powered Email Threat Detection & Forensic Intelligence Platform</div>
  <div class="meta">
    <div class="meta-item"><div class="meta-label">Case ID</div><div class="meta-value">${report.caseId}</div></div>
    <div class="meta-item"><div class="meta-label">Report ID</div><div class="meta-value">${report.id}</div></div>
    <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">${now}</div></div>
    <div class="meta-item"><div class="meta-label">Analyst</div><div class="meta-value">${report.analyst}</div></div>
    <div class="meta-item"><div class="meta-label">Risk Score</div><div class="meta-value"><span class="badge" style="background:${riskColor};font-size:13px">${report.risk}/100 ${riskLabel}</span></div></div>
    <div class="meta-item"><div class="meta-label">Classification</div><div class="meta-value"><span class="badge" style="background:${riskColor}">${report.type}</span></div></div>
  </div>
</div>

<div class="disclaimer">⚠️ <strong>Disclaimer:</strong> IP geolocation represents <em>Probable Infrastructure Location</em> and may not represent the physical location of the threat actor.</div>

<div class="section">
  <div class="section-title">📋 Executive Summary</div>
  <div class="section-body">
    <div class="kv-grid">
      <div class="kv-item"><label>Classification</label><value>${report.type}</value></div>
      <div class="kv-item"><label>Risk Score</label><value style="color:${riskColor};font-weight:700">${report.risk}/100</value></div>
      <div class="kv-item"><label>Case ID</label><value>${report.caseId}</value></div>
      <div class="kv-item"><label>Status</label><value>${report.status}</value></div>
    </div>
    ${email ? `<div style="margin-top:10px">
      <div class="kv-grid">
        <div class="kv-item"><label>From</label><value>${email.from}</value></div>
        <div class="kv-item"><label>To</label><value>${email.to}</value></div>
        <div class="kv-item"><label>Subject</label><value>${email.subject}</value></div>
        <div class="kv-item"><label>Date</label><value>${email.date}</value></div>
      </div>
    </div>` : ''}
  </div>
</div>

${authSection}
${iocSection}
${relaySection}
${scoringSection}
${aiSection}

<div class="section">
  <div class="section-title">✅ Recommendations</div>
  <div class="section-body">
    <ol class="rec-list">
      ${report.risk >= 60 ? `
        <li>Quarantine the email and block all extracted domains and IPs at perimeter firewall.</li>
        <li>Alert the intended recipient and advise against clicking any links or opening attachments.</li>
        <li>Conduct user awareness training if the recipient interacted with the email.</li>
        <li>Submit extracted IOCs to threat intelligence platforms (MISP, OpenCTI).</li>
        <li>Review mail gateway rules to prevent similar emails from bypassing filters.</li>
        <li>Document findings and preserve all evidence per incident response policy.</li>
        <li>Implement DMARC reporting for your domain to monitor spoofing attempts.</li>
      ` : `
        <li>No immediate action required. Continue monitoring for related activity.</li>
        <li>Archive analysis results per data retention policy.</li>
      `}
    </ol>
  </div>
</div>

<div class="section">
  <div class="section-title">🔒 Evidence Integrity</div>
  <div class="section-body">
    <div class="kv-grid">
      <div class="kv-item"><label>Evidence Hash (SHA256)</label><value class="mono">${result?.evidenceHash || 'N/A'}</value></div>
      <div class="kv-item"><label>Analysis Timestamp</label><value>${result?.analysisTimestamp || now}</value></div>
    </div>
    <div style="margin-top:8px;font-size:11px;color:#475569">Chain of custody: Email Uploaded → Analyzed → Case Created → Report Generated</div>
  </div>
</div>

<div class="footer">
  <strong>MailTrace AI</strong> — AI-Powered Email Threat Detection & Forensic Intelligence Platform<br>
  Report generated: ${now} | Report ID: ${report.id}<br>
  <em>This report is confidential and intended for authorized investigators only.</em>
</div>

</div>
</body>
</html>`;
}

function downloadReportAsPDF(report: ReportDisplay) {
  const html = generatePrintableHTML(report);
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');
  if (win) {
    // Automatically trigger print dialog after page loads
    win.addEventListener('load', () => {
      setTimeout(() => win.print(), 300);
    });
  } else {
    // Fallback: download as HTML
    const a = document.createElement('a');
    a.href = url;
    a.download = `MailTrace-Report-${report.caseId}.html`;
    a.click();
  }
}

// ─── Report Modal (Preview) ──────────────────────────────────────────────────

interface ReportDisplay {
  id: string;
  caseId: string;
  title: string;
  type: string;
  risk: number;
  analyst: string;
  date: string;
  status: string;
  demoId?: string;
  backendId?: string;
}

function ReportModal({ report, onClose }: { report: ReportDisplay; onClose: () => void }) {
  const result = report.demoId ? mockAnalysisResults[report.demoId] : null;
  const email = report.demoId ? demoEmails.find(d => d.id === report.demoId) : null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-8 py-5 border-b border-slate-100 flex items-center justify-between bg-[#0f172a] flex-shrink-0">
          <div>
            <div className="text-xs text-slate-400 uppercase tracking-widest mb-1">MAILTRACE AI FORENSIC REPORT</div>
            <h2 className="text-lg font-bold text-white">Forensic Investigation Report</h2>
            <div className="text-xs text-slate-400 mt-1">Case {report.caseId} · Generated {report.date}</div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onClose} className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white text-sm font-medium rounded-lg transition-colors">Close</button>
            <button
              onClick={() => downloadReportAsPDF(report)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors"
            >
              <Download className="w-4 h-4" /> Download PDF
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-8 space-y-8">
          {/* Executive Summary */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">1. Executive Summary</h3>
            <div className={`${report.risk >= 60 ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'} border rounded-xl p-5`}>
              <div className="flex items-center gap-3 mb-3">
                {report.risk >= 60 ? <AlertTriangle className="w-5 h-5 text-red-500" /> : <CheckCircle className="w-5 h-5 text-emerald-500" />}
                <span className={`text-base font-bold ${report.risk >= 60 ? 'text-red-800' : 'text-emerald-800'}`}>
                  {report.risk >= 81 ? 'CRITICAL' : report.risk >= 61 ? 'HIGH' : 'LOW'} THREAT — {report.type}
                </span>
              </div>
              <p className="text-sm text-slate-700 leading-relaxed">
                {result?.explainableAI?.slice(0, 300) || `This email has been classified as ${report.type} with a risk score of ${report.risk}/100. Full forensic analysis has been conducted on all email headers, authentication records, extracted indicators of compromise, and social engineering signals.`}
              </p>
            </div>
          </section>

          {/* Classification & Score */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">2. Threat Classification & Risk Score</h3>
            <div className="grid grid-cols-3 gap-4">
              <div className={`text-center p-4 border rounded-xl ${report.risk >= 81 ? 'bg-red-50 border-red-200' : report.risk >= 61 ? 'bg-orange-50 border-orange-200' : 'bg-emerald-50 border-emerald-200'}`}>
                <div className={`text-4xl font-bold mb-1 ${report.risk >= 81 ? 'text-red-600' : report.risk >= 61 ? 'text-orange-600' : 'text-emerald-600'}`}>{report.risk}/100</div>
                <div className={`text-sm font-semibold ${report.risk >= 81 ? 'text-red-700' : report.risk >= 61 ? 'text-orange-700' : 'text-emerald-700'}`}>
                  {report.risk >= 81 ? 'CRITICAL' : report.risk >= 61 ? 'HIGH' : 'LOW'}
                </div>
                <div className="text-xs text-slate-500 mt-1">Overall Risk Score</div>
              </div>
              <div className="text-center p-4 bg-orange-50 border border-orange-200 rounded-xl">
                <div className="text-lg font-bold text-orange-700 mb-1">{report.type}</div>
                <div className="text-xs text-slate-500 mt-1">Primary Classification</div>
              </div>
              <div className="text-center p-4 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-sm font-mono font-medium text-slate-700 text-xs break-all">{(result?.evidenceHash || 'N/A').slice(0, 24)}...</div>
                <div className="text-xs text-slate-400 mt-1">Evidence SHA256 (truncated)</div>
              </div>
            </div>
          </section>

          {/* Email Metadata */}
          {email && (
            <section>
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">3. Email Metadata</h3>
              <div className="grid grid-cols-2 gap-x-8 gap-y-2">
                {[
                  ['From', email.from],
                  ['To', email.to],
                  ['Subject', email.subject],
                  ['Date', email.date],
                  ['Message-ID', email.messageId],
                  ['Reply-To', result?.auth?.replyToMismatch ? 'MISMATCH DETECTED' : 'Same as From'],
                ].map(([k, v]) => (
                  <div key={k} className="flex gap-3 py-2 border-b border-slate-50 text-sm">
                    <span className="text-slate-400 w-24 flex-shrink-0">{k}</span>
                    <span className="text-slate-700 font-medium break-all">{v}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Auth Results */}
          {result && (
            <section>
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">4. SPF / DKIM / DMARC Results</h3>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'SPF', status: result.auth.spf, detail: result.auth.spfDetail },
                  { label: 'DKIM', status: result.auth.dkim, detail: result.auth.dkimDetail },
                  { label: 'DMARC', status: result.auth.dmarc, detail: result.auth.dmarcDetail },
                ].map(card => (
                  <div key={card.label} className={`border rounded-xl p-4 ${card.status === 'fail' ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'}`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-slate-800">{card.label}</span>
                      <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${card.status === 'fail' ? 'bg-red-100 text-red-700' : 'bg-emerald-100 text-emerald-700'}`}>{card.status.toUpperCase()}</span>
                    </div>
                    <p className="text-xs text-slate-500">{card.detail.slice(0, 100)}...</p>
                  </div>
                ))}
              </div>
              {result.auth.replyToMismatch && (
                <div className="mt-3 bg-red-50 border border-red-200 rounded-xl p-4 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                  <p className="text-sm text-red-700 font-medium">{result.auth.replyToMismatchDetail}</p>
                </div>
              )}
            </section>
          )}

          {/* IOCs */}
          {result && result.iocs.length > 0 && (
            <section>
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">5. Extracted Indicators of Compromise</h3>
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border border-slate-200">
                    <th className="text-left text-xs text-slate-500 p-3">Type</th>
                    <th className="text-left text-xs text-slate-500 p-3">Indicator</th>
                    <th className="text-left text-xs text-slate-500 p-3">Reputation</th>
                    <th className="text-left text-xs text-slate-500 p-3">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {result.iocs.map(ioc => (
                    <tr key={ioc.id} className="border-b border-slate-100">
                      <td className="p-3 text-xs capitalize text-slate-500">{ioc.type}</td>
                      <td className="p-3 font-mono text-xs text-slate-700">{ioc.indicator}</td>
                      <td className={`p-3 text-xs font-bold capitalize ${ioc.reputation === 'malicious' ? 'text-red-600' : ioc.reputation === 'suspicious' ? 'text-orange-600' : 'text-emerald-600'}`}>{ioc.reputation}</td>
                      <td className="p-3 text-xs font-bold capitalize text-slate-700">{ioc.riskLevel}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {/* Relay path */}
          {result && result.relayPath.length > 0 && (
            <section>
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">6. Probable Infrastructure Location</h3>
              <div className="bg-orange-50 border border-orange-200 rounded-xl p-5">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-orange-500 flex-shrink-0" />
                  <div>
                    <div className="font-semibold text-orange-800 mb-1">Probable Infrastructure Location: {result.relayPath[result.relayPath.length - 1]?.location} ({result.relayPath[result.relayPath.length - 1]?.confidence} confidence)</div>
                    <p className="text-xs text-orange-600">
                      IP geolocation represents the observed infrastructure and may not represent the physical location of the threat actor.
                    </p>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* AI Explanation */}
          {result && (
            <section>
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">7. AI Threat Explanation</h3>
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
                <p className="text-sm text-slate-700 leading-relaxed">{result.explainableAI}</p>
              </div>
            </section>
          )}

          {/* Evidence */}
          <section className="bg-emerald-50 border border-emerald-200 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <Lock className="w-4 h-4 text-emerald-600" />
              <h3 className="text-sm font-bold text-emerald-800">Evidence Integrity: VERIFIED</h3>
            </div>
            {result && (
              <>
                <div className="text-xs font-mono text-slate-600">SHA256: {result.evidenceHash}</div>
                <div className="text-xs text-slate-400 mt-1">Analysis timestamp: {result.analysisTimestamp}</div>
              </>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

// ─── Create Report Modal ──────────────────────────────────────────────────────

function CreateReportModal({ onClose, onCreated }: { onClose: () => void; onCreated: (r: ReportDisplay) => void }) {
  const [caseId, setCaseId] = useState('');
  const [title, setTitle] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const handleCreate = async () => {
    if (!caseId.trim()) { setError('Please enter a case ID'); return; }
    setCreating(true);
    setError('');
    try {
      const report = await reportsAPI.create(caseId.trim(), title.trim() || undefined);
      onCreated({
        id: report.report_id || report.id,
        caseId: report.case_ref || report.case_id,
        title: report.title,
        type: report.classification || 'Unknown',
        risk: report.risk_score || 0,
        analyst: report.analyst_name || 'You',
        date: new Date(report.created_at).toLocaleString(),
        status: report.status || 'Completed',
        backendId: report.id,
      });
    } catch (err) {
      // Demo fallback
      const demoCase = mockCases.find(c => c.id === caseId.trim());
      if (demoCase) {
        onCreated({
          id: `RPT-${Date.now().toString(36).toUpperCase()}`,
          caseId: demoCase.id,
          title: title || `Forensic Report — ${demoCase.id}`,
          type: demoCase.classification,
          risk: demoCase.riskScore,
          analyst: 'AM',
          date: new Date().toLocaleString(),
          status: 'Completed',
          demoId: demoCase.demoId,
        });
      } else {
        setError((err as Error).message || 'Case not found. Use a case ID from the Cases page.');
      }
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
        <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-800">Generate Forensic Report</h2>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center hover:bg-slate-100 rounded-lg"><X className="w-4 h-4 text-slate-400" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1.5">Case ID *</label>
            <input value={caseId} onChange={e => setCaseId(e.target.value)} placeholder="e.g. MT-2026-00124"
              className="w-full px-3 py-2.5 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
            <p className="text-[10px] text-slate-400 mt-1">Available: MT-2026-00124, MT-2026-00123, MT-2026-00121</p>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider block mb-1.5">Title (optional)</label>
            <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Auto-generated if blank"
              className="w-full px-3 py-2.5 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
          </div>
          {error && (
            <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
              <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
              <p className="text-xs text-red-700">{error}</p>
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-slate-100 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 rounded-xl transition-colors">Cancel</button>
          <button onClick={handleCreate} disabled={creating || !caseId.trim()}
            className="flex items-center gap-2 px-5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white font-semibold rounded-xl text-sm transition-colors">
            {creating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <FileText className="w-3.5 h-3.5" />}
            Generate
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const INITIAL_REPORTS: ReportDisplay[] = [
  { id: 'RPT-001', caseId: 'MT-2026-00124', title: 'BEC Investigation — Urgent Vendor Payment', type: 'Business Email Compromise', risk: 94, analyst: 'Admin User', date: 'Today 11:54 AM', status: 'Completed', demoId: 'demo-3' },
  { id: 'RPT-002', caseId: 'MT-2026-00123', title: 'Credential Phishing — Payroll Verification', type: 'Credential Phishing', risk: 86, analyst: 'Admin User', date: 'Today 10:21 AM', status: 'Completed', demoId: 'demo-2' },
  { id: 'RPT-003', caseId: 'MT-2026-00118', title: 'BEC — Q3 Budget Approval', type: 'Business Email Compromise', risk: 89, analyst: 'Sarah Kim', date: 'Aug 25, 3:22 PM', status: 'Completed' },
  { id: 'RPT-004', caseId: 'MT-2026-00115', title: 'BEC — Board Resolution Wire Transfer', type: 'Business Email Compromise', risk: 96, analyst: 'Raj Kumar', date: 'Aug 24, 5:00 PM', status: 'Completed' },
];

export default function ReportsPage() {
  const [showReport, setShowReport] = useState<ReportDisplay | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [reports, setReports] = useState<ReportDisplay[]>(INITIAL_REPORTS);
  const [loading, setLoading] = useState(true);
  const [isLive, setIsLive] = useState(false);
  const [search, setSearch] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const loadReports = useCallback(async () => {
    setRefreshing(true);
    try {
      const data = await reportsAPI.list();
      if (data && data.length > 0) {
        const normalized: ReportDisplay[] = data.map((r: Report) => ({
          id: r.report_id || r.id,
          caseId: r.case_ref || r.case_id,
          title: r.title,
          type: r.classification || 'Unknown',
          risk: r.risk_score || 0,
          analyst: r.analyst_name || 'Unknown',
          date: new Date(r.created_at).toLocaleString(),
          status: r.status || 'Completed',
          backendId: r.id,
        }));
        setReports(normalized);
        setIsLive(true);
      } else {
        throw new Error('empty');
      }
    } catch {
      setReports(INITIAL_REPORTS);
      setIsLive(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { loadReports(); }, [loadReports]);

  const filtered = reports.filter(r =>
    !search || r.title.toLowerCase().includes(search.toLowerCase()) ||
    r.caseId.toLowerCase().includes(search.toLowerCase()) ||
    r.type.toLowerCase().includes(search.toLowerCase())
  );

  const handleReportCreated = (r: ReportDisplay) => {
    setReports(prev => [r, ...prev]);
    setShowCreate(false);
    setShowReport(r);
  };

  const getRiskBg = (risk: number) =>
    risk >= 81 ? 'bg-red-50 border-red-200 text-red-700' :
    risk >= 61 ? 'bg-orange-50 border-orange-200 text-orange-700' :
    risk >= 41 ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
    'bg-emerald-50 border-emerald-200 text-emerald-700';

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Reports" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">FORENSIC DOCUMENTATION</div>
            <h1 className="text-2xl font-bold text-slate-800">
              Reports
              <span className={`ml-3 text-sm px-2 py-0.5 rounded-full font-semibold ${isLive ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                {isLive ? '● LIVE' : '● DEMO'}
              </span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={loadReports} disabled={refreshing} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors shadow-sm"
            >
              <Plus className="w-4 h-4" />
              Generate report
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Total Reports', value: String(reports.length), icon: <FileText className="w-4 h-4" /> },
            { label: 'Critical Cases', value: String(reports.filter(r => r.risk >= 81).length), icon: <AlertTriangle className="w-4 h-4" /> },
            { label: 'This Session', value: String(reports.filter(r => r.date.includes('Today') || r.date.includes(new Date().toLocaleDateString())).length), icon: <Clock className="w-4 h-4" /> },
          ].map(({ label, value, icon }) => (
            <div key={label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex items-center gap-4">
              <div className="w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center text-blue-500">{icon}</div>
              <div>
                <div className="text-2xl font-bold text-slate-800">{value}</div>
                <div className="text-sm text-slate-500">{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Reports list */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <h3 className="text-sm font-semibold text-slate-700">Generated Reports</h3>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search reports..." className="pl-9 pr-4 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 w-56" />
            </div>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-6 py-3">Report ID</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Title</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Type</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Risk</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Analyst</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Date</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? [...Array(4)].map((_, i) => (
                <tr key={i} className="border-b border-slate-50">
                  {[...Array(7)].map((_, j) => <td key={j} className="px-5 py-4"><div className="h-3 bg-slate-100 rounded animate-pulse" /></td>)}
                </tr>
              )) : filtered.map(r => (
                <tr key={r.id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4">
                    <span className="text-sm font-mono text-blue-600 font-medium">{r.id}</span>
                    <div className="text-xs text-slate-400">{r.caseId}</div>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm text-slate-700 font-medium">{r.title}</span>
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-xs font-medium px-2 py-1 rounded-full bg-orange-50 text-orange-700">{r.type}</span>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`text-xs font-bold px-2 py-1 rounded-full border ${getRiskBg(r.risk)}`}>{r.risk}/100</span>
                  </td>
                  <td className="px-4 py-4 text-sm text-slate-600">{r.analyst}</td>
                  <td className="px-4 py-4 text-xs text-slate-400">{r.date}</td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-2">
                      <button onClick={() => setShowReport(r)} className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors">
                        <Eye className="w-3 h-3" /> View
                      </button>
                      <button
                        onClick={() => downloadReportAsPDF(r)}
                        className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50 transition-colors"
                      >
                        <Download className="w-3 h-3" /> PDF
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-6 py-3 border-t border-slate-100 text-xs text-slate-400">
            Showing {filtered.length} of {reports.length} reports
          </div>
        </div>
      </div>

      {showReport && <ReportModal report={showReport} onClose={() => setShowReport(null)} />}
      {showCreate && <CreateReportModal onClose={() => setShowCreate(false)} onCreated={handleReportCreated} />}
    </div>
  );
}
