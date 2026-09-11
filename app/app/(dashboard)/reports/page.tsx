'use client';

import { useState } from 'react';
import { FileText, Download, Eye, Plus, Search, CheckCircle, AlertTriangle, Shield, Globe, Server, Link2, Brain, Clock, Lock } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { mockCases } from '@/lib/mockData';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import { demoEmails } from '@/lib/demoEmails';

function ReportModal({ onClose }: { onClose: () => void }) {
  const c = mockCases[0];
  const result = mockAnalysisResults['demo-3'];
  const email = demoEmails[2];

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-8 py-5 border-b border-slate-100 flex items-center justify-between bg-[#0f172a]">
          <div>
            <div className="text-xs text-slate-400 uppercase tracking-widest mb-1">MAILTRACE AI FORENSIC REPORT</div>
            <h2 className="text-lg font-bold text-white">Forensic Investigation Report</h2>
            <div className="text-xs text-slate-400 mt-1">Case {c.id} · Generated {new Date().toLocaleString()}</div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onClose} className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white text-sm font-medium rounded-lg transition-colors">Close</button>
            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg transition-colors">
              <Download className="w-4 h-4" /> Download PDF
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-8 space-y-8">
          {/* Executive Summary */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">1. Executive Summary</h3>
            <div className="bg-red-50 border border-red-200 rounded-xl p-5">
              <div className="flex items-center gap-3 mb-3">
                <AlertTriangle className="w-5 h-5 text-red-500" />
                <span className="text-base font-bold text-red-800">CRITICAL THREAT DETECTED — Business Email Compromise</span>
              </div>
              <p className="text-sm text-red-700 leading-relaxed">
                A sophisticated Business Email Compromise attempt targeting Acme Corporation&apos;s finance department was detected and analyzed. The email impersonated a senior executive using a lookalike domain and employed multiple social engineering vectors including urgency, authority, and confidentiality pressure to request an unauthorized wire transfer of USD 87,500.
              </p>
            </div>
          </section>

          {/* Classification & Score */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">2. Threat Classification & Risk Score</h3>
            <div className="grid grid-cols-3 gap-4">
              <div className="text-center p-4 bg-red-50 border border-red-200 rounded-xl">
                <div className="text-4xl font-bold text-red-600 mb-1">94/100</div>
                <div className="text-sm font-semibold text-red-700">CRITICAL</div>
                <div className="text-xs text-slate-500 mt-1">Overall Risk Score</div>
              </div>
              <div className="text-center p-4 bg-orange-50 border border-orange-200 rounded-xl">
                <div className="text-lg font-bold text-orange-700 mb-1">Business Email Compromise</div>
                <div className="text-xs text-slate-500 mt-1">Primary Classification</div>
              </div>
              <div className="text-center p-4 bg-slate-50 border border-slate-200 rounded-xl">
                <div className="text-sm font-mono font-medium text-slate-700 break-all text-xs">{result.evidenceHash.slice(0, 24)}...</div>
                <div className="text-xs text-slate-400 mt-1">Evidence SHA256 (truncated)</div>
              </div>
            </div>
          </section>

          {/* Email Metadata */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">3. Email Metadata</h3>
            <div className="grid grid-cols-2 gap-x-8 gap-y-2">
              {[
                ['From', email.from],
                ['To', email.to],
                ['Subject', email.subject],
                ['Date', email.date],
                ['Message-ID', email.messageId],
                ['Reply-To', 'finance.verify@proton-example.com'],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3 py-2 border-b border-slate-50 text-sm">
                  <span className="text-slate-400 w-24 flex-shrink-0">{k}</span>
                  <span className="text-slate-700 font-medium break-all">{v}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Auth Results */}
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
          </section>

          {/* IOCs */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">5. Extracted Indicators of Compromise</h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-50 border border-slate-200 rounded-lg">
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

          {/* Infrastructure */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">6. Probable Infrastructure Location</h3>
            <div className="bg-orange-50 border border-orange-200 rounded-xl p-5">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-orange-500 flex-shrink-0" />
                <div>
                  <div className="font-semibold text-orange-800 mb-1">Probable Infrastructure Location: Singapore (82% confidence)</div>
                  <div className="text-sm text-orange-700 mb-2">
                    Sending IP: {result.ipIntel.ip} · ASN: {result.ipIntel.asn}
                  </div>
                  <p className="text-xs text-orange-600">
                    IP geolocation represents the observed infrastructure and may not represent the physical location of the threat actor. This information should be used for infrastructure attribution purposes only.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* AI Explanation */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">7. AI Threat Explanation</h3>
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <p className="text-sm text-slate-700 leading-relaxed">{result.explainableAI}</p>
            </div>
          </section>

          {/* Recommendations */}
          <section>
            <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider border-b border-slate-200 pb-2 mb-4">8. Recommendations</h3>
            <div className="space-y-2">
              {[
                'Block sending domain micros0ft-secure.com at the email gateway level',
                'Block IP 185.231.72.12 at the network perimeter firewall',
                'Alert finance team to this BEC pattern and verify any pending payment requests by phone',
                'Report the domain to the registrar (Pte. Reg. Services Ltd.) for takedown',
                'Submit IOCs to threat intelligence sharing platforms (MISP, OpenCTI)',
                'Review similar cases for related infrastructure correlation',
                'Implement DMARC reporting for acmecorp.com to monitor spoofing attempts',
              ].map((rec, i) => (
                <div key={i} className="flex items-start gap-2.5">
                  <span className="text-xs font-bold text-blue-600 mt-0.5 w-5 flex-shrink-0">{i + 1}.</span>
                  <p className="text-sm text-slate-700">{rec}</p>
                </div>
              ))}
            </div>
          </section>

          {/* Evidence */}
          <section className="bg-emerald-50 border border-emerald-200 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <Lock className="w-4 h-4 text-emerald-600" />
              <h3 className="text-sm font-bold text-emerald-800">Evidence Integrity: VERIFIED</h3>
            </div>
            <div className="text-xs font-mono text-slate-600">SHA256: {result.evidenceHash}</div>
            <div className="text-xs text-slate-400 mt-1">Analysis timestamp: {result.analysisTimestamp}</div>
          </section>
        </div>
      </div>
    </div>
  );
}

const reportsList = [
  { id: 'RPT-001', caseId: 'MT-2026-00124', title: 'BEC Investigation — Urgent Vendor Payment', type: 'Business Email Compromise', risk: 94, analyst: 'AM', date: 'Today 11:54 AM', status: 'Completed' },
  { id: 'RPT-002', caseId: 'MT-2026-00123', title: 'Credential Phishing — Payroll Verification', type: 'Credential Phishing', risk: 86, analyst: 'AM', date: 'Today 10:21 AM', status: 'Completed' },
  { id: 'RPT-003', caseId: 'MT-2026-00118', title: 'BEC — Q3 Budget Approval', type: 'Business Email Compromise', risk: 89, analyst: 'SK', date: 'Aug 25, 3:22 PM', status: 'Completed' },
  { id: 'RPT-004', caseId: 'MT-2026-00115', title: 'BEC — Board Resolution Wire Transfer', type: 'Business Email Compromise', risk: 96, analyst: 'RK', date: 'Aug 24, 5:00 PM', status: 'Completed' },
];

export default function ReportsPage() {
  const [showReport, setShowReport] = useState(false);

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Reports" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">FORENSIC DOCUMENTATION</div>
            <h1 className="text-2xl font-bold text-slate-800">Reports</h1>
          </div>
          <button
            onClick={() => setShowReport(true)}
            className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors"
          >
            <Plus className="w-4 h-4" />
            Generate report
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Total Reports', value: '47', icon: <FileText className="w-4 h-4" /> },
            { label: 'This Month', value: '12', icon: <Clock className="w-4 h-4" /> },
            { label: 'Pending Review', value: '3', icon: <Eye className="w-4 h-4" /> },
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
            <h3 className="text-sm font-semibold text-slate-700">Recent Reports</h3>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
              <input placeholder="Search reports..." className="pl-9 pr-4 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500" />
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
              {reportsList.map(r => (
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
                    <span className="text-xs font-bold px-2 py-1 rounded-full border bg-red-50 border-red-200 text-red-700">{r.risk}/100</span>
                  </td>
                  <td className="px-4 py-4 text-sm text-slate-600">{r.analyst}</td>
                  <td className="px-4 py-4 text-xs text-slate-400">{r.date}</td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-2">
                      <button onClick={() => setShowReport(true)} className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-600 border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors">
                        <Eye className="w-3 h-3" /> View
                      </button>
                      <button className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-blue-600 border border-blue-200 rounded-lg hover:bg-blue-50 transition-colors">
                        <Download className="w-3 h-3" /> PDF
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showReport && <ReportModal onClose={() => setShowReport(false)} />}
    </div>
  );
}
