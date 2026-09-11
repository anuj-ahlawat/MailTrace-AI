'use client';

import { useState } from 'react';
import {
  Upload, Clipboard, Sparkles, ChevronRight, Play, Shield, Link2, Network, Brain,
  CheckCircle, AlertTriangle, XCircle, Info, Copy, Plus, Search, Download, Lock,
  Globe, Server, BarChart2, Activity, Flag, ExternalLink, Eye, FileText,
} from 'lucide-react';
import TopBar from '@/components/TopBar';
import { demoEmails, type DemoEmail } from '@/lib/demoEmails';
import { mockAnalysisResults, type AnalysisResult } from '@/lib/mockAnalysis';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

// ─── Helper Components ──────────────────────────────────────────────────────

const AuthBadge = ({ status }: { status: 'pass' | 'fail' | 'unknown' }) => {
  const map = {
    pass: 'bg-emerald-50 border-emerald-200 text-emerald-700',
    fail: 'bg-red-50 border-red-200 text-red-700',
    unknown: 'bg-slate-50 border-slate-200 text-slate-600',
  };
  const icons = {
    pass: <CheckCircle className="w-3.5 h-3.5" />,
    fail: <XCircle className="w-3.5 h-3.5" />,
    unknown: <Info className="w-3.5 h-3.5" />,
  };
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border ${map[status]}`}>
      {icons[status]}
      {status.toUpperCase()}
    </span>
  );
};

const SeverityBadge = ({ severity }: { severity: string }) => {
  const map: Record<string, string> = {
    critical: 'bg-red-50 border-red-200 text-red-700',
    high: 'bg-orange-50 border-orange-200 text-orange-700',
    medium: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    low: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  };
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${map[severity] || map.low}`}>
      {severity}
    </span>
  );
};

const RiskGauge = ({ score, level }: { score: number; level: string }) => {
  const color = score >= 81 ? '#ef4444' : score >= 61 ? '#f97316' : score >= 41 ? '#eab308' : '#22c55e';
  const label = score >= 81 ? 'CRITICAL' : score >= 61 ? 'HIGH' : score >= 41 ? 'SUSPICIOUS' : score >= 21 ? 'LOW RISK' : 'SAFE';
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-40 h-40">
        <svg className="w-40 h-40 -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#f1f5f9" strokeWidth="10" />
          <circle
            cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={circumference} strokeDashoffset={offset}
            strokeLinecap="round" className="transition-all duration-1000"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-slate-500">/100</span>
        </div>
      </div>
      <div className="mt-3 text-center">
        <span className="text-lg font-bold" style={{ color }}>{label}</span>
      </div>
      <div className="flex gap-1 mt-2">
        {['Safe', 'Low', 'Suspicious', 'High', 'Critical'].map((l, i) => {
          const threshold = [0, 21, 41, 61, 81];
          const isActive = score >= threshold[i];
          const colors = ['#22c55e', '#84cc16', '#eab308', '#f97316', '#ef4444'];
          return (
            <div key={l} className="flex flex-col items-center">
              <div className="w-7 h-1.5 rounded-full" style={{ backgroundColor: isActive ? colors[i] : '#e2e8f0' }} />
              <span className="text-[9px] text-slate-400 mt-0.5">{l}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const ThreatClassificationBar = ({ label, value, color }: { label: string; value: number; color: string }) => (
  <div className="flex items-center gap-3 mb-2">
    <span className="text-sm text-slate-600 w-40 flex-shrink-0">{label}</span>
    <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${value}%`, backgroundColor: color }} />
    </div>
    <span className="text-sm font-semibold w-10 text-right" style={{ color }}>{value}%</span>
  </div>
);

// ─── IOC Table ─────────────────────────────────────────────────────────────

const IOCTable = ({ iocs }: { iocs: AnalysisResult['iocs'] }) => {
  const repColors: Record<string, string> = {
    malicious: 'bg-red-50 border-red-200 text-red-700',
    suspicious: 'bg-orange-50 border-orange-200 text-orange-700',
    unknown: 'bg-slate-50 border-slate-200 text-slate-600',
    clean: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  };
  const typeIcons: Record<string, React.ReactNode> = {
    domain: <Globe className="w-3.5 h-3.5" />,
    ip: <Server className="w-3.5 h-3.5" />,
    url: <Link2 className="w-3.5 h-3.5" />,
    email: <Flag className="w-3.5 h-3.5" />,
    hash: <FileText className="w-3.5 h-3.5" />,
    filename: <FileText className="w-3.5 h-3.5" />,
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-100">
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Type</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Indicator</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Reputation</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Source</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Risk</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Actions</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map(ioc => (
            <tr key={ioc.id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5 text-slate-600 capitalize">
                  {typeIcons[ioc.type]}
                  {ioc.type}
                </div>
              </td>
              <td className="px-4 py-3">
                <span className="font-mono text-xs bg-slate-50 px-2 py-1 rounded border border-slate-200 text-slate-700">
                  {ioc.indicator}
                </span>
              </td>
              <td className="px-4 py-3">
                <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border capitalize ${repColors[ioc.reputation]}`}>
                  {ioc.reputation}
                </span>
              </td>
              <td className="px-4 py-3 text-slate-500 text-xs">{ioc.source}</td>
              <td className="px-4 py-3">
                <SeverityBadge severity={ioc.riskLevel} />
              </td>
              <td className="px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <button className="p-1.5 hover:bg-slate-100 rounded-lg transition-colors" title="Copy">
                    <Copy className="w-3.5 h-3.5 text-slate-400" />
                  </button>
                  <button className="p-1.5 hover:bg-slate-100 rounded-lg transition-colors" title="Add to Case">
                    <Plus className="w-3.5 h-3.5 text-slate-400" />
                  </button>
                  <button className="p-1.5 hover:bg-slate-100 rounded-lg transition-colors" title="Search Related">
                    <Search className="w-3.5 h-3.5 text-slate-400" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// ─── URL Analysis ──────────────────────────────────────────────────────────

const URLAnalysisCard = ({ url }: { url: AnalysisResult['urlAnalysis'][0] }) => (
  <div className="border border-slate-200 rounded-xl p-4 mb-4">
    {url.deception && (
      <div className="mb-4 flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
        <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
        <p className="text-sm text-red-700 font-medium">Displayed URL does not match destination. Potential URL deception detected.</p>
      </div>
    )}
    <div className="grid grid-cols-2 gap-4">
      <div>
        <div className="text-xs text-slate-400 font-medium mb-1">Displayed URL</div>
        <div className="font-mono text-xs bg-slate-50 px-3 py-2 rounded-lg border border-slate-200 text-slate-700 break-all">{url.displayedUrl}</div>
      </div>
      <div>
        <div className="text-xs text-slate-400 font-medium mb-1">Actual Destination</div>
        <div className={`font-mono text-xs px-3 py-2 rounded-lg border break-all ${url.deception ? 'bg-red-50 border-red-200 text-red-700' : 'bg-slate-50 border-slate-200 text-slate-700'}`}>{url.actualUrl}</div>
      </div>
    </div>
    <div className="grid grid-cols-4 gap-3 mt-4">
      {[
        { label: 'HTTPS', value: url.httpsEnabled ? 'Yes' : 'No', ok: url.httpsEnabled },
        { label: 'Redirects', value: url.redirectCount.toString(), ok: url.redirectCount === 0 },
        { label: 'URL Length', value: url.urlLength.toString(), ok: url.urlLength < 80 },
        { label: 'Encoded Chars', value: url.hasEncodedChars ? 'Yes' : 'No', ok: !url.hasEncodedChars },
        { label: 'Suspicious TLD', value: url.suspiciousTld ? 'Yes' : 'No', ok: !url.suspiciousTld },
        { label: 'Brand Similarity', value: `${url.lookalikeSimilarity}%`, ok: url.lookalikeSimilarity < 50 },
        { label: 'Reputation', value: url.reputation, ok: url.reputation === 'clean' },
        { label: 'Risk Score', value: `${url.riskScore}/100`, ok: url.riskScore < 30 },
      ].map(({ label, value, ok }) => (
        <div key={label} className={`rounded-lg p-2.5 border ${ok ? 'bg-emerald-50 border-emerald-100' : 'bg-red-50 border-red-100'}`}>
          <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wider">{label}</div>
          <div className={`text-sm font-bold mt-0.5 ${ok ? 'text-emerald-700' : 'text-red-700'} capitalize`}>{value}</div>
        </div>
      ))}
    </div>
  </div>
);

// ─── Domain Intelligence ───────────────────────────────────────────────────

const DomainCard = ({ domain }: { domain: AnalysisResult['domainIntel'] }) => (
  <div className="border border-slate-200 rounded-xl p-4">
    <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm mb-4">
      {[
        ['Domain', domain.domain],
        ['Registrar', domain.registrar],
        ['Registered', domain.registrationDate],
        ['Domain Age', `${domain.domainAgeDays} days`],
        ['Expires', domain.expiryDate],
        ['Country', domain.country],
        ['ASN', domain.asn],
        ['Resolved IP', domain.resolvedIp],
        ['Hosting', domain.hostingProvider],
        ['Reputation', domain.reputation],
      ].map(([k, v]) => (
        <div key={k} className="flex justify-between py-1 border-b border-slate-50">
          <span className="text-slate-500 font-medium">{k}</span>
          <span className={`text-slate-700 font-medium text-right max-w-[180px] truncate capitalize ${v === 'malicious' ? 'text-red-600' : v === 'suspicious' ? 'text-orange-600' : v === 'clean' ? 'text-emerald-600' : ''}`}>{v}</span>
        </div>
      ))}
    </div>
    {domain.brandSimilarity && (
      <div className="bg-red-50 border border-red-200 rounded-xl p-4">
        <div className="text-xs font-semibold text-red-700 uppercase tracking-wider mb-3">Brand Similarity Analysis</div>
        <div className="flex items-center gap-4 mb-2">
          <span className="font-mono text-sm font-bold text-slate-700">{domain.brandSimilarity.originalDomain}</span>
          <span className="text-slate-400 text-sm">vs</span>
          <span className="font-mono text-sm font-bold text-red-700">{domain.domain}</span>
        </div>
        <div className="flex items-center gap-3 mb-2">
          <div className="flex-1 h-2 bg-slate-100 rounded-full">
            <div className="h-full bg-red-500 rounded-full" style={{ width: `${domain.brandSimilarity.similarityScore}%` }} />
          </div>
          <span className="text-red-700 font-bold text-sm">{domain.brandSimilarity.similarityScore}%</span>
        </div>
        <p className="text-xs text-red-600 font-medium">{domain.brandSimilarity.classification}</p>
      </div>
    )}
  </div>
);

// ─── Social Engineering ────────────────────────────────────────────────────

const SocialEngCard = ({ se }: { se: AnalysisResult['socialEngineering'] }) => {
  const items = [
    { label: 'Urgency', value: se.urgency },
    { label: 'Authority', value: se.authority },
    { label: 'Financial Request', value: se.financialRequest },
    { label: 'Credential Request', value: se.credentialRequest },
    { label: 'Executive Impersonation', value: se.executiveImpersonation },
    { label: 'Fear Induction', value: se.fearInduction },
    { label: 'Confidentiality Pressure', value: se.confidentialityPressure },
  ];
  return (
    <div className="space-y-2">
      {items.map(({ label, value }) => (
        <div key={label} className="flex items-center gap-3">
          <span className="text-sm text-slate-600 w-52 flex-shrink-0">{label}</span>
          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${value >= 70 ? 'bg-red-500' : value >= 40 ? 'bg-orange-400' : 'bg-emerald-400'}`}
              style={{ width: `${value}%` }}
            />
          </div>
          <span className={`text-sm font-bold w-12 text-right ${value >= 70 ? 'text-red-600' : value >= 40 ? 'text-orange-600' : 'text-emerald-600'}`}>{value}%</span>
        </div>
      ))}
    </div>
  );
};

// ─── Header Forensics ─────────────────────────────────────────────────────

const HeaderForensics = ({ email, result }: { email: DemoEmail; result: AnalysisResult }) => (
  <div className="space-y-4">
    <div className="grid grid-cols-2 gap-4">
      {[
        { label: 'From', value: email.from, warning: result.auth.replyToMismatch ? null : null },
        { label: 'To', value: email.to },
        { label: 'Subject', value: email.subject },
        { label: 'Date', value: email.date },
        { label: 'Message-ID', value: email.messageId },
        { label: 'Reply-To', value: result.auth.replyToMismatch ? 'finance.verify@proton-example.com' : email.from, isWarning: result.auth.replyToMismatch },
      ].map(({ label, value, isWarning }) => (
        <div key={label} className={`p-3 rounded-lg border ${isWarning ? 'border-red-200 bg-red-50' : 'border-slate-100 bg-slate-50'}`}>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">{label}</div>
          <div className={`text-sm font-medium break-all ${isWarning ? 'text-red-700' : 'text-slate-700'}`}>{value}</div>
          {isWarning && (
            <div className="flex items-center gap-1.5 mt-2">
              <AlertTriangle className="w-3 h-3 text-red-500" />
              <span className="text-xs text-red-600 font-medium">{result.auth.replyToMismatchDetail}</span>
            </div>
          )}
        </div>
      ))}
    </div>

    <div>
      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Raw Headers</div>
      <pre className="text-xs font-mono bg-[#0f172a] text-green-400 p-4 rounded-xl overflow-x-auto max-h-64 border border-slate-800">
        {email.rawHeaders}
      </pre>
    </div>
  </div>
);

// ─── Scoring Breakdown ─────────────────────────────────────────────────────

const ScoringBreakdown = ({ breakdown }: { breakdown: AnalysisResult['scoringBreakdown'] }) => {
  const items = [
    { name: 'NLP Phishing (25%)', score: breakdown.nlpPhishing, max: 25 },
    { name: 'Authentication (20%)', score: breakdown.authentication, max: 20 },
    { name: 'Domain Risk (15%)', score: breakdown.domainRisk, max: 15 },
    { name: 'URL Analysis (15%)', score: breakdown.urlAnalysis, max: 15 },
    { name: 'Infrastructure (10%)', score: breakdown.infrastructureReputation, max: 10 },
    { name: 'Header Anomalies (10%)', score: breakdown.headerAnomalies, max: 10 },
    { name: 'Attachment Risk (5%)', score: breakdown.attachmentRisk, max: 5 },
  ];

  return (
    <div className="space-y-2">
      {items.map(item => (
        <div key={item.name} className="flex items-center gap-3">
          <span className="text-xs text-slate-600 w-48 flex-shrink-0">{item.name}</span>
          <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${item.score / item.max > 0.7 ? 'bg-red-500' : 'bg-blue-500'}`}
              style={{ width: `${(item.score / item.max) * 100}%` }}
            />
          </div>
          <span className="text-xs font-semibold text-slate-600 w-16 text-right">{item.score} / {item.max}</span>
        </div>
      ))}
    </div>
  );
};

// ─── Main Page ─────────────────────────────────────────────────────────────

type Tab = 'upload' | 'paste' | 'demo';

export default function AnalyzePage() {
  const [tab, setTab] = useState<Tab>('demo');
  const [selectedDemo, setSelectedDemo] = useState<DemoEmail | null>(null);
  const [pastedText, setPastedText] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [activeSection, setActiveSection] = useState('score');

  const handleRunAnalysis = async () => {
    if (!selectedDemo) return;
    setAnalyzing(true);
    await new Promise(r => setTimeout(r, 1800));
    setResult(mockAnalysisResults[selectedDemo.id]);
    setAnalyzing(false);
    setActiveSection('score');
  };

  const pipelineSteps = [
    { icon: <Flag className="w-4 h-4" />, label: 'Email structure', sub: 'Headers, body, attachments' },
    { icon: <Shield className="w-4 h-4" />, label: 'Authentication', sub: 'SPF, DKIM, DMARC alignment' },
    { icon: <Link2 className="w-4 h-4" />, label: 'Indicators', sub: 'Domains, URLs, IPs, hashes' },
    { icon: <Network className="w-4 h-4" />, label: 'Infrastructure', sub: 'Relay path and probable location' },
    { icon: <Brain className="w-4 h-4" />, label: 'Explainable scoring', sub: 'Signals weighted for review' },
  ];

  const sections = [
    { id: 'score', label: 'Threat Score' },
    { id: 'auth', label: 'Authentication' },
    { id: 'indicators', label: 'Risk Indicators' },
    { id: 'iocs', label: 'IOCs' },
    { id: 'url', label: 'URL Analysis' },
    { id: 'domain', label: 'Domain Intel' },
    { id: 'social', label: 'Social Engineering' },
    { id: 'headers', label: 'Header Forensics' },
    { id: 'scoring', label: 'Scoring Breakdown' },
    { id: 'ai', label: 'AI Explanation' },
  ];

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Analyze Email" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">FORENSIC WORKSPACE</div>
            <h1 className="text-2xl font-bold text-slate-800">Analyze suspicious email</h1>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-sm text-emerald-600 font-medium">Analysis engine ready</span>
          </div>
        </div>

        <div className="flex gap-6">
          {/* Left: Input panel */}
          <div className="flex-1">
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-6">
              {/* Tabs */}
              <div className="flex border-b border-slate-200 mb-6 -mx-6 px-6">
                {[
                  { id: 'upload', icon: <Upload className="w-4 h-4" />, label: 'Upload email' },
                  { id: 'paste', icon: <Clipboard className="w-4 h-4" />, label: 'Paste raw email' },
                  { id: 'demo', icon: <Sparkles className="w-4 h-4" />, label: 'Demo samples' },
                ].map(t => (
                  <button
                    key={t.id}
                    onClick={() => setTab(t.id as Tab)}
                    className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px mr-2 transition-colors ${
                      tab === t.id
                        ? 'border-blue-600 text-blue-600'
                        : 'border-transparent text-slate-500 hover:text-slate-700'
                    }`}
                  >
                    {t.icon}
                    {t.label}
                  </button>
                ))}
              </div>

              {/* Upload tab */}
              {tab === 'upload' && (
                <label className="block border-2 border-dashed border-slate-200 rounded-xl p-12 text-center cursor-pointer hover:border-blue-300 hover:bg-blue-50/30 transition-all">
                  <input type="file" accept=".eml,.msg" className="hidden" />
                  <Upload className="w-10 h-10 text-slate-300 mx-auto mb-3" />
                  <p className="text-slate-600 font-medium mb-1">Drop .eml or .msg file here</p>
                  <p className="text-slate-400 text-sm">or click to browse files</p>
                  <p className="text-xs text-slate-300 mt-3">Evidence is hashed and preserved automatically</p>
                </label>
              )}

              {/* Paste tab */}
              {tab === 'paste' && (
                <div>
                  <textarea
                    value={pastedText}
                    onChange={e => setPastedText(e.target.value)}
                    placeholder="Paste raw email headers and body here..."
                    className="w-full h-48 font-mono text-xs bg-[#0f172a] text-green-400 border border-slate-700 rounded-xl p-4 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-slate-600"
                  />
                </div>
              )}

              {/* Demo tab */}
              {tab === 'demo' && (
                <div className="space-y-3">
                  {demoEmails.map(demo => (
                    <button
                      key={demo.id}
                      onClick={() => setSelectedDemo(demo)}
                      className={`w-full flex items-center gap-4 p-4 rounded-xl border-2 text-left transition-all ${
                        selectedDemo?.id === demo.id
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                      }`}
                    >
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${
                        demo.riskLevel === 'safe' ? 'bg-emerald-100' : 'bg-red-100'
                      }`}>
                        <Flag className={`w-4 h-4 ${demo.riskLevel === 'safe' ? 'text-emerald-600' : 'text-red-500'}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-semibold text-slate-800 text-sm">{demo.name}</div>
                        <div className="text-xs text-slate-500 truncate">{demo.description}</div>
                      </div>
                      <div className="flex items-center gap-3 flex-shrink-0">
                        <span className={`text-sm font-bold px-3 py-1 rounded-full ${
                          demo.riskScore >= 81 ? 'bg-red-100 text-red-700' :
                          demo.riskScore >= 61 ? 'bg-orange-100 text-orange-700' :
                          'bg-emerald-100 text-emerald-700'
                        }`}>
                          ● {demo.riskScore}/100
                        </span>
                        <ChevronRight className="w-4 h-4 text-slate-400" />
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {/* Run button */}
              <div className="mt-6 flex items-center justify-between pt-5 border-t border-slate-100">
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Lock className="w-3.5 h-3.5" />
                  Evidence is hashed and preserved for this analysis
                </div>
                <button
                  onClick={handleRunAnalysis}
                  disabled={!selectedDemo && tab === 'demo'}
                  className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white font-semibold rounded-xl transition-colors"
                >
                  {analyzing ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Run threat analysis
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* ─── Results ─────────────────────────────────────────────── */}
            {result && selectedDemo && (
              <div className="animate-fade-in">
                {/* Section nav */}
                <div className="flex flex-wrap gap-2 mb-4">
                  {sections.map(s => (
                    <button
                      key={s.id}
                      onClick={() => setActiveSection(s.id)}
                      className={`text-xs font-medium px-3 py-1.5 rounded-lg transition-colors ${
                        activeSection === s.id
                          ? 'bg-blue-600 text-white'
                          : 'bg-white border border-slate-200 text-slate-600 hover:border-blue-300'
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>

                {/* Label */}
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  ANALYSIS RESULT · {selectedDemo.name.toUpperCase()}
                </div>

                {/* Email meta */}
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-slate-800 mb-2">{selectedDemo.subject}</h2>
                      <div className="flex items-center gap-2 text-sm text-slate-500">
                        <span className="font-medium text-slate-700">{selectedDemo.from}</span>
                        <span className="text-slate-300">→</span>
                        <span>{selectedDemo.to}</span>
                      </div>
                    </div>
                    <button className="flex items-center gap-2 px-4 py-2 border border-slate-200 rounded-xl text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors">
                      <Download className="w-4 h-4" />
                      Generate report
                    </button>
                  </div>
                </div>

                {/* Threat Score */}
                {activeSection === 'score' && (
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 flex flex-col items-center">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">FINAL THREAT SCORE</div>
                      <RiskGauge score={result.overallRiskScore} level={result.riskLevel} />
                      <div className="mt-4 text-center">
                        <span className="text-sm text-slate-500 font-medium">Classification: </span>
                        <span className="text-sm font-bold text-slate-800">{result.classification}</span>
                      </div>
                    </div>
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">THREAT CLASSIFICATION</div>
                      <ThreatClassificationBar label="Phishing" value={result.classification_scores.phishing} color="#ef4444" />
                      <ThreatClassificationBar label="Business Email Compromise" value={result.classification_scores.bec} color="#f97316" />
                      <ThreatClassificationBar label="Impersonation" value={result.classification_scores.impersonation} color="#8b5cf6" />
                      <ThreatClassificationBar label="Credential Theft" value={result.classification_scores.credentialTheft} color="#3b82f6" />
                      <ThreatClassificationBar label="Malware Delivery" value={result.classification_scores.malwareDelivery} color="#6b7280" />
                    </div>
                  </div>
                )}

                {/* Authentication */}
                {activeSection === 'auth' && (
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    {[
                      { label: 'SPF', status: result.auth.spf, detail: result.auth.spfDetail },
                      { label: 'DKIM', status: result.auth.dkim, detail: result.auth.dkimDetail },
                      { label: 'DMARC', status: result.auth.dmarc, detail: result.auth.dmarcDetail },
                    ].map(card => (
                      <div key={card.label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-base font-bold text-slate-800">{card.label}</span>
                          <AuthBadge status={card.status} />
                        </div>
                        <p className="text-xs text-slate-500 leading-relaxed">{card.detail}</p>
                      </div>
                    ))}
                    {result.auth.replyToMismatch && (
                      <div className="col-span-3 bg-red-50 border border-red-200 rounded-xl p-5">
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-4 h-4 text-red-500" />
                          <span className="font-semibold text-red-700">Reply-To Mismatch Detected</span>
                        </div>
                        <p className="text-sm text-red-600">{result.auth.replyToMismatchDetail}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Risk Indicators */}
                {activeSection === 'indicators' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">TOP RISK INDICATORS</div>
                    <div className="space-y-2.5">
                      {result.riskIndicators.map(ri => (
                        <div key={ri.id} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 border border-slate-100">
                          <div className={`w-1.5 h-1.5 rounded-full mt-2 flex-shrink-0 ${
                            ri.severity === 'critical' ? 'bg-red-500' :
                            ri.severity === 'high' ? 'bg-orange-500' :
                            ri.severity === 'medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                          }`} />
                          <div className="flex-1">
                            <p className="text-sm font-medium text-slate-700">{ri.label}</p>
                            <span className="text-xs text-slate-400">{ri.category}</span>
                          </div>
                          <SeverityBadge severity={ri.severity} />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* IOCs */}
                {activeSection === 'iocs' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm mb-4">
                    <div className="px-6 py-4 border-b border-slate-100">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">EXTRACTED INDICATORS OF COMPROMISE</div>
                    </div>
                    <IOCTable iocs={result.iocs} />
                  </div>
                )}

                {/* URL Analysis */}
                {activeSection === 'url' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">URL ANALYSIS</div>
                    {result.urlAnalysis.length > 0 ? (
                      result.urlAnalysis.map((url, i) => <URLAnalysisCard key={i} url={url} />)
                    ) : (
                      <p className="text-slate-400 text-sm text-center py-6">No URLs detected in this email.</p>
                    )}
                  </div>
                )}

                {/* Domain Intelligence */}
                {activeSection === 'domain' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">DOMAIN INTELLIGENCE</div>
                    <DomainCard domain={result.domainIntel} />
                  </div>
                )}

                {/* Social Engineering */}
                {activeSection === 'social' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">SOCIAL ENGINEERING INDICATORS</div>
                    <SocialEngCard se={result.socialEngineering} />
                  </div>
                )}

                {/* Header Forensics */}
                {activeSection === 'headers' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">HEADER FORENSICS</div>
                    <HeaderForensics email={selectedDemo} result={result} />
                  </div>
                )}

                {/* Scoring Breakdown */}
                {activeSection === 'scoring' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">AI SCORING BREAKDOWN</div>
                    <ScoringBreakdown breakdown={result.scoringBreakdown} />
                    <div className="mt-4 pt-4 border-t border-slate-100 flex items-center justify-between">
                      <span className="text-sm text-slate-500 font-medium">Total weighted score</span>
                      <span className={`text-lg font-bold ${result.overallRiskScore >= 81 ? 'text-red-600' : result.overallRiskScore >= 61 ? 'text-orange-600' : 'text-emerald-600'}`}>
                        {result.overallRiskScore}/100
                      </span>
                    </div>
                  </div>
                )}

                {/* AI Explanation */}
                {activeSection === 'ai' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="flex items-center gap-2 mb-4">
                      <Brain className="w-4 h-4 text-blue-600" />
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">EXPLAINABLE AI SUMMARY</div>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
                      <p className="text-sm text-slate-700 leading-relaxed">{result.explainableAI}</p>
                    </div>
                    <div className="mt-4 pt-4 border-t border-slate-100 flex items-center gap-2 text-xs text-slate-400">
                      <Lock className="w-3 h-3" />
                      Evidence hash: <span className="font-mono">{result.evidenceHash}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right: Pipeline sidebar */}
          <div className="w-72 flex-shrink-0">
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 sticky top-20">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">ANALYSIS PIPELINE</div>
              <h3 className="text-base font-semibold text-slate-800 mb-4">What we inspect</h3>
              <div className="space-y-3">
                {pipelineSteps.map(step => (
                  <div key={step.label} className="flex items-start gap-3">
                    <div className="w-8 h-8 bg-blue-50 border border-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 text-blue-500">
                      {step.icon}
                    </div>
                    <div className="flex-1">
                      <div className="text-sm font-semibold text-slate-700">{step.label}</div>
                      <div className="text-xs text-slate-400">{step.sub}</div>
                    </div>
                    <CheckCircle className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-1" />
                  </div>
                ))}
              </div>

              {result && (
                <div className="mt-5 pt-4 border-t border-slate-100">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">EVIDENCE</div>
                  <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1.5">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-xs font-semibold text-emerald-700">VERIFIED</span>
                    </div>
                    <div className="text-xs text-slate-500 font-mono break-all leading-relaxed">{result.evidenceHash.slice(0, 40)}...</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
