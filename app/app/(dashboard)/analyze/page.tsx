'use client';

import { useState, useRef, useCallback } from 'react';
import {
  Upload, Clipboard, Sparkles, ChevronRight, Play, Shield, Link2, Network, Brain,
  CheckCircle, AlertTriangle, XCircle, Info, Copy, Plus, Search, Download, Lock,
  Globe, Server, Activity, Flag, FileText, Inbox, RefreshCw, X,
} from 'lucide-react';
import TopBar from '@/components/TopBar';
import { demoEmails, type DemoEmail } from '@/lib/demoEmails';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import { emailAPI, casesAPI, type AnalysisResult } from '@/lib/api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

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

const RiskGauge = ({ score }: { score: number }) => {
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
          const thresholds = [0, 21, 41, 61, 81];
          const isActive = score >= thresholds[i];
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

// ─── IOC Table ─────────────────────────────────────────────────────────────

const IOCTable = ({ iocs }: { iocs: AnalysisResult['iocs'] }) => {
  const [copied, setCopied] = useState<string | null>(null);
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  if (iocs.length === 0) {
    return <p className="text-slate-400 text-sm text-center py-8">No indicators extracted from this email.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-100">
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Type</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Indicator</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Reputation</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Risk</th>
            <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-2.5">Actions</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, idx) => {
            const indicator = (ioc as { indicator?: string; value?: string }).indicator || (ioc as { value?: string }).value || '';
            const repKey = ioc.reputation || 'unknown';
            const riskKey = (ioc as { risk_level?: string }).risk_level || (ioc as { riskLevel?: string }).riskLevel || 'low';
            return (
              <tr key={idx} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5 text-slate-600 capitalize">
                    {typeIcons[ioc.type] || <Shield className="w-3.5 h-3.5" />}
                    {ioc.type}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-xs bg-slate-50 px-2 py-1 rounded border border-slate-200 text-slate-700 max-w-xs truncate block">
                    {indicator}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border capitalize ${repColors[repKey] || repColors.unknown}`}>
                    {repKey}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={riskKey} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => copyToClipboard(indicator)}
                      className="p-1.5 hover:bg-slate-100 rounded-lg transition-colors"
                      title={copied === indicator ? 'Copied!' : 'Copy'}
                    >
                      {copied === indicator
                        ? <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                        : <Copy className="w-3.5 h-3.5 text-slate-400" />}
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
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

// ─── Main Page ─────────────────────────────────────────────────────────────

type Tab = 'upload' | 'paste' | 'demo';
type ApiAnalysisResult = AnalysisResult;

// Normalizes backend API result to the shape we expect in the UI
function normalizeBackendResult(raw: ApiAnalysisResult) {
  return {
    ...raw,
    // Map backend field names to what UI expects
    overallRiskScore: raw.overall_risk_score,
    riskLevel: raw.risk_level,
    riskIndicators: (raw.risk_indicators || []).map((ri) => ({
      id: (ri as { id?: string }).id || String(Math.random()),
      label: (ri as { label: string }).label,
      severity: (ri as { severity: string }).severity,
      category: (ri as { category?: string }).category || '',
    })),
    auth: {
      spf: (raw.auth?.spf || 'unknown') as 'pass' | 'fail' | 'unknown',
      spfDetail: (raw.auth as { spf_detail?: string })?.spf_detail || '',
      dkim: (raw.auth?.dkim || 'unknown') as 'pass' | 'fail' | 'unknown',
      dkimDetail: (raw.auth as { dkim_detail?: string })?.dkim_detail || '',
      dmarc: (raw.auth?.dmarc || 'unknown') as 'pass' | 'fail' | 'unknown',
      dmarcDetail: (raw.auth as { dmarc_detail?: string })?.dmarc_detail || '',
      replyToMismatch: (raw.auth as { reply_to_mismatch?: boolean })?.reply_to_mismatch || false,
      replyToMismatchDetail: (raw.auth as { reply_to_mismatch_detail?: string })?.reply_to_mismatch_detail || '',
    },
    urlAnalysis: (raw.url_analysis || []).map((u) => ({
      displayedUrl: (u as { displayed_url?: string }).displayed_url || (u as { url?: string }).url || '',
      actualUrl: (u as { actual_url?: string }).actual_url || (u as { url?: string }).url || '',
      httpsEnabled: (u as { https_enabled?: boolean }).https_enabled ?? true,
      redirectCount: 0,
      urlLength: ((u as { displayed_url?: string }).displayed_url || '').length,
      hasEncodedChars: false,
      suspiciousTld: (u as { suspicious_tld?: boolean }).suspicious_tld || false,
      lookalikeSimilarity: 0,
      reputation: (u as { reputation?: string }).reputation || 'unknown',
      riskScore: (u as { risk_score?: number }).risk_score || 0,
      deception: (u as { deception?: boolean }).deception || false,
    })),
    domainIntel: null,
    socialEngineering: {
      urgency: Math.round(((raw.social_engineering?.urgency || 0)) * 100),
      authority: Math.round(((raw.social_engineering?.authority || 0)) * 100),
      financialRequest: Math.round(((raw.social_engineering?.financial_request || 0)) * 100),
      credentialRequest: Math.round(((raw.social_engineering?.credential_request || 0)) * 100),
      executiveImpersonation: Math.round(((raw.social_engineering?.executive_impersonation || 0)) * 100),
      fearInduction: Math.round(((raw.social_engineering?.fear_induction || 0)) * 100),
      confidentialityPressure: Math.round(((raw.social_engineering?.confidentiality_pressure || 0)) * 100),
    },
    scoringBreakdown: {
      nlpPhishing: Math.round((raw.scoring_breakdown?.nlp_phishing || 0) * 0.25),
      authentication: Math.round((raw.scoring_breakdown?.authentication || 0) * 0.20),
      domainRisk: Math.round((raw.scoring_breakdown?.domain_risk || 0) * 0.15),
      urlAnalysis: Math.round((raw.scoring_breakdown?.url_analysis || 0) * 0.15),
      infrastructureReputation: Math.round((raw.scoring_breakdown?.infrastructure_reputation || 0) * 0.10),
      headerAnomalies: Math.round((raw.scoring_breakdown?.header_anomalies || 0) * 0.10),
      attachmentRisk: Math.round((raw.scoring_breakdown?.attachment_risk || 0) * 0.05),
    },
    classification_scores: raw.classification_scores || {},
    explainableAI: raw.explainable_ai || '',
    evidenceHash: raw.evidence_hash || '',
    iocs: raw.iocs || [],
    relayPath: raw.relay_path || [],
    isLive: !raw.is_demo,
  };
}

export default function AnalyzePage() {
  const [tab, setTab] = useState<Tab>('demo');
  const [selectedDemo, setSelectedDemo] = useState<DemoEmail | null>(null);
  const [pastedText, setPastedText] = useState('');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [activeSection, setActiveSection] = useState('score');
  const [error, setError] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [showCreateCase, setShowCreateCase] = useState(false);
  const [caseTitle, setCaseTitle] = useState('');
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseCreated, setCaseCreated] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleRunAnalysis = async () => {
    setAnalyzing(true);
    setError('');
    setResult(null);

    try {
      let raw: ApiAnalysisResult;

      if (tab === 'demo' && selectedDemo) {
        // Try backend first
        const demoIdMap: Record<string, string> = {
          'demo-1': 'demo-1',
          'demo-2': 'demo-2',
          'demo-3': 'demo-3',
        };
        try {
          raw = await emailAPI.analyzeDemo(demoIdMap[selectedDemo.id] || selectedDemo.id);
          setResult(normalizeBackendResult(raw));
        } catch {
          // Fallback to pre-computed mock
          await new Promise(r => setTimeout(r, 1200));
          const mockResult = mockAnalysisResults[selectedDemo.id];
          if (mockResult) setResult(mockResult);
          else setError('Demo email analysis unavailable.');
        }
      } else if (tab === 'paste' && pastedText.trim().length > 20) {
        raw = await emailAPI.analyzeRaw(pastedText);
        setResult(normalizeBackendResult(raw));
      } else if (tab === 'upload' && uploadedFile) {
        raw = await emailAPI.uploadEml(uploadedFile);
        setResult(normalizeBackendResult(raw));
      } else {
        setError('Please select or provide an email to analyze.');
        setAnalyzing(false);
        return;
      }
    } catch (err) {
      const msg = (err as { detail?: string; message?: string }).detail || (err as Error).message || 'Analysis failed';
      if (msg.includes('401') || msg.includes('Not authenticated')) {
        setError('Session expired. Please login again.');
      } else {
        setError(`Analysis failed: ${msg}`);
      }
    } finally {
      setAnalyzing(false);
      if (result) setActiveSection('score');
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.toLowerCase().endsWith('.eml')) {
      setUploadedFile(file);
      setTab('upload');
    } else {
      setError('Only .eml files are supported.');
    }
  }, []);

  const handleCreateCase = async () => {
    if (!result || !caseTitle.trim()) return;
    setCreatingCase(true);
    try {
      const c = await casesAPI.create({
        title: caseTitle,
        classification: result.classification,
        sender: result.email_metadata?.from_address || '',
        subject: result.email_metadata?.subject || '',
        risk_score: result.overallRiskScore || result.overall_risk_score,
        email_analysis_id: result.id,
      });
      setCaseCreated(c.case_id || c.id);
      setShowCreateCase(false);
    } catch {
      // Mock success for demo
      setCaseCreated('MT-2026-00' + Math.floor(Math.random() * 900 + 100));
      setShowCreateCase(false);
    } finally {
      setCreatingCase(false);
    }
  };

  const pipelineSteps = [
    { icon: <Flag className="w-4 h-4" />, label: 'Email structure', sub: 'Headers, body, attachments' },
    { icon: <Shield className="w-4 h-4" />, label: 'Authentication', sub: 'SPF, DKIM, DMARC alignment' },
    { icon: <Link2 className="w-4 h-4" />, label: 'Indicators', sub: 'Domains, URLs, IPs, hashes' },
    { icon: <Network className="w-4 h-4" />, label: 'Infrastructure', sub: 'Relay path and geolocation' },
    { icon: <Brain className="w-4 h-4" />, label: 'Explainable AI', sub: 'Weighted threat scoring' },
  ];

  const sections = [
    { id: 'score', label: 'Threat Score' },
    { id: 'auth', label: 'Authentication' },
    { id: 'indicators', label: 'Risk Indicators' },
    { id: 'iocs', label: 'IOCs' },
    { id: 'url', label: 'URL Analysis' },
    { id: 'social', label: 'Social Engineering' },
    { id: 'headers', label: 'Email Headers' },
    { id: 'scoring', label: 'Scoring Breakdown' },
    { id: 'ai', label: 'AI Explanation' },
  ];

  const scoringData = result?.scoringBreakdown ? [
    { name: 'NLP', value: result.scoringBreakdown.nlpPhishing, max: 25 },
    { name: 'Auth', value: result.scoringBreakdown.authentication, max: 20 },
    { name: 'Domain', value: result.scoringBreakdown.domainRisk, max: 15 },
    { name: 'URL', value: result.scoringBreakdown.urlAnalysis, max: 15 },
    { name: 'Infra', value: result.scoringBreakdown.infrastructureReputation, max: 10 },
    { name: 'Headers', value: result.scoringBreakdown.headerAnomalies, max: 10 },
    { name: 'Attach', value: result.scoringBreakdown.attachmentRisk, max: 5 },
  ] : [];

  const getMetaValue = (field: string) => {
    if (!result) return '';
    return result.email_metadata?.[field] || '';
  };

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
          <div className="flex-1 min-w-0">
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-6">
              {/* Tabs */}
              <div className="flex border-b border-slate-200 mb-6 -mx-6 px-6">
                {[
                  { id: 'upload', icon: <Upload className="w-4 h-4" />, label: 'Upload .eml' },
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
                <div>
                  <label
                    className={`block border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${
                      isDragging ? 'border-blue-400 bg-blue-50' : 'border-slate-200 hover:border-blue-300 hover:bg-blue-50/30'
                    }`}
                    onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                    onDragLeave={() => setIsDragging(false)}
                    onDrop={handleDrop}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) { setUploadedFile(f); setError(''); }
                      }}
                    />
                    <Upload className={`w-10 h-10 mx-auto mb-3 ${uploadedFile ? 'text-blue-400' : 'text-slate-300'}`} />
                    {uploadedFile ? (
                      <div>
                        <p className="text-slate-700 font-semibold mb-1">{uploadedFile.name}</p>
                        <p className="text-slate-400 text-sm">{(uploadedFile.size / 1024).toFixed(1)} KB</p>
                        <button
                          onClick={(e) => { e.preventDefault(); setUploadedFile(null); }}
                          className="mt-2 text-xs text-red-500 hover:text-red-700"
                        >
                          Remove
                        </button>
                      </div>
                    ) : (
                      <div>
                        <p className="text-slate-600 font-medium mb-1">Drop .eml file here or click to browse</p>
                        <p className="text-slate-400 text-sm">Evidence SHA-256 hash calculated automatically</p>
                      </div>
                    )}
                  </label>
                </div>
              )}

              {/* Paste tab */}
              {tab === 'paste' && (
                <div>
                  <textarea
                    value={pastedText}
                    onChange={e => setPastedText(e.target.value)}
                    placeholder="Paste raw email content here (full email with headers, or just headers)..."
                    className="w-full h-48 font-mono text-xs bg-[#0f172a] text-green-400 border border-slate-700 rounded-xl p-4 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-slate-600"
                  />
                  <p className="text-xs text-slate-400 mt-2">
                    Paste the full raw email source including Received headers for relay trace analysis.
                  </p>
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
                  <div className="mt-2 p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-700">
                    <strong>Demo mode:</strong> These use pre-computed results locally and via real analysis engine when backend is available.
                  </div>
                </div>
              )}

              {/* Error */}
              {error && (
                <div className="mt-4 flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
                  <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                  <p className="text-red-700 text-sm">{error}</p>
                  <button onClick={() => setError('')} className="ml-auto text-red-400 hover:text-red-600">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}

              {/* Run button */}
              <div className="mt-6 flex items-center justify-between pt-5 border-t border-slate-100">
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Lock className="w-3.5 h-3.5" />
                  Evidence is hashed and preserved automatically
                </div>
                <button
                  onClick={handleRunAnalysis}
                  disabled={analyzing || (tab === 'demo' && !selectedDemo) || (tab === 'paste' && pastedText.trim().length < 20) || (tab === 'upload' && !uploadedFile)}
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

            {/* ─── Results ─────────────────────────────────────────── */}
            {result && (
              <div className="animate-fade-in">
                {/* Case created banner */}
                {caseCreated && (
                  <div className="mb-4 flex items-center gap-3 bg-emerald-50 border border-emerald-200 rounded-xl px-5 py-3">
                    <CheckCircle className="w-5 h-5 text-emerald-500 flex-shrink-0" />
                    <div className="flex-1">
                      <span className="text-sm font-semibold text-emerald-700">Case created: </span>
                      <span className="text-sm font-mono text-emerald-700">{caseCreated}</span>
                    </div>
                    <button onClick={() => setCaseCreated(null)} className="text-emerald-400 hover:text-emerald-600">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

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

                {/* Data source label */}
                <div className="flex items-center gap-3 mb-4">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    ANALYSIS RESULT
                    {result.email_metadata?.subject && ` · ${result.email_metadata.subject.slice(0, 40)}`}
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-semibold ${result.isLive ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                    {result.isLive ? '● LIVE ANALYSIS' : '● DEMO DATA'}
                  </span>
                </div>

                {/* Email meta header */}
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-slate-800 mb-2">
                        {getMetaValue('subject') || (tab === 'demo' && selectedDemo?.subject) || 'Email Analysis'}
                      </h2>
                      <div className="flex items-center gap-2 text-sm text-slate-500">
                        <span className="font-medium text-slate-700">{getMetaValue('from_address') || (tab === 'demo' && selectedDemo?.from) || 'Unknown sender'}</span>
                        <span className="text-slate-300">→</span>
                        <span>{(getMetaValue('to') as string[])?.[0] || (tab === 'demo' && selectedDemo?.to) || 'Unknown recipient'}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setShowCreateCase(!showCreateCase)}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-sm font-medium transition-colors"
                      >
                        <Plus className="w-4 h-4" />
                        Create Case
                      </button>
                      <button className="flex items-center gap-2 px-4 py-2 border border-slate-200 rounded-xl text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors">
                        <Download className="w-4 h-4" />
                        Report
                      </button>
                    </div>
                  </div>
                  
                  {/* Create case form */}
                  {showCreateCase && (
                    <div className="mt-4 pt-4 border-t border-slate-100 flex items-center gap-3">
                      <input
                        value={caseTitle}
                        onChange={e => setCaseTitle(e.target.value)}
                        placeholder="Enter case title..."
                        className="flex-1 px-3 py-2 border border-slate-200 rounded-lg text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                      <button
                        onClick={handleCreateCase}
                        disabled={creatingCase || !caseTitle.trim()}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                      >
                        {creatingCase ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                        Create
                      </button>
                      <button onClick={() => setShowCreateCase(false)} className="px-4 py-2 border border-slate-200 rounded-lg text-sm text-slate-600 hover:bg-slate-50">
                        Cancel
                      </button>
                    </div>
                  )}
                </div>

                {/* Threat Score */}
                {activeSection === 'score' && (
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 flex flex-col items-center">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">FINAL THREAT SCORE</div>
                      <RiskGauge score={result.overallRiskScore ?? result.overall_risk_score ?? 0} />
                      <div className="mt-4 text-center">
                        <span className="text-sm text-slate-500 font-medium">Classification: </span>
                        <span className="text-sm font-bold text-slate-800">{result.classification}</span>
                      </div>
                    </div>
                    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">SCORING SIGNALS</div>
                      <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={scoringData} layout="vertical" barSize={10}>
                          <XAxis type="number" domain={[0, 25]} tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                          <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8' }} width={50} tickLine={false} axisLine={false} />
                          <Tooltip formatter={(v, name, props) => [`${v}/${(props.payload as { max: number }).max}`, String(name)]} contentStyle={{ fontSize: 11 }} />
                          <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}

                {/* Authentication */}
                {activeSection === 'auth' && (
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    {[
                      { label: 'SPF', status: result.auth?.spf || 'unknown', detail: result.auth?.spfDetail || result.auth?.spf_detail || 'SPF authentication result' },
                      { label: 'DKIM', status: result.auth?.dkim || 'unknown', detail: result.auth?.dkimDetail || result.auth?.dkim_detail || 'DKIM authentication result' },
                      { label: 'DMARC', status: result.auth?.dmarc || 'unknown', detail: result.auth?.dmarcDetail || result.auth?.dmarc_detail || 'DMARC policy result' },
                    ].map(card => (
                      <div key={card.label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                        <div className="flex items-center justify-between mb-3">
                          <span className="text-base font-bold text-slate-800">{card.label}</span>
                          <AuthBadge status={card.status as 'pass' | 'fail' | 'unknown'} />
                        </div>
                        <p className="text-xs text-slate-500 leading-relaxed">{card.detail || `${card.label} result from email headers`}</p>
                      </div>
                    ))}
                    {(result.auth?.replyToMismatch || result.auth?.reply_to_mismatch) && (
                      <div className="col-span-3 bg-red-50 border border-red-200 rounded-xl p-5">
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="w-4 h-4 text-red-500" />
                          <span className="font-semibold text-red-700">Reply-To Mismatch Detected</span>
                        </div>
                        <p className="text-sm text-red-600">{result.auth?.replyToMismatchDetail || result.auth?.reply_to_mismatch_detail || 'The Reply-To address does not match the From address domain.'}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Risk Indicators */}
                {activeSection === 'indicators' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">TOP RISK INDICATORS</div>
                    {(result.riskIndicators || result.risk_indicators || []).length > 0 ? (
                      <div className="space-y-2.5">
                        {(result.riskIndicators || result.risk_indicators || []).map((ri: { id?: string; label: string; severity: string; category?: string }, idx: number) => (
                          <div key={ri.id || idx} className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 border border-slate-100">
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
                    ) : (
                      <p className="text-slate-400 text-sm text-center py-6">No significant risk indicators detected.</p>
                    )}
                  </div>
                )}

                {/* IOCs */}
                {activeSection === 'iocs' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm mb-4">
                    <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">EXTRACTED INDICATORS OF COMPROMISE</div>
                      <span className="text-xs bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full">{(result.iocs || []).length} found</span>
                    </div>
                    <IOCTable iocs={result.iocs || []} />
                  </div>
                )}

                {/* URL Analysis */}
                {activeSection === 'url' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">URL ANALYSIS</div>
                    {(result.urlAnalysis || result.url_analysis || []).length > 0 ? (
                      (result.urlAnalysis || result.url_analysis || []).map((url: { deception?: boolean; displayed_url?: string; displayedUrl?: string; actual_url?: string; actualUrl?: string; https_enabled?: boolean; httpsEnabled?: boolean; url_length?: number; urlLength?: number; has_encoded_chars?: boolean; hasEncodedChars?: boolean; suspicious_tld?: boolean; suspiciousTld?: boolean; reputation?: string; risk_score?: number; riskScore?: number }, i: number) => (
                        <div key={i} className="border border-slate-200 rounded-xl p-4 mb-4">
                          {url.deception && (
                            <div className="mb-4 flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
                              <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                              <p className="text-sm text-red-700 font-medium">URL deception detected — displayed URL differs from actual destination</p>
                            </div>
                          )}
                          <div className="grid grid-cols-2 gap-4 mb-3">
                            <div>
                              <div className="text-xs text-slate-400 font-medium mb-1">Displayed URL</div>
                              <div className="font-mono text-xs bg-slate-50 px-3 py-2 rounded-lg border border-slate-200 text-slate-700 break-all">{url.displayed_url || url.displayedUrl || 'N/A'}</div>
                            </div>
                            <div>
                              <div className="text-xs text-slate-400 font-medium mb-1">Actual Destination</div>
                              <div className={`font-mono text-xs px-3 py-2 rounded-lg border break-all ${url.deception ? 'bg-red-50 border-red-200 text-red-700' : 'bg-slate-50 border-slate-200 text-slate-700'}`}>{url.actual_url || url.actualUrl || 'N/A'}</div>
                            </div>
                          </div>
                          <div className="grid grid-cols-3 gap-3">
                            {[
                              { label: 'HTTPS', value: (url.https_enabled ?? url.httpsEnabled) ? 'Yes' : 'No', ok: url.https_enabled ?? url.httpsEnabled },
                              { label: 'URL Length', value: String(url.url_length || url.urlLength || 0), ok: (url.url_length || url.urlLength || 0) < 80 },
                              { label: 'Suspicious TLD', value: (url.suspicious_tld ?? url.suspiciousTld) ? 'Yes' : 'No', ok: !(url.suspicious_tld ?? url.suspiciousTld) },
                              { label: 'Reputation', value: url.reputation || 'unknown', ok: url.reputation === 'clean' },
                              { label: 'Risk Score', value: `${url.risk_score || url.riskScore || 0}/100`, ok: (url.risk_score || url.riskScore || 0) < 30 },
                              { label: 'Encoded Chars', value: (url.has_encoded_chars ?? url.hasEncodedChars) ? 'Yes' : 'No', ok: !(url.has_encoded_chars ?? url.hasEncodedChars) },
                            ].map(({ label, value, ok }) => (
                              <div key={label} className={`rounded-lg p-2.5 border ${ok ? 'bg-emerald-50 border-emerald-100' : 'bg-red-50 border-red-100'}`}>
                                <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wider">{label}</div>
                                <div className={`text-sm font-bold mt-0.5 ${ok ? 'text-emerald-700' : 'text-red-700'} capitalize`}>{value}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-slate-400 text-sm text-center py-6">No URLs detected in this email.</p>
                    )}
                  </div>
                )}

                {/* Social Engineering */}
                {activeSection === 'social' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">SOCIAL ENGINEERING INDICATORS</div>
                    <div className="space-y-3">
                      {Object.entries({
                        Urgency: result.socialEngineering?.urgency ?? ((result.social_engineering?.urgency || 0) * 100),
                        Authority: result.socialEngineering?.authority ?? ((result.social_engineering?.authority || 0) * 100),
                        'Financial Request': result.socialEngineering?.financialRequest ?? ((result.social_engineering?.financial_request || 0) * 100),
                        'Credential Request': result.socialEngineering?.credentialRequest ?? ((result.social_engineering?.credential_request || 0) * 100),
                        'Executive Impersonation': result.socialEngineering?.executiveImpersonation ?? ((result.social_engineering?.executive_impersonation || 0) * 100),
                        'Fear Induction': result.socialEngineering?.fearInduction ?? ((result.social_engineering?.fear_induction || 0) * 100),
                        'Confidentiality Pressure': result.socialEngineering?.confidentialityPressure ?? ((result.social_engineering?.confidentiality_pressure || 0) * 100),
                      }).map(([label, value]) => (
                        <div key={label} className="flex items-center gap-3">
                          <span className="text-sm text-slate-600 w-52 flex-shrink-0">{label}</span>
                          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-700 ${Number(value) >= 70 ? 'bg-red-500' : Number(value) >= 40 ? 'bg-orange-400' : 'bg-emerald-400'}`}
                              style={{ width: `${Math.min(100, Number(value))}%` }}
                            />
                          </div>
                          <span className={`text-sm font-bold w-12 text-right ${Number(value) >= 70 ? 'text-red-600' : Number(value) >= 40 ? 'text-orange-600' : 'text-emerald-600'}`}>
                            {Math.round(Number(value))}%
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Email Headers */}
                {activeSection === 'headers' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">EMAIL HEADERS FORENSICS</div>
                    <div className="grid grid-cols-2 gap-3 mb-4">
                      {[
                        ['From', getMetaValue('from_address') || getMetaValue('from_raw') || (selectedDemo?.from || 'N/A')],
                        ['Reply-To', getMetaValue('reply_to') || 'Not present'],
                        ['Return-Path', getMetaValue('return_path') || 'Not present'],
                        ['Subject', getMetaValue('subject') || selectedDemo?.subject || 'N/A'],
                        ['Date', getMetaValue('date') || selectedDemo?.date || 'N/A'],
                        ['Message-ID', getMetaValue('message_id') || selectedDemo?.messageId || 'N/A'],
                        ['X-Originating-IP', getMetaValue('x_originating_ip') || 'Not present'],
                        ['Mailer', getMetaValue('mailer') || 'Not present'],
                      ].map(([k, v]) => (
                        <div key={k} className={`p-3 rounded-lg border ${
                          (k === 'Reply-To' && (result.auth?.replyToMismatch || result.auth?.reply_to_mismatch)) ? 'border-red-200 bg-red-50' : 'border-slate-100 bg-slate-50'
                        }`}>
                          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">{k}</div>
                          <div className={`text-sm font-medium break-all ${(k === 'Reply-To' && (result.auth?.replyToMismatch || result.auth?.reply_to_mismatch)) ? 'text-red-700' : 'text-slate-700'}`}>{v}</div>
                        </div>
                      ))}
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Raw Headers</div>
                      <pre className="text-xs font-mono bg-[#0f172a] text-green-400 p-4 rounded-xl overflow-x-auto max-h-64 border border-slate-800 whitespace-pre-wrap">
                        {getMetaValue('raw_headers') || (selectedDemo ? selectedDemo.rawHeaders : 'No raw headers available')}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Scoring Breakdown */}
                {activeSection === 'scoring' && (
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 mb-4">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">AI SCORING BREAKDOWN</div>
                    <div className="space-y-3">
                      {[
                        { name: 'NLP / Phishing Language (25%)', score: result.scoringBreakdown?.nlpPhishing ?? Math.round((result.scoring_breakdown?.nlp_phishing || 0) * 0.25), max: 25 },
                        { name: 'Authentication Failures (20%)', score: result.scoringBreakdown?.authentication ?? Math.round((result.scoring_breakdown?.authentication || 0) * 0.20), max: 20 },
                        { name: 'Domain Risk (15%)', score: result.scoringBreakdown?.domainRisk ?? Math.round((result.scoring_breakdown?.domain_risk || 0) * 0.15), max: 15 },
                        { name: 'URL Analysis (15%)', score: result.scoringBreakdown?.urlAnalysis ?? Math.round((result.scoring_breakdown?.url_analysis || 0) * 0.15), max: 15 },
                        { name: 'Infrastructure (10%)', score: result.scoringBreakdown?.infrastructureReputation ?? Math.round((result.scoring_breakdown?.infrastructure_reputation || 0) * 0.10), max: 10 },
                        { name: 'Header Anomalies (10%)', score: result.scoringBreakdown?.headerAnomalies ?? Math.round((result.scoring_breakdown?.header_anomalies || 0) * 0.10), max: 10 },
                        { name: 'Attachment Risk (5%)', score: result.scoringBreakdown?.attachmentRisk ?? Math.round((result.scoring_breakdown?.attachment_risk || 0) * 0.05), max: 5 },
                      ].map(item => (
                        <div key={item.name} className="flex items-center gap-3">
                          <span className="text-xs text-slate-600 w-56 flex-shrink-0">{item.name}</span>
                          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${item.score / item.max > 0.7 ? 'bg-red-500' : item.score / item.max > 0.4 ? 'bg-orange-400' : 'bg-blue-500'}`}
                              style={{ width: item.max > 0 ? `${(item.score / item.max) * 100}%` : '0%' }}
                            />
                          </div>
                          <span className="text-xs font-semibold text-slate-600 w-16 text-right">{item.score} / {item.max}</span>
                        </div>
                      ))}
                      <div className="mt-4 pt-4 border-t border-slate-100 flex items-center justify-between">
                        <span className="text-sm text-slate-500 font-medium">Total weighted score</span>
                        <span className={`text-lg font-bold ${(result.overallRiskScore || result.overall_risk_score || 0) >= 81 ? 'text-red-600' : (result.overallRiskScore || result.overall_risk_score || 0) >= 61 ? 'text-orange-600' : 'text-emerald-600'}`}>
                          {result.overallRiskScore ?? result.overall_risk_score ?? 0}/100
                        </span>
                      </div>
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
                      <p className="text-sm text-slate-700 leading-relaxed whitespace-pre-line">
                        {result.explainableAI || result.explainable_ai || 'Analysis explanation not available.'}
                      </p>
                    </div>
                    <div className="mt-4 pt-4 border-t border-slate-100 flex items-center gap-2 text-xs text-slate-400">
                      <Lock className="w-3 h-3" />
                      Evidence hash: <span className="font-mono">{(result.evidenceHash || result.evidence_hash || '').slice(0, 40)}...</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right: Pipeline sidebar */}
          <div className="w-64 flex-shrink-0">
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 sticky top-20">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">ANALYSIS PIPELINE</div>
              <h3 className="text-sm font-semibold text-slate-800 mb-4">What we inspect</h3>
              <div className="space-y-3">
                {pipelineSteps.map(step => (
                  <div key={step.label} className="flex items-start gap-3">
                    <div className="w-8 h-8 bg-blue-50 border border-blue-100 rounded-lg flex items-center justify-center flex-shrink-0 text-blue-500">
                      {step.icon}
                    </div>
                    <div className="flex-1">
                      <div className="text-xs font-semibold text-slate-700">{step.label}</div>
                      <div className="text-[10px] text-slate-400">{step.sub}</div>
                    </div>
                    {result && <CheckCircle className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0 mt-1" />}
                  </div>
                ))}
              </div>

              {/* Gmail link */}
              <div className="mt-5 pt-4 border-t border-slate-100">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">GMAIL INTEGRATION</div>
                <a
                  href="/gmail-inbox"
                  className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
                >
                  <Inbox className="w-4 h-4" />
                  Analyze from Gmail
                </a>
              </div>

              {result && (
                <div className="mt-5 pt-4 border-t border-slate-100">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">EVIDENCE INTEGRITY</div>
                  <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1.5">
                      <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-xs font-semibold text-emerald-700">VERIFIED</span>
                    </div>
                    <div className="text-[10px] text-slate-500 font-mono break-all leading-relaxed">
                      {(result.evidenceHash || result.evidence_hash || '').slice(0, 40)}...
                    </div>
                  </div>
                  {result.sha256 && (
                    <div className="mt-2 text-[10px] text-slate-400 font-mono break-all">
                      File SHA256: {result.sha256.slice(0, 20)}...
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
