'use client';

import { useState, useEffect } from 'react';
import { Mail, Shield, RefreshCw, Inbox, CheckCircle, AlertTriangle, XCircle, Info, Play, ExternalLink, Search, Link, Zap, Lock } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { gmailAPI, emailAPI, type GmailEmail, type AnalysisResult } from '@/lib/api';

const DEMO_EMAILS: GmailEmail[] = [
  { id: 'gm-001', from: 'CEO <ceo@micros0ft-secure.com>', subject: 'Urgent Vendor Payment Approval', date: '2026-08-26 11:45', snippet: 'Hi, I need you to process an urgent wire transfer today...', is_read: false, risk_badge: 'CRITICAL', source: 'demo' },
  { id: 'gm-002', from: 'Microsoft Payroll <payroll@microsOft-support.com>', subject: 'Action required: verify your payroll account', date: '2026-08-26 10:18', snippet: 'URGENT: Your payroll account requires immediate verification...', is_read: false, risk_badge: 'HIGH', source: 'demo' },
  { id: 'gm-003', from: 'Microsoft Security <security-noreply@microsoft.com>', subject: 'Your Microsoft 365 security summary', date: '2026-08-26 09:15', snippet: 'Here is your monthly Microsoft 365 security summary for August 2026...', is_read: true, risk_badge: 'SAFE', source: 'demo' },
  { id: 'gm-004', from: 'Amazon AWS <aws-noreply@amazon.com>', subject: 'Your AWS invoice for August 2026', date: '2026-08-25 14:30', snippet: 'Your invoice for the billing period ending Aug 31, 2026...', is_read: true, risk_badge: null, source: 'demo' },
  { id: 'gm-005', from: 'vendor@globalparts-supply.com', subject: 'Updated bank account details for payments', date: '2026-08-24 16:22', snippet: 'Please note our bank details have changed. Please update your records...', is_read: false, risk_badge: 'HIGH', source: 'demo' },
  { id: 'gm-006', from: 'IT Support <admin@it-helpdesk-support.info>', subject: 'Your account will be suspended in 24 hours', date: '2026-08-24 11:04', snippet: 'Your corporate account has been flagged for suspicious activity...', is_read: false, risk_badge: 'SUSPICIOUS', source: 'demo' },
  { id: 'gm-007', from: 'HR Team <hr-team@acm3-corp.com>', subject: 'Important HR Policy Update for All Staff', date: '2026-08-23 15:38', snippet: 'Please review and acknowledge the updated HR policies...', is_read: true, risk_badge: 'SUSPICIOUS', source: 'demo' },
  { id: 'gm-008', from: 'Raj Kumar <raj.kumar@acmecorp.com>', subject: 'Case MT-2026-00120 update', date: '2026-08-23 13:11', snippet: 'Team, I have escalated the case to senior management...', is_read: true, risk_badge: null, source: 'demo' },
];

const getRiskBadge = (badge: string | null | undefined) => {
  if (!badge) return null;
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-700 border-red-200',
    HIGH: 'bg-orange-100 text-orange-700 border-orange-200',
    SUSPICIOUS: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    SAFE: 'bg-emerald-100 text-emerald-700 border-emerald-200',
  };
  const iconMap: Record<string, React.ReactNode> = {
    CRITICAL: <XCircle className="w-3 h-3" />,
    HIGH: <AlertTriangle className="w-3 h-3" />,
    SUSPICIOUS: <AlertTriangle className="w-3 h-3" />,
    SAFE: <CheckCircle className="w-3 h-3" />,
  };
  return { style: map[badge] || 'bg-slate-100 text-slate-600 border-slate-200', icon: iconMap[badge] || <Info className="w-3 h-3" /> };
};

export default function GmailInboxPage() {
  const [emails, setEmails] = useState<GmailEmail[]>([]);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [gmailEmail, setGmailEmail] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [selected, setSelected] = useState<GmailEmail | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [search, setSearch] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => { loadStatus(); }, []);

  const loadStatus = async () => {
    try {
      const status = await gmailAPI.status();
      setConnected(status.connected);
      setDemoMode(status.demo_mode || false);
      setGmailEmail(status.email || null);
      if (status.connected || status.demo_mode) {
        await loadEmails();
      } else {
        setLoading(false);
      }
    } catch {
      // Backend unavailable — show demo inbox
      setDemoMode(true);
      setConnected(false);
      setEmails(DEMO_EMAILS);
      setLoading(false);
    }
  };

  const loadEmails = async () => {
    setRefreshing(true);
    try {
      const inbox = await gmailAPI.listEmails(30);
      setEmails(inbox.emails.length > 0 ? inbox.emails : DEMO_EMAILS);
      setDemoMode(inbox.demo_mode);
    } catch {
      setEmails(DEMO_EMAILS);
      setDemoMode(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const { auth_url } = await gmailAPI.authUrl();
      window.location.href = auth_url;
    } catch {
      // Demo mode - simulate connection
      setConnected(false);
      setDemoMode(true);
      setEmails(DEMO_EMAILS);
      setConnecting(false);
    }
  };

  const handleAnalyze = async (email: GmailEmail) => {
    setSelected(email);
    setAnalyzing(true);
    setAnalysisResult(null);
    try {
      // Try backend
      if (connected && !demoMode) {
        const result = await gmailAPI.analyzeEmail(email.id);
        setAnalysisResult(result);
      } else {
        // Map demo emails to mock analysis
        const demoIdMap: Record<string, string> = {
          'gm-001': 'demo-3',
          'gm-002': 'demo-2',
          'gm-003': 'demo-1',
        };
        if (demoIdMap[email.id]) {
          try {
            const result = await emailAPI.analyzeDemo(demoIdMap[email.id]);
            setAnalysisResult(result);
          } catch {
            setAnalysisResult(null);
          }
        }
      }
    } catch {
      setAnalysisResult(null);
    } finally {
      setAnalyzing(false);
    }
  };

  const filteredEmails = emails.filter(e =>
    !search || e.from.toLowerCase().includes(search.toLowerCase()) ||
    e.subject.toLowerCase().includes(search.toLowerCase()) ||
    e.snippet.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Gmail Inbox" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">GMAIL INTEGRATION</div>
            <h1 className="text-2xl font-bold text-slate-800">Gmail Inbox</h1>
            <p className="text-sm text-slate-500 mt-1">
              {connected && gmailEmail ? `Connected: ${gmailEmail}` : demoMode ? 'Demo inbox — connect Gmail to analyze real emails' : 'Connect your Gmail account to scan for threats'}
            </p>
          </div>
          <div className="flex items-center gap-3">
            {(connected || demoMode) && (
              <button
                onClick={loadEmails}
                disabled={refreshing}
                className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            )}
            {!connected && (
              <button
                onClick={handleConnect}
                disabled={connecting}
                className="flex items-center gap-2 px-5 py-2.5 bg-red-500 hover:bg-red-600 text-white font-semibold rounded-xl transition-colors shadow-sm"
              >
                <Link className="w-4 h-4" />
                {connecting ? 'Connecting...' : 'Connect Gmail'}
              </button>
            )}
            {connected && (
              <div className="flex items-center gap-2 px-4 py-2.5 bg-emerald-50 border border-emerald-200 rounded-xl">
                <CheckCircle className="w-4 h-4 text-emerald-500" />
                <span className="text-sm text-emerald-700 font-medium">Connected</span>
              </div>
            )}
          </div>
        </div>

        {/* How it works banner (when not connected) */}
        {!connected && !demoMode && !loading && (
          <div className="mb-6 bg-gradient-to-br from-red-500 to-orange-500 rounded-2xl p-6 text-white">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center flex-shrink-0">
                <Mail className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-bold mb-1">Connect Gmail for Real-Time Threat Detection</h3>
                <p className="text-red-100 text-sm mb-4">
                  MailTrace AI connects securely to your Gmail using OAuth 2.0. We never store your email credentials. 
                  Once connected, you can scan any email from your inbox for phishing, BEC, and malware threats.
                </p>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { icon: <Lock className="w-4 h-4" />, title: 'OAuth 2.0 Secure', desc: 'No password stored' },
                    { icon: <Zap className="w-4 h-4" />, title: 'Instant Analysis', desc: 'Results in seconds' },
                    { icon: <Shield className="w-4 h-4" />, title: 'Full Forensics', desc: 'Headers + IOCs + AI' },
                  ].map(({ icon, title, desc }) => (
                    <div key={title} className="bg-white/10 rounded-xl p-3">
                      <div className="flex items-center gap-2 mb-1">{icon}<span className="font-semibold text-sm">{title}</span></div>
                      <p className="text-xs text-red-100">{desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-3">
              <button
                onClick={handleConnect}
                disabled={connecting}
                className="flex items-center gap-2 px-6 py-2.5 bg-white text-red-600 font-bold rounded-xl hover:bg-red-50 transition-colors"
              >
                <Link className="w-4 h-4" />
                {connecting ? 'Connecting...' : 'Connect Google Account'}
              </button>
              <button
                onClick={() => { setDemoMode(true); setEmails(DEMO_EMAILS); }}
                className="flex items-center gap-2 px-6 py-2.5 bg-white/20 hover:bg-white/30 font-semibold rounded-xl transition-colors text-sm"
              >
                View Demo Inbox
              </button>
            </div>
          </div>
        )}

        {/* Demo mode banner */}
        {demoMode && (
          <div className="mb-4 flex items-start gap-3 bg-amber-50 border border-amber-200 rounded-xl px-5 py-3">
            <Info className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-amber-700">
              <strong>Demo Inbox</strong> — Showing simulated emails with pre-computed threat badges. 
              <button onClick={handleConnect} className="ml-2 underline font-medium">Connect real Gmail →</button>
            </div>
          </div>
        )}

        {/* Main content */}
        {(loading) ? (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-20 bg-white rounded-xl border border-slate-200 animate-pulse" />
            ))}
          </div>
        ) : (emails.length > 0 || demoMode) ? (
          <div className="flex gap-5">
            {/* Email list */}
            <div className="w-[450px] flex-shrink-0">
              {/* Search */}
              <div className="relative mb-3">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search inbox..."
                  className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* Stats bar */}
              <div className="flex items-center gap-3 mb-3 text-xs text-slate-500">
                <span>{filteredEmails.length} emails</span>
                <span>•</span>
                <span className="text-red-500 font-medium">{filteredEmails.filter(e => e.risk_badge === 'CRITICAL' || e.risk_badge === 'HIGH').length} threats</span>
                <span>•</span>
                <span>{filteredEmails.filter(e => !e.is_read).length} unread</span>
              </div>

              {/* Email list */}
              <div className="space-y-1.5 max-h-[calc(100vh-280px)] overflow-y-auto pr-1">
                {filteredEmails.map(email => {
                  const badge = getRiskBadge(email.risk_badge);
                  return (
                    <button
                      key={email.id}
                      onClick={() => { setSelected(email); setAnalysisResult(null); }}
                      className={`w-full text-left p-4 rounded-xl border-2 transition-all ${
                        selected?.id === email.id
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-slate-100 hover:border-slate-200 hover:bg-slate-50 bg-white'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-2 min-w-0">
                          {!email.is_read && <div className="w-2 h-2 bg-blue-500 rounded-full flex-shrink-0" />}
                          <span className={`text-sm font-semibold truncate ${email.is_read ? 'text-slate-600' : 'text-slate-800'}`}>{email.from}</span>
                        </div>
                        {badge && (
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border flex items-center gap-1 flex-shrink-0 ${badge.style}`}>
                            {badge.icon} {email.risk_badge}
                          </span>
                        )}
                      </div>
                      <div className="text-sm font-medium text-slate-700 mb-1 truncate">{email.subject}</div>
                      <div className="text-xs text-slate-400 truncate">{email.snippet}</div>
                      <div className="text-[10px] text-slate-400 mt-1.5">{email.date}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Email detail + analysis panel */}
            <div className="flex-1 min-w-0">
              {selected ? (
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
                  {/* Email header */}
                  <div className="px-6 py-5 border-b border-slate-100">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <h2 className="text-lg font-bold text-slate-800 mb-1">{selected.subject}</h2>
                        <div className="text-sm text-slate-500 mb-2">
                          <span className="font-medium text-slate-700">{selected.from}</span>
                          <span className="text-slate-300 mx-2">·</span>
                          <span>{selected.date}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {getRiskBadge(selected.risk_badge) && (
                          <span className={`text-xs font-bold px-3 py-1 rounded-full border flex items-center gap-1.5 ${getRiskBadge(selected.risk_badge)?.style}`}>
                            {getRiskBadge(selected.risk_badge)?.icon} {selected.risk_badge}
                          </span>
                        )}
                        <button
                          onClick={() => handleAnalyze(selected)}
                          disabled={analyzing}
                          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl text-sm transition-colors"
                        >
                          {analyzing ? (
                            <>
                              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                              Analyzing...
                            </>
                          ) : (
                            <>
                              <Play className="w-3.5 h-3.5" />
                              Run Analysis
                            </>
                          )}
                        </button>
                        <a href="/analyze" className="flex items-center gap-1.5 px-4 py-2 border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
                          <ExternalLink className="w-3.5 h-3.5" />
                          Full Analyze
                        </a>
                      </div>
                    </div>

                    {/* Email body preview */}
                    <div className="mt-4 p-4 bg-slate-50 rounded-xl border border-slate-200 text-sm text-slate-600 leading-relaxed italic">
                      {selected.snippet}...
                    </div>
                  </div>

                  {/* Analysis results */}
                  {analyzing && (
                    <div className="px-6 py-8 flex flex-col items-center gap-4">
                      <div className="w-12 h-12 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
                      <div className="text-sm text-slate-500 font-medium">Running threat analysis pipeline...</div>
                      <div className="text-xs text-slate-400">
                        Parsing headers · Verifying authentication · Extracting IOCs · Scoring
                      </div>
                    </div>
                  )}

                  {analysisResult && !analyzing && (
                    <div className="px-6 py-5">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">ANALYSIS RESULTS</div>
                      
                      {/* Score */}
                      <div className="flex items-center gap-6 mb-5">
                        <div className="flex-shrink-0 text-center">
                          <div className={`w-20 h-20 rounded-full flex items-center justify-center border-4 ${
                            (analysisResult.overall_risk_score || 0) >= 81 ? 'border-red-400 bg-red-50' :
                            (analysisResult.overall_risk_score || 0) >= 61 ? 'border-orange-400 bg-orange-50' :
                            (analysisResult.overall_risk_score || 0) >= 41 ? 'border-yellow-400 bg-yellow-50' :
                            'border-emerald-400 bg-emerald-50'
                          }`}>
                            <div>
                              <div className={`text-2xl font-bold ${(analysisResult.overall_risk_score || 0) >= 81 ? 'text-red-600' : (analysisResult.overall_risk_score || 0) >= 61 ? 'text-orange-600' : 'text-emerald-600'}`}>
                                {analysisResult.overall_risk_score || 0}
                              </div>
                              <div className="text-[10px] text-slate-400">/100</div>
                            </div>
                          </div>
                          <div className="text-xs font-semibold text-slate-500 mt-1">{analysisResult.risk_level}</div>
                        </div>
                        <div>
                          <div className="text-sm font-bold text-slate-800 mb-1">{analysisResult.classification}</div>
                          <div className="grid grid-cols-3 gap-2">
                            {[
                              { label: 'SPF', val: analysisResult.auth?.spf },
                              { label: 'DKIM', val: analysisResult.auth?.dkim },
                              { label: 'DMARC', val: analysisResult.auth?.dmarc },
                            ].map(({ label, val }) => (
                              <div key={label} className={`text-xs px-2 py-1 rounded-lg border text-center font-semibold ${
                                val === 'pass' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-red-50 border-red-200 text-red-700'
                              }`}>
                                {label}: {String(val || 'unknown').toUpperCase()}
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* IOC count */}
                      <div className="flex items-center gap-3 mb-4">
                        <div className="flex-1 bg-red-50 border border-red-100 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-red-600">{(analysisResult.iocs || []).length}</div>
                          <div className="text-xs text-red-500 font-medium">IOCs Found</div>
                        </div>
                        <div className="flex-1 bg-orange-50 border border-orange-100 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-orange-600">{(analysisResult.url_analysis || []).length}</div>
                          <div className="text-xs text-orange-500 font-medium">URLs Analyzed</div>
                        </div>
                        <div className="flex-1 bg-blue-50 border border-blue-100 rounded-xl p-3 text-center">
                          <div className="text-xl font-bold text-blue-600">{(analysisResult.risk_indicators || []).length}</div>
                          <div className="text-xs text-blue-500 font-medium">Risk Indicators</div>
                        </div>
                      </div>

                      {/* AI Summary */}
                      {analysisResult.explainable_ai && (
                        <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                          <div className="flex items-center gap-2 mb-2">
                            <Shield className="w-3.5 h-3.5 text-blue-500" />
                            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">AI Summary</span>
                          </div>
                          <p className="text-sm text-slate-600 leading-relaxed">{analysisResult.explainable_ai.slice(0, 400)}...</p>
                        </div>
                      )}

                      <div className="mt-4 flex items-center gap-3">
                        <a href="/analyze" className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium">
                          View Full Analysis <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                        <span className="text-slate-300">|</span>
                        <a href="/cases" className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium">
                          Open Cases <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  )}

                  {!analysisResult && !analyzing && (
                    <div className="px-6 py-8 text-center">
                      <Inbox className="w-10 h-10 text-slate-200 mx-auto mb-3" />
                      <p className="text-sm text-slate-400 mb-1">No analysis run yet</p>
                      <p className="text-xs text-slate-300">Click "Run Analysis" to analyze this email for threats</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-16 text-center">
                  <Mail className="w-12 h-12 text-slate-200 mx-auto mb-4" />
                  <p className="text-slate-400 font-medium mb-1">Select an email to analyze</p>
                  <p className="text-xs text-slate-300">Click any email from the list on the left</p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-16 text-center">
            <Inbox className="w-12 h-12 text-slate-200 mx-auto mb-4" />
            <p className="text-slate-500 font-medium mb-2">No emails to show</p>
            <button onClick={handleConnect} className="text-blue-600 text-sm font-medium hover:underline">
              Connect Gmail to get started
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
