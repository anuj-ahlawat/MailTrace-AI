'use client';

import { useState, useEffect, useCallback } from 'react';
import { Search, Plus, MapPin, Clock, ChevronDown, Shield, X, AlertTriangle, CheckCircle, Copy, Download, Flag, Link2, Globe, Server, Brain, Network, RefreshCw, FileText } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { casesAPI, emailAPI, type Case as ApiCase } from '@/lib/api';
import { mockCases } from '@/lib/mockData';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import { demoEmails } from '@/lib/demoEmails';

type SortKey = 'risk' | 'date' | 'status';
type FilterStatus = 'all' | 'new' | 'investigating' | 'escalated' | 'resolved';

const getRiskBg = (score: number) =>
  score >= 81 ? 'bg-red-50 border-red-200 text-red-700' :
  score >= 61 ? 'bg-orange-50 border-orange-200 text-orange-700' :
  score >= 41 ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
  'bg-emerald-50 border-emerald-200 text-emerald-700';

const getStatusStyle = (status: string) => {
  const map: Record<string, string> = {
    new: 'bg-slate-100 text-slate-600',
    NEW: 'bg-slate-100 text-slate-600',
    investigating: 'bg-yellow-50 text-yellow-700',
    INVESTIGATING: 'bg-yellow-50 text-yellow-700',
    escalated: 'bg-red-50 text-red-700',
    ESCALATED: 'bg-red-50 text-red-700',
    resolved: 'bg-emerald-50 text-emerald-700',
    RESOLVED: 'bg-emerald-50 text-emerald-700',
  };
  return map[status] || 'bg-slate-100 text-slate-600';
};

const getClassificationStyle = (cls: string) => {
  if (cls?.includes('Compromise') || cls?.includes('BEC')) return 'bg-orange-50 text-orange-700';
  if (cls?.includes('Phishing') || cls?.includes('Credential')) return 'bg-red-50 text-red-700';
  if (cls?.includes('Legitimate')) return 'bg-emerald-50 text-emerald-700';
  if (cls?.includes('Suspicious')) return 'bg-yellow-50 text-yellow-700';
  if (cls?.includes('Malware')) return 'bg-purple-50 text-purple-700';
  if (cls?.includes('Invoice') || cls?.includes('Fraud')) return 'bg-amber-50 text-amber-700';
  return 'bg-slate-100 text-slate-600';
};

// Normalize both backend ApiCase and mockCase to a unified shape
interface NormalizedCase {
  id: string;
  case_id: string;
  subject: string;
  sender: string;
  classification: string;
  riskScore: number;
  origin: string;
  status: string;
  timestamp: string;
  analyst: string;
  demoId?: string;
  email_analysis_id?: string;
  notes?: Array<{ content: string; author: string; created_at: string }>;
}

function normalizeCases(raw: ApiCase[]): NormalizedCase[] {
  return raw.map(c => ({
    id: c.case_id || c.id,
    case_id: c.case_id || c.id,
    subject: c.subject || '',
    sender: c.sender || '',
    classification: c.classification || 'Unknown',
    riskScore: c.risk_score || 0,
    origin: c.origin || 'Unknown',
    status: (c.status || 'new').toLowerCase(),
    timestamp: c.created_at ? new Date(c.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'N/A',
    analyst: c.analyst_name?.split(' ').map(w => w[0]).join('').toUpperCase() || 'AM',
    email_analysis_id: c.email_analysis_id,
    notes: c.notes || [],
  }));
}

function normalizeMockCases(): NormalizedCase[] {
  return mockCases.map(c => ({
    id: c.id,
    case_id: c.id,
    subject: c.subject,
    sender: c.sender,
    classification: c.classification,
    riskScore: c.riskScore,
    origin: c.origin,
    status: c.status,
    timestamp: c.timestamp,
    analyst: c.analyst,
    demoId: c.demoId,
  }));
}

function CaseModal({ c, onClose, onStatusChange }: { c: NormalizedCase; onClose: () => void; onStatusChange: (id: string, status: string) => void }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [note, setNote] = useState('');
  const [addingNote, setAddingNote] = useState(false);
  const [notes, setNotes] = useState(c.notes || []);
  const [changingStatus, setChangingStatus] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [analysisData, setAnalysisData] = useState<any | null>(null);

  const result = c.demoId ? mockAnalysisResults[c.demoId] : null;
  const email = c.demoId ? demoEmails.find(d => d.id === c.demoId) : null;

  useEffect(() => {
    if (!result && c.email_analysis_id) {
      emailAPI.get(c.email_analysis_id)
        .then(r => setAnalysisData(r))
        .catch(() => setAnalysisData(null));
    }
  }, [c.email_analysis_id, result]);

  const tabs = ['Overview', 'Email Content', 'Authentication', 'Indicators', 'Infrastructure', 'Notes'];

  const AuthBadge = ({ status }: { status: 'pass' | 'fail' | 'unknown' }) => {
    const map = { pass: 'bg-emerald-50 border-emerald-200 text-emerald-700', fail: 'bg-red-50 border-red-200 text-red-700', unknown: 'bg-slate-50 border-slate-200 text-slate-500' };
    const icons = { pass: <CheckCircle className="w-3 h-3" />, fail: <X className="w-3 h-3" />, unknown: <AlertTriangle className="w-3 h-3" /> };
    return (
      <span className={`inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full border ${map[status]}`}>
        {icons[status]} {status.toUpperCase()}
      </span>
    );
  };

  const handleAddNote = async () => {
    if (!note.trim()) return;
    setAddingNote(true);
    try {
      await casesAPI.addNote(c.id, note);
      const newNote = { content: note, author: 'You', created_at: new Date().toISOString() };
      setNotes(prev => [...prev, newNote]);
      setNote('');
    } catch {
      // Demo fallback
      setNotes(prev => [...prev, { content: note, author: 'You', created_at: new Date().toISOString() }]);
      setNote('');
    } finally {
      setAddingNote(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    setChangingStatus(true);
    try {
      await casesAPI.update(c.id, { status: newStatus.toUpperCase() });
      onStatusChange(c.id, newStatus);
    } catch {
      onStatusChange(c.id, newStatus);
    } finally {
      setChangingStatus(false);
    }
  };

  const activeAuth = result?.auth || analysisData?.auth;
  const activeIOCs = result?.iocs || analysisData?.iocs || [];
  const activeRelayPath = result?.relayPath || analysisData?.relay_path || [];
  const activeIndicators = result?.riskIndicators || analysisData?.risk_indicators || [];

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-100 flex items-start justify-between flex-shrink-0">
          <div className="flex items-start gap-4">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${c.riskScore >= 81 ? 'bg-red-100' : 'bg-orange-100'}`}>
              <Shield className={`w-5 h-5 ${c.riskScore >= 81 ? 'text-red-500' : 'text-orange-500'}`} />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold font-mono text-slate-500">{c.case_id}</span>
                <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${getClassificationStyle(c.classification)}`}>{c.classification}</span>
                <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${getRiskBg(c.riskScore)}`}>{c.riskScore}/100</span>
              </div>
              <h2 className="text-lg font-bold text-slate-800 mt-0.5">{c.subject}</h2>
              <p className="text-sm text-slate-500">{c.sender}</p>
            </div>
          </div>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center hover:bg-slate-100 rounded-lg transition-colors">
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-100 overflow-x-auto flex-shrink-0">
          {tabs.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab.toLowerCase().replace(' ', '-'))}
              className={`px-4 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px transition-colors ${
                activeTab === tab.toLowerCase().replace(' ', '-')
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-slate-500 hover:text-slate-700'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="overflow-y-auto flex-1 p-6">
          {/* Overview */}
          {activeTab === 'overview' && (
            <div className="grid grid-cols-2 gap-5">
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Case Details</div>
                <div className="space-y-2 text-sm">
                  {[
                    ['Case ID', c.case_id],
                    ['Sender', c.sender],
                    ['Classification', c.classification],
                    ['Risk Score', `${c.riskScore}/100`],
                    ['Origin', c.origin],
                    ['Created', c.timestamp],
                    ['Analyst', c.analyst],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between py-2 border-b border-slate-50">
                      <span className="text-slate-400 font-medium">{k}</span>
                      <span className="text-slate-700 font-medium text-right max-w-[220px] truncate">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Case Status</div>
                <div className="space-y-2">
                  {['new', 'investigating', 'escalated', 'resolved'].map(s => (
                    <button
                      key={s}
                      onClick={() => handleStatusChange(s)}
                      disabled={changingStatus}
                      className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl border-2 transition-all text-sm font-medium capitalize ${
                        c.status === s
                          ? 'border-blue-500 bg-blue-50 text-blue-700'
                          : 'border-slate-100 hover:border-slate-200 text-slate-600'
                      }`}
                    >
                      {c.status === s && <CheckCircle className="w-4 h-4 text-blue-500" />}
                      {s.charAt(0).toUpperCase() + s.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Email Content */}
          {activeTab === 'email-content' && (
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Email Body</div>
              <pre className="text-sm text-slate-700 font-sans whitespace-pre-wrap bg-slate-50 border border-slate-200 rounded-xl p-5 leading-relaxed max-h-80 overflow-y-auto">
                {email?.body || (result && 'Email body from demo data') || 'Email body not available for this case. Full content accessible via evidence storage.'}
              </pre>
              {email?.rawHeaders && (
                <div className="mt-4">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Raw Headers</div>
                  <pre className="text-xs font-mono bg-[#0f172a] text-green-400 p-4 rounded-xl overflow-x-auto max-h-48 border border-slate-800">
                    {email.rawHeaders}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Authentication */}
          {activeTab === 'authentication' && (
            <div className="grid grid-cols-3 gap-4">
              {activeAuth ? [
                { label: 'SPF', status: activeAuth.spf || activeAuth.spf, detail: activeAuth.spfDetail || activeAuth.spf_detail },
                { label: 'DKIM', status: activeAuth.dkim, detail: activeAuth.dkimDetail || activeAuth.dkim_detail },
                { label: 'DMARC', status: activeAuth.dmarc, detail: activeAuth.dmarcDetail || activeAuth.dmarc_detail },
              ].map(card => (
                <div key={card.label} className="bg-slate-50 rounded-xl border border-slate-200 p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-slate-800">{card.label}</span>
                    <AuthBadge status={card.status as 'pass' | 'fail' | 'unknown'} />
                  </div>
                  <p className="text-xs text-slate-500">{card.detail || `${card.label} authentication result`}</p>
                </div>
              )) : (
                <div className="col-span-3 text-center text-slate-400 py-8">
                  Authentication data not available for this case.
                </div>
              )}
            </div>
          )}

          {/* Indicators */}
          {activeTab === 'indicators' && (
            <div>
              {activeIndicators.length > 0 ? (
                <div className="space-y-2">
                  {activeIndicators.map((ri: { id?: string; label: string; severity: string; category?: string }, idx: number) => (
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
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${
                        ri.severity === 'critical' ? 'bg-red-50 border-red-200 text-red-700' :
                        ri.severity === 'high' ? 'bg-orange-50 border-orange-200 text-orange-700' :
                        ri.severity === 'medium' ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
                        'bg-emerald-50 border-emerald-200 text-emerald-700'
                      }`}>
                        {ri.severity}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-slate-400 py-8">No indicators available for this case.</div>
              )}

              {activeIOCs.length > 0 && (
                <div className="mt-6">
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Indicators of Compromise</div>
                  <div className="space-y-2">
                    {activeIOCs.map((ioc: { id?: string; type: string; indicator?: string; value?: string; reputation: string }, idx: number) => {
                      const indicator = ioc.indicator || ioc.value || '';
                      const typeIcons: Record<string, React.ReactNode> = {
                        domain: <Globe className="w-3.5 h-3.5" />,
                        ip: <Server className="w-3.5 h-3.5" />,
                        url: <Link2 className="w-3.5 h-3.5" />,
                        email: <Flag className="w-3.5 h-3.5" />,
                      };
                      return (
                        <div key={ioc.id || idx} className="flex items-center gap-3 p-3 rounded-lg bg-slate-50 border border-slate-100">
                          <span className="text-slate-500">{typeIcons[ioc.type] || <Shield className="w-3.5 h-3.5" />}</span>
                          <span className="font-mono text-xs text-slate-700 flex-1 truncate">{indicator}</span>
                          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${
                            ioc.reputation === 'malicious' ? 'bg-red-50 border-red-200 text-red-700' :
                            ioc.reputation === 'suspicious' ? 'bg-orange-50 border-orange-200 text-orange-700' :
                            'bg-slate-50 border-slate-200 text-slate-600'
                          }`}>{ioc.reputation}</span>
                          <button className="p-1.5 hover:bg-slate-200 rounded-lg" title="Copy" onClick={() => navigator.clipboard.writeText(indicator)}>
                            <Copy className="w-3.5 h-3.5 text-slate-400" />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Infrastructure */}
          {activeTab === 'infrastructure' && (
            <div>
              {activeRelayPath.length > 0 ? (
                <div className="space-y-3">
                  {activeRelayPath.map((hop: { hop_number?: number; hop?: number; ip: string; hostname: string; timestamp: string; location: string; label: string; confidence: string; notes?: string }, idx: number) => (
                    <div key={idx} className="flex items-start gap-4 p-4 rounded-xl border border-slate-200">
                      <div className="w-8 h-8 bg-blue-50 border border-blue-200 rounded-full flex items-center justify-center text-blue-600 font-bold text-sm flex-shrink-0">
                        {hop.hop_number || hop.hop || idx + 1}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Network className="w-3.5 h-3.5 text-slate-400" />
                          <span className="font-mono text-sm text-slate-700">{hop.ip || 'Private'}</span>
                          <span className="text-xs text-slate-400">{hop.hostname}</span>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-slate-500">
                          <MapPin className="w-3 h-3" />
                          <span><strong>Probable Infrastructure Location:</strong> {hop.location || 'Unknown'}</span>
                          <span>·</span>
                          <span>Confidence: {hop.confidence || 'unknown'}</span>
                        </div>
                        {hop.label && <div className="mt-1 text-xs text-blue-600 font-medium">{hop.label}</div>}
                        {hop.notes && <div className="mt-1 text-xs text-slate-400 italic">{hop.notes}</div>}
                      </div>
                      <div className="text-xs text-slate-400 text-right">{hop.timestamp}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-slate-400 py-8">Infrastructure / relay path data not available for this case.</div>
              )}
            </div>
          )}

          {/* Notes */}
          {activeTab === 'notes' && (
            <div>
              {notes.length > 0 && (
                <div className="space-y-3 mb-6">
                  {notes.map((n, idx) => (
                    <div key={idx} className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-6 h-6 bg-blue-600 rounded-full flex items-center justify-center text-white text-xs font-bold">{n.author.charAt(0)}</div>
                        <span className="text-xs font-semibold text-slate-700">{n.author}</span>
                        <span className="text-xs text-slate-400">{new Date(n.created_at).toLocaleDateString()}</span>
                      </div>
                      <p className="text-sm text-slate-700">{n.content}</p>
                    </div>
                  ))}
                </div>
              )}
              <div className="mt-4">
                <textarea
                  value={note}
                  onChange={e => setNote(e.target.value)}
                  placeholder="Add analyst note..."
                  className="w-full h-24 px-4 py-3 border border-slate-200 rounded-xl text-sm resize-none focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <div className="flex justify-end mt-2">
                  <button
                    onClick={handleAddNote}
                    disabled={addingNote || !note.trim()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-sm font-medium rounded-xl transition-colors flex items-center gap-2"
                  >
                    {addingNote ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
                    Add Note
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-100 flex items-center justify-between flex-shrink-0 bg-slate-50">
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-700 transition-colors">
              <Download className="w-3.5 h-3.5" />
              Export case
            </button>
            <button className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-700 transition-colors">
              <FileText className="w-3.5 h-3.5" />
              Generate report
            </button>
            {result && (
              <button className="flex items-center gap-2 text-xs text-blue-600 hover:text-blue-700 transition-colors">
                <Brain className="w-3.5 h-3.5" />
                View full analysis
              </button>
            )}
          </div>
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-600 transition-colors">Close</button>
        </div>
      </div>
    </div>
  );
}

export default function CasesPage() {
  const [cases, setCases] = useState<NormalizedCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all');
  const [sortKey, setSortKey] = useState<SortKey>('risk');
  const [selectedCase, setSelectedCase] = useState<NormalizedCase | null>(null);
  const [isLive, setIsLive] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const PER_PAGE = 25;

  const loadCases = useCallback(async () => {
    setRefreshing(true);
    try {
      const params: { skip: number; limit: number; status?: string } = { skip: page * PER_PAGE, limit: PER_PAGE };
      if (filterStatus !== 'all') params.status = filterStatus.toUpperCase();
      const data = await casesAPI.list(params);
      if (data.cases && data.cases.length > 0) {
        setCases(normalizeCases(data.cases));
        setTotal(data.total || data.cases.length);
        setIsLive(true);
      } else {
        throw new Error('No cases from backend');
      }
    } catch {
      setCases(normalizeMockCases());
      setTotal(mockCases.length);
      setIsLive(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page, filterStatus]);

  useEffect(() => { loadCases(); }, [loadCases]);

  const filtered = cases
    .filter(c =>
      (!search || c.sender.toLowerCase().includes(search.toLowerCase()) ||
        c.subject.toLowerCase().includes(search.toLowerCase()) ||
        c.case_id.toLowerCase().includes(search.toLowerCase()) ||
        c.classification.toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      if (sortKey === 'risk') return b.riskScore - a.riskScore;
      if (sortKey === 'status') return a.status.localeCompare(b.status);
      return 0;
    });

  const handleStatusChange = (id: string, newStatus: string) => {
    setCases(prev => prev.map(c => c.id === id ? { ...c, status: newStatus } : c));
    if (selectedCase?.id === id) setSelectedCase(prev => prev ? { ...prev, status: newStatus } : null);
  };

  const statusCounts = {
    all: cases.length,
    new: cases.filter(c => c.status === 'new').length,
    investigating: cases.filter(c => c.status === 'investigating').length,
    escalated: cases.filter(c => c.status === 'escalated').length,
    resolved: cases.filter(c => c.status === 'resolved').length,
  };

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Cases" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">INVESTIGATION MANAGEMENT</div>
            <h1 className="text-2xl font-bold text-slate-800">
              Cases
              <span className={`ml-3 text-sm px-2 py-0.5 rounded-full font-semibold ${isLive ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                {isLive ? '● LIVE' : '● DEMO'}
              </span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={loadCases} disabled={refreshing} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors shadow-sm">
              <Plus className="w-4 h-4" />
              New Case
            </button>
          </div>
        </div>

        {/* Status filter pills */}
        <div className="flex items-center gap-2 mb-5 flex-wrap">
          {(['all', 'new', 'investigating', 'escalated', 'resolved'] as FilterStatus[]).map(s => (
            <button
              key={s}
              onClick={() => { setFilterStatus(s); setPage(0); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${
                filterStatus === s
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-white border border-slate-200 text-slate-600 hover:border-blue-300'
              }`}
            >
              <span className="capitalize">{s === 'all' ? 'All cases' : s}</span>
              <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${filterStatus === s ? 'bg-white/20 text-white' : 'bg-slate-100 text-slate-500'}`}>
                {statusCounts[s]}
              </span>
            </button>
          ))}

          <div className="ml-auto flex items-center gap-3">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search cases..."
                className="pl-9 pr-4 py-2 bg-white border border-slate-200 rounded-xl text-sm w-56 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            {/* Sort */}
            <div className="relative">
              <select
                value={sortKey}
                onChange={e => setSortKey(e.target.value as SortKey)}
                className="pl-3 pr-8 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 appearance-none cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="risk">Sort: Risk Score</option>
                <option value="date">Sort: Date</option>
                <option value="status">Sort: Status</option>
              </select>
              <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Cases table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                {['Case ID', 'Sender / Subject', 'Classification', 'Risk', 'Origin', 'Status', 'Time', 'Analyst'].map(h => (
                  <th key={h} className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-5 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(8)].map((_, i) => (
                  <tr key={i} className="border-b border-slate-50">
                    {[...Array(8)].map((_, j) => (
                      <td key={j} className="px-5 py-4"><div className="h-3 bg-slate-100 rounded animate-pulse" /></td>
                    ))}
                  </tr>
                ))
              ) : filtered.map(c => (
                <tr
                  key={c.id}
                  className="border-b border-slate-50 hover:bg-blue-50/30 transition-colors cursor-pointer"
                  onClick={() => setSelectedCase(c)}
                >
                  <td className="px-5 py-3.5">
                    <span className="text-sm text-blue-600 font-medium font-mono">{c.case_id}</span>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="text-sm text-slate-700 truncate max-w-[160px]">{c.sender}</div>
                    <div className="text-xs text-slate-400 truncate max-w-[160px]">{c.subject}</div>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className={`text-xs font-medium px-2 py-1 rounded-full ${getClassificationStyle(c.classification)}`}>
                      {c.classification}
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className={`text-xs font-bold px-2 py-1 rounded-full border ${getRiskBg(c.riskScore)}`}>
                      {c.riskScore}/100
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-1.5 text-sm text-slate-600">
                      <MapPin className="w-3 h-3 text-slate-400" />
                      {c.origin}
                    </div>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className={`text-xs font-medium px-2.5 py-1 rounded-full capitalize ${getStatusStyle(c.status)}`}>
                      ● {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-1.5 text-xs text-slate-400">
                      <Clock className="w-3 h-3" />
                      {c.timestamp}
                    </div>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="w-6 h-6 bg-blue-600 rounded-full flex items-center justify-center text-white text-[10px] font-bold">
                      {c.analyst}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">
              Showing {filtered.length} of {total} cases
            </span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50 disabled:opacity-40">← Previous</button>
              <button className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded-lg font-medium">{page + 1}</button>
              <button onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PER_PAGE >= total} className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50 disabled:opacity-40">Next →</button>
            </div>
          </div>
        </div>
      </div>

      {/* Case modal */}
      {selectedCase && (
        <CaseModal
          c={selectedCase}
          onClose={() => setSelectedCase(null)}
          onStatusChange={handleStatusChange}
        />
      )}
    </div>
  );
}
