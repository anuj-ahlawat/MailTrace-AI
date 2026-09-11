'use client';

import { useState } from 'react';
import { Search, Plus, MapPin, Clock, ChevronDown, Shield, X, AlertTriangle, CheckCircle, Copy, Download, ExternalLink, Flag, Link2, Globe, Server, Brain, Network } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { mockCases, type Case } from '@/lib/mockData';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import { demoEmails } from '@/lib/demoEmails';

const getRiskBg = (score: number) =>
  score >= 81 ? 'bg-red-50 border-red-200 text-red-700' :
  score >= 61 ? 'bg-orange-50 border-orange-200 text-orange-700' :
  score >= 41 ? 'bg-yellow-50 border-yellow-200 text-yellow-700' :
  'bg-emerald-50 border-emerald-200 text-emerald-700';

const getStatusStyle = (status: string) => {
  const map: Record<string, string> = {
    new: 'bg-slate-100 text-slate-600',
    investigating: 'bg-yellow-50 text-yellow-700',
    escalated: 'bg-red-50 text-red-700',
    resolved: 'bg-emerald-50 text-emerald-700',
  };
  return map[status] || map.new;
};

const getClassificationStyle = (cls: string) => {
  if (cls.includes('Compromise')) return 'bg-orange-50 text-orange-700';
  if (cls.includes('Phishing')) return 'bg-red-50 text-red-700';
  if (cls.includes('Legitimate')) return 'bg-emerald-50 text-emerald-700';
  if (cls.includes('Suspicious')) return 'bg-yellow-50 text-yellow-700';
  return 'bg-slate-100 text-slate-600';
};

const getClassIcon = (cls: string) => {
  if (cls.includes('Compromise') || cls.includes('Phishing') || cls.includes('Impersonation') || cls.includes('Fraud')) {
    return <Shield className="w-3.5 h-3.5 text-red-500" />;
  }
  if (cls.includes('Legitimate')) return <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />;
  return <Shield className="w-3.5 h-3.5 text-yellow-500" />;
};

function CaseModal({ c, onClose }: { c: Case; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState('overview');
  const result = c.demoId ? mockAnalysisResults[c.demoId] : null;
  const email = c.demoId ? demoEmails.find(d => d.id === c.demoId) : null;

  const tabs = ['Overview', 'Email Content', 'Header Forensics', 'Authentication', 'Indicators', 'Infrastructure', 'Evidence', 'Analyst Notes'];

  const AuthBadge = ({ status }: { status: 'pass' | 'fail' | 'unknown' }) => {
    const map = { pass: 'bg-emerald-50 border-emerald-200 text-emerald-700', fail: 'bg-red-50 border-red-200 text-red-700', unknown: 'bg-slate-50 border-slate-200 text-slate-500' };
    const icons = { pass: <CheckCircle className="w-3 h-3" />, fail: <X className="w-3 h-3" />, unknown: <AlertTriangle className="w-3 h-3" /> };
    return (
      <span className={`inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full border ${map[status]}`}>
        {icons[status]} {status.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-100 flex items-start justify-between">
          <div className="flex items-start gap-4">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${c.riskScore >= 81 ? 'bg-red-100' : 'bg-orange-100'}`}>
              <Shield className={`w-5 h-5 ${c.riskScore >= 81 ? 'text-red-500' : 'text-orange-500'}`} />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <span className="text-xs font-bold font-mono text-slate-500">{c.id}</span>
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
        <div className="flex border-b border-slate-100 overflow-x-auto">
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
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-2 gap-6">
              <div>
                <h3 className="text-sm font-semibold text-slate-700 mb-3">Case Details</h3>
                <div className="space-y-2.5">
                  {[
                    ['Case ID', c.id],
                    ['Classification', c.classification],
                    ['Risk Score', `${c.riskScore}/100`],
                    ['Status', c.status],
                    ['Origin Infrastructure', c.origin],
                    ['Assigned Analyst', c.analyst],
                    ['Timestamp', c.timestamp],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3">
                      <span className="text-xs text-slate-400 w-40 flex-shrink-0 font-medium pt-0.5">{k}</span>
                      <span className="text-sm text-slate-700 font-medium capitalize">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-700 mb-3">Email Metadata</h3>
                <div className="space-y-2.5">
                  {[
                    ['From', c.sender],
                    ['Subject', c.subject],
                    ['Origin', c.origin],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3">
                      <span className="text-xs text-slate-400 w-16 flex-shrink-0 font-medium pt-0.5">{k}</span>
                      <span className="text-sm text-slate-700 font-medium break-all">{v}</span>
                    </div>
                  ))}
                </div>
                {result && (
                  <div className="mt-5">
                    <h3 className="text-sm font-semibold text-slate-700 mb-3">Quick Auth Status</h3>
                    <div className="flex gap-2">
                      <div className="flex flex-col items-center gap-1">
                        <AuthBadge status={result.auth.spf} />
                        <span className="text-xs text-slate-400">SPF</span>
                      </div>
                      <div className="flex flex-col items-center gap-1">
                        <AuthBadge status={result.auth.dkim} />
                        <span className="text-xs text-slate-400">DKIM</span>
                      </div>
                      <div className="flex flex-col items-center gap-1">
                        <AuthBadge status={result.auth.dmarc} />
                        <span className="text-xs text-slate-400">DMARC</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'email-content' && email && (
            <div>
              <pre className="text-sm text-slate-700 whitespace-pre-wrap bg-slate-50 border border-slate-200 rounded-xl p-5 leading-relaxed font-sans">{email.body}</pre>
            </div>
          )}

          {activeTab === 'header-forensics' && email && (
            <pre className="text-xs font-mono bg-[#0f172a] text-green-400 p-5 rounded-xl overflow-x-auto border border-slate-800">{email.rawHeaders}</pre>
          )}

          {activeTab === 'authentication' && result && (
            <div className="space-y-4">
              {[
                { label: 'SPF', status: result.auth.spf, detail: result.auth.spfDetail },
                { label: 'DKIM', status: result.auth.dkim, detail: result.auth.dkimDetail },
                { label: 'DMARC', status: result.auth.dmarc, detail: result.auth.dmarcDetail },
              ].map(card => (
                <div key={card.label} className="border border-slate-200 rounded-xl p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-slate-800">{card.label}</span>
                    <AuthBadge status={card.status} />
                  </div>
                  <p className="text-sm text-slate-500">{card.detail}</p>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'indicators' && result && (
            <div className="space-y-2">
              {result.riskIndicators.map(ri => (
                <div key={ri.id} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg border border-slate-100">
                  <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${ri.severity === 'critical' ? 'bg-red-500' : ri.severity === 'high' ? 'bg-orange-500' : 'bg-yellow-500'}`} />
                  <p className="text-sm text-slate-700 flex-1">{ri.label}</p>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${ri.severity === 'critical' ? 'bg-red-50 border-red-200 text-red-700' : ri.severity === 'high' ? 'bg-orange-50 border-orange-200 text-orange-700' : 'bg-yellow-50 border-yellow-200 text-yellow-700'}`}>{ri.severity}</span>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'infrastructure' && result && (
            <div className="grid grid-cols-2 gap-4">
              <div className="border border-slate-200 rounded-xl p-4">
                <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2"><Server className="w-4 h-4 text-blue-500" />IP Intelligence</h4>
                {[
                  ['IP', result.ipIntel.ip],
                  ['Country', result.ipIntel.country],
                  ['City', result.ipIntel.city],
                  ['ASN', result.ipIntel.asn],
                  ['ISP', result.ipIntel.isp],
                  ['TOR Node', result.ipIntel.isTor ? 'Yes' : 'No'],
                  ['Reputation', result.ipIntel.reputation],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between py-1 border-b border-slate-50 text-sm">
                    <span className="text-slate-400">{k}</span>
                    <span className={`font-medium capitalize ${v === 'malicious' ? 'text-red-600' : v === 'Yes' ? 'text-red-600' : 'text-slate-700'}`}>{v}</span>
                  </div>
                ))}
              </div>
              <div className="border border-slate-200 rounded-xl p-4">
                <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-orange-500" />Probable Infrastructure</h4>
                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 text-center">
                  <div className="text-2xl font-bold text-orange-700 mb-1">{result.ipIntel.city}</div>
                  <div className="text-sm text-orange-600">{result.ipIntel.country}</div>
                  <div className="mt-3 text-sm font-semibold text-orange-700">Confidence: {result.ipIntel.confidenceScore}%</div>
                </div>
                <p className="text-xs text-slate-400 mt-3 leading-relaxed">IP geolocation represents the observed infrastructure and may not represent the physical location of the threat actor.</p>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && result && (
            <div className="space-y-4">
              <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-5">
                <div className="flex items-center gap-2 mb-3">
                  <CheckCircle className="w-5 h-5 text-emerald-600" />
                  <span className="font-semibold text-emerald-700">Evidence Integrity: VERIFIED</span>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  {[
                    ['Evidence ID', `EV-${c.id}`],
                    ['SHA256 Hash', result.evidenceHash],
                    ['Upload Timestamp', c.timestamp],
                    ['Analyst', c.analyst],
                    ['Case ID', c.id],
                    ['Analysis Timestamp', result.analysisTimestamp],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <div className="text-xs text-slate-400 mb-0.5">{k}</div>
                      <div className="font-mono text-xs text-slate-700 break-all">{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'analyst-notes' && (
            <div>
              <textarea placeholder="Add analyst notes here..." className="w-full h-40 p-4 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-700 resize-none focus:outline-none focus:ring-1 focus:ring-blue-500" />
              <button className="mt-3 px-4 py-2 bg-blue-600 text-white text-sm font-semibold rounded-lg hover:bg-blue-700 transition-colors">Save Notes</button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <select className={`text-sm font-medium px-3 py-1.5 rounded-lg border ${getStatusStyle(c.status)}`} defaultValue={c.status}>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="escalated">Escalated</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-1.5 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors">
              <Download className="w-3.5 h-3.5" /> Export
            </button>
            <button className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors">
              <ExternalLink className="w-3.5 h-3.5" /> Full Analysis
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function CasesPage() {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [classFilter, setClassFilter] = useState('all');
  const [selectedCase, setSelectedCase] = useState<Case | null>(null);

  const filtered = mockCases.filter(c => {
    const matchSearch = !search || c.sender.toLowerCase().includes(search.toLowerCase()) || c.subject.toLowerCase().includes(search.toLowerCase()) || c.id.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === 'all' || c.status === statusFilter;
    const matchClass = classFilter === 'all' || c.classification.toLowerCase().includes(classFilter.toLowerCase());
    return matchSearch && matchStatus && matchClass;
  });

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Cases" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">INVESTIGATION QUEUE</div>
            <h1 className="text-2xl font-bold text-slate-800">Cases</h1>
          </div>
          <button className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors">
            <Plus className="w-4 h-4" />
            New case
          </button>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search cases, senders, domains..."
              className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="px-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none pr-8"
          >
            <option value="all">All statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="escalated">Escalated</option>
            <option value="resolved">Resolved</option>
          </select>
          <select
            value={classFilter}
            onChange={e => setClassFilter(e.target.value)}
            className="px-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="all">All classifications</option>
            <option value="compromise">BEC</option>
            <option value="phishing">Phishing</option>
            <option value="legitimate">Legitimate</option>
            <option value="suspicious">Suspicious</option>
          </select>
        </div>

        {/* Table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-100">
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-5 py-3">CASE ID</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">SENDER / SUBJECT</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">CLASSIFICATION</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">RISK</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">ORIGIN</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">STATUS</th>
                <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">TIME</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(c => (
                <tr
                  key={c.id}
                  onClick={() => setSelectedCase(c)}
                  className="border-b border-slate-50 hover:bg-blue-50/30 transition-colors cursor-pointer group"
                >
                  <td className="px-5 py-4">
                    <span className="text-sm text-blue-600 font-medium font-mono group-hover:text-blue-700">{c.id}</span>
                  </td>
                  <td className="px-4 py-4">
                    <div className="text-sm font-medium text-slate-700 truncate max-w-[200px]">{c.sender}</div>
                    <div className="text-xs text-slate-400 truncate max-w-[200px]">{c.subject}</div>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-2">
                      {getClassIcon(c.classification)}
                      <span className={`text-xs font-medium px-2 py-1 rounded-full ${getClassificationStyle(c.classification)}`}>
                        {c.classification}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${getRiskBg(c.riskScore)}`}>
                      ● {c.riskScore}/100
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <div className="flex items-center gap-1.5 text-sm text-slate-600">
                      <MapPin className="w-3 h-3 text-slate-400" />
                      {c.origin}
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    <span className={`text-xs font-medium px-2 py-1 rounded-full capitalize ${getStatusStyle(c.status)}`}>
                      ● {c.status.charAt(0).toUpperCase() + c.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-400">{c.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div className="text-center py-16 text-slate-400">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="font-medium">No cases match your filters</p>
              <p className="text-sm mt-1">Try adjusting your search or filter criteria</p>
            </div>
          )}
        </div>
      </div>

      {selectedCase && <CaseModal c={selectedCase} onClose={() => setSelectedCase(null)} />}
    </div>
  );
}
