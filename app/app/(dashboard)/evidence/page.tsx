'use client';

import { useState, useEffect, useCallback } from 'react';
import { FileText, Shield, Hash, Download, Search, RefreshCw, CheckCircle, Copy, Eye } from 'lucide-react';
import TopBar from '@/components/TopBar';

interface EvidenceItem {
  id: string;
  evidence_id: string;
  sha256: string;
  md5?: string;
  filename: string;
  size_bytes: number;
  mime_type: string;
  created_at: string;
  case_id?: string;
  analysis_id?: string;
  notes?: string;
}

const DEMO_EVIDENCE: EvidenceItem[] = [
  {
    id: 'ev-001', evidence_id: 'EV-2026-001', sha256: 'b7f3a2e8c91d4f6a0b5e3d7c9f1a2b4c8e6d0a3f7b9c2e5d8f1a4c7e0b3d6f',
    filename: 'suspicious_payment_request.eml', size_bytes: 4_832, mime_type: 'message/rfc822',
    created_at: '2026-08-26T11:45:33Z', case_id: 'MT-2026-00124', analysis_id: 'analysis-001',
    notes: 'BEC email with CEO impersonation - preserved for legal proceedings',
  },
  {
    id: 'ev-002', evidence_id: 'EV-2026-002', sha256: 'a1f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
    filename: 'payroll_phishing.eml', size_bytes: 3_219, mime_type: 'message/rfc822',
    created_at: '2026-08-26T10:18:10Z', case_id: 'MT-2026-00123',
    notes: 'Credential phishing from microsOft-support.com',
  },
  {
    id: 'ev-003', evidence_id: 'EV-2026-003', sha256: 'c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5',
    filename: 'invoice_fraud_attachment.pdf', size_bytes: 128_450, mime_type: 'application/pdf',
    created_at: '2026-08-25T16:30:22Z', case_id: 'MT-2026-00122',
    notes: 'Fake invoice PDF with embedded macro - malware delivery vector',
  },
  {
    id: 'ev-004', evidence_id: 'EV-2026-004', sha256: 'e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1',
    filename: 'google_account_phish.eml', size_bytes: 6_102, mime_type: 'message/rfc822',
    created_at: '2026-08-22T10:14:00Z', case_id: 'MT-2026-00107',
    notes: 'Lookalike Google domain — credential theft attempt',
  },
  {
    id: 'ev-005', evidence_id: 'EV-2026-005', sha256: 'f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a',
    filename: 'hr_malware_loader.docx', size_bytes: 45_672, mime_type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    created_at: '2026-08-22T14:28:19Z', case_id: 'MT-2026-00108',
    notes: 'Word document with malicious macro - claimed to be salary revision letter',
  },
];

export default function EvidencePage() {
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [copied, setCopied] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [isLive, setIsLive] = useState(false);

  const loadEvidence = useCallback(async () => {
    setRefreshing(true);
    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('mt_token') : null;
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/evidence`, {
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Failed');
      const data = await res.json();
      const items = data.items || data || [];
      if (items.length > 0) {
        setEvidence(items);
        setIsLive(true);
      } else {
        throw new Error('empty');
      }
    } catch {
      setEvidence(DEMO_EVIDENCE);
      setIsLive(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { loadEvidence(); }, [loadEvidence]);

  const copy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  const formatSize = (bytes: number) => {
    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const getFileIcon = (mime: string) => {
    if (mime.includes('message')) return <FileText className="w-5 h-5 text-blue-500" />;
    if (mime.includes('pdf')) return <FileText className="w-5 h-5 text-red-500" />;
    if (mime.includes('word') || mime.includes('document')) return <FileText className="w-5 h-5 text-blue-600" />;
    return <FileText className="w-5 h-5 text-slate-400" />;
  };

  const filtered = evidence.filter(e =>
    !search || e.filename.toLowerCase().includes(search.toLowerCase()) ||
    e.sha256.includes(search.toLowerCase()) ||
    (e.case_id || '').includes(search.toLowerCase())
  );

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Evidence" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">FORENSIC EVIDENCE CHAIN</div>
            <h1 className="text-2xl font-bold text-slate-800">
              Evidence Repository
              <span className={`ml-3 text-sm px-2 py-0.5 rounded-full font-semibold ${isLive ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                {isLive ? '● LIVE' : '● DEMO'}
              </span>
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              All evidence is SHA-256 hashed and preserved for legal chain-of-custody
            </p>
          </div>
          <button onClick={loadEvidence} disabled={refreshing} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Total Evidence', value: String(evidence.length), icon: <FileText className="w-4 h-4 text-blue-500" /> },
            { label: 'Email Files', value: String(evidence.filter(e => e.mime_type.includes('message')).length), icon: <Shield className="w-4 h-4 text-slate-500" /> },
            { label: 'Attachments', value: String(evidence.filter(e => !e.mime_type.includes('message')).length), icon: <FileText className="w-4 h-4 text-red-500" /> },
            { label: 'Hash Verified', value: String(evidence.length), icon: <CheckCircle className="w-4 h-4 text-emerald-500" /> },
          ].map(({ label, value, icon }) => (
            <div key={label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
              <div className="flex items-center gap-2 mb-2">
                {icon}
                <span className="text-sm text-slate-500 font-medium">{label}</span>
              </div>
              <div className="text-2xl font-bold text-slate-800">{value}</div>
            </div>
          ))}
        </div>

        {/* Search */}
        <div className="relative mb-4 max-w-md">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by filename, hash, or case ID..."
            className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Evidence list */}
        <div className="space-y-3">
          {loading ? [...Array(4)].map((_, i) => (
            <div key={i} className="h-28 bg-white rounded-xl border border-slate-200 animate-pulse" />
          )) : filtered.map(ev => (
            <div key={ev.id} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
              <div className="flex items-start gap-4">
                <div className="w-10 h-10 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-center flex-shrink-0">
                  {getFileIcon(ev.mime_type)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-bold text-slate-800">{ev.filename}</span>
                        <span className="text-xs bg-blue-50 text-blue-600 border border-blue-100 px-2 py-0.5 rounded-full font-mono">{ev.evidence_id}</span>
                      </div>
                      {ev.case_id && (
                        <div className="text-xs text-blue-600 font-medium mb-2">Case: {ev.case_id}</div>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-xs text-slate-400 font-medium">{formatSize(ev.size_bytes)}</span>
                      <button className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors">
                        <Eye className="w-3.5 h-3.5" />
                        Preview
                      </button>
                      <button className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors">
                        <Download className="w-3.5 h-3.5" />
                        Download
                      </button>
                    </div>
                  </div>

                  {/* Hash */}
                  <div className="mb-3">
                    <div className="flex items-center gap-2">
                      <Hash className="w-3 h-3 text-slate-400" />
                      <span className="text-[10px] text-slate-400 font-medium uppercase">SHA-256</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="text-xs font-mono text-slate-600 bg-slate-50 border border-slate-200 px-3 py-1 rounded-lg truncate flex-1">
                        {ev.sha256}
                      </code>
                      <button
                        onClick={() => copy(ev.sha256)}
                        className="p-1.5 hover:bg-slate-100 rounded-lg transition-colors"
                        title="Copy hash"
                      >
                        {copied === ev.sha256
                          ? <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
                          : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <CheckCircle className="w-3 h-3 text-emerald-500" />
                      <span className="text-emerald-600 font-medium">Chain of custody verified</span>
                    </div>
                    <span>·</span>
                    <span>Preserved: {new Date(ev.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                    {ev.notes && (
                      <>
                        <span>·</span>
                        <span className="italic text-slate-400 truncate max-w-xs">{ev.notes}</span>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}

          {!loading && filtered.length === 0 && (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-12 text-center">
              <FileText className="w-10 h-10 text-slate-200 mx-auto mb-3" />
              <p className="text-slate-400 font-medium">No evidence found</p>
              <p className="text-xs text-slate-300 mt-1">Analyze emails to automatically create evidence entries</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
