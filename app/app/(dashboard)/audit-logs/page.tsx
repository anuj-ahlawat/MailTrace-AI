'use client';

import { useState, useEffect, useCallback } from 'react';
import { Search, CheckCircle, AlertTriangle, Activity, Clock, User, Filter, Download, RefreshCw } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { auditAPI, type AuditLog } from '@/lib/api';
import { mockAuditLogs } from '@/lib/mockData';

type ActionFilter = 'all' | 'login' | 'analysis' | 'case' | 'report';

const getResultStyle = (result: string) => {
  switch ((result || '').toLowerCase()) {
    case 'success': return 'bg-emerald-50 border-emerald-200 text-emerald-700';
    case 'escalated': return 'bg-red-50 border-red-200 text-red-700';
    case 'investigating': return 'bg-yellow-50 border-yellow-200 text-yellow-700';
    case 'failed': return 'bg-red-50 border-red-200 text-red-700';
    default: return 'bg-slate-50 border-slate-200 text-slate-600';
  }
};

const getActionCategory = (action: string): ActionFilter => {
  const a = action.toLowerCase();
  if (a.includes('login') || a.includes('logout')) return 'login';
  if (a.includes('analysis') || a.includes('upload') || a.includes('email')) return 'analysis';
  if (a.includes('case')) return 'case';
  if (a.includes('report')) return 'report';
  return 'all';
};

interface NormalizedLog {
  id: string;
  timestamp: string;
  user: string;
  role?: string;
  action: string;
  caseId: string;
  ip: string;
  result: string;
  resource?: string;
}

function normalizeApiLogs(logs: AuditLog[]): NormalizedLog[] {
  return logs.map(l => ({
    id: l.id,
    timestamp: new Date(l.timestamp).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    user: l.user_email?.split('@')[0] || 'unknown',
    role: l.user_role,
    action: l.action,
    caseId: l.case_id || '-',
    ip: l.ip_address || '—',
    result: l.result || 'Success',
    resource: l.resource,
  }));
}

function normalizeMockLogs(): NormalizedLog[] {
  return mockAuditLogs.map(l => ({
    id: l.id,
    timestamp: l.timestamp,
    user: l.user,
    action: l.action,
    caseId: l.caseId,
    ip: l.ip,
    result: l.result,
  }));
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<NormalizedLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState<ActionFilter>('all');
  const [isLive, setIsLive] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const PER_PAGE = 50;

  const loadLogs = useCallback(async () => {
    setRefreshing(true);
    try {
      const data = await auditAPI.list(page * PER_PAGE, PER_PAGE);
      const normalized = normalizeApiLogs(data.logs || []);
      if (normalized.length > 0) {
        setLogs(normalized);
        setTotal(data.total || normalized.length);
        setIsLive(true);
      } else {
        throw new Error('No logs');
      }
    } catch {
      setLogs(normalizeMockLogs());
      setTotal(mockAuditLogs.length);
      setIsLive(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [page]);

  useEffect(() => { loadLogs(); }, [loadLogs]);

  const filtered = logs.filter(log => {
    const matchSearch = !search || 
      log.user.includes(search.toLowerCase()) || 
      log.action.toLowerCase().includes(search.toLowerCase()) || 
      log.caseId.includes(search) ||
      log.ip.includes(search);
    const matchAction = actionFilter === 'all' || getActionCategory(log.action) === actionFilter;
    return matchSearch && matchAction;
  });

  const stats = {
    total: total,
    todayLogins: logs.filter(l => l.action.toLowerCase().includes('login')).length,
    caseChanges: logs.filter(l => l.action.toLowerCase().includes('case')).length,
    reports: logs.filter(l => l.action.toLowerCase().includes('report')).length,
  };

  const initials = (name: string) => name.split('.').map(n => n[0]?.toUpperCase() || '').join('').slice(0, 2);

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Audit Logs" />
      <div className="p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-6">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">GOVERNANCE & COMPLIANCE</div>
            <h1 className="text-2xl font-bold text-slate-800">
              Audit Logs
              <span className={`ml-3 text-sm px-2 py-0.5 rounded-full font-semibold ${isLive ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                {isLive ? '● LIVE' : '● DEMO'}
              </span>
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={loadLogs} disabled={refreshing} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
              <Download className="w-3.5 h-3.5" />
              Export CSV
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Total Events', value: total.toLocaleString(), icon: <Activity className="w-4 h-4 text-blue-500" /> },
            { label: 'Login Events', value: String(stats.todayLogins), icon: <User className="w-4 h-4 text-emerald-500" /> },
            { label: 'Case Changes', value: String(stats.caseChanges), icon: <AlertTriangle className="w-4 h-4 text-orange-500" /> },
            { label: 'Reports Generated', value: String(stats.reports), icon: <CheckCircle className="w-4 h-4 text-purple-500" /> },
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

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          {/* Action type filter */}
          <div className="flex items-center gap-1.5">
            {(['all', 'login', 'analysis', 'case', 'report'] as ActionFilter[]).map(f => (
              <button
                key={f}
                onClick={() => setActionFilter(f)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${
                  actionFilter === f ? 'bg-blue-600 text-white' : 'bg-white border border-slate-200 text-slate-600 hover:border-blue-300'
                }`}
              >
                {f === 'all' ? 'All events' : f}
              </button>
            ))}
          </div>

          {/* Search */}
          <div className="relative ml-auto">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search logs..."
              className="w-full pl-10 pr-4 py-2 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 w-64"
            />
          </div>

          <button className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
            <Filter className="w-4 h-4" />
            Date Range
          </button>
        </div>

        {/* Table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                {['Timestamp', 'User', 'Action', 'Resource', 'Case', 'IP Address', 'Result'].map(col => (
                  <th key={col} className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-5 py-3">{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                [...Array(8)].map((_, i) => (
                  <tr key={i} className="border-b border-slate-50">
                    {[...Array(7)].map((_, j) => <td key={j} className="px-5 py-4"><div className="h-3 bg-slate-100 rounded animate-pulse" /></td>)}
                  </tr>
                ))
              ) : filtered.length > 0 ? filtered.map(log => (
                <tr key={log.id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3 h-3 text-slate-300" />
                      <span className="text-xs font-mono text-slate-500">{log.timestamp}</span>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 bg-blue-600 rounded-full flex items-center justify-center text-white text-[10px] font-bold flex-shrink-0">
                        {initials(log.user)}
                      </div>
                      <div>
                        <div className="text-xs font-medium text-slate-700">{log.user}</div>
                        {log.role && <div className="text-[10px] text-slate-400">{log.role}</div>}
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="text-sm text-slate-700">{log.action}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="text-xs text-slate-400 font-mono">{log.resource || '—'}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`text-xs font-mono ${log.caseId !== '-' ? 'text-blue-600 font-medium' : 'text-slate-400'}`}>{log.caseId}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="text-xs font-mono text-slate-500">{log.ip}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${getResultStyle(log.result)}`}>
                      {log.result}
                    </span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={7} className="px-5 py-12 text-center text-slate-400">
                    No audit logs match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Showing {filtered.length} of {total} events</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50 disabled:opacity-40">← Previous</button>
              <button className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded-lg font-medium">{page + 1}</button>
              <button onClick={() => setPage(p => p + 1)} disabled={(page + 1) * PER_PAGE >= total} className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50 disabled:opacity-40">Next →</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
