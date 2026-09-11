'use client';

import { useState } from 'react';
import { Search, CheckCircle, AlertTriangle, Filter } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { mockAuditLogs } from '@/lib/mockData';

export default function AuditLogsPage() {
  const [search, setSearch] = useState('');

  const filtered = mockAuditLogs.filter(log =>
    !search || log.user.includes(search) || log.action.toLowerCase().includes(search.toLowerCase()) || log.caseId.includes(search)
  );

  const getResultStyle = (result: string) =>
    ['Success', 'Escalated', 'Investigating'].includes(result) && result === 'Success'
      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
      : result === 'Escalated'
      ? 'bg-red-50 border-red-200 text-red-700'
      : 'bg-yellow-50 border-yellow-200 text-yellow-700';

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Audit Logs" />
      <div className="p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">GOVERNANCE & COMPLIANCE</div>
          <h1 className="text-2xl font-bold text-slate-800">Audit Logs</h1>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          {[
            { label: 'Total Events', value: '1,247', trend: '+12 today' },
            { label: 'Analyst Actions', value: '89', trend: 'Last 24h' },
            { label: 'Case Changes', value: '34', trend: 'Last 24h' },
            { label: 'Reports Generated', value: '12', trend: 'This month' },
          ].map(({ label, value, trend }) => (
            <div key={label} className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
              <div className="text-2xl font-bold text-slate-800 mb-0.5">{value}</div>
              <div className="text-sm text-slate-500">{label}</div>
              <div className="text-xs text-blue-500 font-medium mt-1">{trend}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search logs by user, action, or case ID..."
              className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <button className="flex items-center gap-2 px-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 hover:bg-slate-50 transition-colors">
            <Filter className="w-4 h-4" /> Filters
          </button>
        </div>

        {/* Table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                {['Timestamp', 'User', 'Action', 'Case', 'IP Address', 'Result'].map(col => (
                  <th key={col} className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-5 py-3">{col}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(log => (
                <tr key={log.id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3.5">
                    <span className="text-xs font-mono text-slate-500">{log.timestamp}</span>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 bg-blue-600 rounded-full flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
                        {log.user.split('.').map((n: string) => n[0].toUpperCase()).join('')}
                      </div>
                      <span className="text-sm text-slate-700">{log.user}</span>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <span className="text-sm text-slate-700">{log.action}</span>
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
              ))}
            </tbody>
          </table>

          <div className="px-5 py-3 border-t border-slate-100 flex items-center justify-between">
            <span className="text-xs text-slate-400">Showing {filtered.length} of {mockAuditLogs.length} events</span>
            <div className="flex items-center gap-2">
              <button className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50">← Previous</button>
              <button className="px-3 py-1.5 text-xs bg-blue-600 text-white rounded-lg font-medium">1</button>
              <button className="px-3 py-1.5 text-xs border border-slate-200 rounded-lg text-slate-500 hover:bg-slate-50">Next →</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
