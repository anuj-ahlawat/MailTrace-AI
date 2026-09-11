'use client';

import { useState, useEffect } from 'react';
import { Mail, ShieldAlert, Fish, Users, Network, Activity, TrendingUp, TrendingDown, Plus, ArrowRight, MapPin, Clock } from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import Link from 'next/link';
import TopBar from '@/components/TopBar';
import {
  dashboardStats,
  threatActivityData,
  threatDistributionData,
  authFailuresData,
  topMaliciousDomains,
  topSourceCountries,
  mockCases
} from '@/lib/mockData';

const StatCard = ({
  icon,
  label,
  value,
  change,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  change: number;
  color: string;
}) => (
  <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm hover:shadow-md transition-shadow">
    <div className="flex items-center gap-2.5 mb-3">
      <div className={`text-${color}`}>{icon}</div>
      <span className="text-sm text-slate-500 font-medium">{label}</span>
    </div>
    <div className="text-3xl font-bold text-slate-800 mb-1.5">{value}</div>
    <div className={`flex items-center gap-1 text-xs font-medium ${change >= 0 ? 'text-emerald-600' : 'text-red-500'}`}>
      {change >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      {Math.abs(change)}% vs last 30 days
    </div>
  </div>
);

const getRiskColor = (score: number) => {
  if (score >= 81) return 'text-red-600 bg-red-50 border-red-200';
  if (score >= 61) return 'text-orange-600 bg-orange-50 border-orange-200';
  if (score >= 41) return 'text-yellow-600 bg-yellow-50 border-yellow-200';
  return 'text-emerald-600 bg-emerald-50 border-emerald-200';
};

const getStatusColor = (status: string) => {
  const map: Record<string, string> = {
    new: 'text-slate-600 bg-slate-100',
    investigating: 'text-yellow-700 bg-yellow-50',
    escalated: 'text-red-600 bg-red-50',
    resolved: 'text-emerald-700 bg-emerald-50',
  };
  return map[status] || 'text-slate-600 bg-slate-100';
};

const COLORS = ['#ef4444', '#f97316', '#eab308', '#8b5cf6', '#22c55e', '#3b82f6'];

export default function OverviewPage() {
  const [greeting, setGreeting] = useState('Good morning');
  const [userName, setUserName] = useState('Alex');
  const [dateStr, setDateStr] = useState('');

  useEffect(() => {
    const hour = new Date().getHours();
    if (hour < 12) setGreeting('Good morning');
    else if (hour < 17) setGreeting('Good afternoon');
    else setGreeting('Good evening');

    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('mt_user');
      if (stored) {
        const user = JSON.parse(stored);
        setUserName(user.name.split(' ')[0]);
      }
    }

    setDateStr(new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).toUpperCase());
  }, []);

  const recentCases = mockCases.slice(0, 8);

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Overview" />

      <div className="p-6 max-w-[1400px]">
        {/* Header */}
        <div className="flex items-start justify-between mb-7">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">{dateStr}</div>
            <h1 className="text-3xl font-bold text-slate-800 mb-1">
              {greeting}, {userName} <span className="text-yellow-400">✦</span>
            </h1>
            <p className="text-slate-500">Here&apos;s your organization&apos;s threat posture at a glance.</p>
          </div>
          <Link
            href="/analyze"
            className="flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Analyze new email
          </Link>
        </div>

        {/* Stats grid */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <StatCard icon={<Mail className="w-4 h-4" />} label="Emails analyzed" value="1,284" change={dashboardStats.emailsAnalyzedChange} color="blue-500" />
          <StatCard icon={<ShieldAlert className="w-4 h-4" />} label="Critical threats" value="86" change={dashboardStats.criticalThreatsChange} color="red-500" />
          <StatCard icon={<Fish className="w-4 h-4" />} label="Phishing detected" value="214" change={dashboardStats.phishingChange} color="red-400" />
          <StatCard icon={<Users className="w-4 h-4" />} label="BEC detected" value="37" change={dashboardStats.becChange} color="orange-500" />
          <StatCard icon={<Network className="w-4 h-4" />} label="Active campaigns" value="12" change={dashboardStats.activeCampaignsChange} color="purple-500" />
          <StatCard icon={<Activity className="w-4 h-4" />} label="Average risk score" value="42/100" change={dashboardStats.avgRiskScoreChange} color="blue-400" />
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {/* Threat activity area chart */}
          <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-0.5">THREAT ACTIVITY</div>
                <h3 className="text-base font-semibold text-slate-800">Threats over time</h3>
              </div>
              <select className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5">
                <option>Last 30 days</option>
              </select>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={threatActivityData}>
                <defs>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.15} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0', fontSize: 12 }} />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                <Area type="monotone" dataKey="threats" name="Threats detected" stroke="#3b82f6" strokeWidth={2} fill="url(#colorThreats)" dot={false} />
                <Area type="monotone" dataKey="critical" name="Critical" stroke="#f97316" strokeWidth={2} fill="url(#colorCritical)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Distribution donut */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <div className="mb-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-0.5">CLASSIFICATION</div>
              <h3 className="text-base font-semibold text-slate-800">Threat distribution</h3>
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <PieChart>
                <Pie data={threatDistributionData} cx="50%" cy="50%" innerRadius={40} outerRadius={65} paddingAngle={2} dataKey="value">
                  {threatDistributionData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0', fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-1.5 mt-2">
              {threatDistributionData.slice(0, 4).map((item, i) => (
                <div key={item.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[i] }} />
                    <span className="text-slate-600">{item.name}</span>
                  </div>
                  <span className="text-slate-800 font-semibold">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Auth failures + top domains */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <div className="mb-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-0.5">AUTHENTICATION</div>
              <h3 className="text-base font-semibold text-slate-800">Authentication failures (last 7 days)</h3>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <BarChart data={authFailuresData} barSize={10} barGap={2}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ borderRadius: '8px', border: '1px solid #e2e8f0', fontSize: 12 }} />
                <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="spf" name="SPF Fail" fill="#ef4444" radius={[3, 3, 0, 0]} />
                <Bar dataKey="dkim" name="DKIM Fail" fill="#f97316" radius={[3, 3, 0, 0]} />
                <Bar dataKey="dmarc" name="DMARC Fail" fill="#eab308" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <div className="mb-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-0.5">INTELLIGENCE</div>
              <h3 className="text-base font-semibold text-slate-800">Top malicious domains</h3>
            </div>
            <div className="space-y-3">
              {topMaliciousDomains.map((item, i) => (
                <div key={item.domain} className="flex items-center gap-3">
                  <span className="text-xs text-slate-400 font-mono w-4">{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-slate-700 truncate">{item.domain}</div>
                    <div className="w-full h-1.5 bg-slate-100 rounded-full mt-1.5">
                      <div
                        className={`h-1.5 rounded-full ${item.risk === 'critical' ? 'bg-red-500' : 'bg-orange-400'}`}
                        style={{ width: `${(item.count / 25) * 100}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-xs font-semibold text-slate-600">{item.count}</span>
                </div>
              ))}
            </div>

            <div className="mt-5 pt-4 border-t border-slate-100">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Top source countries</div>
              <div className="space-y-2">
                {topSourceCountries.map(item => (
                  <div key={item.country} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <MapPin className="w-3 h-3 text-slate-400" />
                      <span className="text-slate-700">{item.country}</span>
                    </div>
                    <span className="font-semibold text-slate-600">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Recent cases table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <h3 className="text-base font-semibold text-slate-800">Recent Cases</h3>
            <Link href="/cases" className="flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 font-medium transition-colors">
              View all <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-6 py-3">Case ID</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Sender / Subject</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Classification</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Risk</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Origin</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Status</th>
                  <th className="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 py-3">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentCases.map(c => (
                  <tr key={c.id} className="border-b border-slate-50 hover:bg-slate-50 transition-colors cursor-pointer">
                    <td className="px-6 py-3.5">
                      <Link href="/cases" className="text-sm text-blue-600 hover:text-blue-700 font-medium font-mono">{c.id}</Link>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="text-sm text-slate-700 truncate max-w-[220px]">{c.sender}</div>
                      <div className="text-xs text-slate-400 truncate max-w-[220px]">{c.subject}</div>
                    </td>
                    <td className="px-4 py-3.5">
                      <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                        c.classification === 'Business Email Compromise' ? 'bg-orange-50 text-orange-700' :
                        c.classification === 'Credential Phishing' ? 'bg-red-50 text-red-700' :
                        c.classification === 'Legitimate' ? 'bg-emerald-50 text-emerald-700' :
                        'bg-slate-100 text-slate-600'
                      }`}>
                        {c.classification}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <span className={`text-xs font-bold px-2 py-1 rounded-full border ${getRiskColor(c.riskScore)}`}>
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
                      <span className={`text-xs font-medium px-2 py-1 rounded-full capitalize ${getStatusColor(c.status)}`}>
                        {c.status === 'investigating' ? '● Investigating' :
                         c.status === 'escalated' ? '● Escalated' :
                         c.status === 'resolved' ? '● Resolved' : '● New'}
                      </span>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 text-xs text-slate-400">
                        <Clock className="w-3 h-3" />
                        {c.timestamp}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
