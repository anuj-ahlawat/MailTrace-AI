'use client';

import { useState } from 'react';
import { Search, Globe, Server, Link2, AlertTriangle, CheckCircle, Info, ExternalLink, Copy, Shield } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { mockAnalysisResults } from '@/lib/mockAnalysis';

const result = mockAnalysisResults['demo-3'];

type TITab = 'domain' | 'ip' | 'url';

const AuthBadge = ({ status }: { status: 'pass' | 'fail' | 'unknown' }) => {
  const styles = { pass: 'bg-emerald-50 border-emerald-200 text-emerald-700', fail: 'bg-red-50 border-red-200 text-red-700', unknown: 'bg-slate-50 border-slate-200 text-slate-600' };
  return <span className={`text-xs font-bold px-2.5 py-1 rounded-full border uppercase ${styles[status]}`}>{status}</span>;
};

const RepBadge = ({ rep }: { rep: string }) => {
  const styles: Record<string, string> = {
    malicious: 'bg-red-50 border-red-200 text-red-700',
    suspicious: 'bg-orange-50 border-orange-200 text-orange-700',
    unknown: 'bg-slate-50 border-slate-200 text-slate-600',
    clean: 'bg-emerald-50 border-emerald-200 text-emerald-700',
  };
  return <span className={`text-xs font-bold px-2.5 py-1 rounded-full border capitalize ${styles[rep] || styles.unknown}`}>{rep}</span>;
};

export default function ThreatIntelligencePage() {
  const [tab, setTab] = useState<TITab>('domain');
  const [searchVal, setSearchVal] = useState(tab === 'domain' ? result.domainIntel.domain : tab === 'ip' ? result.ipIntel.ip : '');

  const domain = result.domainIntel;
  const ip = result.ipIntel;
  const url = result.urlAnalysis[0];

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Threat Intelligence" />
      <div className="p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">INDICATOR LOOKUP</div>
          <h1 className="text-2xl font-bold text-slate-800">Threat Intelligence</h1>
        </div>

        {/* Search bar */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-6">
          <div className="flex gap-3">
            <div className="flex border border-slate-200 rounded-xl overflow-hidden">
              {([['domain', <Globe className="w-4 h-4" key="g" />], ['ip', <Server className="w-4 h-4" key="s" />], ['url', <Link2 className="w-4 h-4" key="l" />]] as const).map(([t, icon]) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium capitalize transition-colors ${
                    tab === t ? 'bg-blue-600 text-white' : 'text-slate-500 hover:text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  {icon} {t === 'url' ? 'URL' : t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
            <div className="relative flex-1">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                value={searchVal}
                onChange={e => setSearchVal(e.target.value)}
                placeholder={`Enter ${tab === 'url' ? 'URL' : tab} to analyze...`}
                className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <button className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl text-sm transition-colors">
              Analyze
            </button>
          </div>
        </div>

        {/* Domain Intelligence */}
        {tab === 'domain' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-6">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-10 h-10 bg-red-50 border border-red-200 rounded-xl flex items-center justify-center">
                  <Globe className="w-5 h-5 text-red-500" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">DOMAIN ANALYSIS</div>
                  <h3 className="font-bold text-slate-800 font-mono">{domain.domain}</h3>
                </div>
                <RepBadge rep={domain.reputation} />
              </div>

              <div className="grid grid-cols-2 gap-x-8 gap-y-2 mb-5">
                {[
                  ['Registrar', domain.registrar],
                  ['Registration Date', domain.registrationDate],
                  ['Domain Age', `${domain.domainAgeDays} days`],
                  ['Expiry Date', domain.expiryDate],
                  ['Resolved IP', domain.resolvedIp],
                  ['ASN', domain.asn],
                  ['Hosting', domain.hostingProvider],
                  ['Country', domain.country],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between py-2 border-b border-slate-50 text-sm">
                    <span className="text-slate-400 font-medium">{k}</span>
                    <span className="text-slate-700 font-medium">{v}</span>
                  </div>
                ))}
              </div>

              <div className="mb-4">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Name Servers</div>
                <div className="flex flex-wrap gap-2">
                  {domain.nameServers.map(ns => <span key={ns} className="text-xs font-mono bg-slate-50 border border-slate-200 px-2 py-1 rounded-lg text-slate-600">{ns}</span>)}
                </div>
              </div>

              {domain.brandSimilarity && (
                <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    <span className="text-sm font-bold text-red-700">Brand Similarity Analysis</span>
                  </div>
                  <div className="flex items-center gap-4 mb-2 text-sm font-mono">
                    <span className="text-slate-700">{domain.brandSimilarity.originalDomain}</span>
                    <span className="text-slate-400">vs</span>
                    <span className="text-red-700 font-bold">{domain.domain}</span>
                  </div>
                  <div className="flex items-center gap-3 mb-2">
                    <div className="flex-1 h-2 bg-white rounded-full border border-red-200">
                      <div className="h-full bg-red-500 rounded-full" style={{ width: `${domain.brandSimilarity.similarityScore}%` }} />
                    </div>
                    <span className="text-red-700 font-bold">{domain.brandSimilarity.similarityScore}%</span>
                  </div>
                  <p className="text-xs text-red-600 font-medium">{domain.brandSimilarity.classification}</p>
                </div>
              )}
            </div>

            {/* Risk panel */}
            <div className="space-y-4">
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">RISK ASSESSMENT</div>
                <div className="text-center py-4">
                  <div className="text-5xl font-bold text-red-600 mb-2">87</div>
                  <div className="text-sm text-slate-500 mb-3">Risk Score</div>
                  <RepBadge rep="malicious" />
                </div>
              </div>
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">THREAT FLAGS</div>
                <div className="space-y-2">
                  {[
                    { flag: 'Newly registered domain', severe: true },
                    { flag: 'Bulletproof hosting', severe: true },
                    { flag: 'Zero SPF record', severe: true },
                    { flag: 'Brand impersonation', severe: true },
                    { flag: 'Malicious campaign association', severe: true },
                  ].map(({ flag, severe }) => (
                    <div key={flag} className="flex items-center gap-2">
                      <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severe ? 'bg-red-500' : 'bg-yellow-400'}`} />
                      <span className="text-xs text-slate-600">{flag}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* IP Intelligence */}
        {tab === 'ip' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-6">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-10 h-10 bg-orange-50 border border-orange-200 rounded-xl flex items-center justify-center">
                  <Server className="w-5 h-5 text-orange-500" />
                </div>
                <div>
                  <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">IP INTELLIGENCE</div>
                  <h3 className="font-bold text-slate-800 font-mono">{ip.ip}</h3>
                </div>
                <RepBadge rep={ip.reputation} />
              </div>

              <div className="grid grid-cols-2 gap-x-8 gap-y-2 mb-5">
                {[
                  ['Country', ip.country],
                  ['Region', ip.region],
                  ['City', ip.city],
                  ['ASN', ip.asn],
                  ['ISP', ip.isp],
                  ['Hosting', ip.hostingProvider],
                  ['Reverse DNS', ip.reverseDns],
                  ['Reputation', ip.reputation],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between py-2 border-b border-slate-50 text-sm">
                    <span className="text-slate-400 font-medium">{k}</span>
                    <span className={`font-medium capitalize ${v === 'malicious' ? 'text-red-600' : v === 'suspicious' ? 'text-orange-600' : 'text-slate-700'}`}>{v}</span>
                  </div>
                ))}
              </div>

              {/* Indicators */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'Proxy/VPN', value: ip.isVpn ? 'Detected' : 'Not Detected', bad: ip.isVpn },
                  { label: 'TOR Node', value: ip.isTor ? 'Detected' : 'Not Detected', bad: ip.isTor },
                  { label: 'Open Proxy', value: ip.isProxy ? 'Detected' : 'Not Detected', bad: ip.isProxy },
                ].map(({ label, value, bad }) => (
                  <div key={label} className={`p-3 rounded-xl border text-center ${bad ? 'bg-red-50 border-red-200' : 'bg-emerald-50 border-emerald-200'}`}>
                    <div className="text-xs text-slate-500 mb-1">{label}</div>
                    <div className={`text-sm font-bold ${bad ? 'text-red-700' : 'text-emerald-700'}`}>{value}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-4">
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">PROBABLE INFRASTRUCTURE</div>
                <div className="text-center py-4">
                  <div className="text-2xl font-bold text-slate-800 mb-1">{ip.city}</div>
                  <div className="text-sm text-slate-500 mb-2">{ip.country}</div>
                  <div className="inline-block bg-blue-50 border border-blue-200 text-blue-700 px-3 py-1.5 rounded-lg text-sm font-semibold">
                    {ip.confidenceScore}% Confidence
                  </div>
                  <p className="text-xs text-slate-400 mt-3 leading-relaxed">
                    IP geolocation represents observed infrastructure and may not reflect the threat actor&apos;s physical location.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* URL Intelligence */}
        {tab === 'url' && url && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 bg-red-50 border border-red-200 rounded-xl flex items-center justify-center">
                <Link2 className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">URL ANALYSIS</div>
                <h3 className="font-bold text-slate-800 text-sm font-mono truncate max-w-xl">{url.displayedUrl}</h3>
              </div>
              <RepBadge rep={url.reputation} />
            </div>

            {url.deception && (
              <div className="mb-5 flex items-start gap-2.5 bg-red-50 border border-red-200 rounded-xl px-5 py-4">
                <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-700 font-medium">Displayed URL does not match destination. Potential URL deception / hyperlink spoofing detected.</p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-4 mb-5">
              <div>
                <div className="text-xs text-slate-400 font-medium mb-1">Displayed URL</div>
                <div className="font-mono text-xs bg-slate-50 px-3 py-2 rounded-lg border border-slate-200 text-slate-700 break-all">{url.displayedUrl}</div>
              </div>
              <div>
                <div className="text-xs text-slate-400 font-medium mb-1">Actual Destination</div>
                <div className="font-mono text-xs bg-red-50 px-3 py-2 rounded-lg border border-red-200 text-red-700 break-all">{url.actualUrl}</div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-3">
              {[
                { l: 'HTTPS', v: url.httpsEnabled ? 'Yes' : 'No', ok: url.httpsEnabled },
                { l: 'Redirect Count', v: String(url.redirectCount), ok: url.redirectCount === 0 },
                { l: 'URL Length', v: String(url.urlLength), ok: url.urlLength < 80 },
                { l: 'Encoded Chars', v: url.hasEncodedChars ? 'Yes' : 'No', ok: !url.hasEncodedChars },
                { l: 'Suspicious TLD', v: url.suspiciousTld ? 'Yes' : 'No', ok: !url.suspiciousTld },
                { l: 'Brand Similarity', v: `${url.lookalikeSimilarity}%`, ok: url.lookalikeSimilarity < 50 },
                { l: 'Reputation', v: url.reputation, ok: url.reputation === 'clean' },
                { l: 'Risk Score', v: `${url.riskScore}/100`, ok: url.riskScore < 30 },
              ].map(({ l, v, ok }) => (
                <div key={l} className={`p-3 rounded-xl border ${ok ? 'bg-emerald-50 border-emerald-100' : 'bg-red-50 border-red-100'}`}>
                  <div className="text-[10px] text-slate-500 uppercase tracking-wider font-medium">{l}</div>
                  <div className={`text-sm font-bold mt-0.5 capitalize ${ok ? 'text-emerald-700' : 'text-red-700'}`}>{v}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
