'use client';

import { ExternalLink, Server, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import TopBar from '@/components/TopBar';
import { mockAnalysisResults } from '@/lib/mockAnalysis';
import Link from 'next/link';

const result = mockAnalysisResults['demo-3'];
const hops = result.relayPath;

const confidenceStyle: Record<string, string> = {
  low: 'bg-red-50 border-red-200 text-red-700',
  observed: 'bg-blue-50 border-blue-200 text-blue-700',
  trusted: 'bg-emerald-50 border-emerald-200 text-emerald-700',
};

const hopIcon = (confidence: string) => {
  if (confidence === 'trusted') return <CheckCircle className="w-4 h-4 text-emerald-600" />;
  if (confidence === 'observed') return <Info className="w-4 h-4 text-blue-500" />;
  return <AlertTriangle className="w-4 h-4 text-red-500" />;
};

export default function RouteTracePage() {
  return (
    <div className="pt-14">
      <TopBar breadcrumb="Route Trace" />
      <div className="p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">INFRASTRUCTURE ANALYSIS</div>
          <h1 className="text-2xl font-bold text-slate-800">Route Trace</h1>
        </div>

        {/* Banner */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-6 flex items-start gap-5">
          <div className="w-14 h-14 bg-blue-50 border border-blue-100 rounded-xl flex items-center justify-center flex-shrink-0">
            <Server className="w-7 h-7 text-blue-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-base font-bold text-slate-800 mb-1">Observed email transmission path</h2>
            <p className="text-sm text-slate-500 leading-relaxed">
              Reconstruct the observed relay path without overstating attribution. The selected demo case{' '}
              <span className="font-bold text-slate-700">MT-2026-00124</span> is ready to explore with realistic prototype evidence.
            </p>
          </div>
          <Link href="/cases" className="flex items-center gap-1.5 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors flex-shrink-0">
            Open linked case <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-3 gap-6">
          {/* Timeline */}
          <div className="col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-6">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-6">EMAIL RELAY TIMELINE</div>

            <div className="relative">
              {hops.map((hop, i) => (
                <div key={i} className="flex gap-6 mb-8 last:mb-0 relative">
                  {/* Vertical line */}
                  {i < hops.length - 1 && (
                    <div className="absolute left-[3.75rem] top-14 bottom-[-2rem] w-px border-l-2 border-dashed border-slate-200" />
                  )}

                  {/* Timestamp */}
                  <div className="w-20 text-right flex-shrink-0 pt-2">
                    <span className="text-xs font-mono text-slate-400 font-semibold">{hop.timestamp}</span>
                  </div>

                  {/* Icon */}
                  <div className="relative z-10 flex-shrink-0">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center border-2 ${
                      hop.confidence === 'trusted' ? 'bg-emerald-50 border-emerald-200' :
                      hop.confidence === 'observed' ? 'bg-blue-50 border-blue-200' :
                      'bg-red-50 border-red-200'
                    }`}>
                      <Server className={`w-4 h-4 ${
                        hop.confidence === 'trusted' ? 'text-emerald-600' :
                        hop.confidence === 'observed' ? 'text-blue-500' :
                        'text-red-500'
                      }`} />
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 bg-slate-50 rounded-xl p-4 border border-slate-100">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <div className="font-semibold text-slate-800 mb-0.5">{hop.label}</div>
                        <div className="text-xs text-slate-500 font-mono">
                          {hop.ip} · {hop.location}
                        </div>
                      </div>
                      <span className={`text-xs font-medium px-2.5 py-1 rounded-full border capitalize ${confidenceStyle[hop.confidence]}`}>
                        {hop.confidence === 'low' ? '● Low confidence' : hop.confidence === 'observed' ? '● Observed' : '● Trusted relay'}
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 font-mono">{hop.hostname}</div>
                    {hop.notes && (
                      <div className="mt-2 flex items-start gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-orange-500 mt-0.5 flex-shrink-0" />
                        <p className="text-xs text-orange-600">{hop.notes}</p>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Side panel */}
          <div className="space-y-4">
            {/* Probable origin */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">PROBABLE INFRASTRUCTURE</div>
              <div className="text-center py-4">
                <div className="text-3xl font-bold text-slate-800 mb-1">{result.ipIntel.city}</div>
                <div className="text-sm text-slate-500 mb-3">{result.ipIntel.country}</div>
                <div className="inline-flex items-center gap-2 bg-blue-50 border border-blue-200 text-blue-700 px-3 py-1.5 rounded-lg text-sm font-semibold">
                  Confidence: {result.ipIntel.confidenceScore}%
                </div>
                <p className="text-xs text-slate-400 mt-4 leading-relaxed">
                  IP geolocation represents the observed infrastructure and may not represent the physical location of the threat actor.
                </p>
              </div>
            </div>

            {/* Hops summary */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">PATH SUMMARY</div>
              <div className="space-y-3">
                {hops.map((hop, i) => (
                  <div key={i} className="flex items-center gap-2.5">
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                      hop.confidence === 'trusted' ? 'bg-emerald-100 text-emerald-700' :
                      hop.confidence === 'observed' ? 'bg-blue-100 text-blue-700' :
                      'bg-red-100 text-red-700'
                    }`}>{i + 1}</div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-slate-700 truncate">{hop.label}</div>
                      <div className="text-xs text-slate-400">{hop.location}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Legend */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">CONFIDENCE LEGEND</div>
              <div className="space-y-2.5">
                {[
                  { label: 'Low confidence', sub: 'Probable but unverified', color: 'bg-red-50 border-red-200 text-red-700' },
                  { label: 'Observed', sub: 'Confirmed in headers', color: 'bg-blue-50 border-blue-200 text-blue-700' },
                  { label: 'Trusted relay', sub: 'Known mail infrastructure', color: 'bg-emerald-50 border-emerald-200 text-emerald-700' },
                ].map(item => (
                  <div key={item.label} className="flex items-center gap-2.5">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${item.color}`}>●</span>
                    <div>
                      <div className="text-xs font-medium text-slate-700">{item.label}</div>
                      <div className="text-xs text-slate-400">{item.sub}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
