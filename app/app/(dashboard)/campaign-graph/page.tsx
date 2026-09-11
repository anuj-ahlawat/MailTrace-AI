'use client';

import { useState, useCallback, useEffect } from 'react';
import TopBar from '@/components/TopBar';
import { ExternalLink, Globe, Server, Mail, Shield, AlertTriangle, Info } from 'lucide-react';
import Link from 'next/link';

// ─── Types ─────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  type: 'ip' | 'domain' | 'email' | 'campaign' | 'case';
  label: string;
  subLabel: string;
  x: number;
  y: number;
  color: string;
  selected?: boolean;
}

interface GraphEdge {
  from: string;
  to: string;
}

interface NodeDetail {
  reputation?: string;
  similarity?: string;
  firstObserved?: string;
  relatedCases?: string;
}

// ─── Graph Data ────────────────────────────────────────────────────────────

const initialNodes: GraphNode[] = [
  { id: 'ip1', type: 'ip', label: '185.231.72.12', subLabel: 'IP · Singapore', x: 180, y: 320, color: '#f97316' },
  { id: 'domain1', type: 'domain', label: 'micros0ft-secure.com', subLabel: 'Domain', x: 400, y: 200, color: '#ef4444' },
  { id: 'domain2', type: 'domain', label: 'sbi-verification.net', subLabel: 'Related domain', x: 620, y: 180, color: '#ef4444' },
  { id: 'case1', type: 'case', label: 'MT-2026-00124', subLabel: 'Email case', x: 490, y: 390, color: '#3b82f6' },
  { id: 'case2', type: 'case', label: 'MT-2026-00118', subLabel: 'Email case', x: 680, y: 360, color: '#3b82f6' },
  { id: 'campaign1', type: 'campaign', label: 'BEC-2026-07', subLabel: 'Campaign', x: 580, y: 520, color: '#8b5cf6' },
  { id: 'ip2', type: 'ip', label: '104.18.24.10', subLabel: 'IP · Frankfurt', x: 240, y: 480, color: '#f97316' },
];

const edges: GraphEdge[] = [
  { from: 'ip1', to: 'domain1' },
  { from: 'ip1', to: 'domain2' },
  { from: 'ip2', to: 'domain1' },
  { from: 'domain1', to: 'case1' },
  { from: 'domain2', to: 'case2' },
  { from: 'case1', to: 'campaign1' },
  { from: 'case2', to: 'campaign1' },
];

const nodeDetails: Record<string, NodeDetail> = {
  domain1: { reputation: 'Malicious', similarity: '91%', firstObserved: 'Aug 26, 2026', relatedCases: '2 cases' },
  domain2: { reputation: 'Malicious', similarity: '78%', firstObserved: 'Aug 20, 2026', relatedCases: '1 case' },
  ip1: { reputation: 'Suspicious', firstObserved: 'Aug 23, 2026', relatedCases: '3 cases' },
  ip2: { reputation: 'Suspicious', firstObserved: 'Aug 25, 2026', relatedCases: '2 cases' },
  case1: { relatedCases: 'MT-2026-00124' },
  case2: { relatedCases: 'MT-2026-00118' },
  campaign1: { firstObserved: 'Aug 20, 2026', relatedCases: '4 cases' },
};

const NODE_ICONS: Record<string, React.ReactNode> = {
  ip: <Server className="w-5 h-5" />,
  domain: <Globe className="w-5 h-5" />,
  email: <Mail className="w-5 h-5" />,
  case: <Mail className="w-5 h-5" />,
  campaign: <Shield className="w-5 h-5" />,
};

// ─── Simple SVG Graph ─────────────────────────────────────────────────────

function CampaignGraph({ nodes, edges, selected, onSelect }: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const [dragging, setDragging] = useState<string | null>(null);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>(
    Object.fromEntries(nodes.map(n => [n.id, { x: n.x, y: n.y }]))
  );
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  const handleMouseDown = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    const pos = positions[id];
    setDragging(id);
    setDragOffset({ x: e.clientX - pos.x, y: e.clientY - pos.y });
  };

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!dragging) return;
    setPositions(prev => ({
      ...prev,
      [dragging]: { x: e.clientX - dragOffset.x, y: e.clientY - dragOffset.y }
    }));
  }, [dragging, dragOffset]);

  const handleMouseUp = useCallback(() => setDragging(null), []);

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [handleMouseMove, handleMouseUp]);

  return (
    <svg width="100%" height="100%" className="select-none">
      <defs>
        <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="1" fill="#e2e8f0" />
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#grid)" />

      {/* Edges */}
      {edges.map((edge, i) => {
        const from = positions[edge.from];
        const to = positions[edge.to];
        if (!from || !to) return null;
        return (
          <line
            key={i}
            x1={from.x} y1={from.y} x2={to.x} y2={to.y}
            stroke="#cbd5e1" strokeWidth={1.5} strokeDasharray="5,5" opacity={0.7}
          />
        );
      })}

      {/* Nodes */}
      {nodes.map(node => {
        const pos = positions[node.id];
        if (!pos) return null;
        const isSelected = selected === node.id;
        return (
          <g
            key={node.id}
            transform={`translate(${pos.x}, ${pos.y})`}
            onMouseDown={e => handleMouseDown(e, node.id)}
            onClick={() => onSelect(node.id)}
            className="cursor-pointer"
          >
            <rect
              x={-60} y={-35} width={120} height={70}
              rx={10} ry={10}
              fill="white"
              stroke={isSelected ? node.color : '#e2e8f0'}
              strokeWidth={isSelected ? 2.5 : 1.5}
              filter={isSelected ? 'drop-shadow(0 4px 12px rgba(0,0,0,0.15))' : 'drop-shadow(0 1px 3px rgba(0,0,0,0.08))'}
            />
            <circle cx={-30} cy={0} r={16} fill={`${node.color}20`} stroke={`${node.color}50`} strokeWidth={1} />
            <text x={-30} y={0} textAnchor="middle" dominantBaseline="middle" fill={node.color} fontSize={11}>
              {node.type === 'ip' ? '⊡' : node.type === 'domain' ? '⊕' : node.type === 'campaign' ? '⬡' : '✉'}
            </text>
            <text x={5} y={-8} fontSize={9.5} fontWeight={600} fill="#334155" fontFamily="monospace">
              {node.label.length > 14 ? node.label.slice(0, 14) + '…' : node.label}
            </text>
            <text x={5} y={8} fontSize={8.5} fill="#94a3b8" fontFamily="Inter, sans-serif">
              {node.subLabel}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────

export default function CampaignGraphPage() {
  const [selected, setSelected] = useState<string | null>('domain1');

  const selectedNode = initialNodes.find(n => n.id === selected);
  const details = selected ? nodeDetails[selected] : null;

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Campaign Graph" />
      <div className="p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">RELATIONSHIP ANALYSIS</div>
          <h1 className="text-2xl font-bold text-slate-800">Campaign Graph</h1>
        </div>

        {/* Banner */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 mb-5 flex items-start gap-5">
          <div className="w-14 h-14 bg-blue-50 border border-blue-100 rounded-xl flex items-center justify-center flex-shrink-0">
            <Shield className="w-7 h-7 text-blue-500" />
          </div>
          <div className="flex-1">
            <h2 className="text-base font-bold text-slate-800 mb-1">BEC-2026-07 campaign relationship map</h2>
            <p className="text-sm text-slate-500 leading-relaxed">
              Connect indicators to cases and emerging campaigns. The selected demo case{' '}
              <span className="font-bold text-slate-700">MT-2026-00124</span> is ready to explore with realistic prototype evidence.
            </p>
          </div>
          <Link href="/cases" className="flex items-center gap-1.5 px-4 py-2 border border-slate-200 rounded-lg text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors flex-shrink-0">
            Open linked case <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="flex gap-4">
          {/* Graph canvas */}
          <div className="flex-1 bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden relative" style={{ height: '520px' }}>
            <div className="absolute top-3 left-3 z-10 flex items-center gap-2">
              <span className="flex items-center gap-1.5 text-xs text-emerald-600 font-medium">
                <span className="w-2 h-2 bg-emerald-500 rounded-full" />
                {initialNodes.length} related nodes
              </span>
            </div>
            <div className="absolute top-3 right-3 z-10 text-xs text-slate-400">
              Drag to explore · Scroll to zoom
            </div>
            <CampaignGraph
              nodes={initialNodes}
              edges={edges}
              selected={selected}
              onSelect={setSelected}
            />
          </div>

          {/* Selected node panel */}
          <div className="w-64 flex-shrink-0 bg-white rounded-xl border border-slate-200 shadow-sm p-5">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">SELECTED NODE</div>
            {selectedNode && details ? (
              <>
                <div className="flex items-center gap-3 mb-5">
                  <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: `${selectedNode.color}15`, border: `1px solid ${selectedNode.color}30` }}>
                    <span style={{ color: selectedNode.color }}>{NODE_ICONS[selectedNode.type]}</span>
                  </div>
                  <div>
                    <div className="text-sm font-bold font-mono text-slate-800 break-all">{selectedNode.label}</div>
                    <div className="text-xs text-slate-400">{selectedNode.subLabel}</div>
                  </div>
                </div>

                <div className="space-y-3">
                  {details.reputation && (
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-400">Reputation</span>
                      <span className={`text-xs font-bold ${details.reputation === 'Malicious' ? 'text-red-600' : 'text-orange-600'}`}>{details.reputation}</span>
                    </div>
                  )}
                  {details.similarity && (
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-400">Similarity</span>
                      <span className="text-xs font-bold text-slate-700">{details.similarity}</span>
                    </div>
                  )}
                  {details.firstObserved && (
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-400">First observed</span>
                      <span className="text-xs font-bold text-slate-700">{details.firstObserved}</span>
                    </div>
                  )}
                  {details.relatedCases && (
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-400">Related cases</span>
                      <span className="text-xs font-bold text-slate-700">{details.relatedCases}</span>
                    </div>
                  )}
                </div>

                <button className="mt-5 w-full flex items-center justify-between px-3 py-2.5 border border-slate-200 rounded-lg text-sm text-slate-600 hover:bg-slate-50 transition-colors">
                  View indicator details <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </>
            ) : (
              <div className="text-center py-8 text-slate-400">
                <Info className="w-8 h-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm">Click a node to view details</p>
              </div>
            )}

            {/* Node type legend */}
            <div className="mt-5 pt-4 border-t border-slate-100">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">NODE TYPES</div>
              <div className="space-y-2">
                {[
                  { type: 'IP', color: '#f97316' },
                  { type: 'Domain', color: '#ef4444' },
                  { type: 'Email Case', color: '#3b82f6' },
                  { type: 'Campaign', color: '#8b5cf6' },
                ].map(({ type, color }) => (
                  <div key={type} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: color }} />
                    <span className="text-xs text-slate-600">{type}</span>
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
