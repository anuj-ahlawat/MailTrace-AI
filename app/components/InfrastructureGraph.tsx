'use client';
import { useMemo, useState } from 'react';
import { ReactFlow, Background, Controls, MiniMap, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
type Graph = { nodes: { id: string; type: string; label: string; data: Record<string, unknown> }[]; edges: { id: string; source: string; target: string; label: string }[] };
export default function InfrastructureGraph({ graph }: { graph: Graph }) {
  const [selected, setSelected] = useState<Node | null>(null);
  const nodes = useMemo(() => graph.nodes.map((n, i) => ({ id: n.id, data: { ...n.data, label: `${n.type}\n${n.label}` }, position: { x: (i % 4) * 250, y: Math.floor(i / 4) * 130 }, style: { background: n.type === 'Email' ? '#12304b' : '#fff', color: n.type === 'Email' ? '#fff' : '#12304b', border: '1px solid #b7cbd6', borderRadius: 10, width: 210, fontSize: 11, whiteSpace: 'pre-wrap' as const, overflowWrap: 'anywhere' as const } })), [graph]);
  if (!nodes.length) return <p>No observed infrastructure available.</p>;
  return <><div className="soc-graph"><ReactFlow nodes={nodes} edges={graph.edges} fitView onNodeClick={(_,node) => setSelected(node)}><Background/><Controls/><MiniMap/></ReactFlow></div>{selected && <div className="soc-node-detail"><button onClick={() => setSelected(null)}>Close details</button><h3>{String(selected.data.label)}</h3><pre>{JSON.stringify(selected.data, null, 2)}</pre></div>}</>;
}
