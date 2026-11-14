import { useMemo, useState } from "react";
import { Background, Controls, MarkerType, Position, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphEdge, GraphNode } from "../api";
import { bytes, fmtTime } from "./ui";

const TYPE_STYLE: Record<string, { bg: string; border: string; label: string }> = {
  ip: { bg: "#3f1d2b", border: "#f43f5e", label: "External IP" },
  host: { bg: "#0c2a3a", border: "#38bdf8", label: "Internal host" },
  identity: { bg: "#2a1f47", border: "#a78bfa", label: "Identity" },
  key: { bg: "#3a2f0c", border: "#facc15", label: "Access key" },
  resource: { bg: "#0f2f25", border: "#34d399", label: "Resource" },
  finding: { bg: "#3a1530", border: "#f472b6", label: "GuardDuty finding" },
};

function short(label: string) {
  const s = label.replace("arn:aws:s3:::", "s3://").replace(/^arn:aws:cloudtrail:[^:]+:\d+:trail\//, "trail/");
  return s.length > 34 ? s.slice(0, 31) + "…" : s;
}

export default function AttackGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const [selected, setSelected] = useState<{ kind: "node"; data: GraphNode } | { kind: "edge"; data: GraphEdge } | null>(null);

  const { rfNodes, rfEdges } = useMemo(() => {
    const perColumn: Record<number, number> = {};
    const ordered = [...nodes].sort((a, b) => a.column - b.column || b.rank - a.rank);
    const rfNodes: Node[] = ordered.map((n) => {
      const row = (perColumn[n.column] = (perColumn[n.column] ?? -1) + 1);
      const style = TYPE_STYLE[n.type] ?? TYPE_STYLE.resource;
      return {
        id: n.id,
        position: { x: n.column * 320, y: row * 92 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: {
          label: (
            <div className="text-left">
              <div className="text-[10px] uppercase tracking-wide opacity-70">{style.label} · rank {n.rank.toFixed(2)}</div>
              <div className="font-mono text-[11px]">{short(n.label)}</div>
            </div>
          ),
        },
        style: {
          background: style.bg,
          border: `${1 + Math.round(n.rank * 3)}px solid ${style.border}`,
          color: "#e2e8f0",
          borderRadius: 8,
          width: 230,
          padding: 8,
          boxShadow: n.rank > 0.6 ? `0 0 18px ${style.border}66` : undefined,
        },
      };
    });
    const rfEdges: Edge[] = edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.count > 1 ? `${e.relation} ×${e.count}` : e.relation,
      labelStyle: { fill: "#cbd5e1", fontSize: 10 },
      labelBgStyle: { fill: "#0f172a" },
      type: "smoothstep",
      animated: e.suspicion >= 0.6,
      style: { stroke: e.suspicion >= 0.6 ? "#f43f5e" : e.suspicion >= 0.35 ? "#fb923c" : "#475569", strokeWidth: 1 + e.suspicion * 2.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
    }));
    return { rfNodes, rfEdges };
  }, [nodes, edges]);

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <div className="h-[560px] rounded-lg border border-slate-800 bg-slate-950">
        <ReactFlow
          nodes={rfNodes}
          edges={rfEdges}
          fitView
          minZoom={0.2}
          colorMode="dark"
          onNodeClick={(_, n) => setSelected({ kind: "node", data: nodes.find((x) => x.id === n.id)! })}
          onEdgeClick={(_, e) => setSelected({ kind: "edge", data: edges.find((x) => x.id === e.id)! })}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1e293b" />
          <Controls />
        </ReactFlow>
      </div>
      <div className="space-y-3 text-sm">
        <div className="card">
          <div className="mb-2 text-xs font-semibold uppercase text-slate-400">Legend</div>
          {Object.entries(TYPE_STYLE).map(([k, s]) => (
            <div key={k} className="flex items-center gap-2 text-xs"><span className="h-3 w-3 rounded-sm" style={{ background: s.bg, border: `2px solid ${s.border}` }} />{s.label}</div>
          ))}
          <p className="mt-2 text-xs text-slate-500">
            Node rank R(v) = 0.4·S<sub>out</sub> + 0.3·S<sub>in</sub> + 0.2·PageRank + 0.1·Degree (normalised). Thicker border = higher rank;
            red animated edges = high-suspicion activity.
          </p>
        </div>
        <div className="card">
          {!selected ? <p className="text-slate-500">Click a node or edge.</p> : selected.kind === "node" ? (
            <div className="space-y-1">
              <div className="font-mono text-xs break-all">{selected.data.label}</div>
              <div className="grid grid-cols-2 gap-1 text-xs text-slate-400">
                <span>Type</span><span className="text-slate-200">{selected.data.type}</span>
                <span>Rank</span><span className="text-slate-200">{selected.data.rank}</span>
                <span>Suspicion out / in</span><span className="text-slate-200">{selected.data.suspicion_out} / {selected.data.suspicion_in}</span>
                <span>PageRank</span><span className="text-slate-200">{selected.data.pagerank}</span>
                <span>Sensitivity</span><span className="text-slate-200">{selected.data.sensitivity}</span>
                <span>First seen</span><span className="text-slate-200">{fmtTime(selected.data.first_seen)}</span>
              </div>
            </div>
          ) : (
            <div className="space-y-1 text-xs">
              <div className="font-semibold text-slate-200">{selected.data.relation} ×{selected.data.count}</div>
              <div className="mono break-all text-slate-400">{selected.data.source} → {selected.data.target}</div>
              <div>Suspicion {selected.data.suspicion.toFixed(2)}{selected.data.bytes ? ` · ${bytes(selected.data.bytes)}` : ""}</div>
              <div className="text-slate-400">{fmtTime(selected.data.first_seen)} → {fmtTime(selected.data.last_seen)}</div>
              <div className="text-slate-500">{selected.data.event_ids.length} evidence event(s)</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
