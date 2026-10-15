import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type Simulation } from "d3-force";
import { select } from "d3-selection";
import "d3-transition";
import { zoom as d3zoom, zoomIdentity, type ZoomBehavior, type ZoomTransform } from "d3-zoom";
import { Crosshair, Maximize2, RotateCcw } from "lucide-react";
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { bps, deviceColor, utilColor } from "../lib/format";
import { useReducedMotion, useSize } from "../lib/hooks";
import type { TopoEdge, TopoNode, Topology } from "../lib/types";
import { ROLE_ICON } from "./DeviceIcon";

interface SimNode extends TopoNode {
  x: number;
  y: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}
interface SimLink {
  source: SimNode;
  target: SimNode;
  edge: TopoEdge;
}

const TIER: Record<string, number> = {
  internet: 0, firewall: 1, router: 1, controller: 2, switch: 3, hypervisor: 4, server: 4, nas: 4, ap: 4, iot: 5, other: 4,
};

/** Core switches (lots of switch neighbours) sit one tier above access switches. */
function tierOf(n: TopoNode, degree: Map<string, number>): number {
  const t = TIER[n.role] ?? 4;
  if (n.role === "switch" && (degree.get(n.id) ?? 0) >= 4) return 2.4;
  return t;
}

export interface TopologyProps {
  data: Topology | null;
  compact?: boolean;
  selectedId?: string | null;
  highlight?: string;
  roles?: Set<string>;
  onSelect?: (n: TopoNode | null) => void;
  persistPositions?: boolean;
}

function TopologyGraphInner({ data, compact = false, selectedId, highlight = "", roles, onSelect, persistPositions = true }: TopologyProps) {
  const [wrapRef, size] = useSize<HTMLDivElement>();
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement>(null);
  const simRef = useRef<Simulation<SimNode, SimLink> | null>(null);
  const nodesRef = useRef<Map<string, SimNode>>(new Map());
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [transform, setTransform] = useState<ZoomTransform>(zoomIdentity);
  const [, setFrame] = useState(0);
  const [hover, setHover] = useState<string | null>(null);
  const fitted = useRef(false);
  const reduced = useReducedMotion();

  // ---------------------------------------------------------------- filter
  const visible = useMemo(() => {
    if (!data) return { nodes: [] as TopoNode[], edges: [] as TopoEdge[] };
    const nodes = data.nodes.filter((n) => !roles || roles.size === 0 || roles.has(n.role) || n.role === "internet");
    const ids = new Set(nodes.map((n) => n.id));
    return { nodes, edges: data.edges.filter((e) => ids.has(e.source) && ids.has(e.target)) };
  }, [data, roles]);

  // ------------------------------------------------------- simulation sync
  useEffect(() => {
    const { width, height } = size;
    if (!width || !height) return;
    const degree = new Map<string, number>();
    visible.edges.forEach((e) => {
      degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
      degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
    });
    const prev = nodesRef.current;
    const next = new Map<string, SimNode>();
    const tierGap = compact ? 95 : 130;
    for (const n of visible.nodes) {
      const old = prev.get(n.id);
      const tier = tierOf(n, degree);
      const sn: SimNode = old
        ? Object.assign(old, n, { x: old.x, y: old.y })
        : { ...n, x: n.x ?? width / 2 + (Math.random() - 0.5) * 300, y: n.y ?? tier * tierGap + 60 };
      if (n.x != null && n.y != null && !compact) {
        sn.fx = n.x;
        sn.fy = n.y;
      } else if (!old) {
        sn.fx = sn.fy = null;
      }
      if (n.role === "internet" && n.x == null) {
        sn.fx = width / 2;
        sn.fy = 40;
      }
      (sn as SimNode & { tier: number }).tier = tier;
      next.set(n.id, sn);
    }
    nodesRef.current = next;
    const links: SimLink[] = visible.edges
      .map((e) => ({ source: next.get(e.source)!, target: next.get(e.target)!, edge: e }))
      .filter((l) => l.source && l.target);

    const isNew = !simRef.current || [...next.keys()].some((k) => !prev.has(k)) || prev.size !== next.size;
    simRef.current?.stop();
    const sim = forceSimulation<SimNode, SimLink>([...next.values()])
      .force("link", forceLink<SimNode, SimLink>(links).distance((l) => (l.edge.kind === "wan" ? 110 : compact ? 80 : 115)).strength(0.55))
      .force("charge", forceManyBody<SimNode>().strength(compact ? -380 : -620).distanceMax(600))
      .force("collide", forceCollide<SimNode>(compact ? 34 : 48))
      .force("x", forceX<SimNode>(width / 2).strength(0.04))
      .force("y", forceY<SimNode>((d) => (d as SimNode & { tier: number }).tier * tierGap + 50).strength(0.35))
      .alpha(isNew ? 1 : 0.08)
      .alphaDecay(0.035);
    let raf = 0;
    sim.on("tick", () => {
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; setFrame((f) => f + 1); });
    });
    sim.on("end", () => {
      if (!fitted.current) fit();
    });
    simRef.current = sim;
    return () => {
      sim.stop();
      cancelAnimationFrame(raf);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, size.width, size.height, compact]);

  // ----------------------------------------------------------------- zoom
  useEffect(() => {
    if (!svgRef.current) return;
    const z = d3zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.25, 4])
      // Nodes handle their own dragging; wheel-zoom in compact mode needs ctrl so the page can scroll.
      .filter((ev) => !ev.button && !(ev.target as Element).closest?.("[data-node]") &&
        (ev.type !== "wheel" || !compact || ev.ctrlKey || ev.metaKey))
      .on("zoom", (ev) => setTransform(ev.transform));
    select(svgRef.current).call(z).on("dblclick.zoom", null);
    zoomRef.current = z;
  }, [compact]);

  const fit = useCallback(() => {
    const nodes = [...nodesRef.current.values()];
    if (!nodes.length || !svgRef.current || !zoomRef.current || !size.width) return;
    const xs = nodes.map((n) => n.x), ys = nodes.map((n) => n.y);
    const [minX, maxX, minY, maxY] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const pad = compact ? 50 : 90;
    const top = compact ? 0 : 60; // leave room for the floating toolbar
    const k = Math.min(1.6, (size.width - pad * 2) / Math.max(1, maxX - minX), (size.height - top - pad * 2) / Math.max(1, maxY - minY));
    const t = zoomIdentity.translate(size.width / 2 - ((minX + maxX) / 2) * k, top + (size.height - top) / 2 - ((minY + maxY) / 2) * k).scale(k);
    select(svgRef.current).transition().duration(700).call(zoomRef.current.transform, t);
    fitted.current = true;
  }, [size, compact]);

  // ----------------------------------------------------------------- drag
  const drag = useRef<{ id: string; moved: boolean } | null>(null);
  const onPointerDown = (e: React.PointerEvent, n: SimNode) => {
    e.stopPropagation();
    (e.target as Element).setPointerCapture(e.pointerId);
    drag.current = { id: n.id, moved: false };
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!drag.current || !svgRef.current) return;
    const n = nodesRef.current.get(drag.current.id);
    if (!n) return;
    const r = svgRef.current.getBoundingClientRect();
    const [x, y] = transform.invert([e.clientX - r.left, e.clientY - r.top]);
    n.fx = x;
    n.fy = y;
    drag.current.moved = true;
    simRef.current?.alphaTarget(0.15).restart();
  };
  const onPointerUp = (n: SimNode) => {
    const d = drag.current;
    drag.current = null;
    simRef.current?.alphaTarget(0);
    if (!d) return;
    if (!d.moved) {
      onSelect?.(n.id === selectedId ? null : n);
      return;
    }
    if (persistPositions && !compact && n.device_id != null) {
      api(`/devices/${n.device_id}/position`, { method: "PUT", body: { x: n.fx, y: n.fy } }).catch(() => {});
    }
  };

  const resetLayout = async () => {
    await api("/positions", { method: "DELETE" }).catch(() => {});
    nodesRef.current.forEach((n) => {
      if (n.role !== "internet") n.fx = n.fy = null;
    });
    simRef.current?.alpha(1).restart();
    fitted.current = false;
  };

  // ---------------------------------------------------------------- render
  const nodes = [...nodesRef.current.values()];
  const neighbors = useMemo(() => {
    const focus = hover ?? selectedId;
    if (!focus) return null;
    const s = new Set([focus]);
    visible.edges.forEach((e) => {
      if (e.source === focus) s.add(e.target);
      if (e.target === focus) s.add(e.source);
    });
    return s;
  }, [hover, selectedId, visible.edges]);
  const q = highlight.trim().toLowerCase();
  const matches = (n: TopoNode) => !q || n.name.toLowerCase().includes(q) || (n.host ?? "").includes(q) || (n.model ?? "").toLowerCase().includes(q);
  const nodeR = compact ? 17 : 22;

  return (
    <div ref={wrapRef} className="relative h-full w-full overflow-hidden" onPointerMove={onPointerMove}>
      <svg ref={svgRef} width={size.width} height={size.height} className="block cursor-grab active:cursor-grabbing" onClick={() => onSelect?.(null)}>
        <defs>
          <filter id="nv-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <radialGradient id="nv-node" cx="50%" cy="35%" r="65%">
            <stop offset="0" stopColor="#1b2a4a" />
            <stop offset="1" stopColor="#070c18" />
          </radialGradient>
          <radialGradient id="nv-radar" cx="50%" cy="50%" r="50%">
            <stop offset="0" stopColor="#22d3ee" stopOpacity="0.07" />
            <stop offset="1" stopColor="#22d3ee" stopOpacity="0" />
          </radialGradient>
        </defs>
        <g ref={gRef} transform={transform.toString()}>
          {/* links */}
          {visible.edges.map((e) => {
            const a = nodesRef.current.get(e.source), b = nodesRef.current.get(e.target);
            if (!a || !b) return null;
            const dim = (neighbors && !(neighbors.has(e.source) && neighbors.has(e.target))) || (q && !(matches(a) || matches(b)));
            const down = e.status === "down";
            const util = e.util_pct ?? null;
            const color = down ? "#fb4d6d" : e.kind === "wan" ? "#a78bfa" : utilColor(util);
            const total = (e.rx_bps ?? 0) + (e.tx_bps ?? 0);
            const width = down ? 1.5 : 1.2 + Math.min(4, Math.log10(1 + total / 1e6) * 1.3);
            const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
            const dx = b.x - a.x, dy = b.y - a.y;
            const curve = e.kind === "manual" || e.kind === "description" ? 0.12 : 0.06;
            const cx = mx - dy * curve, cy = my + dx * curve;
            const d = `M${a.x},${a.y} Q${cx},${cy} ${b.x},${b.y}`;
            const pid = `p-${e.id}`.replace(/[^\w-]/g, "_");
            // speed: more traffic -> faster packets
            const dur = Math.max(0.9, 4.5 - Math.log10(1 + total / 1e5) * 0.9);
            const particles = down || reduced || total < 1e3 ? 0 : Math.min(compact ? 2 : 4, 1 + Math.floor((util ?? 5) / 25));
            return (
              <g key={e.id} opacity={dim ? 0.12 : 1} style={{ transition: "opacity .25s" }}>
                <path id={pid} d={d} fill="none" stroke={color} strokeOpacity={0.16} strokeWidth={width + 5} />
                <path d={d} fill="none" stroke={color} strokeOpacity={down ? 0.9 : 0.55} strokeWidth={width}
                  strokeDasharray={down ? "4 6" : e.kind === "manual" || e.kind === "description" ? "2 5" : undefined} />
                {!down && !reduced && (
                  <path d={d} fill="none" stroke={color} strokeWidth={Math.max(1, width - 0.5)} strokeLinecap="round"
                    className="flow-dash" style={{ animationDuration: `${dur * 0.6}s` }} strokeOpacity={0.9} filter="url(#nv-glow)" />
                )}
                {Array.from({ length: particles }, (_, i) => (
                  <circle key={i} r={compact ? 2 : 2.6} fill="#fff" filter="url(#nv-glow)">
                    <animateMotion dur={`${dur}s`} repeatCount="indefinite" begin={`${(i * dur) / particles}s`}
                      keyPoints={i % 2 ? "1;0" : "0;1"} keyTimes="0;1" calcMode="linear">
                      <mpath href={`#${pid}`} />
                    </animateMotion>
                  </circle>
                ))}
                {!compact && (hover === e.source || hover === e.target || selectedId === e.source || selectedId === e.target) && total > 0 && (
                  <g transform={`translate(${(a.x + 2 * cx + b.x) / 4},${(a.y + 2 * cy + b.y) / 4})`}>
                    <rect x={-46} y={-11} width={92} height={22} rx={6} fill="#070b16" stroke={color} strokeOpacity={0.6} />
                    <text textAnchor="middle" dy={4} className="num" fontSize={10.5} fill="#e6f1ff">{bps(total)}</text>
                  </g>
                )}
              </g>
            );
          })}
          {/* nodes */}
          {nodes.map((n) => {
            const Icon = ROLE_ICON[n.role] ?? ROLE_ICON.other;
            const color = n.role === "internet" ? "#a78bfa" : deviceColor(n.status, n.health);
            const alarm = n.status === "down" || n.health === "critical" || n.health === "warning" || n.status === "degraded";
            const sel = selectedId === n.id;
            const dim = (neighbors && !neighbors.has(n.id)) || (q && !matches(n));
            const r = n.role === "internet" ? nodeR + 6 : nodeR;
            return (
              <g key={n.id} data-node transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.18 : 1}
                style={{ transition: "opacity .25s", cursor: "pointer" }}
                onPointerDown={(e) => onPointerDown(e, n)} onPointerUp={() => onPointerUp(n)}
                onPointerEnter={() => setHover(n.id)} onPointerLeave={() => setHover((h) => (h === n.id ? null : h))}
                onClick={(e) => e.stopPropagation()}>
                {n.role === "internet" && <circle r={r * 3} fill="url(#nv-radar)" />}
                {alarm && !reduced && (
                  <circle r={r} fill="none" stroke={color} strokeWidth={2}>
                    <animate attributeName="r" values={`${r};${r * 2.1}`} dur="1.8s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.9;0" dur="1.8s" repeatCount="indefinite" />
                  </circle>
                )}
                {sel && (
                  <circle r={r + 9} fill="none" stroke="#22d3ee" strokeWidth={1.5} strokeDasharray="4 4">
                    {!reduced && <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="8s" repeatCount="indefinite" />}
                  </circle>
                )}
                <circle r={r + 3} fill="none" stroke={color} strokeOpacity={0.35} strokeWidth={1} />
                <circle r={r} fill="url(#nv-node)" stroke={color} strokeWidth={sel || hover === n.id ? 2.4 : 1.6}
                  style={{ filter: `drop-shadow(0 0 ${alarm ? 10 : 6}px ${color}aa)` }} />
                <Icon x={-r * 0.5} y={-r * 0.5} size={r} color={n.status === "down" ? "#fb4d6d" : "#e6f1ff"} strokeWidth={1.7} />
                <text y={r + 15} textAnchor="middle" fontSize={compact ? 10 : 11.5} fill="#e6f1ff" fontWeight={500}
                  style={{ paintOrder: "stroke", stroke: "#04060c", strokeWidth: 4, strokeLinejoin: "round" }}>
                  {n.name}
                </text>
                {!compact && (
                  <text y={r + 28} textAnchor="middle" fontSize={9.5} className="num" fill="#7f8fb0"
                    style={{ paintOrder: "stroke", stroke: "#04060c", strokeWidth: 4 }}>
                    {n.role === "internet"
                      ? n.metrics?.latency_ms != null ? `${n.metrics.latency_ms.toFixed(0)} ms` : ""
                      : n.status === "down" ? "OFFLINE"
                      : n.clients ? `${n.clients} clients`
                      : n.metrics?.cpu != null ? `cpu ${n.metrics.cpu.toFixed(0)}%`
                      : n.host}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="absolute right-3 bottom-3 flex flex-col gap-1.5">
        <button className="btn !p-2" title="Fit to view" onClick={fit}><Maximize2 size={15} /></button>
        <button className="btn !p-2" title="Center" onClick={() => svgRef.current && zoomRef.current &&
          select(svgRef.current).transition().duration(500).call(zoomRef.current.transform, zoomIdentity)}>
          <Crosshair size={15} />
        </button>
        {!compact && <button className="btn !p-2" title="Reset layout (forget dragged positions)" onClick={resetLayout}><RotateCcw size={15} /></button>}
      </div>
    </div>
  );
}

export const TopologyGraph = memo(TopologyGraphInner);
