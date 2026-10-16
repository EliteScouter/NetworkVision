import { Maximize2 } from "lucide-react";
import { motion } from "motion/react";
import { useId, useMemo, useState } from "react";
import { clock } from "../lib/format";
import { useSize } from "../lib/hooks";

type Pt = [number, number | null];

function extent(series: Pt[][], forceZero = true): [number, number, number, number] {
  let x0 = Infinity, x1 = -Infinity, y0 = forceZero ? 0 : Infinity, y1 = -Infinity;
  for (const s of series)
    for (const [x, y] of s) {
      if (x < x0) x0 = x;
      if (x > x1) x1 = x;
      if (y != null) {
        if (y < y0) y0 = y;
        if (y > y1) y1 = y;
      }
    }
  if (!isFinite(y1) || y1 === y0) y1 = y0 + 1;
  if (!isFinite(x0)) [x0, x1] = [0, 1];
  if (x0 === x1) x1 = x0 + 1;
  return [x0, x1, y0, y1 * 1.12];
}

function path(pts: Pt[], sx: (x: number) => number, sy: (y: number) => number): string {
  let d = "";
  let pen = false;
  for (const [x, y] of pts) {
    if (y == null) {
      pen = false;
      continue;
    }
    d += `${pen ? "L" : "M"}${sx(x).toFixed(1)},${sy(y).toFixed(1)}`;
    pen = true;
  }
  return d;
}

export function Sparkline({ data, color = "#22d3ee", height = 32, fill = true }: {
  data: (number | null)[];
  color?: string;
  height?: number;
  fill?: boolean;
}) {
  const id = useId();
  const [ref, { width }] = useSize<HTMLDivElement>();
  const pts: Pt[] = data.map((v, i) => [i, v]);
  const [x0, x1, y0, y1] = extent([pts]);
  const sx = (x: number) => ((x - x0) / (x1 - x0)) * width;
  const sy = (y: number) => height - 2 - ((y - y0) / (y1 - y0)) * (height - 4);
  const line = width ? path(pts, sx, sy) : "";
  const last = [...pts].reverse().find((p) => p[1] != null);
  return (
    <div ref={ref} className="w-full" style={{ height }}>
      {width > 0 && line && (
        <svg width={width} height={height} className="overflow-visible">
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.35" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          {fill && <path d={`${line}L${sx(x1)},${height}L${sx(x0)},${height}Z`} fill={`url(#${id})`} />}
          <path d={line} fill="none" stroke={color} strokeWidth={1.5} style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
          {last && <circle cx={sx(last[0])} cy={sy(last[1]!)} r={2.5} fill={color} />}
        </svg>
      )}
    </div>
  );
}

export interface Series {
  key: string;
  label: string;
  color: string;
  points: Pt[];
  /** Thin dashed line without area fill (used for peak/max overlays). */
  dashed?: boolean;
}

export function AreaChart({ series, height = 220, yFormat = (v) => v.toFixed(0), xFormat, empty = "Collecting data…", onExpand, onSelectRange }: {
  series: Series[];
  height?: number;
  yFormat?: (v: number) => string;
  xFormat?: (t: number) => string;
  empty?: string;
  /** Show an expand affordance; clicking the chart opens the history explorer. */
  onExpand?: () => void;
  /** Enable drag-to-zoom: called with the selected [t0, t1] window. */
  onSelectRange?: (t0: number, t1: number) => void;
}) {
  const uid = useId();
  const [ref, { width }] = useSize<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null);
  const padL = 56, padR = 12, padT = 10, padB = 22;
  const w = Math.max(0, width - padL - padR);
  const h = height - padT - padB;
  const [x0, x1, y0, y1] = useMemo(() => extent(series.map((s) => s.points)), [series]);
  const sx = (x: number) => padL + ((x - x0) / (x1 - x0)) * w;
  const sy = (y: number) => padT + h - ((y - y0) / (y1 - y0)) * h;
  const has = series.some((s) => s.points.filter((p) => p[1] != null).length > 1);
  const xs = series[0]?.points.map((p) => p[0]) ?? [];
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => y0 + (y1 - y0) * f);
  const fmtX = xFormat ?? ((t: number) => clock(t).slice(0, 5));
  const hoverIdx = hover;

  return (
    <div ref={ref} className={`group/chart relative w-full select-none ${onExpand ? "cursor-zoom-in" : ""} ${onSelectRange ? "cursor-crosshair" : ""}`}
      style={{ height }} onClick={() => !drag && onExpand?.()}>
      {!has && <div className="absolute inset-0 grid place-items-center font-mono text-xs text-faint">{empty}</div>}
      {onExpand && (
        <button type="button" aria-label="Open history" onClick={(e) => { e.stopPropagation(); onExpand(); }}
          className="absolute top-0 right-0 z-10 rounded-md border border-edge bg-abyss/80 p-1 text-faint opacity-0 transition group-hover/chart:opacity-100 hover:text-cyan">
          <Maximize2 size={13} />
        </button>
      )}
      {width > 0 && has && (
        <svg
          width={width}
          height={height}
          onMouseLeave={() => { setHover(null); setDrag(null); }}
          onMouseDown={(e) => {
            if (!onSelectRange) return;
            const x = e.clientX - (e.currentTarget as SVGSVGElement).getBoundingClientRect().left;
            setDrag({ a: x, b: x });
          }}
          onMouseUp={() => {
            if (drag && onSelectRange && Math.abs(drag.b - drag.a) > 8) {
              const toT = (x: number) => x0 + ((Math.min(Math.max(x, padL), padL + w) - padL) / w) * (x1 - x0);
              onSelectRange(toT(Math.min(drag.a, drag.b)), toT(Math.max(drag.a, drag.b)));
            }
            setDrag(null);
          }}
          onMouseMove={(e) => {
            const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
            const x = e.clientX - r.left;
            if (drag) setDrag({ ...drag, b: x });
            let best = 0, bd = Infinity;
            xs.forEach((t, i) => {
              const d = Math.abs(sx(t) - x);
              if (d < bd) [bd, best] = [d, i];
            });
            setHover(best);
          }}
        >
          <defs>
            {series.map((s) => (
              <linearGradient key={s.key} id={`${uid}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stopColor={s.color} stopOpacity="0.32" />
                <stop offset="1" stopColor={s.color} stopOpacity="0" />
              </linearGradient>
            ))}
          </defs>
          {ticks.map((t, i) => (
            <g key={i}>
              <line x1={padL} x2={padL + w} y1={sy(t)} y2={sy(t)} stroke="#16233d" strokeDasharray={i ? "2 4" : undefined} />
              <text x={padL - 8} y={sy(t) + 3} textAnchor="end" className="fill-faint font-mono text-[10px]">
                {yFormat(t)}
              </text>
            </g>
          ))}
          {[0, 0.5, 1].map((f) => {
            const t = x0 + (x1 - x0) * f;
            return (
              <text key={f} x={sx(t)} y={height - 6} textAnchor={f === 0 ? "start" : f === 1 ? "end" : "middle"} className="fill-faint font-mono text-[10px]">
                {fmtX(t)}
              </text>
            );
          })}
          {series.map((s) => {
            const line = path(s.points, sx, sy);
            const valid = s.points.filter((p) => p[1] != null);
            const area = valid.length ? `${line}L${sx(valid[valid.length - 1][0])},${padT + h}L${sx(valid[0][0])},${padT + h}Z` : "";
            return (
              <g key={s.key}>
                {!s.dashed && <motion.path d={area} fill={`url(#${uid}-${s.key})`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} />}
                <path d={line} fill="none" stroke={s.color} strokeWidth={s.dashed ? 1 : 1.8} strokeDasharray={s.dashed ? "3 4" : undefined}
                  strokeOpacity={s.dashed ? 0.6 : 1} style={s.dashed ? undefined : { filter: `drop-shadow(0 0 5px ${s.color}aa)` }} />
              </g>
            );
          })}
          {drag && Math.abs(drag.b - drag.a) > 2 && (
            <rect x={Math.min(drag.a, drag.b)} y={padT} width={Math.abs(drag.b - drag.a)} height={h}
              fill="#22d3ee" fillOpacity={0.12} stroke="#22d3ee" strokeOpacity={0.5} />
          )}
          {hoverIdx != null && xs[hoverIdx] != null && (
            <g>
              <line x1={sx(xs[hoverIdx])} x2={sx(xs[hoverIdx])} y1={padT} y2={padT + h} stroke="#22d3ee55" />
              {series.map((s) => {
                const v = s.points[hoverIdx]?.[1];
                return v == null ? null : (
                  <circle key={s.key} cx={sx(xs[hoverIdx])} cy={sy(v)} r={3.5} fill="#04060c" stroke={s.color} strokeWidth={2} />
                );
              })}
            </g>
          )}
        </svg>
      )}
      {hoverIdx != null && xs[hoverIdx] != null && has && (
        <div
          className="pointer-events-none absolute top-1 z-10 rounded-lg border border-edge bg-abyss/95 px-2.5 py-1.5 text-xs shadow-xl"
          style={{ left: Math.min(sx(xs[hoverIdx]) + 12, width - 170) }}
        >
          <div className="mb-1 font-mono text-[10px] text-faint">{clock(xs[hoverIdx], true)}</div>
          {series.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-dim">
                <span className="h-2 w-2 rounded-full" style={{ background: s.color }} />
                {s.label}
              </span>
              <span className="num text-ink">{s.points[hoverIdx]?.[1] != null ? yFormat(s.points[hoverIdx][1]!) : "—"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Radial gauge with tick marks and glow. */
export function Gauge({ value, size = 150, label, color }: { value: number; size?: number; label?: string; color?: string }) {
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  const arc = 0.75; // 270°
  const v = Math.max(0, Math.min(100, value)) / 100;
  const col = color ?? (value >= 85 ? "#34d399" : value >= 60 ? "#fbbf24" : "#fb4d6d");
  const id = useId();
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <defs>
        <linearGradient id={id} x1="0" y1="1" x2="1" y2="0">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor={col} />
        </linearGradient>
      </defs>
      <g transform={`rotate(135 ${size / 2} ${size / 2})`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#16233d" strokeWidth={9}
          strokeDasharray={`${c * arc} ${c}`} strokeLinecap="round" />
        <motion.circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={`url(#${id})`} strokeWidth={9} strokeLinecap="round"
          initial={{ strokeDasharray: `0 ${c}` }}
          animate={{ strokeDasharray: `${c * arc * v} ${c}` }}
          transition={{ duration: 1.4, ease: [0.2, 0.7, 0.2, 1] }}
          style={{ filter: `drop-shadow(0 0 8px ${col})` }}
        />
        {Array.from({ length: 28 }, (_, i) => {
          const a = (i / 27) * arc * 2 * Math.PI;
          const r1 = r - 12, r2 = r - (i % 3 === 0 ? 18 : 15);
          return (
            <line key={i} x1={size / 2 + r1 * Math.cos(a)} y1={size / 2 + r1 * Math.sin(a)}
              x2={size / 2 + r2 * Math.cos(a)} y2={size / 2 + r2 * Math.sin(a)}
              stroke={i / 27 <= v ? col : "#1e2d4d"} strokeWidth={1.5} opacity={0.8} />
          );
        })}
      </g>
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="num" fill="#e6f1ff"
        fontSize={size * 0.24} fontWeight={600} style={{ filter: `drop-shadow(0 0 10px ${col}88)` }}>
        {Math.round(value)}
      </text>
      {label && (
        <text x="50%" y={size / 2 + size * 0.2} textAnchor="middle" className="hud-label" fill="#7f8fb0" fontSize={9.5}
          letterSpacing="0.16em">
          {label}
        </text>
      )}
    </svg>
  );
}
