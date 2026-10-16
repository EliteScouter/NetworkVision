import clsx from "clsx";
import { CalendarRange, Download, History, Undo2, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { create } from "zustand";
import { api } from "../lib/api";
import { bps, bytes, clock } from "../lib/format";
import type { HistoryResponse, HistoryTarget } from "../lib/types";
import { AreaChart, type Series } from "./charts";
import { Badge, Segmented, Spinner, Toggle } from "./ui";

const PRESETS = ["1h", "6h", "24h", "7d", "30d", "90d", "1y"] as const;
type Preset = (typeof PRESETS)[number] | "custom";

/** Open from anywhere: useHistory.getState().open({...}) */
export const useHistory = create<{ target: HistoryTarget | null; open: (t: HistoryTarget) => void; close: () => void }>((set) => ({
  target: null,
  open: (target) => set({ target }),
  close: () => set({ target: null }),
}));

export function formatUnit(unit: HistoryTarget["unit"], v: number | null | undefined): string {
  if (v == null || !isFinite(v)) return "—";
  switch (unit) {
    case "bps": return bps(v);
    case "pct": return `${v.toFixed(1)}%`;
    case "ms": return v < 10 ? `${v.toFixed(2)} ms` : `${v.toFixed(1)} ms`;
    case "count": return Math.round(v).toLocaleString();
    default: return v.toFixed(2);
  }
}

const toLocalInput = (ts: number) => {
  const d = new Date(ts * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};
const fromLocalInput = (s: string) => new Date(s).getTime() / 1000;

export function HistoryExplorerHost() {
  const target = useHistory((s) => s.target);
  const close = useHistory((s) => s.close);
  const [preset, setPreset] = useState<Preset>("24h");
  const [win, setWin] = useState<{ since: number; until: number } | null>(null);
  const [zoomStack, setZoomStack] = useState<{ preset: Preset; win: typeof win }[]>([]);
  const [data, setData] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [peaks, setPeaks] = useState(true);

  useEffect(() => {
    if (!target) return;
    setPreset(target.kind === "speedtest" ? "30d" : "24h");
    setWin(null);
    setZoomStack([]);
  }, [target]);

  useEffect(() => {
    if (!target) return;
    const fn = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", fn);
    return () => window.removeEventListener("keydown", fn);
  }, [target, close]);

  useEffect(() => {
    if (!target) return;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    const query: Record<string, string | number> = { ...(target.filters ?? {}), points: 400 };
    if (preset === "custom" && win) Object.assign(query, { since: Math.floor(win.since), until: Math.ceil(win.until) });
    else query.range = preset === "custom" ? "24h" : preset;
    api<HistoryResponse>(`/history/${target.kind}`, { query, signal: ctrl.signal })
      .then(setData)
      .catch((e) => !ctrl.signal.aborted && setError((e as Error).message))
      .finally(() => !ctrl.signal.aborted && setLoading(false));
    return () => ctrl.abort();
  }, [target, preset, win]);

  const series: Series[] = useMemo(() => {
    if (!target || !data) return [];
    const idx = (k: string) => data.columns.indexOf(k);
    const out: Series[] = target.series.map((s) => ({
      key: s.key, label: s.label, color: s.color,
      points: data.points.map((p) => [p[0] as number, (p[idx(s.key)] ?? null) as number | null]),
    }));
    if (peaks && data.resolution === "hourly" && data.peaks.length) {
      target.series.forEach((s) => out.push({
        key: `${s.key}-peak`, label: `${s.label} peak`, color: s.color, dashed: true,
        points: data.peaks.map((p) => [p[0] as number, (p[idx(s.key)] ?? null) as number | null]),
      }));
    }
    return out;
  }, [target, data, peaks]);

  const exportCsv = () => {
    if (!target || !data) return;
    const cols = data.columns;
    const lines = [cols.map((c) => (c === "ts" ? "time" : c)).join(","),
      ...data.points.map((p) => p.map((v, i) => (i === 0 ? new Date((v as number) * 1000).toISOString() : v ?? "")).join(","))];
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
    a.download = `${target.title.replace(/[^\w-]+/g, "_")}_${preset}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const zoomTo = (t0: number, t1: number) => {
    setZoomStack((z) => [...z, { preset, win }]);
    setPreset("custom");
    setWin({ since: t0, until: t1 });
  };
  const undoZoom = () => {
    const last = zoomStack[zoomStack.length - 1];
    if (!last) return;
    setZoomStack((z) => z.slice(0, -1));
    setPreset(last.preset);
    setWin(last.win);
  };

  const span = data ? data.until - data.since : 0;
  const xFormat = span > 2 * 86400 ? (t: number) => clock(t, true).slice(0, 6) : undefined;

  return (
    <AnimatePresence>
      {target && (
        <motion.div className="fixed inset-0 z-[65] flex items-center justify-center bg-black/70 p-3 backdrop-blur-sm sm:p-6"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
          <motion.div role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}
            initial={{ y: 20, scale: 0.98 }} animate={{ y: 0, scale: 1 }} exit={{ y: 10, scale: 0.98 }}
            className="panel panel-brackets flex max-h-full w-full max-w-6xl flex-col overflow-hidden">
            <header className="flex flex-wrap items-center gap-3 border-b border-edge px-5 py-3.5">
              <History size={17} className="text-cyan" />
              <div className="min-w-0 flex-1">
                <div className="truncate font-semibold">{target.title}</div>
                <div className="font-mono text-[10.5px] text-faint">
                  {data ? `${clock(data.since, true)} → ${clock(data.until, true)} · ${data.samples.toLocaleString()} samples` : " "}
                </div>
              </div>
              {data && <Badge tone={data.resolution === "hourly" ? "violet" : "cyan"}>{data.resolution === "hourly" ? "hourly rollup" : "per-minute"}</Badge>}
              <button className="btn btn-ghost !p-1.5" onClick={close} aria-label="Close"><X size={18} /></button>
            </header>

            <div className="flex flex-wrap items-center gap-3 px-5 pt-4">
              <Segmented value={preset === "custom" ? ("" as Preset) : preset} onChange={(p) => { setPreset(p); setWin(null); setZoomStack([]); }}
                options={PRESETS.map((p) => ({ value: p, label: p }))} />
              <div className={clsx("flex flex-wrap items-center gap-2 rounded-lg border px-2 py-1", preset === "custom" ? "border-cyan/40" : "border-edge")}>
                <CalendarRange size={14} className="text-faint" />
                <input type="datetime-local" className="bg-transparent font-mono text-xs outline-none [color-scheme:dark]"
                  value={toLocalInput(win?.since ?? data?.since ?? Date.now() / 1000 - 86400)}
                  onChange={(e) => { setPreset("custom"); setWin({ since: fromLocalInput(e.target.value), until: win?.until ?? data?.until ?? Date.now() / 1000 }); }} />
                <span className="text-faint">→</span>
                <input type="datetime-local" className="bg-transparent font-mono text-xs outline-none [color-scheme:dark]"
                  value={toLocalInput(win?.until ?? data?.until ?? Date.now() / 1000)}
                  onChange={(e) => { setPreset("custom"); setWin({ since: win?.since ?? data?.since ?? Date.now() / 1000 - 86400, until: fromLocalInput(e.target.value) }); }} />
              </div>
              {zoomStack.length > 0 && <button className="btn !py-1" onClick={undoZoom}><Undo2 size={14} /> Zoom out</button>}
              <div className="ml-auto flex items-center gap-3">
                {data?.resolution === "hourly" && <Toggle checked={peaks} onChange={setPeaks} label="peaks" />}
                <button className="btn !py-1" onClick={exportCsv} disabled={!data?.points.length}><Download size={14} /> CSV</button>
              </div>
            </div>

            <div className="relative min-h-0 flex-1 overflow-y-auto px-5 pt-3 pb-5">
              {error && <div className="mb-3 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">{error}</div>}
              <div className="relative">
                {loading && <div className="absolute inset-0 z-10 grid place-items-center bg-void/40"><Spinner size={24} /></div>}
                <AreaChart series={series} height={340} yFormat={(v) => formatUnit(target.unit, v)} xFormat={xFormat}
                  onSelectRange={zoomTo} empty={loading ? "Loading…" : "No data recorded for this window yet"} />
              </div>
              <div className="mt-1 text-center font-mono text-[10.5px] text-faint">drag across the chart to zoom in</div>

              {data && (
                <div className="mt-4 overflow-x-auto rounded-xl border border-edge">
                  <table className="table-hud">
                    <thead><tr><th>Series</th><th>Last</th><th>Min</th><th>Average</th><th>Max</th><th>95th pct</th>{target.unit === "bps" && <th>Data moved</th>}</tr></thead>
                    <tbody>
                      {target.series.map((s) => {
                        const st = data.stats[s.key];
                        return (
                          <tr key={s.key}>
                            <td><span className="flex items-center gap-2"><i className="h-2 w-2 rounded-full" style={{ background: s.color }} />{s.label}</span></td>
                            {(["last", "min", "avg", "max", "p95"] as const).map((k) => <td key={k} className="num text-xs">{formatUnit(target.unit, st?.[k])}</td>)}
                            {target.unit === "bps" && <td className="num text-xs">{bytes(st?.total_bytes)}</td>}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
