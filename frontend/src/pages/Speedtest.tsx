import clsx from "clsx";
import { ArrowDownToLine, ArrowUpFromLine, Gauge as GaugeIcon, History, Play, Settings2, Timer, Waves } from "lucide-react";
import { animate, motion, useMotionValue, useTransform } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { AreaChart, type Series } from "../components/charts";
import { useHistory } from "../components/HistoryExplorer";
import { Badge, Field, Kv, Panel, Spinner, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { ago, bps, bytes, clock } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { HistoryResponse, SpeedResult, SpeedSettings, SpeedStatus } from "../lib/types";

const TICKS = [0, 10, 50, 100, 250, 500, 1000, 2500, 5000, 10000]; // Mbps, log-ish scale
const ARC = 260; // degrees of sweep

/** Mbps -> 0..1 position on a log scale that still shows 0. */
function pos(mbps: number) {
  const v = Math.max(0, mbps);
  return Math.min(1, Math.log10(1 + v) / Math.log10(1 + TICKS[TICKS.length - 1]));
}

function Speedometer({ mbps, phase, running }: { mbps: number; phase?: string; running: boolean }) {
  const mv = useMotionValue(0);
  useEffect(() => {
    const ctrl = animate(mv, pos(mbps), { type: "spring", stiffness: 60, damping: 14 });
    return () => ctrl.stop();
  }, [mbps, mv]);
  const angle = useTransform(mv, (p) => -ARC / 2 + p * ARC);
  const size = 320, cx = size / 2, cy = size / 2 + 10, r = 130;
  const color = phase === "upload" ? "#f472b6" : "#22d3ee";
  const arcPath = (frac: number) => {
    const a0 = ((-ARC / 2 - 90) * Math.PI) / 180, a1 = ((-ARC / 2 - 90 + ARC * frac) * Math.PI) / 180;
    return `M${cx + r * Math.cos(a0)},${cy + r * Math.sin(a0)} A${r},${r} 0 ${ARC * frac > 180 ? 1 : 0} 1 ${cx + r * Math.cos(a1)},${cy + r * Math.sin(a1)}`;
  };
  const fill = useTransform(mv, (p) => arcPath(Math.max(0.001, p)));
  return (
    <svg width="100%" viewBox={`0 0 ${size} ${size - 30}`} className="max-w-[420px]">
      <path d={arcPath(1)} fill="none" stroke="#16233d" strokeWidth={16} strokeLinecap="round" />
      <motion.path d={fill} fill="none" stroke={color} strokeWidth={16} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 10px ${color})` }} />
      {TICKS.map((t) => {
        const a = ((-ARC / 2 - 90 + ARC * pos(t)) * Math.PI) / 180;
        return (
          <g key={t}>
            <line x1={cx + (r - 22) * Math.cos(a)} y1={cy + (r - 22) * Math.sin(a)} x2={cx + (r - 14) * Math.cos(a)} y2={cy + (r - 14) * Math.sin(a)} stroke="#4a5878" strokeWidth={2} />
            <text x={cx + (r - 38) * Math.cos(a)} y={cy + (r - 38) * Math.sin(a) + 4} textAnchor="middle" fontSize={11} fill="#7f8fb0" className="num">
              {t >= 1000 ? `${t / 1000}G` : t}
            </text>
          </g>
        );
      })}
      <motion.g style={{ rotate: angle, originX: `${cx}px`, originY: `${cy}px` }}>
        <line x1={cx} y1={cy} x2={cx} y2={cy - r + 30} stroke="#e6f1ff" strokeWidth={3} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
      </motion.g>
      <circle cx={cx} cy={cy} r={9} fill="#070b16" stroke={color} strokeWidth={3} />
      <text x={cx} y={cy + 52} textAnchor="middle" className="num" fontSize={38} fontWeight={600} fill="#e6f1ff">
        {mbps >= 1000 ? (mbps / 1000).toFixed(2) : mbps.toFixed(mbps >= 100 ? 0 : 1)}
      </text>
      <text x={cx} y={cy + 72} textAnchor="middle" fontSize={11} letterSpacing="0.15em" fill="#7f8fb0">
        {mbps >= 1000 ? "GBPS" : "MBPS"}{running && phase ? ` · ${phase.toUpperCase()}` : ""}
      </text>
    </svg>
  );
}

/** Bufferbloat grade from extra latency under load (same idea as the Waveform/DSLReports grades). */
function bloatGrade(idle?: number | null, loaded?: number | null) {
  if (idle == null || loaded == null) return null;
  const d = loaded - idle;
  const [g, c] = d < 5 ? ["A+", "#34d399"] : d < 30 ? ["A", "#34d399"] : d < 60 ? ["B", "#22d3ee"] : d < 200 ? ["C", "#fbbf24"] : d < 400 ? ["D", "#fb923c"] : ["F", "#fb4d6d"];
  return { grade: g, color: c, delta: d };
}

const INTERVALS = [15, 30, 60, 120, 240, 360, 720, 1440];

function SettingsPanel({ settings, last, onSaved }: { settings: SpeedSettings; last: SpeedResult | null; onSaved: () => void }) {
  const [f, setF] = useState(settings);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => setF(settings), [settings]);
  const perRun = last?.bytes_used ? last.bytes_used * (f.duration_s / Math.max(1, settings.duration_s)) : null;
  const perDay = perRun && f.enabled ? (perRun * 1440) / f.interval_min : null;
  const save = async () => {
    setBusy(true); setMsg(null);
    try { await api("/speedtest/settings", { method: "PUT", body: f }); setMsg("Saved"); onSaved(); }
    catch (e) { setMsg((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-4">
      <Toggle checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Run automatically" />
      <div className="grid grid-cols-2 gap-3">
        <Field label="Every">
          <select className="input" value={f.interval_min} onChange={(e) => setF({ ...f, interval_min: +e.target.value })}>
            {INTERVALS.map((m) => <option key={m} value={m}>{m < 60 ? `${m} min` : `${m / 60} h`}</option>)}
          </select>
        </Field>
        <Field label="Duration per direction">
          <select className="input" value={f.duration_s} onChange={(e) => setF({ ...f, duration_s: +e.target.value })}>
            {[3, 5, 6, 8, 10, 15, 20].map((s) => <option key={s} value={s}>{s} s</option>)}
          </select>
        </Field>
        <Field label="Parallel streams" help="More streams = better at multi-gig">
          <input className="input" type="number" min={1} max={16} value={f.streams} onChange={(e) => setF({ ...f, streams: +e.target.value })} />
        </Field>
        <Field label="Alert below (% of expected)">
          <input className="input" type="number" min={10} max={100} value={f.alert_pct} onChange={(e) => setF({ ...f, alert_pct: +e.target.value })} />
        </Field>
        <Field label="Expected download (Mbps)" help="Your plan speed; blank = no alert">
          <input className="input" type="number" min={0} value={f.expected_down_mbps ?? ""} onChange={(e) => setF({ ...f, expected_down_mbps: e.target.value ? +e.target.value : null })} />
        </Field>
        <Field label="Expected upload (Mbps)">
          <input className="input" type="number" min={0} value={f.expected_up_mbps ?? ""} onChange={(e) => setF({ ...f, expected_up_mbps: e.target.value ? +e.target.value : null })} />
        </Field>
      </div>
      {perRun && (
        <div className={clsx("rounded-lg border p-2.5 text-xs", (perDay ?? 0) > 50e9 ? "border-warn/40 bg-warn/10 text-warn" : "border-edge bg-black/20 text-dim")}>
          Each test moves about <b>{bytes(perRun)}</b>{perDay ? <> - roughly <b>{bytes(perDay)}/day</b> at this interval</> : null}. Mind any ISP data caps.
        </div>
      )}
      <div className="flex items-center gap-3">
        <button className="btn btn-primary" onClick={save} disabled={busy}>{busy ? <Spinner size={14} /> : null}Save settings</button>
        {msg && <span className="text-xs text-dim">{msg}</span>}
      </div>
    </div>
  );
}

export default function SpeedtestPage() {
  const { data, reload } = useApi<SpeedStatus>("/speedtest", 15000);
  const { data: hist, reload: reloadHist } = useApi<HistoryResponse>("/history/speedtest", 60000, { range: "7d" });
  const live = useLive((s) => s.speed);
  const openHistory = useHistory((s) => s.open);
  const [starting, setStarting] = useState(false);
  useTick(1000);

  const running = (live?.state === "running") || !!data?.running;
  useEffect(() => {
    if (live?.state === "done") { reload(); reloadHist(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live?.state]);

  const last = data?.last ?? null;
  const shown = running ? live?.mbps ?? 0 : (last?.download_bps ?? 0) / 1e6;
  const grade = bloatGrade(last?.latency_ms, last?.loaded_latency_ms);
  const runNow = async () => {
    setStarting(true);
    try { await api("/speedtest/run", { method: "POST" }); } catch { /* already running */ } finally { setStarting(false); reload(); }
  };

  const series = useMemo((): { speed: Series[]; latency: Series[] } => {
    const pts = hist?.points ?? [];
    const col = (k: string) => (hist?.columns ?? []).indexOf(k);
    const mk = (k: string, label: string, color: string): Series => ({ key: k, label, color, points: pts.map((p) => [p[0] as number, (p[col(k)] ?? null) as number | null]) });
    return { speed: [mk("download_bps", "Download", "#22d3ee"), mk("upload_bps", "Upload", "#f472b6")],
      latency: [mk("latency_ms", "Latency", "#a78bfa"), mk("jitter_ms", "Jitter", "#fbbf24")] };
  }, [hist]);

  const openSpeed = () => openHistory({ kind: "speedtest", title: "Internet speed history", unit: "bps",
    series: [{ key: "download_bps", label: "Download", color: "#22d3ee" }, { key: "upload_bps", label: "Upload", color: "#f472b6" }] });
  const openLatency = () => openHistory({ kind: "speedtest", title: "Latency history", unit: "ms",
    series: [{ key: "latency_ms", label: "Latency", color: "#a78bfa" }, { key: "jitter_ms", label: "Jitter", color: "#fbbf24" }] });

  if (!data) return <div className="grid h-64 place-items-center"><Spinner size={26} /></div>;
  const next = data.next_run;

  return (
    <div className="mx-auto max-w-[1600px] space-y-4 p-4 md:p-6">
      <div className="grid gap-4 xl:grid-cols-5">
        <Panel className="xl:col-span-2" title="Speed test" icon={<GaugeIcon size={15} />}
          actions={<Badge tone="cyan">{data.engine === "demo" ? "demo engine" : "Cloudflare"}</Badge>}>
          <div className="flex flex-col items-center">
            <Speedometer mbps={shown} phase={live?.phase} running={running} />
            {running && (
              <div className="mb-3 h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-white/5">
                <motion.div className="h-full rounded-full bg-gradient-to-r from-cyan to-magenta" animate={{ width: `${(live?.progress ?? 0) * 100}%` }} />
              </div>
            )}
            <button className="btn btn-primary h-11 px-6" onClick={runNow} disabled={running || starting}>
              {running ? <><Spinner size={15} /> Testing {live?.phase ?? ""}…</> : <><Play size={16} /> Run test now</>}
            </button>
            <div className="mt-2 font-mono text-[11px] text-faint">
              {data.settings.enabled ? (next ? (next > Date.now() / 1000 ? `next automatic test ${clock(next)}` : "automatic test due") : "") : "automatic tests are off"}
            </div>
          </div>
        </Panel>

        <div className="grid grid-cols-2 gap-3 xl:col-span-3 xl:grid-cols-3">
          {[
            { icon: ArrowDownToLine, label: "Download", value: bps(last?.download_bps), color: "#22d3ee" },
            { icon: ArrowUpFromLine, label: "Upload", value: bps(last?.upload_bps), color: "#f472b6" },
            { icon: Timer, label: "Latency", value: last?.latency_ms != null ? `${last.latency_ms.toFixed(1)} ms` : "—", color: "#a78bfa", sub: last?.jitter_ms != null ? `jitter ${last.jitter_ms.toFixed(2)} ms` : undefined },
            { icon: Waves, label: "Under load", value: last?.loaded_latency_ms != null ? `${last.loaded_latency_ms.toFixed(1)} ms` : "—", color: grade?.color,
              sub: grade ? <>bufferbloat grade <b style={{ color: grade.color }}>{grade.grade}</b> (+{grade.delta.toFixed(0)} ms)</> : undefined },
          ].map((k, i) => (
            <motion.div key={k.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="panel p-4">
              <div className="flex items-center justify-between"><span className="hud-label">{k.label}</span><k.icon size={15} style={{ color: k.color }} /></div>
              <div className="num mt-2 text-2xl font-semibold" style={{ color: k.color }}>{k.value}</div>
              {k.sub && <div className="mt-1 text-[11px] text-dim">{k.sub}</div>}
            </motion.div>
          ))}
          <div className="panel col-span-2 p-4">
            <div className="hud-label mb-1">Last result</div>
            {last ? (
              <>
                <Kv k="When" v={`${clock(last.ts, true)} (${ago(last.ts)})`} />
                <Kv k="ISP" v={last.isp || "—"} />
                <Kv k="Test server" v={last.server || "—"} />
                <Kv k="Data used" v={bytes(last.bytes_used)} />
              </>
            ) : <div className="py-3 text-sm text-faint">No tests yet. Run one now.</div>}
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Speed · 7 days" icon={<History size={15} />}>
          <AreaChart series={series.speed} height={220} yFormat={(v) => bps(v, 0)} onExpand={openSpeed} empty="Charts appear after two or more tests"
            xFormat={(t) => clock(t, true).slice(0, 6)} />
        </Panel>
        <Panel title="Latency · 7 days" icon={<Timer size={15} />}>
          <AreaChart series={series.latency} height={220} yFormat={(v) => `${v.toFixed(1)}ms`} onExpand={openLatency} empty="Charts appear after two or more tests"
            xFormat={(t) => clock(t, true).slice(0, 6)} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Recent tests" icon={<History size={15} />} className="xl:col-span-2" bodyClass="!px-0">
          <div className="max-h-[420px] overflow-auto">
            <table className="table-hud min-w-[760px]">
              <thead><tr><th>When</th><th>Trigger</th><th>Download</th><th>Upload</th><th>Latency</th><th>Jitter</th><th>Loaded</th><th>Data</th><th>Server</th></tr></thead>
              <tbody>
                {data.recent.map((r) => (
                  <tr key={r.id} className={clsx(r.error && "bg-crit/[0.04]")}>
                    <td className="font-mono text-[11px] text-dim">{clock(r.ts, true)}</td>
                    <td><Badge tone={r.trigger === "manual" ? "violet" : "neutral"}>{r.trigger}</Badge></td>
                    {r.error ? <td colSpan={7} className="text-xs text-crit">{r.error}</td> : (
                      <>
                        <td className="num text-xs text-cyan">{bps(r.download_bps)}</td>
                        <td className="num text-xs text-magenta">{bps(r.upload_bps)}</td>
                        <td className="num text-xs">{r.latency_ms?.toFixed(1) ?? "—"} ms</td>
                        <td className="num text-xs text-dim">{r.jitter_ms?.toFixed(2) ?? "—"}</td>
                        <td className="num text-xs text-dim">{r.loaded_latency_ms?.toFixed(1) ?? "—"}</td>
                        <td className="num text-xs text-dim">{bytes(r.bytes_used)}</td>
                        <td className="text-xs text-dim">{r.server}</td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="Schedule & alerts" icon={<Settings2 size={15} />}>
          <SettingsPanel settings={data.settings} last={last} onSaved={reload} />
        </Panel>
      </div>
    </div>
  );
}
