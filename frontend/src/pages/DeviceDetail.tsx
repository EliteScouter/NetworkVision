import clsx from "clsx";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  Cable,
  Cpu,
  Globe,
  Info,
  ListTree,
  type LucideIcon,
  MemoryStick,
  Network,
  RefreshCw,
  ScrollText,
  Search,
  Settings2,
  Thermometer,
  Timer,
  Users,
  Zap,
} from "lucide-react";
import { motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { AreaChart, type Series } from "../components/charts";
import { DeviceIcon, ROLE_LABEL } from "../components/DeviceIcon";
import { Badge, Drawer, Empty, Kv, Meter, Panel, Segmented, Spinner, StatusDot } from "../components/ui";
import { api } from "../lib/api";
import { ago, bps, clock, deviceColor, duration, ms, pct, SEV_NAMES, sevColor, speed, utilColor } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { Alert, DeviceDetail, Iface, LogItem } from "../lib/types";

type Range = "live" | "1h" | "6h" | "24h" | "7d";

function Stat({ icon: Icon, label, value, sub, meter, color }: {
  icon: LucideIcon; label: string; value: React.ReactNode; sub?: React.ReactNode; meter?: number | null; color?: string;
}) {
  return (
    <div className="panel p-3.5">
      <div className="flex items-center justify-between"><span className="hud-label">{label}</span><Icon size={14} className="text-faint" /></div>
      <div className="num mt-1.5 text-xl font-semibold" style={{ color }}>{value}</div>
      {meter != null && <Meter value={meter} className="mt-2" color={color} />}
      {sub && <div className="mt-1 truncate text-[11px] text-dim">{sub}</div>}
    </div>
  );
}

/** Switch faceplate: odd ports on top, even below, SFP cages to the right. */
function Faceplate({ ifaces, onPick }: { ifaces: Iface[]; onPick: (i: Iface) => void }) {
  const phys = ifaces.filter((i) => !["virtual", "tunnel", "lag", "loopback"].includes(i.media));
  const isSfp = (i: Iface) => /sfp/i.test(i.media) || (i.speed_mbps ?? 0) >= 10000;
  const copper = phys.filter((i) => !isSfp(i));
  const sfp = phys.filter(isSfp);
  const port = (i: Iface) => {
    const up = i.oper_up;
    const err = i.errors_per_min > 0 || i.flaps_10m >= 4;
    const c = up ? (err ? "#fb4d6d" : utilColor(i.util_pct)) : "#1e2d4d";
    const active = up && (i.rx_bps ?? 0) + (i.tx_bps ?? 0) > 1000;
    const label = i.index ?? i.name.replace(/\D+/g, "");
    return (
      <button key={i.name} onClick={() => onPick(i)} title={`${i.name}${i.alias ? ` (${i.alias})` : ""} — ${up ? `${speed(i.speed_mbps)} · ${bps((i.rx_bps ?? 0) + (i.tx_bps ?? 0))}` : "down"}`}
        className={clsx("group relative flex flex-col items-center gap-0.5")}>
        <span className={clsx("relative grid place-items-center border transition-transform group-hover:scale-110",
          isSfp(i) ? "h-6 w-8 rounded-[3px]" : "h-6 w-6 rounded-[4px]")}
          style={{ borderColor: up ? `${c}aa` : "#1e2d4d", background: up ? `${c}22` : "#070b16", boxShadow: up ? `0 0 10px -2px ${c}` : undefined }}>
          <span className={clsx("h-1.5 w-1.5 rounded-full", active && "animate-pulse")} style={{ background: up ? c : "#334155" }} />
          {i.poe_w ? <Zap size={8} className="absolute -top-1 -right-1 text-warn" /> : null}
          {i.is_uplink && <span className="absolute -bottom-1 h-0.5 w-3 rounded bg-violet shadow-[0_0_6px_#a78bfa]" />}
        </span>
        <span className="font-mono text-[8.5px] text-faint">{String(label).slice(-3)}</span>
      </button>
    );
  };
  const rows = (list: Iface[]) => {
    const top = list.filter((_, n) => n % 2 === 0), bottom = list.filter((_, n) => n % 2 === 1);
    return list.length > 12 ? (
      <div className="flex flex-col gap-1.5"><div className="flex gap-1.5">{top.map(port)}</div><div className="flex gap-1.5">{bottom.map(port)}</div></div>
    ) : <div className="flex gap-1.5">{list.map(port)}</div>;
  };
  if (phys.length < 2) return null;
  return (
    <div className="overflow-x-auto">
      <div className="inline-flex items-center gap-6 rounded-xl border border-edge bg-gradient-to-b from-[#0d1528] to-[#060a14] px-5 py-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
        {copper.length > 0 && rows(copper)}
        {sfp.length > 0 && <div className="border-l border-edge pl-6">{rows(sfp)}</div>}
      </div>
    </div>
  );
}

function SectionTable({ s }: { s: DeviceDetail["sections"][number] }) {
  const [q, setQ] = useState("");
  const rows = q ? s.rows.filter((r) => r.join(" ").toLowerCase().includes(q.toLowerCase())) : s.rows;
  const cell = (v: unknown) => (typeof v === "boolean" ? <Badge tone={v ? "ok" : "neutral"}>{v ? "yes" : "no"}</Badge> : v == null ? "—" : String(v));
  if (s.kind === "kv") return <div>{s.rows.map((r, i) => <Kv key={i} k={String(r[0])} v={cell(r[1])} />)}</div>;
  return (
    <div>
      {s.rows.length > 8 && (
        <div className="mb-2 flex items-center gap-2 rounded-lg border border-edge bg-black/30 px-2.5">
          <Search size={13} className="text-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={`Filter ${s.rows.length} rows…`} className="h-8 flex-1 bg-transparent text-sm outline-none" />
        </div>
      )}
      <div className="max-h-[420px] overflow-auto rounded-lg border border-edge">
        <table className="table-hud">
          <thead><tr>{s.columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}>{r.map((v, j) => <td key={j} className="font-mono text-xs">{cell(v)}</td>)}</tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

function IfaceDrawer({ deviceId, iface, onClose }: { deviceId: number; iface: Iface | null; onClose: () => void }) {
  const [range, setRange] = useState<Range>("live");
  const { data } = useApi<{ points: (number | null)[][] }>(iface && range !== "live" ? `/devices/${deviceId}/interfaces/metrics` : null, 30000,
    iface ? { ifname: iface.name, range } : undefined);
  const series: Series[] = useMemo(() => {
    if (!iface) return [];
    const pts = range === "live" ? iface.history.map((p) => [p[0], p[1], p[2]]) : (data?.points ?? []);
    return [
      { key: "rx", label: "Rx", color: "#22d3ee", points: pts.map((p) => [p[0] as number, p[1] as number | null]) },
      { key: "tx", label: "Tx", color: "#f472b6", points: pts.map((p) => [p[0] as number, p[2] as number | null]) },
    ];
  }, [iface, data, range]);
  return (
    <Drawer open={!!iface} onClose={onClose} title={iface ? <span>{iface.name} {iface.alias && <span className="text-dim">· {iface.alias}</span>}</span> : ""}>
      {iface && (
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <Badge tone={iface.oper_up ? "up" : "down"}>{iface.oper_up ? "link up" : "link down"}</Badge>
            <Segmented value={range} onChange={setRange} options={(["live", "1h", "6h", "24h", "7d"] as Range[]).map((r) => ({ value: r, label: r }))} />
          </div>
          <AreaChart series={series} height={240} yFormat={(v) => bps(v, 0)} />
          <div className="grid grid-cols-2 gap-x-6">
            <Kv k="Speed" v={speed(iface.speed_mbps)} />
            <Kv k="Utilization" v={pct(iface.util_pct, 1)} />
            <Kv k="Rx" v={bps(iface.rx_bps)} />
            <Kv k="Tx" v={bps(iface.tx_bps)} />
            <Kv k="Errors / min" v={iface.errors_per_min.toFixed(1)} />
            <Kv k="Link changes (10m)" v={iface.flaps_10m} />
            <Kv k="Media" v={iface.media || "—"} />
            <Kv k="MAC" v={iface.mac || "—"} />
            {iface.poe_w != null && <Kv k="PoE" v={`${iface.poe_w.toFixed(1)} W`} />}
            {iface.rx_pps != null && <Kv k="Rx / Tx pps" v={`${iface.rx_pps.toFixed(0)} / ${iface.tx_pps?.toFixed(0)}`} />}
            {iface.vlan && <Kv k="VLAN" v={iface.vlan} />}
            {Object.entries(iface.extra ?? {}).filter(([, v]) => v != null && typeof v !== "object").map(([k, v]) => <Kv key={k} k={k} v={String(v)} />)}
          </div>
          {iface.extra?.sfp ? (
            <div><div className="hud-label mb-1">SFP module</div>
              {Object.entries(iface.extra.sfp as Record<string, unknown>).map(([k, v]) => <Kv key={k} k={k.replace("sfp_", "")} v={String(v)} />)}
            </div>
          ) : null}
        </div>
      )}
    </Drawer>
  );
}

export default function DeviceDetailPage() {
  const { id } = useParams();
  const { data: d, error, reload } = useApi<DeviceDetail>(`/devices/${id}`, 5000);
  const [range, setRange] = useState<Range>("live");
  const { data: hist } = useApi<{ columns: string[]; points: (number | null)[][] }>(range !== "live" ? `/devices/${id}/metrics` : null, 30000, { range });
  const { data: logData } = useApi<{ items: LogItem[] }>(`/logs`, 10000, { device_id: Number(id), limit: 80 });
  const { data: alertHist } = useApi<{ items: Alert[] }>(`/alerts`, 30000, { state: "all", device_id: Number(id), limit: 30 });
  const liveAlerts = useLive((s) => s.alerts);
  const [iface, setIface] = useState<Iface | null>(null);
  const [ifq, setIfq] = useState("");
  const [onlyUp, setOnlyUp] = useState(false);
  const [section, setSection] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  useTick(5000);

  const series = useMemo(() => {
    if (!d) return null;
    let pts: (number | null)[][];
    let idx: Record<string, number>;
    if (range === "live") {
      pts = d.history; // ts, rx, tx, cpu, mem, latency
      idx = { rx_bps: 1, tx_bps: 2, cpu: 3, mem: 4, latency_ms: 5 };
    } else {
      pts = hist?.points ?? [];
      idx = Object.fromEntries((hist?.columns ?? []).map((c, i) => [c, i]));
    }
    const s = (key: string, label: string, color: string): Series => ({ key, label, color, points: pts.map((p) => [p[0] as number, (p[idx[key]] ?? null) as number | null]) });
    return {
      traffic: [s("rx_bps", "Rx", "#22d3ee"), s("tx_bps", "Tx", "#f472b6")],
      sys: [s("cpu", "CPU", "#22d3ee"), s("mem", "Memory", "#a78bfa")],
      latency: [s("latency_ms", "Latency", "#fbbf24")],
    };
  }, [d, hist, range]);

  if (error && !d) return <div className="p-6"><Panel><Empty icon={<AlertTriangle size={28} />} title="Device not found">{error}</Empty></Panel></div>;
  if (!d) return <div className="grid h-64 place-items-center"><Spinner size={26} /></div>;

  const c = deviceColor(d.status, d.health);
  const deviceAlerts = Object.values(liveAlerts).filter((a) => a.device_id === d.id);
  const ifs = d.interfaces.filter((i) => (!onlyUp || i.oper_up) && (!ifq || `${i.name} ${i.alias} ${i.vlan}`.toLowerCase().includes(ifq.toLowerCase())));
  const curSection = d.sections.find((s) => s.id === section) ?? d.sections[0];
  const m = d.metrics;
  const hasSys = d.history.some((p) => p[3] != null || p[4] != null) || range !== "live";
  const hasLatency = d.history.some((p) => p[5] != null) || range !== "live";

  const pollNow = async () => {
    setPolling(true);
    await api(`/devices/${d.id}/poll`, { method: "POST" }).catch(() => {});
    setTimeout(() => { reload(); setPolling(false); }, 2500);
  };

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      {/* header */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="panel panel-brackets relative overflow-hidden p-5">
        <div className="absolute -top-24 -left-24 h-64 w-64 rounded-full opacity-25 blur-3xl" style={{ background: c }} />
        <div className="relative flex flex-wrap items-start gap-4">
          <Link to="/devices" className="btn btn-ghost !p-2" aria-label="Back"><ArrowLeft size={18} /></Link>
          <div className="grid h-14 w-14 place-items-center rounded-2xl border bg-black/30" style={{ borderColor: `${c}66`, color: c, boxShadow: `0 0 30px -8px ${c}` }}>
            <DeviceIcon role={d.role} size={26} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-2xl font-semibold tracking-tight">{d.name}</h2>
              <Badge tone={d.status}>{d.status}</Badge>
              {d.health !== "ok" && <Badge tone={d.health}>{d.health}</Badge>}
              {d.tags.map((t) => <Badge key={t} tone="violet">{t}</Badge>)}
            </div>
            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-dim">
              <span>{d.host || "—"}</span>
              <span>{[d.vendor, d.model].filter(Boolean).join(" ") || d.kind}</span>
              {d.version && <span>v{d.version}</span>}
              <span>{ROLE_LABEL[d.role] ?? d.role}</span>
              {d.location && <span>@ {d.location}</span>}
              {d.parent_id && <Link to={`/devices/${d.parent_id}`} className="text-cyan">managed by #{d.parent_id}</Link>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="mr-2 text-right font-mono text-[11px] text-faint">
              <div>polled {ago(d.last_poll)}</div>
              {d.poll_ms != null && <div>{d.poll_ms.toFixed(0)} ms</div>}
            </div>
            <button className="btn" onClick={pollNow} disabled={polling}><RefreshCw size={15} className={polling ? "animate-spin" : ""} /> Poll now</button>
            {!d.parent_id && <Link to={`/integrations?edit=${d.id}`} className="btn"><Settings2 size={15} /> Configure</Link>}
          </div>
        </div>
        {d.error && (
          <div className={clsx("relative mt-4 flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
            d.status === "down" ? "border-crit/40 bg-crit/10 text-crit" : "border-warn/40 bg-warn/10 text-warn")}>
            <AlertTriangle size={15} /> {d.error}
          </div>
        )}
      </motion.div>

      {/* stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat icon={Cpu} label="CPU" value={pct(m.cpu, 1)} meter={m.cpu} sub={m.load1 != null ? `load ${m.load1.toFixed(2)}` : undefined} />
        <Stat icon={MemoryStick} label="Memory" value={pct(m.mem, 1)} meter={m.mem} color="#a78bfa" />
        <Stat icon={Thermometer} label="Temperature" value={m.temp != null ? `${m.temp.toFixed(0)}°C` : "—"} color={(m.temp ?? 0) > 75 ? "#fb4d6d" : undefined} />
        <Stat icon={Timer} label="Latency" value={ms(m.latency_ms)} sub={m.loss_pct != null ? `${m.loss_pct.toFixed(0)}% loss` : undefined} />
        <Stat icon={Activity} label="Throughput" value={bps(d.rx_bps + d.tx_bps)} sub={<><span className="text-cyan">↓{bps(d.rx_bps)}</span> <span className="text-magenta">↑{bps(d.tx_bps)}</span></>} />
        <Stat icon={m.clients != null ? Users : Timer} label={m.clients != null ? "Clients" : "Uptime"} value={m.clients != null ? m.clients : duration(m.uptime_s)}
          sub={m.clients != null ? `up ${duration(m.uptime_s)}` : undefined} />
      </div>

      {/* charts */}
      <Panel title="Performance" icon={<Activity size={15} />}
        actions={<Segmented value={range} onChange={setRange} options={(["live", "1h", "6h", "24h", "7d"] as Range[]).map((r) => ({ value: r, label: r }))} />}>
        <div className="grid gap-5 lg:grid-cols-3">
          <div><div className="hud-label mb-1">Traffic</div><AreaChart series={series!.traffic} height={190} yFormat={(v) => bps(v, 0)} /></div>
          {hasSys && <div><div className="hud-label mb-1">CPU / Memory %</div><AreaChart series={series!.sys} height={190} yFormat={(v) => `${v.toFixed(0)}%`} /></div>}
          {hasLatency && <div><div className="hud-label mb-1">Latency</div><AreaChart series={series!.latency} height={190} yFormat={(v) => `${v.toFixed(0)}ms`} /></div>}
        </div>
      </Panel>

      {/* ports */}
      {d.interfaces.length > 0 && (
        <Panel title={`Interfaces · ${d.interfaces.filter((i) => i.oper_up).length}/${d.interfaces.length} up`} icon={<Cable size={15} />}
          actions={
            <div className="flex items-center gap-2">
              <button className="chip" data-active={onlyUp} onClick={() => setOnlyUp(!onlyUp)}>up only</button>
              <div className="flex items-center gap-1.5 rounded-lg border border-edge bg-black/30 px-2">
                <Search size={13} className="text-faint" />
                <input value={ifq} onChange={(e) => setIfq(e.target.value)} placeholder="filter" className="h-7 w-28 bg-transparent text-xs outline-none" />
              </div>
            </div>
          }>
          <div className="mb-4"><Faceplate ifaces={d.interfaces} onPick={setIface} /></div>
          <div className="max-h-[520px] overflow-auto rounded-lg border border-edge">
            <table className="table-hud min-w-[860px]">
              <thead><tr><th></th><th>Port</th><th>Description</th><th>Speed</th><th>Rx</th><th>Tx</th><th className="w-40">Util</th><th>Err/min</th><th>Flaps</th><th>PoE</th></tr></thead>
              <tbody>
                {ifs.map((i) => (
                  <tr key={i.name} className="cursor-pointer" onClick={() => setIface(i)}>
                    <td className="w-6"><StatusDot status={i.oper_up ? "up" : i.admin_up === false ? "disabled" : "down"} pulse={false} size={7} /></td>
                    <td className="font-mono text-xs">{i.name}{i.is_uplink && <Badge tone="violet" className="ml-2">uplink</Badge>}</td>
                    <td className="max-w-[220px] truncate text-dim">{i.alias || "—"}</td>
                    <td className="num text-xs text-dim">{i.oper_up ? speed(i.speed_mbps) : "—"}</td>
                    <td className="num text-xs text-cyan">{i.oper_up ? bps(i.rx_bps) : "—"}</td>
                    <td className="num text-xs text-magenta">{i.oper_up ? bps(i.tx_bps) : "—"}</td>
                    <td>{i.util_pct != null && i.oper_up ? <div className="flex items-center gap-2"><Meter value={i.util_pct} className="flex-1" color={utilColor(i.util_pct)} /><span className="num w-10 text-right text-[11px]">{pct(i.util_pct)}</span></div> : <span className="text-faint">—</span>}</td>
                    <td className={clsx("num text-xs", i.errors_per_min > 0 ? "text-crit" : "text-faint")}>{i.errors_per_min.toFixed(0)}</td>
                    <td className={clsx("num text-xs", i.flaps_10m >= 4 ? "text-warn" : "text-faint")}>{i.flaps_10m}</td>
                    <td className="num text-xs text-dim">{i.poe_w != null ? `${i.poe_w.toFixed(1)}W` : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <div className="grid gap-4 xl:grid-cols-3">
        {/* left column */}
        <div className="space-y-4 xl:col-span-2">
          {d.gateways.length > 0 && (
            <Panel title="Gateways" icon={<Globe size={15} />}>
              <div className="grid gap-2 sm:grid-cols-2">
                {d.gateways.map((g) => (
                  <div key={g.name} className="flex items-center gap-3 rounded-xl border border-edge bg-black/20 p-3">
                    <StatusDot status={g.up === false ? "down" : "up"} health={g.up === false ? "critical" : "ok"} />
                    <div className="min-w-0 flex-1"><div className="truncate font-medium">{g.name}</div><div className="truncate font-mono text-[11px] text-faint">{g.address} {g.detail && `· ${g.detail}`}</div></div>
                    <div className="text-right"><div className="num text-sm">{ms(g.latency_ms)}</div><div className="num text-[11px] text-dim">{(g.loss_pct ?? 0).toFixed(1)}% loss</div></div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {d.sections.length > 0 && (
            <Panel title="Configuration & state" icon={<ListTree size={15} />}>
              <div className="mb-3 flex flex-wrap gap-1.5">
                {d.sections.map((s) => (
                  <button key={s.id} className="chip" data-active={curSection?.id === s.id} onClick={() => setSection(s.id)}>{s.title}</button>
                ))}
              </div>
              {curSection && <SectionTable key={curSection.id} s={curSection} />}
            </Panel>
          )}

          <Panel title="Recent logs" icon={<ScrollText size={15} />}
            actions={<Link to={`/logs?device=${d.id}`} className="text-xs text-dim hover:text-cyan">Open in explorer</Link>}>
            <div className="max-h-[380px] overflow-y-auto font-mono text-[12px] leading-6">
              {!logData?.items.length && <div className="py-6 text-center text-faint">No logs from this device yet. Point its syslog at NetworkVision.</div>}
              {logData?.items.map((l) => (
                <div key={l.id} className="flex gap-3 border-b border-edge/40 px-1 hover:bg-white/[0.02]">
                  <span className="shrink-0 text-faint">{clock(l.ts, true)}</span>
                  <span className={clsx("w-14 shrink-0", sevColor(l.severity))}>{SEV_NAMES[l.severity]}</span>
                  <span className="w-24 shrink-0 truncate text-violet/80">{l.app}</span>
                  <span className="break-all text-ink/85">{l.message}</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        {/* right column */}
        <div className="space-y-4">
          <Panel title={`Alerts · ${deviceAlerts.length} active`} icon={<AlertTriangle size={15} />}>
            <div className="max-h-[360px] space-y-2 overflow-y-auto">
              {!alertHist?.items.length && <div className="py-4 text-center text-sm text-faint">No alerts recorded.</div>}
              {alertHist?.items.map((a) => (
                <div key={a.id} className={clsx("rounded-lg border p-2.5", a.resolved_at ? "border-edge opacity-60" : a.severity === "critical" ? "border-crit/40" : "border-warn/30")}>
                  <div className="flex items-center justify-between"><Badge tone={a.resolved_at ? "ok" : a.severity}>{a.resolved_at ? "resolved" : a.severity}</Badge><span className="font-mono text-[10.5px] text-faint">{ago(a.started_at)}</span></div>
                  <div className="mt-1 text-sm">{a.title}</div>
                  {a.detail && <div className="text-xs text-dim">{a.detail}</div>}
                </div>
              ))}
            </div>
          </Panel>

          {d.neighbors.length > 0 && (
            <Panel title="Neighbors" icon={<Network size={15} />}>
              {d.neighbors.map((n, i) => (
                <Kv key={i} k={<span className="font-mono text-xs">{n.local_port || "?"}</span>}
                  v={<span>{n.remote_name || n.remote_mac || n.remote_ip} <span className="text-faint">{n.remote_port}</span></span>} />
              ))}
            </Panel>
          )}

          {d.children.length > 0 && (
            <Panel title={`Managed devices · ${d.children.length}`} icon={<Network size={15} />}>
              <div className="space-y-1.5">
                {d.children.map((ch) => (
                  <Link key={ch.id} to={`/devices/${ch.id}`} className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-white/[0.03]">
                    <StatusDot status={ch.status} health={ch.health} size={7} />
                    <DeviceIcon role={ch.role} size={14} className="text-dim" />
                    <span className="flex-1 truncate text-sm">{ch.name}</span>
                    <span className="font-mono text-[11px] text-faint">{ch.model}</span>
                  </Link>
                ))}
              </div>
            </Panel>
          )}

          <Panel title="Facts" icon={<Info size={15} />}>
            {Object.entries(d.facts).filter(([, v]) => v !== "" && v != null && typeof v !== "object").map(([k, v]) => (
              <Kv key={k} k={k.replace(/_/g, " ")} v={String(v)} />
            ))}
            <Kv k="integration" v={d.kind} />
            <Kv k="last seen" v={d.last_ok ? clock(d.last_ok, true) : "never"} />
          </Panel>
        </div>
      </div>

      <IfaceDrawer deviceId={d.id} iface={iface ? d.interfaces.find((i) => i.name === iface.name) ?? iface : null} onClose={() => setIface(null)} />
    </div>
  );
}
