import clsx from "clsx";
import { Activity, AlertTriangle, Radar, Radio as RadioIcon, Search, ShieldCheck, Signal, Users, Wifi } from "lucide-react";
import { motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { Gauge } from "../components/charts";
import { BAND_COLOR, BandBadge, ClientIcon, SignalBars } from "../components/ClientIcon";
import { useHistory } from "../components/HistoryExplorer";
import { Badge, Empty, Meter, Panel, Segmented, Spinner, StatusDot } from "../components/ui";
import { ago, duration } from "../lib/format";
import { useApi } from "../lib/hooks";
import type { AccessPoint, Neighbor, Radio, WifiResponse } from "../lib/types";

const BANDS = ["2.4", "5", "6"] as const;
type Band = (typeof BANDS)[number];
const FREQ = (band: Band, ch: number) => (band === "2.4" ? (ch === 14 ? 2484 : 2407 + 5 * ch) : band === "5" ? 5000 + 5 * ch : 5950 + 5 * ch);
const AXIS: Record<Band, { min: number; max: number; ticks: number[] }> = {
  "2.4": { min: 2400, max: 2495, ticks: [1, 3, 5, 7, 9, 11, 13] },
  "5": { min: 5160, max: 5895, ticks: [36, 52, 100, 116, 132, 149, 165] },
  "6": { min: 5945, max: 7125, ticks: [1, 37, 69, 101, 133, 165, 197, 229] },
};

const SECURITY: Record<string, string> = { wpapsk: "WPA Personal", wpaeap: "WPA Enterprise", open: "Open", osen: "OSEN" };

/** Airtime ring: own rx / own tx / interference / free. */
function AirtimeRing({ r, size = 92 }: { r: Radio; size?: number }) {
  const stroke = 9, rad = size / 2 - stroke, c = 2 * Math.PI * rad;
  const util = Math.min(100, r.utilization ?? 0);
  const parts = [
    { v: r.self_rx, color: "#22d3ee" },
    { v: r.self_tx, color: "#a78bfa" },
    { v: r.interference ?? 0, color: "#fb4d6d" },
  ];
  let offset = 0;
  const color = util >= 70 ? "#fb4d6d" : util >= 45 ? "#fbbf24" : "#34d399";
  return (
    <svg width={size} height={size} className="shrink-0">
      <circle cx={size / 2} cy={size / 2} r={rad} fill="none" stroke="#16233d" strokeWidth={stroke} />
      {parts.map((p, i) => {
        const len = (Math.min(100, p.v) / 100) * c;
        const el = (
          <motion.circle key={i} cx={size / 2} cy={size / 2} r={rad} fill="none" stroke={p.color} strokeWidth={stroke}
            strokeDashoffset={-offset} transform={`rotate(-90 ${size / 2} ${size / 2})`}
            initial={{ strokeDasharray: `0 ${c}` }} animate={{ strokeDasharray: `${len} ${c}` }} transition={{ duration: 1 }}
            style={{ filter: `drop-shadow(0 0 4px ${p.color}88)` }} />
        );
        offset += len;
        return el;
      })}
      <text x="50%" y="46%" textAnchor="middle" dominantBaseline="central" className="num" fontSize={size * 0.22} fill={color} fontWeight={600}>
        {util.toFixed(0)}%
      </text>
      <text x="50%" y="66%" textAnchor="middle" fontSize={8.5} fill="#7f8fb0" letterSpacing="0.1em">AIRTIME</text>
    </svg>
  );
}

function RadioCard({ ap, r }: { ap: AccessPoint; r: Radio }) {
  const open = useHistory((s) => s.open);
  const canHistory = ap.device_id != null;
  return (
    <button type="button" disabled={!canHistory}
      onClick={() => canHistory && open({
        kind: "radio", title: `${ap.name} · ${r.band} GHz radio`, filters: { device_id: ap.device_id!, radio: r.band }, unit: "pct",
        series: [{ key: "utilization", label: "Utilization", color: "#22d3ee" }, { key: "interference", label: "Interference", color: "#fb4d6d" },
          { key: "retries_pct", label: "Retries", color: "#fbbf24" }],
      })}
      className="flex items-center gap-3 rounded-xl border border-edge bg-black/25 p-3 text-left transition enabled:hover:border-cyan/40 enabled:hover:bg-cyan/[0.03]">
      <AirtimeRing r={r} />
      <div className="min-w-0 flex-1 space-y-1 text-xs">
        <div className="flex items-center gap-2"><BandBadge band={r.band} />{r.standard && <span className="font-mono text-[10px] text-violet">{r.standard}</span>}
          {r.dfs && <span className="font-mono text-[10px] text-faint">DFS</span>}</div>
        <div className="num text-sm text-ink">ch {r.channel ?? "?"} <span className="text-dim">· {r.width ?? "?"} MHz</span></div>
        <div className="flex justify-between text-dim"><span>Clients</span><span className="num text-ink">{r.clients ?? 0}</span></div>
        <div className="flex justify-between text-dim"><span>TX power</span><span className="num text-ink">{r.tx_power ?? "?"} dBm{r.tx_power_mode ? ` · ${r.tx_power_mode}` : ""}</span></div>
        <div className="flex justify-between text-dim"><span>Retries</span><span className={clsx("num", (r.retries_pct ?? 0) > 15 ? "text-warn" : "text-ink")}>{r.retries_pct?.toFixed(1) ?? "?"}%</span></div>
        <div className="flex justify-between text-dim"><span>Interference</span><span className={clsx("num", (r.interference ?? 0) > 30 ? "text-crit" : "text-ink")}>{r.interference?.toFixed(0) ?? "?"}%</span></div>
      </div>
    </button>
  );
}

function ChannelMap({ band, aps, neighbors }: { band: Band; aps: AccessPoint[]; neighbors: Neighbor[] }) {
  const ax = AXIS[band];
  const W = 1000, H = 260, padB = 26, padT = 12;
  const x = (f: number) => ((f - ax.min) / (ax.max - ax.min)) * W;
  const y = (sig: number) => padT + (H - padB - padT) * (1 - Math.max(0, Math.min(1, (sig + 95) / 65)));
  const shape = (ch: number, width: number, sig: number) => {
    const f = FREQ(band, ch);
    const half = (width || 20) / 2;
    const [l, r, top] = [x(f - half), x(f + half), y(sig)];
    const base = H - padB;
    return `M${l},${base} C${l + (r - l) * 0.12},${top} ${r - (r - l) * 0.12},${top} ${r},${base} Z`;
  };
  const own = aps.flatMap((ap) => ap.radios.filter((r) => r.band === band && r.channel != null).map((r) => ({ ap, r })));
  const nb = neighbors.filter((n) => n.band === band && n.channel != null && n.signal != null);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-[260px] w-full" preserveAspectRatio="none">
      {[-90, -80, -70, -60, -50, -40].map((s) => (
        <g key={s}><line x1={0} x2={W} y1={y(s)} y2={y(s)} stroke="#16233d" strokeDasharray="2 6" />
          <text x={4} y={y(s) - 3} fontSize={10} fill="#4a5878" className="num">{s} dBm</text></g>
      ))}
      {nb.map((n, i) => (
        <path key={n.bssid + i} d={shape(n.channel!, n.width ?? 20, n.signal!)} fill="#7f8fb0" fillOpacity={0.06} stroke="#7f8fb0" strokeOpacity={0.35} strokeWidth={1}>
          <title>{`${n.ssid || "(hidden)"} · ch ${n.channel} · ${n.signal} dBm · seen by ${n.seen_by}`}</title>
        </path>
      ))}
      {own.map(({ ap, r }, i) => {
        const c = BAND_COLOR[band];
        const f = FREQ(band, r.channel!);
        return (
          <g key={ap.mac + r.name}>
            <motion.path d={shape(r.channel!, r.width ?? 20, -42 - i * 3)} fill={c} fillOpacity={0.16} stroke={c} strokeWidth={2}
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ filter: `drop-shadow(0 0 6px ${c})` }} />
            <text x={x(f)} y={y(-42 - i * 3) - 6} textAnchor="middle" fontSize={11} fill="#e6f1ff" fontWeight={600}
              style={{ paintOrder: "stroke", stroke: "#04060c", strokeWidth: 4 }}>{ap.name} · ch {r.channel}</text>
          </g>
        );
      })}
      {ax.ticks.map((ch) => (
        <text key={ch} x={x(FREQ(band, ch))} y={H - 8} textAnchor="middle" fontSize={11} fill="#7f8fb0" className="num">{ch}</text>
      ))}
    </svg>
  );
}

function Bars({ data, colors, total }: { data: [string, number][]; colors?: Record<string, string>; total: number }) {
  return (
    <div className="space-y-2">
      {data.map(([k, v]) => (
        <div key={k}>
          <div className="flex justify-between text-xs"><span className="text-dim">{k}</span><span className="num">{v}</span></div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
            <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${total ? (v / total) * 100 : 0}%` }}
              style={{ background: colors?.[k] ?? "#22d3ee", boxShadow: `0 0 8px ${colors?.[k] ?? "#22d3ee"}66` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function WifiPage() {
  const { data, loading } = useApi<WifiResponse>("/wifi", 10000);
  const [band, setBand] = useState<Band>("2.4");
  const [nq, setNq] = useState("");

  const s = data?.summary;
  const problem = useMemo(() => (data?.clients ?? [])
    .filter((c) => (c.signal != null && c.signal < -72) || (c.retries_pct ?? 0) > 20 || (c.satisfaction != null && c.satisfaction < 60))
    .sort((a, b) => (a.satisfaction ?? 100) - (b.satisfaction ?? 100)).slice(0, 12), [data]);
  const neighbors = useMemo(() => (data?.neighbors ?? []).filter((n) => !nq || `${n.ssid} ${n.bssid} ${n.channel}`.toLowerCase().includes(nq.toLowerCase())), [data, nq]);

  if (loading && !data) return <div className="grid h-64 place-items-center"><Spinner size={26} /></div>;
  if (!data?.aps.length) {
    return <div className="p-6"><Panel><Empty icon={<Wifi size={32} />} title="No WiFi data yet">Add your UniFi Network controller under Integrations to see access points, radios, SSIDs and neighbours.</Empty></Panel></div>;
  }
  const busiest = s?.busiest_radio;
  const sigTotal = Object.values(s?.by_signal ?? {}).reduce((a, b) => a + b, 0);
  const bandTotal = Object.values(s?.by_band ?? {}).reduce((a, b) => a + b, 0);
  const stdTotal = Object.values(s?.by_standard ?? {}).reduce((a, b) => a + b, 0);

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <div className="panel flex items-center justify-center p-2 md:row-span-1"><Gauge value={s?.satisfaction ?? 0} size={118} label="EXPERIENCE" /></div>
        {[
          { icon: RadioIcon, label: "Access points", value: `${s?.aps_online}/${s?.aps_total}`, sub: "online" },
          { icon: Users, label: "Wireless clients", value: s?.clients ?? 0, sub: Object.entries(s?.by_band ?? {}).map(([b, n]) => `${b}G ${n}`).join(" · ") },
          { icon: Signal, label: "Average signal", value: s?.avg_signal != null ? `${s.avg_signal.toFixed(0)} dBm` : "—", sub: "across connected clients" },
          { icon: Activity, label: "Busiest radio", value: busiest ? `${busiest.utilization?.toFixed(0)}%` : "—",
            sub: busiest ? `${busiest.band} GHz · ch ${busiest.channel} · ${busiest.clients} clients` : "", warn: (busiest?.utilization ?? 0) >= 60 },
          { icon: Radar, label: "Neighbour networks", value: s?.neighbors ?? 0, sub: `${s?.ssids} SSIDs of yours broadcasting` },
        ].map((k, i) => (
          <motion.div key={k.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }} className="panel p-4">
            <div className="flex items-center justify-between"><span className="hud-label">{k.label}</span><k.icon size={15} className="text-cyan" /></div>
            <div className={clsx("num mt-2 text-2xl font-semibold", k.warn && "text-warn")}>{k.value}</div>
            <div className="mt-1 truncate text-[11px] text-dim">{k.sub}</div>
          </motion.div>
        ))}
      </div>

      {busiest && (busiest.utilization ?? 0) >= 60 && (
        <div className="flex items-start gap-3 rounded-xl border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <div>
            The {busiest.band} GHz radio on channel {busiest.channel} is {busiest.utilization?.toFixed(0)}% busy
            ({busiest.interference?.toFixed(0)}% of that is other networks/noise) with {busiest.clients} clients.
            {busiest.band === "2.4" ? " Consider moving capable clients to 5/6 GHz, using a less crowded channel (1, 6 or 11), or lowering 2.4 GHz TX power." : " Consider a less crowded channel or narrower width."}
          </div>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        {data.aps.map((ap, i) => (
          <Panel key={ap.mac} delay={i * 0.05} title={ap.name} icon={<RadioIcon size={15} />}
            actions={<span className="flex items-center gap-2 text-xs text-dim"><StatusDot status={ap.online ? "up" : "down"} size={7} />
              {ap.device_id ? <Link to={`/devices/${ap.device_id}`} className="hover:text-cyan">{ap.model}</Link> : ap.model}</span>}>
            {!ap.online ? <div className="rounded-lg border border-crit/30 bg-crit/5 p-3 text-sm text-crit">Offline</div> : (
              <>
                <div className="mb-3 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11px] text-faint">
                  <span>{ap.ip}</span><span>{ap.clients ?? 0} clients</span><span>up {duration(ap.uptime_s)}</span>
                  {ap.uplink.name && <span>uplink {ap.uplink.name}{ap.uplink.port ? ` p${ap.uplink.port}` : ""}{ap.uplink.speed ? ` @ ${ap.uplink.speed >= 1000 ? ap.uplink.speed / 1000 + "G" : ap.uplink.speed + "M"}` : ""}</span>}
                  <span>fw {ap.version}</span>
                </div>
                <div className="grid gap-2 sm:grid-cols-2 2xl:grid-cols-3">
                  {ap.radios.map((r) => <RadioCard key={r.name} ap={ap} r={r} />)}
                </div>
              </>
            )}
          </Panel>
        ))}
      </div>
      <div className="flex flex-wrap gap-4 text-[11px] text-dim">
        <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-cyan" />your receive</span>
        <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-violet" />your transmit</span>
        <span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full bg-crit" />other networks / noise</span>
        <span className="text-faint">click a radio for its history</span>
      </div>

      <Panel title="Channel map" icon={<Wifi size={15} />}
        actions={<Segmented value={band} onChange={setBand} options={BANDS.map((b) => ({ value: b, label: `${b} GHz` }))} />}>
        <ChannelMap band={band} aps={data.aps.filter((a) => a.online)} neighbors={data.neighbors} />
        <div className="mt-1 flex flex-wrap justify-between gap-2 text-[11px] text-faint">
          <span>Your radios are highlighted; grey curves are neighbouring networks (height = signal strength at your APs).</span>
          <span>{data.neighbors.filter((n) => n.band === band).length} neighbours on {band} GHz</span>
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="SSIDs" icon={<ShieldCheck size={15} />} className="xl:col-span-2" bodyClass="!px-0">
          <div className="overflow-x-auto">
            <table className="table-hud min-w-[760px]">
              <thead><tr><th>SSID</th><th>Security</th><th>Network</th><th>Bands</th><th className="w-48">Clients</th><th>Experience</th><th>Features</th></tr></thead>
              <tbody>
                {data.ssids.map((w) => (
                  <tr key={w.id} className={clsx(!w.enabled && "opacity-50")}>
                    <td className="font-medium">{w.name}{w.guest && <Badge tone="warning" className="ml-2">guest</Badge>}{w.hidden && <Badge className="ml-2">hidden</Badge>}</td>
                    <td className="text-xs text-dim">{SECURITY[w.security] ?? w.security}{w.wpa_mode ? ` · ${w.wpa_mode.toUpperCase()}` : ""}</td>
                    <td className="text-xs text-dim">{w.network || "—"}</td>
                    <td className="space-x-1">{w.bands.map((b) => <BandBadge key={b} band={b.replace("g", "").replace("2", "2.4")} />)}</td>
                    <td>
                      <div className="flex h-2 overflow-hidden rounded-full bg-white/5">
                        {Object.entries(w.clients_by_band).map(([b, n]) => (
                          <div key={b} style={{ width: `${w.clients ? (n / w.clients) * 100 : 0}%`, background: BAND_COLOR[b] }} title={`${b} GHz: ${n}`} />
                        ))}
                      </div>
                      <div className="num mt-1 text-[11px] text-dim">{w.clients} clients</div>
                    </td>
                    <td className="num text-xs">{w.satisfaction != null ? `${w.satisfaction.toFixed(0)}%` : "—"}</td>
                    <td className="font-mono text-[10px] text-faint">{[w.fast_roaming && "802.11r", w.pmf && w.pmf !== "disabled" && `PMF ${w.pmf}`, w.mlo && "MLO", w.l2_isolation && "isolation"].filter(Boolean).join(" · ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Client mix" icon={<Users size={15} />}>
          <div className="space-y-5">
            <div><div className="hud-label mb-2">Signal quality</div>
              <Bars total={sigTotal} data={Object.entries(s?.by_signal ?? {})} colors={{ excellent: "#34d399", good: "#22d3ee", fair: "#fbbf24", poor: "#fb4d6d" }} /></div>
            <div><div className="hud-label mb-2">Band</div>
              <Bars total={bandTotal} data={Object.entries(s?.by_band ?? {}).sort().map(([b, n]) => [`${b} GHz`, n] as [string, number])}
                colors={{ "2.4 GHz": BAND_COLOR["2.4"], "5 GHz": BAND_COLOR["5"], "6 GHz": BAND_COLOR["6"] }} /></div>
            <div><div className="hud-label mb-2">Wi-Fi standard</div>
              <Bars total={stdTotal} data={Object.entries(s?.by_standard ?? {}).sort((a, b) => b[1] - a[1])} /></div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title={`Clients needing attention · ${problem.length}`} icon={<AlertTriangle size={15} />}>
          {!problem.length ? <Empty icon={<ShieldCheck size={26} className="text-ok" />} title="Every wireless client looks healthy" /> : (
            <div className="space-y-1.5">
              {problem.map((c) => (
                <Link key={c.mac} to="/clients" className="flex items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-white/[0.03]">
                  <ClientIcon category={c.category} size={15} className="text-dim" />
                  <span className="min-w-0 flex-1 truncate text-sm">{c.display_name}</span>
                  <BandBadge band={c.band} />
                  <SignalBars signal={c.signal} />
                  <span className="num w-14 text-right text-[11px] text-dim">{c.signal} dBm</span>
                  <span className={clsx("num w-14 text-right text-[11px]", (c.retries_pct ?? 0) > 20 ? "text-warn" : "text-dim")}>{c.retries_pct?.toFixed(0) ?? "?"}% rt</span>
                  <div className="w-16"><Meter value={c.satisfaction} color={(c.satisfaction ?? 0) >= 60 ? "#fbbf24" : "#fb4d6d"} /></div>
                </Link>
              ))}
            </div>
          )}
        </Panel>

        <Panel title={`Neighbouring networks · ${data.neighbors.length}`} icon={<Radar size={15} />}
          actions={<div className="flex items-center gap-1.5 rounded-lg border border-edge bg-black/30 px-2"><Search size={13} className="text-faint" />
            <input value={nq} onChange={(e) => setNq(e.target.value)} placeholder="filter" className="h-7 w-28 bg-transparent text-xs outline-none" /></div>}>
          <div className="max-h-[360px] overflow-auto rounded-lg border border-edge">
            <table className="table-hud">
              <thead><tr><th>SSID</th><th>Band</th><th>Ch</th><th>Signal</th><th>Security</th><th>Seen by</th><th>Seen</th></tr></thead>
              <tbody>
                {neighbors.slice(0, 200).map((n, i) => (
                  <tr key={n.bssid + i}>
                    <td className="max-w-[180px] truncate text-sm">{n.ssid || <span className="text-faint">(hidden)</span>}{n.is_rogue && <Badge tone="critical" className="ml-2">rogue</Badge>}</td>
                    <td><BandBadge band={n.band} /></td>
                    <td className="num text-xs">{n.channel}</td>
                    <td><span className="inline-flex items-center gap-2"><SignalBars signal={n.signal} /><span className="num text-[11px] text-dim">{n.signal}</span></span></td>
                    <td className="font-mono text-[10.5px] text-dim">{n.security}</td>
                    <td className="max-w-[120px] truncate text-xs text-dim">{n.seen_by}</td>
                    <td className="font-mono text-[10.5px] text-faint">{ago(n.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
