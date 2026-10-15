import clsx from "clsx";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Bell,
  Cable,
  ChevronRight,
  Globe,
  type LucideIcon,
  Network,
  Radar,
  ScrollText,
  Server,
  Users,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useMemo } from "react";
import { Link, useNavigate } from "react-router";
import { AreaChart, Gauge, Sparkline } from "../components/charts";
import { DeviceIcon } from "../components/DeviceIcon";
import { TopologyGraph } from "../components/TopologyGraph";
import { Badge, CountUp, Empty, Meter, Panel, StatusDot } from "../components/ui";
import { ago, bps, bpsParts, clock, deviceColor, ms, SEV_NAMES, sevColor, utilColor } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { Overview, Topology } from "../lib/types";

function Kpi({ icon: Icon, label, children, sub, tone = "#22d3ee", delay = 0, to }: {
  icon: LucideIcon;
  label: string;
  children: React.ReactNode;
  sub?: React.ReactNode;
  tone?: string;
  delay?: number;
  to?: string;
}) {
  const body = (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      whileHover={{ y: -2 }}
      className="panel group relative h-full overflow-hidden p-4"
    >
      <div className="absolute -top-10 -right-10 h-28 w-28 rounded-full opacity-20 blur-2xl transition-opacity group-hover:opacity-40"
        style={{ background: tone }} />
      <div className="flex items-center justify-between">
        <span className="hud-label">{label}</span>
        <Icon size={16} style={{ color: tone }} />
      </div>
      <div className="mt-2 text-[26px] leading-none font-semibold tracking-tight">{children}</div>
      {sub && <div className="mt-2 text-xs text-dim">{sub}</div>}
    </motion.div>
  );
  return to ? <Link to={to} className="block">{body}</Link> : body;
}

function Bps({ v }: { v: number }) {
  const [n, u] = bpsParts(v);
  return (
    <span className="num">
      {n}
      <span className="ml-1 text-sm font-normal text-dim">{u}</span>
    </span>
  );
}

export default function OverviewPage() {
  const { data: ov } = useApi<Overview>("/overview", 5000);
  const { data: topo } = useApi<Topology>("/topology", 10000);
  const devices = useLive((s) => s.devices);
  const logs = useLive((s) => s.logs);
  const alerts = useLive((s) => s.alerts);
  const nav = useNavigate();
  useTick(5000);

  const activeAlerts = useMemo(
    () => Object.values(alerts).sort((a, b) => ({ critical: 0, warning: 1, info: 2 }[a.severity] - { critical: 0, warning: 1, info: 2 }[b.severity]) || b.started_at - a.started_at),
    [alerts],
  );
  const crit = activeAlerts.filter((a) => a.severity === "critical").length;
  const warn = activeAlerts.filter((a) => a.severity === "warning").length;
  const devList = Object.values(devices).filter((d) => d.enabled).sort((a, b) => {
    const rank = (d: typeof a) => (d.status === "down" ? 0 : d.health === "critical" ? 1 : d.health === "warning" || d.status === "degraded" ? 2 : 3);
    return rank(a) - rank(b) || a.name.localeCompare(b.name);
  });
  const down = devList.filter((d) => d.status === "down").length;
  const score = Math.max(0, Math.min(100, 100 - crit * 12 - warn * 4 - down * 8));
  const primaryGw = ov?.wan.gateways.find((g) => g.up !== false && g.latency_ms != null) ?? ov?.wan.gateways[0];
  const wanSeries = useMemo(() => {
    const h = ov?.wan.history ?? [];
    return [
      { key: "rx", label: "Download", color: "#22d3ee", points: h.map((p) => [p[0], p[1]] as [number, number | null]) },
      { key: "tx", label: "Upload", color: "#f472b6", points: h.map((p) => [p[0], p[2]] as [number, number | null]) },
    ];
  }, [ov?.wan.history]);

  return (
    <div className="mx-auto grid max-w-[1800px] grid-cols-12 gap-4 p-4 md:p-6">
      {/* Health + KPIs */}
      <Panel className="col-span-12 lg:col-span-3" title="Network health" icon={<Activity size={15} />}>
        <div className="flex items-center justify-center gap-4 lg:flex-col xl:flex-row">
          <Gauge value={score} label="SCORE" size={160} />
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2"><StatusDot status="up" pulse={false} /> <span className="num">{ov?.devices.up ?? "–"}</span> <span className="text-dim">online</span></div>
            <div className="flex items-center gap-2"><StatusDot status="degraded" pulse={false} /> <span className="num">{ov?.devices.degraded ?? "–"}</span> <span className="text-dim">degraded</span></div>
            <div className="flex items-center gap-2"><StatusDot status="down" pulse={!!down} /> <span className="num">{down}</span> <span className="text-dim">down</span></div>
            <div className="pt-1 text-xs text-faint">{crit} critical · {warn} warnings</div>
          </div>
        </div>
      </Panel>

      <div className="col-span-12 grid grid-cols-2 gap-4 sm:grid-cols-4 lg:col-span-9">
        <Kpi icon={Server} label="Devices" to="/devices" delay={0.02} tone="#34d399"
          sub={<>{ov?.devices.total ?? 0} monitored · {ov?.ports.up ?? 0}/{ov?.ports.total ?? 0} ports up</>}>
          <CountUp value={ov?.devices.up ?? 0} />
          <span className="text-base text-dim"> / {ov?.devices.total ?? 0}</span>
        </Kpi>
        <Kpi icon={Bell} label="Active alerts" to="/alerts" delay={0.05} tone={crit ? "#fb4d6d" : warn ? "#fbbf24" : "#34d399"}
          sub={<span><span className="text-crit">{crit} crit</span> · <span className="text-warn">{warn} warn</span> · {activeAlerts.length - crit - warn} info</span>}>
          <CountUp value={activeAlerts.length} className={crit ? "text-crit" : warn ? "text-warn" : ""} />
        </Kpi>
        <Kpi icon={ArrowDownToLine} label="WAN download" delay={0.08} tone="#22d3ee"
          sub={<Sparkline data={(ov?.wan.history ?? []).slice(-40).map((p) => p[1])} height={22} />}>
          <Bps v={ov?.wan.rx_bps ?? 0} />
        </Kpi>
        <Kpi icon={ArrowUpFromLine} label="WAN upload" delay={0.11} tone="#f472b6"
          sub={<Sparkline data={(ov?.wan.history ?? []).slice(-40).map((p) => p[2])} color="#f472b6" height={22} />}>
          <Bps v={ov?.wan.tx_bps ?? 0} />
        </Kpi>
        <Kpi icon={Globe} label="Internet latency" delay={0.14} tone={primaryGw?.up === false ? "#fb4d6d" : "#a78bfa"}
          sub={primaryGw ? <>{primaryGw.name} · loss {primaryGw.loss_pct ?? 0}%</> : "no gateway monitored"}>
          <span className="num">{primaryGw?.latency_ms != null ? primaryGw.latency_ms.toFixed(1) : "—"}</span>
          <span className="ml-1 text-sm text-dim">ms</span>
        </Kpi>
        <Kpi icon={Users} label="Clients" delay={0.17} tone="#38bdf8" sub="active leases / associations">
          <CountUp value={ov?.clients ?? 0} />
        </Kpi>
        <Kpi icon={Cable} label="Fabric throughput" delay={0.2} tone="#a78bfa" sub="sum of all monitored ports">
          <Bps v={ov?.throughput_bps ?? 0} />
        </Kpi>
        <Kpi icon={ScrollText} label="Log rate" to="/logs" delay={0.23} tone="#fbbf24" sub={`${ov?.ports.errors ?? 0} ports with errors`}>
          <CountUp value={ov?.logs_per_min ?? 0} />
          <span className="ml-1 text-sm text-dim">/min</span>
        </Kpi>
      </div>

      {/* Topology + alerts */}
      <Panel className="col-span-12 xl:col-span-8" title="Live topology" icon={<Network size={15} />} bodyClass="!p-0" delay={0.1}
        actions={<Link to="/topology" className="flex items-center gap-1 text-xs text-dim hover:text-cyan">Full view <ChevronRight size={14} /></Link>}>
        <div className="h-[440px]">
          <TopologyGraph data={topo} compact persistPositions={false}
            onSelect={(n) => n?.device_id != null && nav(`/devices/${n.device_id}`)} />
        </div>
      </Panel>

      <Panel className="col-span-12 xl:col-span-4" title="Alert feed" icon={<Radar size={15} />} delay={0.15}
        actions={<Link to="/alerts" className="text-xs text-dim hover:text-cyan">All</Link>}>
        <div className="h-[440px] space-y-2 overflow-y-auto pr-1">
          {activeAlerts.length === 0 && <Empty icon={<Radar size={28} />} title="All clear">No active alerts. Enjoy the quiet.</Empty>}
          <AnimatePresence initial={false}>
            {activeAlerts.slice(0, 30).map((a) => (
              <motion.button key={a.id} layout initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}
                onClick={() => a.device_id && nav(`/devices/${a.device_id}`)}
                className={clsx("relative w-full overflow-hidden rounded-xl border bg-black/20 p-3 text-left transition hover:bg-white/[0.03]",
                  a.severity === "critical" ? "border-crit/30" : a.severity === "warning" ? "border-warn/25" : "border-edge")}>
                <span className={clsx("absolute inset-y-0 left-0 w-0.5", a.severity === "critical" ? "bg-crit" : a.severity === "warning" ? "bg-warn" : "bg-info")} />
                <div className="flex items-center justify-between gap-2">
                  <Badge tone={a.severity}>{a.severity}</Badge>
                  <span className="font-mono text-[10.5px] text-faint">{ago(a.started_at)}</span>
                </div>
                <div className="mt-1.5 truncate text-sm">{a.title}</div>
                {a.detail && <div className="truncate text-xs text-dim">{a.detail}</div>}
              </motion.button>
            ))}
          </AnimatePresence>
        </div>
      </Panel>

      {/* WAN chart + gateways */}
      <Panel className="col-span-12 xl:col-span-8" title="Internet throughput" icon={<Globe size={15} />} delay={0.2}
        actions={<div className="flex gap-3 text-xs"><span className="flex items-center gap-1.5 text-dim"><i className="h-2 w-2 rounded-full bg-cyan" />Down</span><span className="flex items-center gap-1.5 text-dim"><i className="h-2 w-2 rounded-full bg-magenta" />Up</span></div>}>
        <AreaChart series={wanSeries} height={230} yFormat={(v) => bps(v, 0)} empty="Waiting for WAN samples…" />
      </Panel>

      <Panel className="col-span-12 xl:col-span-4" title="Gateways" icon={<Activity size={15} />} delay={0.22}>
        <div className="space-y-2">
          {!ov?.wan.gateways.length && <Empty title="No gateways">Add pfSense, OPNsense or UniFi to see WAN gateways.</Empty>}
          {ov?.wan.gateways.map((g) => (
            <div key={`${g.device}-${g.name}`} className="flex items-center gap-3 rounded-xl border border-edge bg-black/20 p-3">
              <StatusDot status={g.up === false ? "down" : (g.loss_pct ?? 0) > 5 ? "degraded" : "up"} health={g.up === false ? "critical" : "ok"} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{g.name}</div>
                <div className="truncate font-mono text-[11px] text-faint">{g.device} → {g.address || "—"}</div>
              </div>
              <div className="text-right">
                <div className="num text-sm" style={{ color: (g.latency_ms ?? 0) > 100 ? "#fbbf24" : "#e6f1ff" }}>{ms(g.latency_ms)}</div>
                <div className={clsx("num text-[11px]", (g.loss_pct ?? 0) > 0 ? "text-warn" : "text-faint")}>{(g.loss_pct ?? 0).toFixed(1)}% loss</div>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* Device matrix + top talkers */}
      <Panel className="col-span-12 xl:col-span-8" title="Device matrix" icon={<Server size={15} />} delay={0.25}
        actions={<Link to="/devices" className="text-xs text-dim hover:text-cyan">Manage</Link>}>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 2xl:grid-cols-4">
          {devList.map((d, i) => {
            const c = deviceColor(d.status, d.health);
            return (
              <motion.div key={d.id} initial={{ opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.02 * i }}>
                <Link to={`/devices/${d.id}`}
                  className="group relative block overflow-hidden rounded-xl border bg-black/25 p-3 transition hover:-translate-y-0.5"
                  style={{ borderColor: `${c}40`, boxShadow: d.status === "down" || d.health === "critical" ? `0 0 22px -8px ${c}` : undefined }}>
                  <div className="flex items-center gap-2">
                    <DeviceIcon role={d.role} size={15} className="text-dim group-hover:text-cyan" />
                    <span className="min-w-0 flex-1 truncate text-sm font-medium">{d.name}</span>
                    <StatusDot status={d.status} health={d.health} size={7} />
                  </div>
                  <div className="mt-0.5 truncate font-mono text-[10.5px] text-faint">{d.model || d.host}</div>
                  {d.status === "down" ? (
                    <div className="mt-2.5 font-mono text-[11px] text-crit">OFFLINE · {ago(d.last_ok)}</div>
                  ) : (
                    <div className="mt-2 space-y-1.5">
                      {d.metrics.cpu != null && <div className="flex items-center gap-2"><span className="w-7 font-mono text-[9.5px] text-faint">CPU</span><Meter value={d.metrics.cpu} className="flex-1" /></div>}
                      {d.metrics.mem != null && <div className="flex items-center gap-2"><span className="w-7 font-mono text-[9.5px] text-faint">MEM</span><Meter value={d.metrics.mem} className="flex-1" color="#a78bfa" /></div>}
                      {d.metrics.cpu == null && d.metrics.mem == null && <Sparkline data={d.spark.map((p) => (p[1] ?? 0) + (p[2] ?? 0))} height={20} />}
                    </div>
                  )}
                </Link>
              </motion.div>
            );
          })}
        </div>
      </Panel>

      <Panel className="col-span-12 xl:col-span-4" title="Top talkers" icon={<Cable size={15} />} delay={0.28}>
        <div className="space-y-2.5">
          {ov?.top_talkers.map((t) => {
            const total = t.rx_bps + t.tx_bps;
            const max = (ov.top_talkers[0]?.rx_bps ?? 0) + (ov.top_talkers[0]?.tx_bps ?? 0) || 1;
            return (
              <Link key={`${t.device_id}-${t.ifname}`} to={`/devices/${t.device_id}`} className="block">
                <div className="flex items-baseline justify-between gap-2 text-sm">
                  <span className="truncate"><span className="text-ink">{t.device}</span> <span className="text-dim">{t.ifname}</span>{t.alias && <span className="text-faint"> · {t.alias}</span>}</span>
                  <span className="num shrink-0 text-xs">{bps(total)}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
                  <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${(total / max) * 100}%` }}
                    style={{ background: `linear-gradient(90deg, #22d3ee, ${utilColor(t.util_pct)})` }} />
                </div>
              </Link>
            );
          })}
        </div>
      </Panel>

      {/* Live log stream */}
      <Panel className="col-span-12" title="Live event stream" icon={<ScrollText size={15} />} delay={0.3}
        actions={<Link to="/logs" className="flex items-center gap-1 text-xs text-dim hover:text-cyan">Open log explorer <ChevronRight size={14} /></Link>}>
        <div className="h-56 overflow-hidden font-mono text-[12px] leading-6 [mask-image:linear-gradient(to_bottom,black_70%,transparent)]">
          {logs.length === 0 && <div className="py-8 text-center text-faint">Listening for syslog and device events…</div>}
          <AnimatePresence initial={false}>
            {logs.slice(0, 18).map((l, i) => (
              <motion.div key={`${l.ts}-${i}-${l.message.slice(0, 20)}`} layout initial={{ opacity: 0, x: -12, backgroundColor: "rgba(34,211,238,0.12)" }}
                animate={{ opacity: 1, x: 0, backgroundColor: "rgba(34,211,238,0)" }} transition={{ duration: 0.6 }}
                className="flex gap-3 truncate rounded px-1">
                <span className="shrink-0 text-faint">{clock(l.ts)}</span>
                <span className={clsx("w-14 shrink-0", sevColor(l.severity))}>{SEV_NAMES[l.severity]}</span>
                <span className="w-32 shrink-0 truncate text-cyan/80">{l.device ?? devices[l.device_id ?? -1]?.name ?? l.host}</span>
                <span className="w-24 shrink-0 truncate text-violet/80">{l.app}</span>
                <span className="truncate text-ink/85">{l.message}</span>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </Panel>
    </div>
  );
}
