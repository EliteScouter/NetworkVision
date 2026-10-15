import clsx from "clsx";
import { ArrowDownUp, LayoutGrid, Plus, Rows3, Search, Server } from "lucide-react";
import { motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { Sparkline } from "../components/charts";
import { DeviceIcon, ROLE_LABEL } from "../components/DeviceIcon";
import { Badge, Empty, Meter, Segmented, StatusDot } from "../components/ui";
import { ago, bps, deviceColor, ms, pct } from "../lib/format";
import { useLocalState, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { DeviceSummary } from "../lib/types";

type SortKey = "name" | "status" | "cpu" | "mem" | "traffic" | "latency";
const STATUSES = ["up", "degraded", "down", "unknown", "disabled"] as const;

function statusRank(d: DeviceSummary) {
  return d.status === "down" ? 0 : d.health === "critical" ? 1 : d.status === "degraded" || d.health === "warning" ? 2 : d.status === "up" ? 3 : 4;
}

export default function DevicesPage() {
  const devices = useLive((s) => s.devices);
  const nav = useNavigate();
  useTick(5000);
  const [q, setQ] = useState("");
  const [view, setView] = useLocalState<"grid" | "table">("devices-view", "grid");
  const [status, setStatus] = useLocalState<string[]>("devices-status", []);
  const [roles, setRoles] = useLocalState<string[]>("devices-roles", []);
  const [vendor, setVendor] = useLocalState<string>("devices-vendor", "");
  const [sort, setSort] = useLocalState<{ key: SortKey; dir: 1 | -1 }>("devices-sort", { key: "status", dir: 1 });

  const all = Object.values(devices);
  const vendors = useMemo(() => [...new Set(all.map((d) => d.vendor).filter(Boolean))].sort(), [all]);
  const allRoles = useMemo(() => [...new Set(all.map((d) => d.role))].sort(), [all]);
  const parentName = (id: number | null) => (id != null ? devices[id]?.name : undefined);

  const list = useMemo(() => {
    const t = q.toLowerCase().trim();
    const filtered = all.filter((d) =>
      (!t || [d.name, d.host, d.model, d.vendor, d.location, ...d.tags].join(" ").toLowerCase().includes(t)) &&
      (!status.length || status.includes(d.status)) &&
      (!roles.length || roles.includes(d.role)) &&
      (!vendor || d.vendor === vendor));
    const val = (d: DeviceSummary): number | string => {
      switch (sort.key) {
        case "name": return d.name.toLowerCase();
        case "status": return statusRank(d);
        case "cpu": return d.metrics.cpu ?? -1;
        case "mem": return d.metrics.mem ?? -1;
        case "traffic": return d.rx_bps + d.tx_bps;
        case "latency": return d.metrics.latency_ms ?? -1;
      }
    };
    return filtered.sort((a, b) => {
      const [x, y] = [val(a), val(b)];
      return (x < y ? -1 : x > y ? 1 : a.name.localeCompare(b.name)) * sort.dir;
    });
  }, [all, q, status, roles, vendor, sort]);

  const toggle = (arr: string[], set: (v: string[]) => void, v: string) => set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  const counts = Object.fromEntries(STATUSES.map((s) => [s, all.filter((d) => d.status === s).length]));
  const th = (key: SortKey, label: string) => (
    <th className="cursor-pointer hover:text-ink" onClick={() => setSort({ key, dir: sort.key === key ? (-sort.dir as 1 | -1) : 1 })}>
      <span className="inline-flex items-center gap-1">{label}{sort.key === key && <ArrowDownUp size={11} className="text-cyan" />}</span>
    </th>
  );

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      <div className="panel flex flex-wrap items-center gap-3 p-3">
        <div className="flex min-w-[220px] flex-1 items-center gap-2 rounded-xl border border-edge bg-black/30 px-3">
          <Search size={15} className="text-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name, IP, model, tag, location…"
            className="h-9 flex-1 bg-transparent text-sm outline-none placeholder:text-faint" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {STATUSES.filter((s) => counts[s]).map((s) => (
            <button key={s} className="chip" data-active={status.includes(s)} onClick={() => toggle(status, setStatus, s)}>
              <StatusDot status={s} size={6} pulse={false} /> {s} <span className="num text-faint">{counts[s]}</span>
            </button>
          ))}
        </div>
        <select className="input !w-auto !py-1.5" value={vendor} onChange={(e) => setVendor(e.target.value)}>
          <option value="">All vendors</option>
          {vendors.map((v) => <option key={v}>{v}</option>)}
        </select>
        <Segmented value={view} onChange={setView} options={[
          { value: "grid", label: <LayoutGrid size={14} /> },
          { value: "table", label: <Rows3 size={14} /> },
        ]} />
        <Link to="/integrations?add=1" className="btn btn-primary"><Plus size={15} /> Add device</Link>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {allRoles.map((r) => (
          <button key={r} className="chip" data-active={roles.includes(r)} onClick={() => toggle(roles, setRoles, r)}>
            <DeviceIcon role={r} size={12} /> {ROLE_LABEL[r] ?? r} <span className="num text-faint">{all.filter((d) => d.role === r).length}</span>
          </button>
        ))}
        {(roles.length > 0 || status.length > 0 || vendor || q) && (
          <button className="chip" onClick={() => { setRoles([]); setStatus([]); setVendor(""); setQ(""); }}>reset filters</button>
        )}
        <span className="ml-auto self-center font-mono text-xs text-faint">{list.length} of {all.length}</span>
      </div>

      {!all.length && (
        <div className="panel"><Empty icon={<Server size={32} />} title="No devices yet">
          Add your firewall, UniFi controller or switches under <Link to="/integrations" className="text-cyan">Integrations</Link>.
        </Empty></div>
      )}

      {view === "grid" ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
          {list.map((d, i) => {
            const c = deviceColor(d.status, d.health);
            return (
              <motion.div key={d.id} layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i, 20) * 0.02 }}>
                <Link to={`/devices/${d.id}`} className="panel group block p-4 transition hover:-translate-y-0.5"
                  style={{ boxShadow: d.status === "down" || d.health === "critical" ? `0 0 30px -12px ${c}` : undefined }}>
                  <div className="flex items-start gap-3">
                    <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border bg-black/30 transition group-hover:shadow-[0_0_18px_-4px_#22d3ee]"
                      style={{ borderColor: `${c}55`, color: c }}>
                      <DeviceIcon role={d.role} size={19} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate font-semibold">{d.name}</span>
                        <StatusDot status={d.status} health={d.health} size={7} />
                      </div>
                      <div className="truncate font-mono text-[11px] text-faint">{d.host || "—"} · {d.model || d.kind}</div>
                    </div>
                    {(d.alert_counts.critical || d.alert_counts.warning) ? (
                      <Badge tone={d.alert_counts.critical ? "critical" : "warning"}>{(d.alert_counts.critical ?? 0) + (d.alert_counts.warning ?? 0)} alerts</Badge>
                    ) : null}
                  </div>
                  {d.status === "down" ? (
                    <div className="mt-4 rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-xs text-crit">
                      {d.error ?? "Unreachable"} · last seen {ago(d.last_ok)}
                    </div>
                  ) : (
                    <>
                      <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                        <div><div className="hud-label !text-[9.5px]">CPU</div><div className="num text-sm">{pct(d.metrics.cpu)}</div></div>
                        <div><div className="hud-label !text-[9.5px]">MEM</div><div className="num text-sm">{pct(d.metrics.mem)}</div></div>
                        <div><div className="hud-label !text-[9.5px]">{d.metrics.latency_ms != null ? "PING" : "PORTS"}</div>
                          <div className="num text-sm">{d.metrics.latency_ms != null ? ms(d.metrics.latency_ms) : `${d.ports_up}/${d.ports_total}`}</div></div>
                      </div>
                      <div className="mt-3"><Sparkline data={d.spark.map((p) => (p[1] ?? 0) + (p[2] ?? 0))} height={30} color={c === "#34d399" ? "#22d3ee" : c} /></div>
                      <div className="mt-1 flex justify-between font-mono text-[10.5px] text-faint">
                        <span>{bps(d.rx_bps + d.tx_bps)}</span>
                        <span>{parentName(d.parent_id) ? `via ${parentName(d.parent_id)}` : d.vendor}</span>
                      </div>
                    </>
                  )}
                </Link>
              </motion.div>
            );
          })}
        </div>
      ) : (
        <div className="panel overflow-x-auto !p-0">
          <table className="table-hud min-w-[1000px]">
            <thead><tr>
              {th("status", "")}{th("name", "Device")}<th>Role</th><th>Address</th><th>Model</th>
              {th("cpu", "CPU")}{th("mem", "Mem")}{th("traffic", "Traffic")}<th>Ports</th>{th("latency", "Ping")}<th>Seen</th>
            </tr></thead>
            <tbody>
              {list.map((d) => (
                <tr key={d.id} className="cursor-pointer" onClick={() => nav(`/devices/${d.id}`)}>
                  <td className="w-8"><StatusDot status={d.status} health={d.health} size={8} /></td>
                  <td>
                    <div className="font-medium">{d.name}</div>
                    {parentName(d.parent_id) && <div className="text-[11px] text-faint">via {parentName(d.parent_id)}</div>}
                  </td>
                  <td className="text-dim"><span className="inline-flex items-center gap-1.5"><DeviceIcon role={d.role} size={13} />{ROLE_LABEL[d.role] ?? d.role}</span></td>
                  <td className="font-mono text-xs text-dim">{d.host}</td>
                  <td className="text-dim">{d.model}<div className="font-mono text-[10.5px] text-faint">{d.version}</div></td>
                  <td className="w-28"><div className="num text-xs">{pct(d.metrics.cpu)}</div>{d.metrics.cpu != null && <Meter value={d.metrics.cpu} />}</td>
                  <td className="w-28"><div className="num text-xs">{pct(d.metrics.mem)}</div>{d.metrics.mem != null && <Meter value={d.metrics.mem} color="#a78bfa" />}</td>
                  <td className="num text-xs">{bps(d.rx_bps + d.tx_bps)}</td>
                  <td className="num text-xs">{d.ports_total ? `${d.ports_up}/${d.ports_total}` : "—"}</td>
                  <td className={clsx("num text-xs", (d.metrics.latency_ms ?? 0) > 100 && "text-warn")}>{ms(d.metrics.latency_ms)}</td>
                  <td className="font-mono text-[11px] text-faint">{ago(d.last_ok)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
