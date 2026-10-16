import { ChevronRight, Link2, Plus, Search, Trash2, X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { DeviceIcon, ROLE_LABEL } from "../components/DeviceIcon";
import { TopologyGraph } from "../components/TopologyGraph";
import { Badge, Drawer, Field, Kv, Meter, StatusDot } from "../components/ui";
import { api } from "../lib/api";
import { bps, ms, pct, speed } from "../lib/format";
import { useApi, useLocalState } from "../lib/hooks";
import type { TopoNode, Topology } from "../lib/types";

const KIND_LABEL: Record<string, string> = {
  lldp: "LLDP", uplink: "Controller uplink", manual: "Manual", description: "Port description", wan: "WAN",
};

function AddLink({ nodes, onDone }: { nodes: TopoNode[]; onDone: () => void }) {
  const devs = nodes.filter((n) => n.device_id != null).sort((a, b) => a.name.localeCompare(b.name));
  const [f, setF] = useState({ a_device_id: "", a_port: "", b_device_id: "", b_port: "", label: "" });
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    try {
      await api("/links", { method: "POST", body: { ...f, a_device_id: +f.a_device_id,
        b_device_id: f.b_device_id === "internet" ? "internet" : +f.b_device_id } });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <div className="space-y-4">
      <p className="text-sm text-dim">
        Most links are discovered automatically (LLDP, UniFi uplinks, port descriptions that name a device). Add a manual link for
        anything that can't be discovered — unmanaged switches, VMs on a hypervisor bridge, etc. Pick “Internet” as device B
        for a router or firewall that reaches the internet but isn't detected as an edge (map only — WAN totals are unchanged).
      </p>
      {(["a", "b"] as const).map((s) => (
        <div key={s} className="grid grid-cols-2 gap-3">
          <Field label={`Device ${s.toUpperCase()}`}>
            <select className="input" value={f[`${s}_device_id`]} onChange={(e) => setF({ ...f, [`${s}_device_id`]: e.target.value })}>
              <option value="">Select…</option>
              {devs.map((d) => <option key={d.id} value={d.device_id!}>{d.name}</option>)}
              {s === "b" && <option value="internet">🌐 Internet</option>}
            </select>
          </Field>
          <Field label="Port (optional)">
            <input className="input" value={f[`${s}_port`]} onChange={(e) => setF({ ...f, [`${s}_port`]: e.target.value })} placeholder="e.g. Port 7" />
          </Field>
        </div>
      ))}
      <Field label="Label"><input className="input" value={f.label} onChange={(e) => setF({ ...f, label: e.target.value })} /></Field>
      {err && <div className="text-sm text-crit">{err}</div>}
      <button className="btn btn-primary" disabled={!f.a_device_id || !f.b_device_id} onClick={save}><Plus size={15} />Add link</button>
    </div>
  );
}

export default function TopologyPage() {
  const { data, reload } = useApi<Topology>("/topology", 8000);
  const [selected, setSelected] = useState<TopoNode | null>(null);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useLocalState<string[]>("topo-roles", []);
  const [adding, setAdding] = useState(false);
  const roles = useMemo(() => new Set(roleFilter), [roleFilter]);
  const allRoles = useMemo(() => [...new Set((data?.nodes ?? []).map((n) => n.role).filter((r) => r !== "internet"))].sort(), [data]);
  const sel = selected ? data?.nodes.find((n) => n.id === selected.id) ?? selected : null;
  const selEdges = sel ? (data?.edges ?? []).filter((e) => e.source === sel.id || e.target === sel.id) : [];
  const nameOf = (id: string) => data?.nodes.find((n) => n.id === id)?.name ?? id;

  const toggleRole = (r: string) => setRoleFilter(roles.has(r) ? roleFilter.filter((x) => x !== r) : [...roleFilter, r]);

  return (
    <div className="relative h-[calc(100vh-4rem)] max-md:h-[calc(100vh-8rem)]">
      <TopologyGraph data={data} selectedId={sel?.id ?? null} highlight={search} roles={roles} onSelect={setSelected} />

      {/* toolbar */}
      <div className="pointer-events-none absolute inset-x-0 top-0 flex flex-wrap items-start gap-3 p-4">
        <div className="panel pointer-events-auto flex items-center gap-2 !rounded-xl px-3 py-2">
          <Search size={15} className="text-faint" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Highlight devices…"
            className="w-44 bg-transparent text-sm outline-none placeholder:text-faint" />
          {search && <button onClick={() => setSearch("")} className="text-faint hover:text-ink"><X size={14} /></button>}
        </div>
        <div className="panel pointer-events-auto flex flex-wrap items-center gap-1.5 !rounded-xl px-2 py-1.5">
          {allRoles.map((r) => (
            <button key={r} className="chip" data-active={roles.has(r)} onClick={() => toggleRole(r)}>
              <DeviceIcon role={r} size={12} /> {ROLE_LABEL[r] ?? r}
            </button>
          ))}
          {roles.size > 0 && <button className="chip" onClick={() => setRoleFilter([])}>clear</button>}
        </div>
        <button className="btn pointer-events-auto ml-auto" onClick={() => setAdding(true)}><Link2 size={15} /> Add link</button>
      </div>

      {/* legend */}
      <div className="panel pointer-events-none absolute bottom-4 left-4 hidden !rounded-xl p-3 text-[11px] sm:block">
        <div className="hud-label mb-2">Link utilization</div>
        <div className="flex items-center gap-3">
          {[["#22d3ee", "<20%"], ["#a78bfa", "20–50%"], ["#fbbf24", "50–80%"], ["#fb4d6d", ">80% / down"]].map(([c, l]) => (
            <span key={l} className="flex items-center gap-1.5 text-dim"><i className="h-1 w-5 rounded" style={{ background: c, boxShadow: `0 0 6px ${c}` }} />{l}</span>
          ))}
        </div>
        <div className="mt-2 text-faint">Drag nodes to pin them · scroll to zoom · dashed = manual/description link</div>
      </div>

      {/* inspector */}
      <AnimatePresence>
        {sel && (
          <motion.aside initial={{ opacity: 0, x: 30 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 30 }}
            className="panel panel-brackets absolute top-20 right-4 bottom-4 flex w-[340px] max-w-[calc(100%-2rem)] flex-col overflow-hidden">
            <div className="flex items-start gap-3 border-b border-edge p-4">
              <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan/30 bg-cyan/10 text-cyan">
                <DeviceIcon role={sel.role} size={20} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate font-semibold">{sel.name}</div>
                <div className="flex items-center gap-2 text-xs text-dim">
                  <StatusDot status={sel.status} health={sel.health} size={6} /> {sel.status} · {ROLE_LABEL[sel.role] ?? sel.role}
                </div>
              </div>
              <button className="text-faint hover:text-ink" onClick={() => setSelected(null)}><X size={16} /></button>
            </div>
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
              {sel.device_id != null && (
                <div>
                  <Kv k="Address" v={sel.host} />
                  <Kv k="Model" v={sel.model || "—"} />
                  <Kv k="Version" v={sel.version || "—"} />
                  {sel.metrics?.latency_ms != null && <Kv k="Latency" v={ms(sel.metrics.latency_ms)} />}
                  {sel.clients != null && <Kv k="Clients" v={sel.clients} />}
                  <Kv k="Throughput" v={bps((sel.rx_bps ?? 0) + (sel.tx_bps ?? 0))} />
                  {sel.metrics?.cpu != null && <div className="mt-3 space-y-1"><div className="flex justify-between text-xs text-dim"><span>CPU</span><span className="num">{pct(sel.metrics.cpu)}</span></div><Meter value={sel.metrics.cpu} /></div>}
                  {sel.metrics?.mem != null && <div className="mt-2 space-y-1"><div className="flex justify-between text-xs text-dim"><span>Memory</span><span className="num">{pct(sel.metrics.mem)}</span></div><Meter value={sel.metrics.mem} color="#a78bfa" /></div>}
                </div>
              )}
              <div>
                <div className="hud-label mb-2">Links ({selEdges.length})</div>
                <div className="space-y-2">
                  {selEdges.map((e) => {
                    const mine = e.source === sel.id;
                    return (
                      <div key={e.id} className="rounded-lg border border-edge bg-black/25 p-2.5 text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-sm text-ink">{nameOf(mine ? e.target : e.source)}</span>
                          <Badge tone={e.status === "down" ? "down" : e.kind === "manual" ? "violet" : "cyan"}>{KIND_LABEL[e.kind]}</Badge>
                        </div>
                        <div className="mt-1 font-mono text-faint">
                          {(mine ? e.source_port : e.target_port) || "?"} ↔ {(mine ? e.target_port : e.source_port) || "?"}
                          {e.speed_mbps ? ` · ${speed(e.speed_mbps)}` : ""}
                        </div>
                        <div className="mt-1 flex items-center justify-between font-mono">
                          <span className="text-cyan">↓ {bps(e.rx_bps)}</span>
                          <span className="text-magenta">↑ {bps(e.tx_bps)}</span>
                          <span className="text-dim">{pct(e.util_pct)}</span>
                        </div>
                        {(e.link_id != null || e.internet_link != null) && (
                          <button className="mt-2 flex items-center gap-1 text-crit/80 hover:text-crit"
                            onClick={async () => {
                              await api(e.internet_link != null ? `/links/internet/${e.internet_link}` : `/links/${e.link_id}`, { method: "DELETE" });
                              reload();
                            }}>
                            <Trash2 size={12} /> remove manual link
                          </button>
                        )}
                      </div>
                    );
                  })}
                  {!selEdges.length && <div className="text-xs text-faint">No links discovered for this device.</div>}
                </div>
              </div>
            </div>
            {sel.device_id != null && (
              <Link to={`/devices/${sel.device_id}`} className="btn btn-primary m-4 justify-center">Open device <ChevronRight size={15} /></Link>
            )}
          </motion.aside>
        )}
      </AnimatePresence>

      <Drawer open={adding} onClose={() => setAdding(false)} title="Add manual link" width={480}>
        <AddLink nodes={data?.nodes ?? []} onDone={() => { setAdding(false); reload(); }} />
      </Drawer>
    </div>
  );
}
