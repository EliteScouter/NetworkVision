import clsx from "clsx";
import { AlertTriangle, BadgeCheck, CopyX, Network, Radar, Search, Server, Shuffle, Sparkles, Tag, Users } from "lucide-react";
import { motion } from "motion/react";
import { useMemo, useState } from "react";
import { Badge, CountUp, Empty, Panel, StatusDot } from "../components/ui";
import { api } from "../lib/api";
import { ago, clock } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import type { DhcpClient, DhcpIssue, DhcpOverview } from "../lib/types";

const ISSUE_META: Record<DhcpIssue["type"], { icon: typeof CopyX; label: string }> = {
  ip_conflict: { icon: CopyX, label: "IP conflict" },
  duplicate_hostname: { icon: Users, label: "Duplicate hostname" },
  address_hopping: { icon: Shuffle, label: "Address hopping" },
  multiple_servers: { icon: Server, label: "Multiple DHCP servers" },
};

type Filter = "active" | "unknown" | "new" | "conflict";

function IssueCard({ issue, i }: { issue: DhcpIssue; i: number }) {
  const meta = ISSUE_META[issue.type];
  const warn = issue.severity === "warning";
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
      className={clsx("relative overflow-hidden rounded-xl border bg-black/25 p-4", warn ? "border-warn/40 shadow-[0_0_26px_-12px_#fbbf24]" : "border-edge")}>
      <span className={clsx("absolute inset-y-0 left-0 w-1", warn ? "bg-warn" : "bg-info")} />
      <div className="flex items-center gap-2">
        <meta.icon size={16} className={warn ? "text-warn" : "text-info"} />
        <Badge tone={issue.severity}>{meta.label}</Badge>
      </div>
      <div className="mt-2 font-medium">{issue.title}</div>
      <div className="text-xs text-dim">{issue.detail}</div>
      <div className="mt-3 space-y-1">
        {issue.members.slice(0, 8).map((m, j) => (
          <div key={j} className="flex items-center gap-3 font-mono text-[11.5px]">
            {"server" in m ? (
              <><span className="text-ink">{String(m.server)}</span><span className="text-faint">last lease {ago(Number(m.last_seen))}</span></>
            ) : (
              <>
                <span className="w-28 shrink-0 text-ink">{String(m.ip)}</span>
                <span className="w-36 shrink-0 text-cyan/80">{String(m.mac)}</span>
                <span className="truncate text-dim">{String(m.hostname || "—")}</span>
              </>
            )}
          </div>
        ))}
      </div>
    </motion.div>
  );
}

export default function DhcpPage() {
  const { data, reload } = useApi<DhcpOverview>("/dhcp", 10000);
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState<Filter[]>(["active"]);
  const [editing, setEditing] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  useTick(10000);

  const now = Date.now() / 1000;
  const clients = useMemo(() => {
    const t = q.toLowerCase().trim();
    return (data?.clients ?? []).filter((c) =>
      (!t || `${c.ip} ${c.mac} ${c.hostname} ${c.label}`.toLowerCase().includes(t)) &&
      (!filters.includes("active") || c.active) &&
      (!filters.includes("unknown") || !c.known) &&
      (!filters.includes("new") || now - c.first_seen < 86400) &&
      (!filters.includes("conflict") || c.conflict));
  }, [data, q, filters, now]);

  const toggle = (f: Filter) => setFilters(filters.includes(f) ? filters.filter((x) => x !== f) : [...filters, f]);
  const setKnown = async (c: DhcpClient, known: boolean, newLabel?: string) => {
    await api("/dhcp/known", { method: "POST", body: { mac: c.mac, known, label: newLabel ?? null } });
    setEditing(null);
    reload();
  };
  const st = data?.stats;

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      {data?.learning && (
        <div className="flex items-center gap-2 rounded-xl border border-info/40 bg-info/10 px-4 py-2.5 text-sm text-info">
          <Sparkles size={16} /> Learning your network — "new device" alerts start once the baseline is built.
        </div>
      )}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        {[
          { icon: Network, label: "Active clients", v: st?.active ?? 0, tone: "#22d3ee" },
          { icon: Users, label: "Unique devices", v: st?.macs ?? 0, tone: "#a78bfa" },
          { icon: Sparkles, label: "New in 24h", v: st?.new_24h ?? 0, tone: "#38bdf8" },
          { icon: Tag, label: "Not marked known", v: st?.unknown ?? 0, tone: "#fbbf24" },
          { icon: AlertTriangle, label: "Issues", v: st?.issues ?? 0, tone: st?.issues ? "#fb4d6d" : "#34d399" },
        ].map((k, i) => (
          <motion.div key={k.label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
            className="panel group relative overflow-hidden p-4">
            <div className="absolute -top-10 -right-10 h-28 w-28 rounded-full opacity-20 blur-2xl" style={{ background: k.tone }} />
            <div className="flex items-center justify-between"><span className="hud-label">{k.label}</span><k.icon size={16} style={{ color: k.tone }} /></div>
            <div className="mt-2 text-[26px] leading-none font-semibold"><CountUp value={k.v} /></div>
          </motion.div>
        ))}
      </div>

      <Panel title={`Detected issues · ${data?.issues.length ?? 0}`} icon={<AlertTriangle size={15} />}>
        {!data?.issues.length ? (
          <Empty icon={<BadgeCheck size={28} className="text-ok" />} title="No DHCP problems detected">
            No IP conflicts, duplicate hostnames, address hopping or competing DHCP servers.
          </Empty>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
            {data.issues.map((i, n) => <IssueCard key={i.key} issue={i} i={n} />)}
          </div>
        )}
      </Panel>

      <Panel title="Address history" icon={<Radar size={15} />} bodyClass="!px-0"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {(["active", "unknown", "new", "conflict"] as Filter[]).map((f) => (
              <button key={f} className="chip" data-active={filters.includes(f)} onClick={() => toggle(f)}>
                {f === "new" ? "new 24h" : f === "unknown" ? "not known" : f}
              </button>
            ))}
            <div className="flex items-center gap-1.5 rounded-lg border border-edge bg-black/30 px-2">
              <Search size={13} className="text-faint" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, MAC, hostname…" className="h-7 w-44 bg-transparent text-xs outline-none" />
            </div>
          </div>
        }>
        <div className="max-h-[600px] overflow-auto">
          <table className="table-hud min-w-[900px]">
            <thead><tr><th></th><th>Device</th><th>IP</th><th>MAC</th><th>Seen by</th><th>First seen</th><th>Last seen</th><th></th></tr></thead>
            <tbody>
              {clients.map((c) => (
                <tr key={`${c.mac}-${c.ip}`} className={clsx(c.conflict && "bg-warn/[0.05]")}>
                  <td className="w-6"><StatusDot status={c.active ? "up" : "unknown"} pulse={false} size={7} /></td>
                  <td>
                    {editing === c.mac ? (
                      <form onSubmit={(e) => { e.preventDefault(); setKnown(c, true, label); }} className="flex gap-1">
                        <input autoFocus className="input !py-1 !text-xs" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Friendly name" />
                        <button className="btn !px-2 !py-1 text-xs">Save</button>
                      </form>
                    ) : (
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{c.label || c.hostname || "—"}</span>
                          {c.known && <BadgeCheck size={13} className="text-ok" />}
                          {now - c.first_seen < 86400 && <Badge tone="cyan">new</Badge>}
                          {c.conflict && <Badge tone="warning">conflict</Badge>}
                        </div>
                        {c.label && c.hostname && <div className="text-[11px] text-faint">{c.hostname}</div>}
                      </div>
                    )}
                  </td>
                  <td className="font-mono text-xs">{c.ip}</td>
                  <td className="font-mono text-xs text-dim">{c.mac}</td>
                  <td className="space-x-1">{c.seen_by.map((s) => <Badge key={s} tone={s === "lease" ? "violet" : "neutral"}>{s}</Badge>)}</td>
                  <td className="font-mono text-[11px] text-faint" title={clock(c.first_seen, true)}>{ago(c.first_seen)}</td>
                  <td className="font-mono text-[11px] text-faint">{ago(c.last_seen)}</td>
                  <td className="text-right whitespace-nowrap">
                    <button className="btn btn-ghost !px-2 !py-1 text-xs" onClick={() => { setEditing(c.mac); setLabel(c.label || c.hostname); }}>
                      <Tag size={12} /> Name
                    </button>
                    <button className="btn btn-ghost !px-2 !py-1 text-xs" onClick={() => setKnown(c, !c.known)}>
                      <BadgeCheck size={12} /> {c.known ? "Unmark" : "Known"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!clients.length && (
            <Empty icon={<Radar size={28} />} title="No clients match">
              Clients come from pfSense/OPNsense DHCP leases and UniFi client lists. Add those integrations to populate this view.
            </Empty>
          )}
        </div>
      </Panel>
    </div>
  );
}
