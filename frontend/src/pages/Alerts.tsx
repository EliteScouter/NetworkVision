import clsx from "clsx";
import { Bell, BellOff, Check, CheckCheck, Search, ShieldCheck } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { Badge, Empty, Segmented } from "../components/ui";
import { api } from "../lib/api";
import { ago, clock, duration } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { Alert } from "../lib/types";

const RULE_LABEL: Record<string, string> = {
  device_down: "Device down", poll_error: "Integration error", high_cpu: "High CPU", high_mem: "High memory",
  high_temp: "Temperature", high_latency: "Latency", packet_loss: "Packet loss", gateway_down: "Gateway down",
  gateway_loss: "Gateway loss", gateway_latency: "Gateway latency", port_flapping: "Port flapping", port_down: "Link down",
  port_errors: "Port errors", port_saturated: "Saturation", firmware_update: "Firmware", log_event: "Critical log",
};

export default function AlertsPage() {
  const [tab, setTab] = useState<"active" | "history">("active");
  const [sev, setSev] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [hideAck, setHideAck] = useState(false);
  const active = useLive((s) => s.alerts);
  const { data: history, reload } = useApi<{ items: Alert[] }>(tab === "history" ? "/alerts" : null, 30000, { state: "resolved", limit: 500 });
  useTick(10000);

  const list = useMemo(() => {
    const src = tab === "active" ? Object.values(active) : history?.items ?? [];
    const t = q.toLowerCase();
    return src
      .filter((a) => (!sev.length || sev.includes(a.severity)) && (!hideAck || !a.acknowledged_at) &&
        (!t || `${a.title} ${a.detail} ${a.device_name} ${a.rule}`.toLowerCase().includes(t)))
      .sort((a, b) => tab === "active"
        ? ({ critical: 0, warning: 1, info: 2 }[a.severity] - { critical: 0, warning: 1, info: 2 }[b.severity]) || b.started_at - a.started_at
        : (b.resolved_at ?? 0) - (a.resolved_at ?? 0));
  }, [tab, active, history, sev, q, hideAck]);

  const counts = { critical: 0, warning: 0, info: 0 } as Record<string, number>;
  Object.values(active).forEach((a) => counts[a.severity]++);

  const act = async (a: Alert, action: "ack" | "unack" | "resolve") => {
    const updated = await api<Alert>(`/alerts/${a.id}/${action}`, { method: "POST" });
    useLive.getState().applyAlert(action === "resolve" ? "resolved" : "updated", updated);
    if (tab === "history") reload();
  };
  const ackAll = async () => {
    for (const a of list.filter((x) => !x.acknowledged_at)) await act(a, "ack");
  };

  return (
    <div className="mx-auto max-w-[1400px] space-y-4 p-4 md:p-6">
      <div className="grid grid-cols-3 gap-3">
        {(["critical", "warning", "info"] as const).map((s, i) => (
          <motion.button key={s} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
            onClick={() => setSev(sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s])}
            className={clsx("panel p-4 text-left transition", sev.includes(s) && "ring-1 ring-cyan/50")}>
            <div className="hud-label">{s}</div>
            <div className={clsx("num mt-1 text-3xl font-semibold", s === "critical" ? "text-crit" : s === "warning" ? "text-warn" : "text-info")}>{counts[s]}</div>
          </motion.button>
        ))}
      </div>

      <div className="panel flex flex-wrap items-center gap-3 p-3">
        <Segmented value={tab} onChange={setTab} options={[{ value: "active", label: "Active" }, { value: "history", label: "History" }]} />
        <div className="flex min-w-[200px] flex-1 items-center gap-2 rounded-xl border border-edge bg-black/30 px-3">
          <Search size={15} className="text-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter alerts…" className="h-9 flex-1 bg-transparent text-sm outline-none" />
        </div>
        {tab === "active" && (
          <>
            <button className="chip" data-active={hideAck} onClick={() => setHideAck(!hideAck)}><BellOff size={12} /> hide acknowledged</button>
            <button className="btn" onClick={ackAll} disabled={!list.some((a) => !a.acknowledged_at)}><CheckCheck size={15} /> Ack all shown</button>
          </>
        )}
      </div>

      <div className="space-y-2">
        {!list.length && (
          <div className="panel"><Empty icon={<ShieldCheck size={32} className="text-ok" />} title={tab === "active" ? "No active alerts" : "No history yet"}>
            {tab === "active" ? "Everything is nominal." : "Resolved alerts will show up here."}
          </Empty></div>
        )}
        <AnimatePresence initial={false}>
          {list.map((a) => (
            <motion.div key={a.id} layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: a.acknowledged_at && tab === "active" ? 0.6 : 1, y: 0 }}
              exit={{ opacity: 0, x: 40, transition: { duration: 0.2 } }}
              className={clsx("panel relative flex flex-wrap items-center gap-4 overflow-hidden p-4",
                tab === "active" && a.severity === "critical" && !a.acknowledged_at && "shadow-[0_0_30px_-14px_#fb4d6d]")}>
              <span className={clsx("absolute inset-y-0 left-0 w-1", a.severity === "critical" ? "bg-crit" : a.severity === "warning" ? "bg-warn" : "bg-info")} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={a.severity}>{a.severity}</Badge>
                  <Badge>{RULE_LABEL[a.rule] ?? a.rule}</Badge>
                  {a.count > 1 && <Badge tone="violet">×{a.count}</Badge>}
                  {a.acknowledged_at && <Badge tone="ok"><Check size={10} /> ack by {a.acknowledged_by}</Badge>}
                </div>
                <div className="mt-1.5 font-medium">{a.title}</div>
                {a.detail && <div className="text-sm break-all text-dim">{a.detail}</div>}
                <div className="mt-1 font-mono text-[11px] text-faint">
                  started {clock(a.started_at, true)} · {a.resolved_at ? `lasted ${duration(a.resolved_at - a.started_at)}` : `ongoing for ${duration(Date.now() / 1000 - a.started_at)}`}
                  {!a.resolved_at && ` · last seen ${ago(a.last_seen_at)}`}
                </div>
              </div>
              {a.device_id && <Link to={`/devices/${a.device_id}`} className="btn btn-ghost text-dim">{a.device_name ?? `device ${a.device_id}`}</Link>}
              {tab === "active" && (
                <div className="flex gap-2">
                  <button className="btn" onClick={() => act(a, a.acknowledged_at ? "unack" : "ack")}>
                    <Bell size={14} /> {a.acknowledged_at ? "Unack" : "Ack"}
                  </button>
                  <button className="btn" onClick={() => act(a, "resolve")} title="Resolve now (re-opens if the condition persists)">
                    <Check size={14} /> Resolve
                  </button>
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
