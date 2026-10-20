import { Bell, BellOff, Check, ChevronRight, History, ListTree, SlidersHorizontal, Wrench } from "lucide-react";
import { Link } from "react-router";
import { alertLinks, RULE_LABEL, splitDetail } from "../lib/alerts";
import { api } from "../lib/api";
import { ago, clock, duration } from "../lib/format";
import { useApi } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { Alert, DhcpOverview } from "../lib/types";
import { Badge, Drawer, Spinner } from "./ui";

/** Everything about one alert: full text, timing, earlier occurrences, evidence and actions. */
export function AlertDrawer({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  // Follow live updates (count, ack, resolve) for the alert that's open.
  const live = useLive((s) => (alert ? s.alerts[alert.id] : undefined));
  const a = live ?? alert;
  const { data: past } = useApi<{ items: Alert[] }>(a ? "/alerts" : null, 0, { state: "resolved", key: a?.key ?? "", limit: 20 });
  const { data: dhcp } = useApi<DhcpOverview>(a?.key.startsWith("dhcp:") ? "/dhcp" : null, 0);
  const issue = dhcp?.issues.find((i) => i.key === a?.key);

  const act = async (action: "ack" | "unack" | "resolve") => {
    if (!a) return;
    const updated = await api<Alert>(`/alerts/${a.id}/${action}`, { method: "POST" });
    useLive.getState().applyAlert(action === "resolve" ? "resolved" : "updated", updated);
    if (action === "resolve") onClose();
  };

  const { text, items } = a ? splitDetail(a.detail) : { text: "", items: [] };
  const members = issue?.members.map((m) => ("text" in m ? String(m.text)
    : "server" in m ? `${m.server} · last lease ${ago(Number(m.last_seen))}`
    : [m.ip, m.mac, m.hostname].filter(Boolean).join("  "))) ?? items;
  const occurrences = (past?.items ?? []).filter((p) => p.key === a?.key && p.id !== a?.id);

  return (
    <Drawer open={!!a} onClose={onClose} width={620} title={a && (
      <span className="flex items-center gap-2"><Badge tone={a.severity}>{a.severity}</Badge>{RULE_LABEL[a.rule] ?? a.rule}</span>
    )}>
      {a && (
        <div className="space-y-5">
          <div>
            <h3 className="text-lg leading-snug font-medium">{a.title}</h3>
            {(issue?.detail || text) && <p className="mt-2 text-sm text-dim [overflow-wrap:anywhere]">{issue?.detail || text}</p>}
            <div className="mt-3 flex flex-wrap gap-1.5">
              {a.resolved_at ? <Badge tone="ok">resolved {ago(a.resolved_at)}</Badge> : <Badge tone={a.severity}>active</Badge>}
              {a.acknowledged_at && <Badge tone="ok"><Check size={10} /> ack by {a.acknowledged_by}</Badge>}
              {a.suppressed && <Badge tone="neutral"><Wrench size={10} /> maintenance window</Badge>}
              {a.device_name && <Badge tone="cyan">{a.device_name}</Badge>}
            </div>
          </div>

          <dl className="grid grid-cols-2 gap-3 rounded-xl border border-edge bg-black/20 p-3 text-sm sm:grid-cols-4">
            {[
              ["Started", `${clock(a.started_at, true)}`, ago(a.started_at)],
              ["Last seen", clock(a.last_seen_at, true), ago(a.last_seen_at)],
              ["Duration", duration((a.resolved_at ?? Date.now() / 1000) - a.started_at), a.resolved_at ? "until resolved" : "so far"],
              ["Occurrences", String(a.count || 1), occurrences.length ? `+${occurrences.length} earlier` : "first time"],
            ].map(([k, v, sub]) => (
              <div key={k}>
                <dt className="hud-label !text-[9.5px]">{k}</dt>
                <dd className="font-mono text-[12.5px]">{v}</dd>
                <dd className="text-[11px] text-faint">{sub}</dd>
              </div>
            ))}
          </dl>

          {members.length > 0 && (
            <section>
              <div className="mb-2 flex items-center gap-2 text-xs text-dim"><ListTree size={13} className="text-cyan" /> Details · {members.length}</div>
              <ul className="max-h-72 space-y-1 overflow-y-auto rounded-xl border border-edge bg-black/20 p-2 font-mono text-[11.5px]">
                {members.map((m, i) => <li key={i} className="rounded px-2 py-1 text-ink/90 odd:bg-white/[0.02] [overflow-wrap:anywhere]">{m}</li>)}
              </ul>
            </section>
          )}

          <section className="flex flex-wrap gap-2">
            {alertLinks(a).map((l) => (
              <Link key={l.to} to={l.to} onClick={onClose} className="btn">{l.label} <ChevronRight size={14} /></Link>
            ))}
          </section>

          {!a.resolved_at && (
            <section className="flex flex-wrap gap-2 border-t border-edge pt-4">
              <button className="btn" onClick={() => act(a.acknowledged_at ? "unack" : "ack")}>
                {a.acknowledged_at ? <><BellOff size={14} /> Unacknowledge</> : <><Bell size={14} /> Acknowledge</>}
              </button>
              <button className="btn" onClick={() => act("resolve")} title="Closes it now; it re-opens if the condition is still true">
                <Check size={14} /> Resolve
              </button>
              <Link to={a.device_id ? `/devices/${a.device_id}` : "/settings?tab=alerts"} onClick={onClose} className="btn btn-ghost ml-auto"
                title={a.device_id ? "Mute this rule or device in the device's alert tuning" : "Turn this rule off in Settings"}>
                <SlidersHorizontal size={14} /> {a.device_id ? "Tune for this device" : "Mute this rule"}
              </Link>
            </section>
          )}

          <section>
            <div className="mb-2 flex items-center gap-2 text-xs text-dim"><History size={13} className="text-violet" /> Earlier occurrences</div>
            {!past ? <Spinner size={14} /> : occurrences.length === 0 ? (
              <div className="text-xs text-faint">None — this is the first time.</div>
            ) : (
              <ul className="space-y-1 text-xs">
                {occurrences.map((p) => (
                  <li key={p.id} className="flex items-center justify-between gap-3 rounded-lg border border-edge bg-black/20 px-3 py-1.5">
                    <span className="font-mono">{clock(p.started_at, true)}</span>
                    <span className="text-faint">lasted {duration((p.resolved_at ?? p.last_seen_at) - p.started_at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <div className="font-mono text-[10px] text-faint [overflow-wrap:anywhere]">{a.key}</div>
        </div>
      )}
    </Drawer>
  );
}
