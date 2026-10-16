import clsx from "clsx";
import {
  Activity,
  ArrowUpRight,
  Ban,
  Crosshair,
  Fingerprint,
  Globe2,
  KeyRound,
  Radar,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Target,
  UserX,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { AreaChart, type Series } from "../components/charts";
import { Badge, CountUp, Drawer, Empty, Kv, Panel, Segmented, Spinner } from "../components/ui";
import { ago, clock, SEV_NAMES, sevColor } from "../lib/format";
import { api } from "../lib/api";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { IpReport, SecCategory, SecEvent, SecTimelinePoint, SecuritySummary } from "../lib/types";

type Range = "1h" | "6h" | "24h" | "7d" | "30d";

const CAT: Record<SecCategory, { label: string; color: string; tone: string }> = {
  block: { label: "Blocked", color: "#22d3ee", tone: "cyan" },
  pass: { label: "Allowed", color: "#34d399", tone: "ok" },
  auth_fail: { label: "Login failed", color: "#fbbf24", tone: "warning" },
  auth_ok: { label: "Login OK", color: "#34d399", tone: "ok" },
  ids: { label: "IDS", color: "#fb4d6d", tone: "critical" },
};

export function flag(cc: string | null | undefined): string {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}

let regionNames: Intl.DisplayNames | null = null;
export function countryName(cc: string): string {
  try {
    regionNames ??= new Intl.DisplayNames(["en"], { type: "region" });
    return regionNames.of(cc.toUpperCase()) ?? cc;
  } catch {
    return cc;
  }
}

function Country({ cc, internal }: { cc: string | null; internal?: boolean }) {
  if (internal) return <Badge tone="violet">LAN</Badge>;
  if (!cc) return <span className="text-faint">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs" title={cc}>
      <span className="text-base leading-none">{flag(cc)}</span><span className="text-dim">{countryName(cc)}</span>
    </span>
  );
}

function timelineSeries(points: SecTimelinePoint[], cats: SecCategory[]): Series[] {
  return cats.map((c) => ({ key: c, label: CAT[c].label, color: CAT[c].color, points: points.map((p) => [p.ts, p[c]] as [number, number]) }));
}

/** Deep link into the Firewall log explorer with pre-applied filter chips. */
export function firewallLink(chips: { field: string; value: string }[], range: Range = "24h"): string {
  const fwRange = range === "30d" ? "7d" : range; // the firewall explorer keeps at most 7 days
  return `/firewall?range=${fwRange}&f=${encodeURIComponent(JSON.stringify({ chips, q: "", hideNoise: false }))}`;
}

/** Stable identity for a feed event (no list index: that remounts every row on each new event). */
const eventKey = (e: SecEvent) => `${e.ts}|${e.category}|${e.src}|${e.dport ?? ""}|${e.service}|${e.user}`;

interface EventsSpec { title: string; category: SecCategory[]; service?: string; port?: number }

function EventsDrawer({ spec, range, onClose, onPick }: {
  spec: EventsSpec | null; range: Range; onClose: () => void; onPick: (ip: string) => void;
}) {
  const query = spec ? { category: spec.category, range, service: spec.service, port: spec.port, limit: 200 } : undefined;
  const { data, loading } = useApi<{ items: (SecEvent & { id: number; device?: string | null })[]; more: boolean }>(
    spec ? "/security/events" : null, 30000, query);
  const [older, setOlder] = useState<(SecEvent & { id: number; device?: string | null })[]>([]);
  const [more, setMore] = useState(true);
  const items = [...(data?.items ?? []), ...older];
  const loadOlder = async () => {
    const last = items[items.length - 1];
    if (!last || !query) return;
    const r = await api<{ items: typeof older; more: boolean }>("/security/events", { query: { ...query, before: last.ts } });
    setOlder((o) => [...o, ...r.items]);
    setMore(r.more);
  };
  return (
    <Drawer open={!!spec} onClose={() => { setOlder([]); setMore(true); onClose(); }} width={860}
      title={spec && <span className="flex items-center gap-2">{spec.title}<Badge>{range}</Badge></span>}>
      {loading && !data ? <div className="grid h-40 place-items-center"><Spinner /></div> : !items.length ? (
        <Empty icon={<ShieldCheck size={28} className="text-ok" />} title="No events in this range" />
      ) : (
        <div className="rounded-lg border border-edge">
          <table className="table-hud">
            <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Target</th><th>User</th><th className="text-right">Count</th><th>Device</th></tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id} className="cursor-pointer" onClick={() => onPick(e.src)} title="Open this IP's history">
                  <td className="font-mono text-[11px] text-dim">{clock(e.ts, true)}</td>
                  <td><Badge tone={CAT[e.category].tone}>{CAT[e.category].label}</Badge></td>
                  <td className="font-mono text-xs"><span className="mr-1">{e.internal ? "🏠" : flag(e.country)}</span>{e.src}</td>
                  <td className="text-xs text-dim">{e.service}{e.dport ? ` :${e.dport}` : ""}</td>
                  <td className="font-mono text-xs">{e.user || "—"}</td>
                  <td className="num text-right text-xs">{e.count}</td>
                  <td className="text-xs text-faint">{e.device ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {(data?.more || older.length > 0) && more && (
            <div className="flex justify-center p-3"><button className="btn" onClick={loadOlder}>Load older</button></div>
          )}
        </div>
      )}
    </Drawer>
  );
}

function Stat({ icon: Icon, label, value, tone, sub, delay, onClick, hint }: {
  icon: typeof Ban; label: string; value: number; tone: string; sub?: React.ReactNode; delay: number;
  onClick?: () => void; hint?: string;
}) {
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay }}
      role={onClick ? "button" : undefined} tabIndex={onClick ? 0 : undefined} title={hint}
      onClick={onClick} onKeyDown={(e) => onClick && (e.key === "Enter" || e.key === " ") && onClick()}
      className={clsx("panel group relative overflow-hidden p-4", onClick && "cursor-pointer transition hover:-translate-y-0.5")}>
      <div className="absolute -top-10 -right-10 h-28 w-28 rounded-full opacity-20 blur-2xl transition-opacity group-hover:opacity-40" style={{ background: tone }} />
      <div className="flex items-center justify-between"><span className="hud-label">{label}</span>
        <span className="flex items-center gap-1">{onClick && <ArrowUpRight size={13} className="text-faint opacity-0 transition group-hover:opacity-100" />}
          <Icon size={16} style={{ color: tone }} /></span></div>
      <div className="mt-2 text-[26px] leading-none font-semibold"><CountUp value={value} /></div>
      {sub && <div className="mt-2 text-xs text-dim">{sub}</div>}
    </motion.div>
  );
}

function IpDrawer({ ip, onClose }: { ip: string | null; onClose: () => void }) {
  const [range, setRange] = useState<Range>("7d");
  const nav = useNavigate();
  const { data, loading } = useApi<IpReport>(ip ? `/security/ip/${encodeURIComponent(ip)}` : null, 30000, { range });
  return (
    <Drawer open={!!ip} onClose={onClose} width={820}
      title={ip && <span className="flex items-center gap-2 font-mono">{data?.country && <span>{flag(data.country)}</span>}{ip}
        {data?.internal && <Badge tone="violet">internal host</Badge>}</span>}>
      {loading && !data ? <div className="grid h-40 place-items-center"><Spinner /></div> : data && (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="font-mono text-xs text-dim">
              first seen {data.first_seen ? clock(data.first_seen, true) : "—"} · last seen {ago(data.last_seen)}
            </div>
            <div className="flex items-center gap-2">
              <button className="btn !py-1" onClick={() => ip && nav(firewallLink([{ field: "ip", value: ip }], range))}>
                <ArrowUpRight size={14} /> Open in Firewall log
              </button>
              <Segmented value={range} onChange={setRange} options={(["24h", "7d", "30d"] as Range[]).map((r) => ({ value: r, label: r }))} />
            </div>
          </div>
          <div className="grid grid-cols-5 gap-2">
            {(Object.keys(CAT) as SecCategory[]).map((c) => (
              <div key={c} className="rounded-xl border border-edge bg-black/20 p-3 text-center">
                <div className="hud-label !text-[9.5px]">{CAT[c].label}</div>
                <div className="num mt-1 text-lg" style={{ color: data.totals[c] ? CAT[c].color : undefined }}>{data.totals[c].toLocaleString()}</div>
              </div>
            ))}
          </div>
          <AreaChart series={timelineSeries(data.timeline, ["block", "auth_fail", "ids", "pass"])} height={180} yFormat={(v) => v.toFixed(0)} />
          {data.credentials.length > 0 && (
            <div>
              <div className="hud-label mb-2 flex items-center gap-1.5"><KeyRound size={12} /> Logins & signatures</div>
              <div className="flex flex-wrap gap-1.5">
                {data.credentials.map((c, i) => (
                  <Badge key={i} tone={CAT[c.category].tone}>{c.service}{c.user && ` · ${c.user}`} ×{c.count}</Badge>
                ))}
              </div>
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <div className="hud-label mb-2">Ports touched</div>
              <div className="max-h-56 overflow-y-auto rounded-lg border border-edge">
                <table className="table-hud">
                  <thead><tr><th>Port</th><th>Service</th><th>Result</th><th className="text-right">Hits</th></tr></thead>
                  <tbody>{data.ports.map((p, i) => (
                    <tr key={i}><td className="num text-xs">{p.port}/{p.proto}</td><td className="text-dim">{p.service}</td>
                      <td><Badge tone={CAT[p.category].tone}>{CAT[p.category].label}</Badge></td><td className="num text-right text-xs">{p.count}</td></tr>
                  ))}</tbody>
                </table>
                {!data.ports.length && <div className="p-4 text-center text-xs text-faint">No firewall hits.</div>}
              </div>
            </div>
            <div>
              <div className="hud-label mb-2">Targets</div>
              {data.targets.map((t) => <Kv key={t.ip} k={<span className="font-mono text-xs">{t.ip}</span>} v={t.count.toLocaleString()} />)}
              {!data.targets.length && <div className="text-xs text-faint">—</div>}
              {data.alerts.length > 0 && (
                <>
                  <div className="hud-label mt-4 mb-2">Alerts</div>
                  {data.alerts.map((a) => (
                    <div key={a.id} className="mb-1.5 flex items-center gap-2 text-sm">
                      <Badge tone={a.resolved_at ? "ok" : a.severity}>{a.resolved_at ? "resolved" : a.severity}</Badge>
                      <span className="truncate">{a.title}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="hud-label">Raw log lines</span>
              <Link to={`/logs?q=${encodeURIComponent(data.ip)}`} className="text-xs text-dim hover:text-cyan">Open in log explorer</Link>
            </div>
            <div className="max-h-72 overflow-y-auto rounded-lg border border-edge font-mono text-[11.5px] leading-6">
              {data.logs.map((l) => (
                <div key={l.id} className="flex gap-3 border-b border-edge/40 px-2">
                  <span className="shrink-0 text-faint">{clock(l.ts, true)}</span>
                  <span className={clsx("w-12 shrink-0", sevColor(l.severity))}>{SEV_NAMES[l.severity]}</span>
                  <span className="w-20 shrink-0 truncate text-violet/80">{l.app}</span>
                  <span className="break-all text-ink/85">{l.message}</span>
                </div>
              ))}
              {!data.logs.length && <div className="p-4 text-center text-faint">No raw lines in range.</div>}
            </div>
          </div>
        </div>
      )}
    </Drawer>
  );
}

function FeedRow({ e, onPick }: { e: SecEvent; onPick: (ip: string) => void }) {
  const c = CAT[e.category];
  return (
    // New rows open from zero height at the top, so older rows glide down instead of jumping.
    <motion.button initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 29 }}
      transition={{ duration: 0.35, ease: [0.2, 0.7, 0.2, 1] }} onClick={() => onPick(e.src)}
      className="flex w-full items-center gap-2.5 overflow-hidden rounded-lg px-2 text-left font-mono text-[11.5px] hover:bg-white/[0.03]">
      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: c.color, boxShadow: `0 0 8px ${c.color}` }} />
      <span className="w-14 shrink-0 text-faint">{clock(e.ts)}</span>
      <span className="w-5 shrink-0">{e.internal ? "🏠" : flag(e.country)}</span>
      <span className="w-28 shrink-0 truncate text-ink">{e.src}</span>
      <span className="min-w-0 flex-1 truncate" style={{ color: c.color }}>
        {e.category === "block" ? `✕ ${e.service}${e.dport ? ` :${e.dport}` : ""}` : e.category === "ids" ? e.service
          : `${c.label} · ${e.service}${e.user ? ` (${e.user})` : ""}`}
      </span>
    </motion.button>
  );
}

export default function SecurityPage() {
  const [range, setRange] = useState<Range>("24h");
  const { data, loading } = useApi<SecuritySummary>("/security/summary", 15000, { range });
  const live = useLive((s) => s.security);
  const [pick, setPick] = useState<string | null>(null);
  const [events, setEvents] = useState<EventsSpec | null>(null);
  const [countryFilter, setCountryFilter] = useState<string | null>(null);
  const [feedCats, setFeedCats] = useState<SecCategory[]>(["block", "auth_fail", "auth_ok", "ids"]);
  const nav = useNavigate();
  useTick(10000);

  // Live events and the server's recent list are merged (not swapped): otherwise the first live
  // event replaced the whole list and the feed collapsed to a single row.
  const feed = useMemo(() => {
    const seen = new Set<string>();
    return [...live, ...(data?.recent ?? [])]
      .filter((e) => feedCats.includes(e.category))
      .sort((a, b) => b.ts - a.ts)
      .filter((e) => { const k = eventKey(e); if (seen.has(k)) return false; seen.add(k); return true; })
      .slice(0, 60);
  }, [live, data?.recent, feedCats]);
  const sources = (data?.top_sources ?? []).filter((s) => !countryFilter || s.country === countryFilter);
  const scrollTo = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });

  const t = data?.totals;
  const breaches = data?.detections.filter((d) => d.rule === "sec_login_after_failures") ?? [];
  const maxPort = Math.max(1, ...(data?.top_ports.map((p) => p.count) ?? [1]));
  const maxCountry = Math.max(1, ...(data?.countries.map((c) => c.attacks) ?? [1]));

  return (
    <div className="mx-auto grid max-w-[1800px] grid-cols-12 gap-4 p-4 md:p-6">
      <div className="col-span-12 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 text-sm text-dim">
          <ShieldAlert size={18} className="text-cyan" />
          Firewall, authentication and IDS activity across every device
          {loading && <Spinner size={14} />}
        </div>
        <Segmented value={range} onChange={setRange} options={(["1h", "6h", "24h", "7d", "30d"] as Range[]).map((r) => ({ value: r, label: r }))} />
      </div>

      <AnimatePresence>
        {breaches.map((b) => (
          <motion.div key={b.id} initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }}
            className="col-span-12 flex items-center gap-3 rounded-xl border border-crit/50 bg-crit/10 p-4 shadow-[0_0_40px_-12px_#fb4d6d]">
            <Siren size={22} className="shrink-0 animate-pulse text-crit" />
            <div className="min-w-0 flex-1">
              <div className="font-semibold text-crit">{b.title}</div>
              <div className="text-sm text-ink/80">{b.detail}</div>
            </div>
            <span className="font-mono text-xs text-faint">{ago(b.started_at)}</span>
          </motion.div>
        ))}
      </AnimatePresence>

      <div className="col-span-12 grid grid-cols-2 gap-4 md:grid-cols-5">
        <Stat icon={Ban} label="Blocked" value={t?.block ?? 0} tone="#22d3ee" delay={0} hint="Open blocked traffic in the Firewall log"
          onClick={() => nav(firewallLink([{ field: "action", value: "block" }], range))}
          sub={<button className="hover:text-ok hover:underline" onClick={(e) => { e.stopPropagation(); nav(firewallLink([{ field: "action", value: "pass" }], range)); }}>
            {(t?.pass ?? 0).toLocaleString()} allowed</button>} />
        <Stat icon={UserX} label="Failed logins" value={t?.auth_fail ?? 0} tone="#fbbf24" delay={0.04} hint="Show every failed login"
          onClick={() => setEvents({ title: "Failed logins", category: ["auth_fail"] })}
          sub={<button className="hover:text-ok hover:underline" onClick={(e) => { e.stopPropagation(); setEvents({ title: "Successful logins", category: ["auth_ok"] }); }}>
            {t?.auth_ok ?? 0} successful</button>} />
        <Stat icon={Fingerprint} label="IDS alerts" value={t?.ids ?? 0} tone="#fb4d6d" delay={0.08} sub="Suricata / Snort"
          onClick={() => setEvents({ title: "IDS alerts", category: ["ids"] })} hint="Show every IDS alert" />
        <Stat icon={Crosshair} label="Attacking sources" value={data?.attackers ?? 0} tone="#a78bfa" delay={0.12}
          onClick={() => { setCountryFilter(null); scrollTo("sec-sources"); }} hint="Jump to the attacker list"
          sub={data?.top_sources[0] ? `top: ${data.top_sources[0].ip}` : "unique IPs"} />
        <Stat icon={Siren} label="Active detections" value={data?.detections.length ?? 0} tone={data?.detections.length ? "#fb4d6d" : "#34d399"}
          delay={0.16} sub="brute force · scans · IDS" onClick={() => scrollTo("sec-detections")} hint="Jump to active detections" />
      </div>

      <Panel className="col-span-12 xl:col-span-8" title="Attack timeline" icon={<Activity size={15} />}
        actions={<div className="flex gap-3 text-xs">{(["block", "auth_fail", "ids"] as SecCategory[]).map((c) => (
          <span key={c} className="flex items-center gap-1.5 text-dim"><i className="h-2 w-2 rounded-full" style={{ background: CAT[c].color }} />{CAT[c].label}</span>))}</div>}>
        <AreaChart series={timelineSeries(data?.timeline ?? [], ["block", "auth_fail", "ids"])} height={240} yFormat={(v) => v.toFixed(0)}
          empty="No security events yet — see the README for what to enable on your firewall." />
      </Panel>

      <Panel className="col-span-12 scroll-mt-24 xl:col-span-4" title="Active detections" icon={<Siren size={15} />}>
        <span id="sec-detections" />
        <div className="h-[240px] space-y-2 overflow-y-auto pr-1">
          {!data?.detections.length && <Empty icon={<ShieldCheck size={28} className="text-ok" />} title="No active threats">Brute force, scans and IDS hits show up here.</Empty>}
          {data?.detections.map((a) => {
            const ip = a.src;
            return (
              <button key={a.id} onClick={() => ip && setPick(ip)}
                className={clsx("relative w-full overflow-hidden rounded-xl border bg-black/20 p-3 text-left hover:bg-white/[0.03]",
                  a.severity === "critical" ? "border-crit/40" : "border-warn/30")}>
                <span className={clsx("absolute inset-y-0 left-0 w-0.5", a.severity === "critical" ? "bg-crit" : "bg-warn")} />
                <div className="flex items-center justify-between"><Badge tone={a.severity}>{a.rule.replace("sec_", "").replace(/_/g, " ")}</Badge>
                  <span className="font-mono text-[10.5px] text-faint">{ago(a.last_seen_at)}{a.count > 1 && ` · ×${a.count}`}</span></div>
                <div className="mt-1.5 truncate text-sm">{a.title}</div>
                <div className="truncate text-xs text-dim">{a.detail}</div>
              </button>
            );
          })}
        </div>
      </Panel>

      <Panel className="col-span-12 scroll-mt-24 xl:col-span-8" title="Top attacking sources" icon={<Crosshair size={15} />} bodyClass="!px-0"
        actions={countryFilter && <button className="chip" data-active onClick={() => setCountryFilter(null)}>{flag(countryFilter)} {countryName(countryFilter)} ✕</button>}>
        <span id="sec-sources" />
        <div className="max-h-[440px] overflow-auto">
          <table className="table-hud min-w-[720px]">
            <thead><tr><th>Source</th><th>Origin</th><th className="text-right">Total</th><th>Breakdown</th><th className="text-right">Ports</th><th>Last seen</th></tr></thead>
            <tbody>
              {sources.map((s, i) => (
                <motion.tr key={s.ip} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(i, 15) * 0.02 }}
                  className="cursor-pointer" onClick={() => setPick(s.ip)}>
                  <td className="font-mono text-xs text-ink">{s.ip}{s.auth_ok > 0 && s.auth_fail > 0 && <Badge tone="critical" className="ml-2">got in?</Badge>}</td>
                  <td><Country cc={s.country} internal={s.internal} /></td>
                  <td className="num text-right text-xs">{s.attacks.toLocaleString()}</td>
                  <td>
                    <div className="flex h-1.5 w-40 overflow-hidden rounded-full bg-white/5">
                      {(["block", "auth_fail", "ids"] as const).map((c) => s[c] > 0 && (
                        <div key={c} style={{ flex: s[c], background: CAT[c].color }} title={`${CAT[c].label}: ${s[c]}`} />
                      ))}
                    </div>
                  </td>
                  <td className="num text-right text-xs text-dim">{s.ports}</td>
                  <td className="font-mono text-[11px] text-faint">{ago(s.last_seen)}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
          {!data?.top_sources.length && <Empty icon={<Radar size={28} />} title="No attackers seen">Nothing hostile in this time range.</Empty>}
        </div>
      </Panel>

      <Panel className="col-span-12 xl:col-span-4" title="Origin countries" icon={<Globe2 size={15} />}>
        {data?.geoip === "none" ? (
          <div className="space-y-2 py-6 text-center text-sm text-dim">
            <Globe2 size={28} className="mx-auto text-faint" />
            <div>GeoIP is not configured.</div>
            <div className="text-xs text-faint">Set <code className="text-violet">NV_GEOIP_LICENSE_KEY</code> (free MaxMind account) or drop
              GeoLite2-Country.mmdb into the data volume.</div>
          </div>
        ) : (
          <div className="max-h-[400px] space-y-2.5 overflow-y-auto pr-1">
            {data?.geoip === "demo" && <div className="text-[11px] text-faint">Demo countries (simulated)</div>}
            {data?.countries.map((c) => (
              <button key={c.country} className={clsx("block w-full rounded-lg px-1 text-left transition hover:bg-white/[0.03]",
                countryFilter === c.country && "bg-cyan/10")} onClick={() => { setCountryFilter(countryFilter === c.country ? null : c.country); scrollTo("sec-sources"); }}
                title="Filter attacking sources to this country">
                <div className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2" title={c.country}><span className="text-lg leading-none">{flag(c.country)}</span><span className="text-xs">{countryName(c.country)}</span></span>
                  <span className="num text-xs">{c.attacks.toLocaleString()}</span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
                  <motion.div className="h-full rounded-full bg-gradient-to-r from-violet to-crit" initial={{ width: 0 }}
                    animate={{ width: `${(c.attacks / maxCountry) * 100}%` }} />
                </div>
              </button>
            ))}
            {!data?.countries.length && <div className="py-4 text-center text-xs text-faint">No external attackers in range.</div>}
          </div>
        )}
      </Panel>

      <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Targeted ports" icon={<Target size={15} />}>
        <div className="space-y-2.5">
          {data?.top_ports.map((p) => (
            <button key={`${p.port}-${p.proto}`} className="block w-full rounded-lg px-1 text-left transition hover:bg-white/[0.03]"
              title="Show blocked traffic to this port in the Firewall log"
              onClick={() => nav(firewallLink([{ field: "action", value: "block" }, { field: "port", value: String(p.port) }], range))}>
              <div className="flex items-baseline justify-between text-sm">
                <span><span className="num text-ink">{p.port}</span><span className="text-faint">/{p.proto}</span> <span className="text-dim">{p.service}</span></span>
                <span className="num text-xs">{p.count.toLocaleString()} <span className="text-faint">· {p.sources} src</span></span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-white/5">
                <motion.div className="h-full rounded-full bg-gradient-to-r from-cyan to-violet" initial={{ width: 0 }} animate={{ width: `${(p.count / maxPort) * 100}%` }} />
              </div>
            </button>
          ))}
          {!data?.top_ports.length && <div className="py-6 text-center text-xs text-faint">No blocked traffic logged.</div>}
        </div>
      </Panel>

      <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Targeted services" icon={<KeyRound size={15} />}>
        <div className="space-y-2">
          {data?.services.map((s, i) => (
            <button key={i} className="flex w-full items-center gap-3 rounded-lg border border-edge bg-black/20 px-3 py-2 text-left transition hover:border-cyan/40"
              onClick={() => setEvents({ title: `${CAT[s.category].label} · ${s.service}`, category: [s.category], service: s.service })}>
              <Badge tone={CAT[s.category].tone}>{CAT[s.category].label}</Badge>
              <span className="min-w-0 flex-1 truncate text-sm">{s.service}</span>
              <span className="num text-xs">{s.count.toLocaleString()}</span>
              <span className="font-mono text-[10.5px] text-faint">{s.sources} src</span>
            </button>
          ))}
          {!data?.services.length && <div className="py-6 text-center text-xs text-faint">No login or IDS activity in range.</div>}
        </div>
      </Panel>

      <Panel className="col-span-12 xl:col-span-4" title="Live feed" icon={<ScrollText size={15} />} bodyClass="relative min-h-[340px]"
        actions={<div className="flex gap-1">{(["block", "auth_fail", "ids"] as SecCategory[]).map((c) => (
          <button key={c} className="chip !px-2 !py-0.5 !text-[10.5px]" data-active={feedCats.includes(c)}
            onClick={() => setFeedCats(feedCats.includes(c) ? feedCats.filter((x) => x !== c) : [...feedCats, c])}>
            {{ block: "Block", auth_fail: "Auth", ids: "IDS" }[c as "block" | "auth_fail" | "ids"]}</button>))}</div>}>
        <div className="absolute inset-0 overflow-hidden px-4 pb-4 [mask-image:linear-gradient(to_bottom,black_85%,transparent)]">
          {!feed.length && <div className="py-10 text-center text-xs text-faint">Waiting for events…</div>}
          <AnimatePresence initial={false}>
            {feed.map((e) => <FeedRow key={eventKey(e)} e={e} onPick={setPick} />)}
          </AnimatePresence>
        </div>
      </Panel>

      <IpDrawer ip={pick} onClose={() => setPick(null)} />
      <EventsDrawer spec={events} range={range} onClose={() => setEvents(null)} onPick={(ip) => { setEvents(null); setPick(ip); }} />
    </div>
  );
}
