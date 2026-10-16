import clsx from "clsx";
import {
  Ban,
  BrickWall,
  Check,
  ChevronDown,
  Copy,
  Crosshair,
  EyeOff,
  Filter,
  ListFilter,
  Pause,
  Play,
  Plus,
  Save,
  Search,
  ShieldAlert,
  Trash2,
  Undo2,
  X,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { Badge, CountUp, Empty, Panel, Segmented, Spinner, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { clock } from "../lib/format";
import { useLocalState, useSize } from "../lib/hooks";
import { useLive } from "../lib/store";

// ------------------------------------------------------------------ types
interface FwEvent {
  id: number;
  ts: number;
  device_id: number | null;
  action: string;
  direction: string;
  iface: string;
  iface_name: string;
  rule_id: string;
  rule: string;
  ipver: number;
  proto: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  tcp_flags: string;
  length: number | null;
  info: string;
  noise: boolean;
}
interface EventsResponse { items: FwEvent[]; next_cursor: string | null; total?: number; total_capped?: boolean; since: number; until: number }
interface Bucket { ts: number; pass: number; block: number; other: number; skipped: number }
interface TimelineResponse { since: number; until: number; step: number; source: "counters" | "events"; series: Bucket[] }
interface TopIp { ip: string; count: number; blocked: number; last: number }
interface StatsResponse {
  actions: Record<string, number>;
  top_sources: TopIp[];
  top_blocked_sources: TopIp[];
  top_destinations: TopIp[];
  top_ports: { port: number; proto: string; count: number; blocked: number }[];
  top_rules: { rule_id: string; rule: string; count: number; blocked: number }[];
  interfaces: { iface: string; count: number; blocked: number }[];
  protocols: { proto: string; count: number; blocked: number }[];
}
interface FacetsResponse {
  interfaces: { iface: string; count: number }[];
  rules: { rule_id: string; rule: string; count: number }[];
  ingest: Record<string, number>;
  settings: { store_pass: boolean; store_noise: boolean; keep_raw_logs: boolean; retention_days: number; enabled: boolean };
}

type Field = "action" | "iface" | "rule" | "proto" | "src" | "dst" | "ip" | "port" | "sport" | "direction" | "ipver";
interface Chip { field: Field; value: string; neg?: boolean; label?: string }
interface View { chips: Chip[]; q: string; hideNoise: boolean }
interface SavedView extends View { name: string }

// ---------------------------------------------------------------- helpers
const RANGES = { "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 } as const;
type Range = keyof typeof RANGES;
const FIELDS: Field[] = ["action", "iface", "rule", "proto", "src", "dst", "ip", "port", "sport", "direction", "ipver"];
const FIELD_LABEL: Record<Field, string> = {
  action: "action", iface: "interface", rule: "rule", proto: "proto", src: "source", dst: "dest", ip: "ip",
  port: "port", sport: "src port", direction: "dir", ipver: "IPv",
};
const SERVICES: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
  135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
  465: "smtps", 514: "syslog", 546: "dhcpv6", 547: "dhcpv6", 587: "smtp", 853: "dot", 993: "imaps", 1194: "openvpn",
  1433: "mssql", 1723: "pptp", 1883: "mqtt", 1900: "ssdp", 2375: "docker", 3306: "mysql", 3389: "rdp", 5060: "sip",
  5353: "mdns", 5355: "llmnr", 5432: "postgres", 5900: "vnc", 6379: "redis", 8006: "proxmox", 8080: "http-alt",
  8443: "https-alt", 9443: "portainer", 9200: "elastic", 11211: "memcached", 27017: "mongodb", 32400: "plex", 51820: "wireguard",
};
const WAN_RE = /wan|internet|isp|uplink/i;
const BLOCKED = new Set(["block", "reject"]);

/** IPv6 shortened for a table cell: first two + last two groups, full address in the tooltip. */
function shortIp(ip: string): string {
  if (!ip.includes(":") || ip.length <= 22) return ip;
  const [head, tail] = ip.split("::");
  if (tail !== undefined) {
    const h = head.split(":").slice(0, 2).join(":");
    const t = tail.split(":").slice(-2).join(":");
    return `${h}::…${t}`;
  }
  const g = ip.split(":");
  return `${g.slice(0, 2).join(":")}:…:${g.slice(-2).join(":")}`;
}
const hostPort = (ip: string, port: number | null) => (port == null ? ip : ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
const isPrivate = (ip: string) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) ||
  /^(fe8|fe9|fea|feb|fc|fd|ff|::1$)/i.test(ip);
const ruleText = (e: { rule: string; rule_id: string }) => e.rule || (e.rule_id ? `rule ${e.rule_id.length > 12 ? e.rule_id.slice(0, 8) + "…" : e.rule_id}` : "—");
const protoText = (e: FwEvent) => `${e.proto.toUpperCase().replace("IPV6-ICMP", "ICMPv6")}${e.tcp_flags ? `:${e.tcp_flags}` : ""}`;
const compact = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}k` : n.toLocaleString());

function toQuery(view: View, devices: number[]): Record<string, string | number | boolean | (string | number)[] | undefined> {
  const q: Record<string, string | number | boolean | (string | number)[] | undefined> = {};
  for (const f of FIELDS) {
    const vals = view.chips.filter((c) => c.field === f).map((c) => (c.neg ? `!${c.value}` : c.value));
    if (!vals.length) continue;
    q[f] = f === "direction" || f === "ipver" ? vals[vals.length - 1] : vals;
  }
  if (view.q.trim()) q.q = view.q.trim();
  if (view.hideNoise) q.hide_noise = true;
  if (devices.length) q.device_id = devices;
  return q;
}

const TOKEN = /^(!|-)?(action|iface|interface|rule|proto|src|source|dst|dest|ip|port|dport|sport|dir|direction|ipver):(.+)$/i;
const ALIAS: Record<string, Field> = { interface: "iface", source: "src", dest: "dst", dport: "port", dir: "direction" };

// ------------------------------------------------------------- timeline
function Timeline({ data, onZoom, loading }: { data: TimelineResponse | null; onZoom: (t0: number, t1: number) => void; loading: boolean }) {
  const [ref, { width }] = useSize<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [drag, setDrag] = useState<{ a: number; b: number } | null>(null);
  const series = data?.series ?? [];
  const H = 132, padB = 18;
  const max = Math.max(1, ...series.map((s) => s.pass + s.block + s.other));
  const bw = series.length ? width / series.length : 0;
  const idxAt = (x: number) => Math.max(0, Math.min(series.length - 1, Math.floor(x / Math.max(bw, 1))));
  const ticks = series.length ? [0, Math.floor(series.length / 2), series.length - 1] : [];
  const long = data ? data.until - data.since > 2 * 86400 : false;
  const fmt = (t: number) => (long ? clock(t, true).slice(0, 12) : clock(t).slice(0, 5));
  const hv = hover != null ? series[hover] : null;

  return (
    <div ref={ref} className="relative w-full cursor-crosshair select-none" style={{ height: H }}
      onMouseLeave={() => { setHover(null); setDrag(null); }}
      onMouseDown={(e) => { const x = e.clientX - e.currentTarget.getBoundingClientRect().left; setDrag({ a: x, b: x }); }}
      onMouseMove={(e) => {
        const x = e.clientX - e.currentTarget.getBoundingClientRect().left;
        setHover(idxAt(x));
        if (drag) setDrag({ ...drag, b: x });
      }}
      onMouseUp={() => {
        if (!drag || !data || !series.length) return setDrag(null);
        const i0 = idxAt(Math.min(drag.a, drag.b)), i1 = idxAt(Math.max(drag.a, drag.b));
        setDrag(null);
        onZoom(series[i0].ts, series[i1].ts + data.step); // a click zooms into one bucket, a drag into the span
      }}>
      {loading && !series.length && <div className="absolute inset-0 grid place-items-center"><Spinner /></div>}
      {width > 0 && (
        <svg width={width} height={H} className="overflow-visible">
          {[0.5, 1].map((f) => (
            <line key={f} x1={0} x2={width} y1={(H - padB) * (1 - f)} y2={(H - padB) * (1 - f)} stroke="#16233d" strokeDasharray="2 4" />
          ))}
          {series.map((s, i) => {
            const total = s.pass + s.block + s.other;
            const h = (total / max) * (H - padB - 4);
            const hb = (s.block / max) * (H - padB - 4), ho = (s.other / max) * (H - padB - 4);
            const x = i * bw + Math.min(1, bw * 0.15), w = Math.max(1, bw - Math.min(2, bw * 0.3));
            const y0 = H - padB;
            return (
              <motion.g key={s.ts} initial={{ opacity: 0, y: 12 }} animate={{ opacity: hover == null || hover === i ? 1 : 0.55, y: 0 }}
                transition={{ duration: 0.35, delay: Math.min(i * 0.004, 0.4) }}>
                <rect x={x} y={y0 - hb} width={w} height={hb} fill="#fb4d6d" rx={1} />
                <rect x={x} y={y0 - hb - ho} width={w} height={ho} fill="#a78bfa" />
                <rect x={x} y={y0 - h} width={w} height={h - hb - ho} fill="#34d399" fillOpacity={0.7} rx={1} />
              </motion.g>
            );
          })}
          {ticks.map((i, k) => (
            <text key={i} x={k === 0 ? 0 : k === 2 ? width : (i + 0.5) * bw} y={H - 4} textAnchor={k === 0 ? "start" : k === 2 ? "end" : "middle"}
              className="fill-faint font-mono text-[10px]">{fmt(series[i].ts)}</text>
          ))}
          <text x={width} y={10} textAnchor="end" className="fill-faint font-mono text-[10px]">{compact(max)}</text>
          {drag && Math.abs(drag.b - drag.a) > 3 && (
            <rect x={Math.min(drag.a, drag.b)} y={0} width={Math.abs(drag.b - drag.a)} height={H - padB} fill="#22d3ee" fillOpacity={0.12}
              stroke="#22d3ee" strokeOpacity={0.5} />
          )}
        </svg>
      )}
      {hv && data && (
        <div className="pointer-events-none absolute top-0 z-10 rounded-lg border border-edge bg-abyss/95 px-2.5 py-1.5 text-xs shadow-xl"
          style={{ left: Math.min((hover ?? 0) * bw + bw + 8, Math.max(0, width - 180)) }}>
          <div className="mb-1 font-mono text-[10px] text-faint">{clock(hv.ts, true)} · {data.step >= 60 ? `${Math.round(data.step / 60)} min` : `${data.step}s`}</div>
          <div className="flex justify-between gap-4"><span className="text-crit">blocked</span><span className="num">{hv.block.toLocaleString()}</span></div>
          <div className="flex justify-between gap-4"><span className="text-ok">passed</span><span className="num">{hv.pass.toLocaleString()}</span></div>
          {hv.other > 0 && <div className="flex justify-between gap-4"><span className="text-violet">other</span><span className="num">{hv.other.toLocaleString()}</span></div>}
          {hv.skipped > 0 && <div className="flex justify-between gap-4 text-faint"><span>not stored</span><span className="num">{hv.skipped.toLocaleString()}</span></div>}
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------- top-N
function TopList<T>({ rows, render, count, blocked, onPick, empty = "Nothing in this window" }: {
  rows: T[] | undefined;
  render: (r: T) => ReactNode;
  count: (r: T) => number;
  blocked?: (r: T) => number;
  onPick: (r: T, neg: boolean) => void;
  empty?: string;
}) {
  if (!rows) return <div className="space-y-2">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-5" />)}</div>;
  if (!rows.length) return <div className="py-3 text-center text-xs text-faint">{empty}</div>;
  const max = Math.max(...rows.map(count), 1);
  return (
    <ul className="space-y-1">
      {rows.map((r, i) => {
        const n = count(r), b = blocked ? blocked(r) : 0;
        return (
          <motion.li key={i} initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.025 }}>
            <button onClick={(e) => onPick(r, e.shiftKey || e.altKey)} title="Click to filter · shift-click to exclude"
              className="group relative block w-full overflow-hidden rounded-md px-2 py-1 text-left hover:bg-white/[0.03]">
              <span className="absolute inset-y-0 left-0 bg-cyan/[0.07]" style={{ width: `${(n / max) * 100}%` }} />
              {b > 0 && <span className="absolute inset-y-0 left-0 bg-crit/15" style={{ width: `${(b / max) * 100}%` }} />}
              <span className="relative flex items-center justify-between gap-3 font-mono text-[11.5px]">
                <span className="min-w-0 truncate text-ink/90 group-hover:text-cyan">{render(r)}</span>
                <span className="num shrink-0 text-dim">{compact(n)}</span>
              </span>
            </button>
          </motion.li>
        );
      })}
    </ul>
  );
}

// --------------------------------------------------------------- tokens
function Tok({ children, title, onPick, className }: { children: ReactNode; title?: string; onPick: (neg: boolean) => void; className?: string }) {
  return (
    <button type="button" title={`${title ?? ""}${title ? "\n" : ""}click: filter · shift-click: exclude`}
      onClick={(e) => { e.stopPropagation(); onPick(e.shiftKey || e.altKey); }}
      className={clsx("max-w-full truncate rounded px-0.5 text-left transition-colors hover:bg-cyan/10 hover:text-cyan", className)}>
      {children}
    </button>
  );
}

function ActionIcon({ action }: { action: string }) {
  if (action === "pass") return <Check size={16} strokeWidth={3} className="text-ok drop-shadow-[0_0_6px_#34d39988]" />;
  if (action === "reject") return <Ban size={15} strokeWidth={2.5} className="text-warn" />;
  if (BLOCKED.has(action)) return <X size={16} strokeWidth={3} className="text-crit drop-shadow-[0_0_6px_#fb4d6d88]" />;
  return <span className="font-mono text-[10px] text-violet">{action}</span>;
}

// ---------------------------------------------------------------- page
export default function FirewallPage() {
  const [params, setParams] = useSearchParams();
  const devices = useLive((s) => s.devices);
  const [range, setRange] = useState<Range>((params.get("range") as Range) in RANGES ? (params.get("range") as Range) : "1h");
  const [win, setWin] = useState<{ since: number; until: number } | null>(null);
  const [zoomStack, setZoomStack] = useState<{ range: Range; win: typeof win }[]>([]);
  const [view, setView] = useState<View>(() => {
    try {
      const raw = params.get("f");
      if (raw) return JSON.parse(raw) as View;
    } catch { /* ignore */ }
    return { chips: [], q: "", hideNoise: false };
  });
  const [text, setText] = useState(view.q);
  const [devIds, setDevIds] = useState<number[]>([]);
  const [paused, setPaused] = useState(false);
  const [saved, setSaved] = useLocalState<SavedView[]>("fw-views", []);
  const [items, setItems] = useState<FwEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [total, setTotal] = useState<{ n: number; capped: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [facets, setFacets] = useState<FacetsResponse | null>(null);
  const fresh = useRef<Set<number>>(new Set());
  const live = !paused && !win;

  // Debounced free text.
  useEffect(() => {
    const t = setTimeout(() => setView((v) => (v.q === text ? v : { ...v, q: text })), 350);
    return () => clearTimeout(t);
  }, [text]);
  useEffect(() => {
    const p: Record<string, string> = {};
    if (view.chips.length || view.q || view.hideNoise) p.f = JSON.stringify(view);
    if (range !== "1h") p.range = range;
    setParams(p, { replace: true });
  }, [view, range, setParams]);

  const firewalls = useMemo(() => Object.values(devices).filter((d) => d.role === "firewall" || d.role === "router")
    .sort((a, b) => a.name.localeCompare(b.name)), [devices]);
  const query = useMemo(() => {
    const q = toQuery(view, devIds);
    if (win) Object.assign(q, { since: Math.floor(win.since), until: Math.ceil(win.until) });
    else q.range = range;
    return q;
  }, [view, devIds, win, range]);
  const qkey = JSON.stringify(query);

  // First page (+ live refresh): merge new rows on top, remember which are new for the flash.
  const loadFirst = useCallback(async (refresh: boolean) => {
    if (!refresh) setLoading(true);
    try {
      const r = await api<EventsResponse>("/firewall/events", { query: { ...query, limit: 200, count: true } });
      setError(null);
      setTotal(r.total != null ? { n: r.total, capped: !!r.total_capped } : null);
      setItems((prev) => {
        if (!refresh || !prev.length) {
          fresh.current = new Set();
          setCursor(r.next_cursor);
          return r.items;
        }
        const known = new Set(prev.map((e) => e.id));
        const add = r.items.filter((e) => !known.has(e.id));
        fresh.current = new Set(add.map((e) => e.id));
        if (!add.length) return prev;
        return [...add, ...prev].sort((a, b) => b.ts - a.ts || b.id - a.id).slice(0, 3000);
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qkey]);

  const loadOlder = async () => {
    if (!cursor) return;
    setLoading(true);
    try {
      const r = await api<EventsResponse>("/firewall/events", { query: { ...query, limit: 200, cursor, count: false } });
      setItems((prev) => [...prev, ...r.items]);
      setCursor(r.next_cursor);
    } finally {
      setLoading(false);
    }
  };

  const loadAggs = useCallback(async () => {
    const [t, s] = await Promise.allSettled([
      api<TimelineResponse>("/firewall/timeline", { query: { ...query, points: 120 } }),
      api<StatsResponse>("/firewall/stats", { query: { ...query, limit: 8 } }),
    ]);
    if (t.status === "fulfilled") setTimeline(t.value);
    if (s.status === "fulfilled") setStats(s.value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qkey]);

  useEffect(() => { setOpen(null); loadFirst(false); loadAggs(); }, [loadFirst, loadAggs]);
  useEffect(() => {
    if (!live) return;
    const a = window.setInterval(() => document.visibilityState === "visible" && loadFirst(true), 3000);
    const b = window.setInterval(() => document.visibilityState === "visible" && loadAggs(), 15000);
    return () => { window.clearInterval(a); window.clearInterval(b); };
  }, [live, loadFirst, loadAggs]);
  useEffect(() => {
    const load = () => api<FacetsResponse>("/firewall/facets").then(setFacets).catch(() => undefined);
    load();
    const t = window.setInterval(load, 60000);
    return () => window.clearInterval(t);
  }, []);

  // ------------------------------------------------------------ filters
  const addChip = (c: Chip) => setView((v) => {
    const rest = v.chips.filter((x) => !(x.field === c.field && x.value === c.value));
    // A positive chip on a single-valued field replaces the old one.
    const single = c.field === "direction" || c.field === "ipver";
    return { ...v, chips: [...(single ? rest.filter((x) => x.field !== c.field) : rest), c] };
  });
  const removeChip = (i: number) => setView((v) => ({ ...v, chips: v.chips.filter((_, k) => k !== i) }));
  const pick = (field: Field, value: string | number, neg = false, label?: string) => addChip({ field, value: String(value), neg, label });
  const submitText = () => {
    const words = text.trim().split(/\s+/).filter(Boolean);
    const rest: string[] = [];
    const chips: Chip[] = [];
    for (const w of words) {
      const m = TOKEN.exec(w);
      if (m) chips.push({ field: ALIAS[m[2].toLowerCase()] ?? (m[2].toLowerCase() as Field), value: m[3], neg: !!m[1] });
      else rest.push(w);
    }
    if (!chips.length) return;
    chips.forEach(addChip);
    setText(rest.join(" "));
  };
  const zoomTo = (t0: number, t1: number) => {
    setZoomStack((z) => [...z, { range, win }]);
    setWin({ since: t0, until: Math.min(t1, Date.now() / 1000) });
  };
  const undoZoom = () => {
    const last = zoomStack[zoomStack.length - 1];
    if (!last) return;
    setZoomStack((z) => z.slice(0, -1));
    setRange(last.range);
    setWin(last.win);
  };

  const wanName = facets?.interfaces.find((i) => WAN_RE.test(i.iface))?.iface ?? "INTERNET";
  const quick: { name: string; icon: ReactNode; view: View }[] = [
    { name: `Blocked inbound on ${wanName}`, icon: <ShieldAlert size={13} />, view: { q: "", hideNoise: false, chips: [
      { field: "action", value: "block" }, { field: "direction", value: "in" }, { field: "iface", value: wanName }] } },
    { name: "Hide IPv6 multicast noise", icon: <EyeOff size={13} />, view: { ...view, hideNoise: true } },
    { name: "Passed only", icon: <Check size={13} />, view: { q: "", hideNoise: view.hideNoise, chips: [{ field: "action", value: "pass" }] } },
    { name: "Blocked only", icon: <X size={13} />, view: { q: "", hideNoise: view.hideNoise, chips: [{ field: "action", value: "block" }] } },
  ];
  const applyView = (v: View) => { setView(v); setText(v.q); };
  const saveView = () => {
    const name = window.prompt("Name this quick filter", view.chips.map((c) => `${c.neg ? "not " : ""}${c.label ?? c.value}`).join(", ") || "My filter");
    if (name) setSaved([...saved.filter((s) => s.name !== name), { ...view, name }]);
  };

  const actions = stats?.actions ?? {};
  const totalEvents = Object.values(actions).reduce((a, b) => a + b, 0);
  const blocked = (actions.block ?? 0) + (actions.reject ?? 0);
  const skipped = timeline?.series.reduce((a, b) => a + b.skipped, 0) ?? 0;
  const devName = (id: number | null) => (id != null ? devices[id]?.name : undefined) ?? "unattributed";
  const noData = !loading && !items.length && !error;
  const filtered = view.chips.length > 0 || !!view.q || view.hideNoise;

  return (
    <div className="mx-auto max-w-[1900px] space-y-4 p-4 md:p-6">
      {/* ---------------------------------------------------- filter bar */}
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="panel relative z-10 space-y-3 p-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex min-w-[280px] flex-1 flex-wrap items-center gap-1.5 rounded-xl border border-edge bg-black/30 px-3 py-1.5 focus-within:border-cyan/50">
            <Search size={15} className="text-faint" />
            <AnimatePresence initial={false}>
              {view.chips.map((c, i) => (
                <motion.span key={`${c.field}${c.value}${c.neg}`} layout initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.8 }}
                  className={clsx("inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px]",
                    c.neg ? "border-crit/40 bg-crit/10 text-crit" : "border-cyan/40 bg-cyan/10 text-cyan")}>
                  <button onClick={() => setView((v) => ({ ...v, chips: v.chips.map((x, k) => (k === i ? { ...x, neg: !x.neg } : x)) }))}
                    title="Toggle include / exclude" className="text-faint hover:text-ink">{FIELD_LABEL[c.field]}{c.neg ? " ≠" : " ="}</button>
                  <span className="max-w-[220px] truncate">{c.label ?? c.value}</span>
                  <button onClick={() => removeChip(i)} className="text-faint hover:text-ink" aria-label="Remove filter"><X size={11} /></button>
                </motion.span>
              ))}
            </AnimatePresence>
            <input value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => {
              if (e.key === "Enter") submitText();
              if (e.key === "Backspace" && !text && view.chips.length) removeChip(view.chips.length - 1);
            }}
              placeholder={view.chips.length ? "" : "Search… or src:1.2.3.0/24 port:443 !iface:HOME rule:1770009104 (Enter)"}
              className="h-7 min-w-[160px] flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-faint" />
            {(filtered || text) && (
              <button onClick={() => applyView({ chips: [], q: "", hideNoise: false })} className="text-faint hover:text-ink" title="Clear all filters"><X size={14} /></button>
            )}
          </div>
          <Toggle checked={view.hideNoise} onChange={(v) => setView({ ...view, hideNoise: v })} label="hide multicast noise" />
          <Segmented value={win ? ("" as Range) : range} onChange={(r) => { setRange(r); setWin(null); setZoomStack([]); }}
            options={(Object.keys(RANGES) as Range[]).map((r) => ({ value: r, label: r }))} />
          <button className={clsx("btn", live && "!border-ok/50 !text-ok")} onClick={() => { if (win) { setWin(null); setZoomStack([]); setPaused(false); } else setPaused(!paused); }}>
            {live ? <><span className="relative flex h-2 w-2"><span className="absolute inset-0 animate-ping rounded-full bg-ok/70" /><span className="relative h-2 w-2 rounded-full bg-ok" /></span> Live</>
              : win ? <><Play size={14} /> Back to live</> : <><Pause size={14} /> Paused</>}
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <ListFilter size={13} className="mr-1 text-faint" />
          {quick.map((v) => (
            <button key={v.name} className="chip" onClick={() => applyView(v.view)}>{v.icon}{v.name}</button>
          ))}
          {saved.map((v) => (
            <span key={v.name} className="chip group !pr-1.5" data-active={JSON.stringify({ ...v, name: undefined }) === JSON.stringify({ ...view, name: undefined })}>
              <button onClick={() => applyView({ chips: v.chips, q: v.q, hideNoise: v.hideNoise })}><Filter size={12} className="mr-1 inline" />{v.name}</button>
              <button className="opacity-0 group-hover:opacity-100 hover:text-crit" onClick={() => setSaved(saved.filter((s) => s.name !== v.name))} aria-label="Delete quick filter"><Trash2 size={11} /></button>
            </span>
          ))}
          {filtered && <button className="chip !border-dashed" onClick={saveView}><Save size={12} /> save current</button>}
          {firewalls.length > 1 && <span className="mx-1 h-4 w-px bg-edge" />}
          {firewalls.length > 1 && firewalls.map((d) => (
            <button key={d.id} className="chip" data-active={devIds.includes(d.id)}
              onClick={() => setDevIds(devIds.includes(d.id) ? devIds.filter((x) => x !== d.id) : [...devIds, d.id])}>{d.name}</button>
          ))}
        </div>
      </motion.div>

      {/* --------------------------------------------- KPIs + timeline */}
      <Panel title={win ? `Timeline · ${clock(win.since, true)} → ${clock(win.until, true)}` : `Timeline · last ${range}`} icon={<BrickWall size={15} />}
        actions={<div className="flex items-center gap-3 text-[11px] text-dim">
          {zoomStack.length > 0 && <button className="btn !py-0.5 !text-[11px]" onClick={undoZoom}><Undo2 size={12} /> Zoom out</button>}
          <span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-crit" />block</span>
          <span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-ok/70" />pass</span>
          <span className="hidden items-center gap-1 sm:flex"><i className="h-2 w-2 rounded-sm bg-violet" />other</span>
        </div>}>
        <div className="grid gap-4 lg:grid-cols-[230px_1fr]">
          <div className="grid grid-cols-2 gap-2 lg:grid-cols-1 lg:gap-1.5">
            <Kpi label="events" value={totalEvents} sub={total?.capped ? "stored rows ≥ 100k" : undefined} />
            <Kpi label="blocked" value={blocked} tone="text-crit" sub={totalEvents ? `${((blocked / totalEvents) * 100).toFixed(1)}%` : undefined} />
            <Kpi label="passed" value={actions.pass ?? 0} tone="text-ok" />
            <Kpi label="counted, not stored" value={skipped} tone="text-faint"
              sub={facets && (!facets.settings.store_pass || !facets.settings.store_noise) ? "storage filters on" : timeline?.source === "events" ? "n/a with these filters" : "all stored"} />
          </div>
          <div className="min-w-0">
            <Timeline data={timeline} onZoom={zoomTo} loading={loading} />
            <div className="mt-1 text-center font-mono text-[10.5px] text-faint">click a bar or drag across the chart to zoom in</div>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 2xl:grid-cols-[1fr_380px]">
        {/* --------------------------------------------------- table */}
        <div className="panel min-w-0 overflow-hidden !p-0">
          <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
            <div className="flex items-center gap-2">
              <BrickWall size={15} className="text-cyan" />
              <span className="hud-label !text-[11px] !text-ink/80">Firewall log</span>
              {total && <span className="font-mono text-[11px] text-faint">{total.n.toLocaleString()}{total.capped ? "+" : ""} matching · showing {items.length.toLocaleString()}</span>}
            </div>
            {loading && <Spinner size={14} />}
          </div>
          {error && <div className="m-3 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">{error}</div>}
          <div className="max-h-[calc(100vh-17rem)] min-h-[360px] overflow-auto">
            <table className="table-hud min-w-[980px] font-mono !text-[12px]">
              <thead>
                <tr>
                  <th className="w-10">Act</th><th className="w-[150px]">Time</th><th>Interface</th><th>Rule</th>
                  <th>Source</th><th>Destination</th><th>Proto</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => {
                  const isOpen = open === e.id;
                  const isNew = fresh.current.has(e.id);
                  const bad = BLOCKED.has(e.action);
                  return (
                    <FwRow key={e.id} e={e} isOpen={isOpen} isNew={isNew} bad={bad} onToggle={() => setOpen(isOpen ? null : e.id)}
                      pick={pick} devName={devName} />
                  );
                })}
              </tbody>
            </table>
            {noData && (
              <Empty icon={<BrickWall size={28} />} title={filtered ? "No firewall events match" : "No firewall events yet"}>
                {filtered ? "Try widening the time range or removing a filter." : (
                  <>Point pfSense (Status › System Logs › Settings › Remote Logging, “Firewall Events”) or OPNsense at NetworkVision’s
                    syslog port. filterlog lines show up here within seconds.</>
                )}
              </Empty>
            )}
            {items.length > 0 && (
              <div className="flex justify-center p-4">
                {loading ? <Spinner /> : cursor ? <button className="btn" onClick={loadOlder}>Load older</button>
                  : <span className="text-xs text-faint">— end of range —</span>}
              </div>
            )}
          </div>
        </div>

        {/* ------------------------------------------------- top-N */}
        <div className="grid content-start gap-4 md:grid-cols-2 2xl:grid-cols-1">
          <Panel title="Top blocked sources" icon={<ShieldAlert size={14} />} delay={0.05}>
            <TopList rows={stats?.top_blocked_sources} count={(r) => r.count} blocked={(r) => r.blocked}
              render={(r) => <span title={r.ip}>{shortIp(r.ip)}{!isPrivate(r.ip) && <span className="ml-1.5 text-[10px] text-faint">ext</span>}</span>}
              onPick={(r, neg) => pick("src", r.ip, neg)} empty="Nothing blocked in this window" />
          </Panel>
          <Panel title="Top targeted ports" icon={<Crosshair size={14} />} delay={0.1}>
            <TopList rows={stats?.top_ports} count={(r) => r.count} blocked={(r) => r.blocked}
              render={(r) => <>{r.port}<span className="ml-1.5 text-faint">{r.proto}{SERVICES[r.port] ? ` · ${SERVICES[r.port]}` : ""}</span></>}
              onPick={(r, neg) => pick("port", r.port, neg)} />
          </Panel>
          <Panel title="Top rules" icon={<BrickWall size={14} />} delay={0.15}>
            <TopList rows={stats?.top_rules} count={(r) => r.count} blocked={(r) => r.blocked}
              render={(r) => <>{ruleText(r)}{r.rule && r.rule_id && <span className="ml-1.5 text-faint">({r.rule_id.length > 12 ? r.rule_id.slice(0, 8) + "…" : r.rule_id})</span>}</>}
              onPick={(r, neg) => pick("rule", r.rule_id, neg, ruleText(r))} />
          </Panel>
          <Panel title="By interface" icon={<Filter size={14} />} delay={0.2}>
            <TopList rows={stats?.interfaces} count={(r) => r.count} blocked={(r) => r.blocked}
              render={(r) => <>{r.iface || "—"}<span className="ml-1.5 text-faint">{r.count ? `${Math.round((r.blocked / r.count) * 100)}% blocked` : ""}</span></>}
              onPick={(r, neg) => pick("iface", r.iface, neg)} />
          </Panel>
          <Panel title="Top destinations" icon={<Plus size={14} />} delay={0.25}>
            <TopList rows={stats?.top_destinations} count={(r) => r.count} blocked={(r) => r.blocked}
              render={(r) => <span title={r.ip}>{shortIp(r.ip)}</span>} onPick={(r, neg) => pick("dst", r.ip, neg)} />
          </Panel>
          {facets && (
            <div className="px-1 font-mono text-[10.5px] leading-relaxed text-faint">
              ingest: {compact(facets.ingest.parsed ?? 0)} parsed · {compact(facets.ingest.stored ?? 0)} stored · {compact(facets.ingest.skipped ?? 0)} counted only
              {facets.ingest.dropped ? ` · ${compact(facets.ingest.dropped)} dropped` : ""} · retention {facets.settings.retention_days} d
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, tone, sub }: { label: string; value: number; tone?: string; sub?: string }) {
  return (
    <div className="rounded-xl border border-edge bg-black/20 px-3 py-1.5">
      <div className="hud-label !text-[9.5px]">{label}</div>
      <div className="flex items-baseline justify-between gap-2">
        <CountUp value={value} className={clsx("text-lg font-semibold", tone ?? "text-ink")} />
        {sub && <span className="truncate font-mono text-[10px] text-faint">{sub}</span>}
      </div>
    </div>
  );
}

function FwRow({ e, isOpen, isNew, bad, onToggle, pick, devName }: {
  e: FwEvent;
  isOpen: boolean;
  isNew: boolean;
  bad: boolean;
  onToggle: () => void;
  pick: (field: Field, value: string | number, neg?: boolean, label?: string) => void;
  devName: (id: number | null) => string;
}) {
  const svc = e.dst_port != null ? SERVICES[e.dst_port] : undefined;
  return (
    <>
      <motion.tr onClick={onToggle} initial={isNew ? { backgroundColor: "rgba(34,211,238,0.18)" } : false}
        animate={{ backgroundColor: isOpen ? "rgba(34,211,238,0.06)" : "rgba(0,0,0,0)" }} transition={{ duration: 1.6 }}
        className={clsx("cursor-pointer", e.noise && "opacity-60")} style={{ contentVisibility: "auto", containIntrinsicSize: "auto 34px" }}>
        <td className="!py-1.5"><Tok onPick={(neg) => pick("action", e.action, neg)} title={e.action}><ActionIcon action={e.action} /></Tok></td>
        <td className="!py-1.5 whitespace-nowrap text-dim">
          <ChevronDown size={12} className={clsx("mr-1 inline text-faint transition-transform", !isOpen && "-rotate-90")} />{clock(e.ts, true)}
        </td>
        <td className="!py-1.5">
          <Tok onPick={(neg) => pick("iface", e.iface_name || e.iface, neg)} title={`${e.iface} · ${e.direction}`}>
            <span className={clsx("inline-flex items-center gap-1 rounded-md border px-1.5 py-px text-[10.5px] tracking-wide",
              WAN_RE.test(e.iface_name) ? "border-violet/40 bg-violet/10 text-violet" : "border-sky/30 bg-sky/10 text-sky")}>
              {e.iface_name || e.iface}<span className="text-faint">{e.direction === "out" ? "↑" : "↓"}</span>
            </span>
          </Tok>
        </td>
        <td className="max-w-[300px] !py-1.5">
          <Tok onPick={(neg) => pick("rule", e.rule_id, neg, ruleText(e))} title={e.rule_id} className={bad ? "text-ink/90" : "text-ink/75"}>
            {ruleText(e)}{e.rule && e.rule_id && <span className="ml-1 text-faint">({e.rule_id.length > 12 ? e.rule_id.slice(0, 8) + "…" : e.rule_id})</span>}
          </Tok>
        </td>
        <td className="max-w-[260px] !py-1.5 whitespace-nowrap">
          <Tok onPick={(neg) => pick("src", e.src_ip, neg)} title={e.src_ip} className={!isPrivate(e.src_ip) && bad ? "text-warn" : "text-ink/90"}>{shortIp(e.src_ip)}</Tok>
          {e.src_port != null && <span className="text-faint">:<Tok onPick={(neg) => pick("sport", e.src_port!, neg)} className="text-faint">{e.src_port}</Tok></span>}
        </td>
        <td className="max-w-[300px] !py-1.5 whitespace-nowrap">
          <Tok onPick={(neg) => pick("dst", e.dst_ip, neg)} title={e.dst_ip} className="text-ink/90">{shortIp(e.dst_ip)}</Tok>
          {e.dst_port != null && <span className="text-faint">:<Tok onPick={(neg) => pick("port", e.dst_port!, neg)} className="text-cyan/90">{e.dst_port}</Tok></span>}
          {svc && <span className="ml-1.5 text-[10px] text-faint">{svc}</span>}
        </td>
        <td className="!py-1.5 whitespace-nowrap"><Tok onPick={(neg) => pick("proto", e.proto, neg)} className="text-dim">{protoText(e)}</Tok></td>
      </motion.tr>
      <AnimatePresence>
        {isOpen && (
          <tr>
            <td colSpan={7} className="!p-0">
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                <div className="grid gap-x-6 gap-y-1 bg-cyan/[0.03] px-6 py-3 text-[11.5px] text-dim sm:grid-cols-2 xl:grid-cols-4">
                  <Detail k="firewall" v={devName(e.device_id)} />
                  <Detail k="action / dir" v={<span className={bad ? "text-crit" : "text-ok"}>{e.action} · {e.direction || "—"}</span>} />
                  <Detail k="interface" v={`${e.iface_name}${e.iface_name !== e.iface ? ` (${e.iface})` : ""}`} />
                  <Detail k="rule" v={`${e.rule || "unknown"} · ${e.rule_id || "—"}`} />
                  <Detail k="source" v={hostPort(e.src_ip, e.src_port)} copy={e.src_ip} />
                  <Detail k="destination" v={hostPort(e.dst_ip, e.dst_port)} copy={e.dst_ip} />
                  <Detail k="protocol" v={`${protoText(e)} · IPv${e.ipver}${e.length != null ? ` · ${e.length} bytes` : ""}`} />
                  <Detail k="details" v={[e.info, e.noise ? "multicast/link-local noise" : ""].filter(Boolean).join(" · ") || "—"} />
                  <div className="col-span-full mt-2 flex flex-wrap gap-2">
                    <button className="btn !py-1 !text-[11px]" onClick={() => pick("src", e.src_ip)}><Filter size={12} /> Only this source</button>
                    <button className="btn !py-1 !text-[11px]" onClick={() => pick("src", e.src_ip, true)}><EyeOff size={12} /> Hide this source</button>
                    {e.dst_port != null && <button className="btn !py-1 !text-[11px]" onClick={() => pick("port", e.dst_port!)}><Crosshair size={12} /> Port {e.dst_port}</button>}
                    <button className="btn !py-1 !text-[11px]" onClick={() => pick("rule", e.rule_id, false, ruleText(e))}><BrickWall size={12} /> This rule</button>
                    {!isPrivate(e.src_ip) && (
                      <a className="btn !py-1 !text-[11px]" href={`https://bgp.he.net/ip/${encodeURIComponent(e.src_ip)}`} target="_blank" rel="noreferrer noopener">
                        Look up {shortIp(e.src_ip)} ↗
                      </a>
                    )}
                    <Badge tone={bad ? "critical" : "ok"} className="ml-auto self-center">#{e.id}</Badge>
                  </div>
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

function Detail({ k, v, copy }: { k: string; v: ReactNode; copy?: string }) {
  return (
    <div className="flex min-w-0 items-baseline gap-2 border-b border-edge/40 py-1">
      <span className="w-24 shrink-0 text-faint">{k}</span>
      <span className="min-w-0 text-ink/90 [overflow-wrap:anywhere]">{v}</span>
      {copy && (
        <button className="ml-auto shrink-0 text-faint hover:text-cyan" title="Copy" onClick={() => navigator.clipboard?.writeText(copy)}>
          <Copy size={11} />
        </button>
      )}
    </div>
  );
}
