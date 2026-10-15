import clsx from "clsx";
import { ChevronDown, Pause, Play, ScrollText, Search, X } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { Empty, Panel, Segmented, Spinner } from "../components/ui";
import { api } from "../lib/api";
import { clock, SEV_NAMES, sevColor } from "../lib/format";
import { useApi } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { LogItem } from "../lib/types";

type Range = "15m" | "1h" | "6h" | "24h" | "7d";
const RANGE_S: Record<Range, number> = { "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800 };
const SEV_LEVELS = [
  { v: 7, label: "All" },
  { v: 6, label: "Info+" },
  { v: 4, label: "Warn+" },
  { v: 3, label: "Error+" },
  { v: 2, label: "Crit" },
];

function Histogram({ series, onPick }: { series: { ts: number; error: number; warning: number; info: number }[]; onPick: (ts: number) => void }) {
  const max = Math.max(1, ...series.map((s) => s.error + s.warning + s.info));
  return (
    <div className="flex h-24 items-end gap-[2px]">
      {series.map((s) => {
        const total = s.error + s.warning + s.info;
        return (
          <button key={s.ts} onClick={() => onPick(s.ts)} title={`${clock(s.ts, true)} · ${total} lines (${s.error} err, ${s.warning} warn)`}
            className="group relative flex h-full flex-1 flex-col justify-end">
            <motion.div initial={{ scaleY: 0 }} animate={{ scaleY: 1 }} style={{ originY: 1, height: `${(total / max) * 100}%` }}
              className="flex w-full flex-col overflow-hidden rounded-t-[2px] group-hover:brightness-150">
              <div style={{ flex: s.error }} className="bg-crit" />
              <div style={{ flex: s.warning }} className="bg-warn" />
              <div style={{ flex: s.info }} className="bg-cyan/60" />
            </motion.div>
          </button>
        );
      })}
    </div>
  );
}

export default function LogsPage() {
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [sev, setSev] = useState(7);
  const [range, setRange] = useState<Range>("1h");
  const [source, setSource] = useState("");
  const [app, setApp] = useState("");
  const [devIds, setDevIds] = useState<number[]>(params.get("device") ? [Number(params.get("device"))] : []);
  const [until, setUntil] = useState<number | null>(null);
  const [items, setItems] = useState<LogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [more, setMore] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const devices = useLive((s) => s.devices);
  const live = useLive((s) => s.logs);
  const paused = useLive((s) => s.logsPaused);
  const setPaused = useLive((s) => s.setLogsPaused);

  useEffect(() => {
    const t = setTimeout(() => setQuery(q), 300);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    const p: Record<string, string> = {};
    if (query) p.q = query;
    if (devIds.length === 1) p.device = String(devIds[0]);
    setParams(p, { replace: true });
  }, [query, devIds, setParams]);

  const since = until ? until - RANGE_S[range] / 60 : Date.now() / 1000 - RANGE_S[range];
  const filters = { q: query, severity: sev < 7 ? sev : undefined, source: source || undefined, app: app || undefined, device_id: devIds };
  const { data: hist } = useApi<{ series: { ts: number; error: number; warning: number; info: number }[]; step: number }>(
    "/logs/histogram", 15000, { q: query, severity: sev < 7 ? sev : undefined, source: source || undefined, device_id: devIds, range });
  const { data: apps } = useApi<{ apps: { app: string; count: number }[] }>("/logs/apps", 60000);

  const load = async (append = false) => {
    setLoading(true);
    try {
      const r = await api<{ items: LogItem[] }>("/logs", {
        query: { ...filters, since, until: until ?? undefined, limit: 250, before_id: append ? items[items.length - 1]?.id : undefined },
      });
      setItems(append ? [...items, ...r.items] : r.items);
      setMore(r.items.length === 250);
    } finally {
      setLoading(false);
    }
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load(); }, [query, sev, range, source, app, devIds.join(","), until]);

  // Live tail: prepend streamed lines that match the current filters.
  const merged = useMemo(() => {
    if (until || paused) return items;
    const newest = items[0]?.ts ?? 0;
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    const fresh = live.filter((l) => l.ts > newest &&
      l.severity <= sev && (!source || l.source === source) && (!app || l.app === app) &&
      (!devIds.length || (l.device_id != null && devIds.includes(l.device_id))) &&
      terms.every((t) => {
        const hay = `${l.message} ${l.app} ${l.host}`.toLowerCase();
        return t.startsWith("-") && t.length > 1 ? !hay.includes(t.slice(1)) : hay.includes(t);
      }));
    return [...fresh, ...items];
  }, [items, live, until, paused, query, sev, source, app, devIds]);

  const devList = Object.values(devices).sort((a, b) => a.name.localeCompare(b.name));
  const toggleDev = (id: number) => setDevIds(devIds.includes(id) ? devIds.filter((x) => x !== id) : [...devIds, id]);

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      <div className="panel space-y-3 p-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex min-w-[260px] flex-1 items-center gap-2 rounded-xl border border-edge bg-black/30 px-3">
            <Search size={15} className="text-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder='Search messages… (prefix a word with "-" to exclude it)'
              className="h-9 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans placeholder:text-faint" />
            {q && <button onClick={() => setQ("")} className="text-faint hover:text-ink"><X size={14} /></button>}
          </div>
          <Segmented value={String(sev)} onChange={(v) => setSev(Number(v))} options={SEV_LEVELS.map((s) => ({ value: String(s.v), label: s.label }))} />
          <Segmented value={range} onChange={(v) => { setRange(v); setUntil(null); }} options={(Object.keys(RANGE_S) as Range[]).map((r) => ({ value: r, label: r }))} />
          <select className="input !w-auto !py-1.5" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">All sources</option><option value="syslog">Syslog</option><option value="api">Device API</option>
          </select>
          <select className="input !w-auto !py-1.5" value={app} onChange={(e) => setApp(e.target.value)}>
            <option value="">All programs</option>
            {apps?.apps.map((a) => <option key={a.app} value={a.app}>{a.app} ({a.count})</option>)}
          </select>
          <button className={clsx("btn", !paused && !until && "!border-ok/50 !text-ok")} onClick={() => { setUntil(null); setPaused(!paused); }}>
            {paused || until ? <Play size={14} /> : <Pause size={14} />} {until ? "Back to live" : paused ? "Resume" : "Live"}
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {devList.map((d) => (
            <button key={d.id} className="chip" data-active={devIds.includes(d.id)} onClick={() => toggleDev(d.id)}>{d.name}</button>
          ))}
          {devIds.length > 0 && <button className="chip" onClick={() => setDevIds([])}>all devices</button>}
        </div>
      </div>

      <Panel title={`Volume · last ${range}`} icon={<ScrollText size={15} />}
        actions={<div className="flex gap-3 text-[11px] text-dim"><span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-crit" />error</span><span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-warn" />warning</span><span className="flex items-center gap-1"><i className="h-2 w-2 rounded-sm bg-cyan/60" />info</span></div>}>
        <Histogram series={hist?.series ?? []} onPick={(ts) => { setUntil(ts + (hist?.step ?? 60)); setPaused(true); }} />
        {until && <div className="mt-2 font-mono text-xs text-cyan">Showing logs up to {clock(until, true)} — click “Back to live” to resume.</div>}
      </Panel>

      <div className="panel overflow-hidden !p-0">
        <div className="max-h-[calc(100vh-24rem)] min-h-[300px] overflow-y-auto font-mono text-[12.5px]">
          {!merged.length && !loading && <Empty icon={<ScrollText size={28} />} title="No log lines match">Try widening the time range or clearing filters.</Empty>}
          {merged.map((l, i) => {
            const key = l.id ?? -i - 1;
            const open = expanded === key;
            return (
              <div key={`${key}-${l.ts}`} onClick={() => setExpanded(open ? null : key)}
                className={clsx("cursor-pointer border-b border-edge/40 px-4 py-1.5 transition-colors hover:bg-white/[0.025]",
                  l.severity <= 3 && "bg-crit/[0.04]", open && "bg-cyan/[0.05]")}>
                <div className="flex gap-3">
                  <ChevronDown size={13} className={clsx("mt-1 shrink-0 text-faint transition-transform", !open && "-rotate-90")} />
                  <span className="shrink-0 text-faint">{clock(l.ts, true)}</span>
                  <span className={clsx("w-14 shrink-0 font-semibold", sevColor(l.severity))}>{SEV_NAMES[l.severity]}</span>
                  <span className="w-32 shrink-0 truncate text-cyan/85">{l.device ?? devices[l.device_id ?? -1]?.name ?? l.host}</span>
                  <span className="w-28 shrink-0 truncate text-violet/85">{l.app || "—"}</span>
                  <span className={clsx("min-w-0 text-ink/85", open ? "break-all whitespace-pre-wrap" : "truncate")}>{l.message}</span>
                </div>
                {open && (
                  <div className="mt-2 ml-7 grid grid-cols-2 gap-x-6 gap-y-1 text-[11.5px] text-dim sm:grid-cols-4">
                    <span>host: <span className="text-ink">{l.host}</span></span>
                    <span>facility: <span className="text-ink">{l.facility || "—"}</span></span>
                    <span>source: <span className="text-ink">{l.source}</span></span>
                    <span>epoch: <span className="text-ink">{l.ts.toFixed(3)}</span></span>
                  </div>
                )}
              </div>
            );
          })}
          {merged.length > 0 && (
            <div className="flex justify-center p-4">
              {loading ? <Spinner /> : more ? <button className="btn" onClick={() => load(true)}>Load older</button> : <span className="text-xs text-faint">— end of range —</span>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
