import clsx from "clsx";
import {
  BellRing,
  CalendarClock,
  Check,
  Database,
  Gauge,
  ListChecks,
  Plus,
  RotateCcw,
  Save,
  Send,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type ReactNode, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { Badge, Empty, Field, Panel, Segmented, Spinner, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { clock, duration } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { MaintenanceWindow, SettingsData } from "../lib/types";

const MASK = "••••••••";
type Tab = "alerts" | "retention" | "notifications" | "maintenance";
type Draft = Record<string, string | number | null>;

const THRESHOLDS: [string, string, string, string][] = [
  ["alert_cpu_pct", "CPU", "%", "Device CPU at or above this"],
  ["alert_mem_pct", "Memory", "%", "Memory use at or above this"],
  ["alert_temp_c", "Temperature", "°C", "+10 °C over this escalates to critical"],
  ["alert_latency_ms", "Latency", "ms", "Ping / gateway round-trip time"],
  ["alert_loss_pct", "Packet loss", "%", "Ping / gateway loss"],
  ["alert_if_util_pct", "Interface utilization", "%", "Of negotiated link speed"],
  ["alert_if_errors_per_min", "Interface errors", "/min", "In + out errors"],
  ["alert_consecutive", "Consecutive polls", "polls", "A threshold must hold this many polls before it alerts"],
];
const RETENTION: [string, string, string][] = [
  ["retention_days_metrics", "Raw metrics", "Per-minute samples for live and 24h charts"],
  ["retention_days_rollup", "Hourly rollups", "Long-range charts (30 days, a year). Minimum 7"],
  ["retention_days_logs", "Logs", "Syslog and API log lines"],
  ["retention_days_alerts", "Resolved alerts", "Alert history"],
];
const CHANNELS: [string, string, string][] = [
  ["notify_discord_webhook_url", "Discord webhook", "https://discord.com/api/webhooks/…"],
  ["notify_slack_webhook_url", "Slack webhook", "https://hooks.slack.com/services/…"],
  ["notify_ntfy_url", "ntfy topic URL", "https://ntfy.sh/my-topic"],
  ["notify_ntfy_token", "ntfy access token", "optional"],
  ["notify_webhook_url", "Generic webhook (JSON POST)", "https://…"],
];
export const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export default function SettingsPage() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) || "alerts";
  const setTab = (t: Tab) => setParams({ tab: t }, { replace: true });
  const { data, setData, error } = useApi<SettingsData>("/settings");
  const [draft, setDraft] = useState<Draft>({});
  const [rules, setRules] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const dirty = Object.keys(draft).length > 0 || rules !== null;

  const save = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const secret = (k: string) => data?.fields[k]?.secret;
      const values = Object.fromEntries(Object.entries(draft)
        .filter(([k, v]) => secret(k) || v !== "")
        .map(([k, v]) => [k, v === null || secret(k) || k === "notify_min_severity" ? v : Number(v)]));
      const r = await api<SettingsData>("/settings", { method: "PUT", body: { values, disabled_rules: rules ?? undefined } });
      setData(r);
      setDraft({});
      setRules(null);
      setMsg({ ok: true, text: "Saved - applies from the next poll" });
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };

  const ctx = { data, draft, setDraft };
  return (
    <div className="mx-auto max-w-[1400px] space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={tab} onChange={setTab} options={[
          { value: "alerts", label: "Alert rules" }, { value: "retention", label: "Retention" },
          { value: "notifications", label: "Notifications" }, { value: "maintenance", label: "Maintenance" },
        ]} />
        <AnimatePresence>
          {tab !== "maintenance" && (dirty || msg) && (
            <motion.div initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="ml-auto flex items-center gap-2">
              {msg && <span className={clsx("text-xs", msg.ok ? "text-ok" : "text-crit")}>{msg.text}</span>}
              {dirty && (
                <>
                  <button className="btn" onClick={() => { setDraft({}); setRules(null); setMsg(null); }}>Discard</button>
                  <button className="btn btn-primary" onClick={save} disabled={saving}>
                    {saving ? <Spinner size={14} /> : <Save size={15} />} Save changes
                  </button>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {error && !data && <Panel><Empty title="Could not load settings">{error}</Empty></Panel>}
      {!data && !error && <div className="grid h-40 place-items-center"><Spinner size={24} /></div>}

      {data && tab === "alerts" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Thresholds" icon={<Gauge size={15} />}>
            <div className="grid gap-4 sm:grid-cols-2">
              {THRESHOLDS.map(([name, label, unit, help]) => (
                <SettingInput key={name} {...ctx} name={name} label={label} unit={unit} help={help} />
              ))}
            </div>
            <p className="mt-4 text-xs text-faint">
              Per-device overrides, muted devices and muted ports live on each device's page (<span className="text-dim">Alert tuning</span>).
            </p>
          </Panel>
          <Panel title="Rules" icon={<ListChecks size={15} />} delay={0.05}>
            <p className="mb-3 text-xs text-dim">Disabled rules never open alerts on any device. Open alerts of a disabled rule resolve on the next poll.</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.entries(data.rules).map(([rule, label]) => {
                const off = (rules ?? data.disabled_rules).includes(rule);
                return (
                  <div key={rule} className={clsx("flex items-center justify-between rounded-lg border px-3 py-2 transition-colors",
                    off ? "border-edge bg-black/20" : "border-cyan/20 bg-cyan/[0.03]")}>
                    <div className="min-w-0">
                      <div className={clsx("truncate text-sm", off && "text-faint line-through")}>{label}</div>
                      <div className="font-mono text-[10px] text-faint">{rule}</div>
                    </div>
                    <Toggle checked={!off} onChange={(on) => {
                      const cur = rules ?? data.disabled_rules;
                      setRules(on ? cur.filter((r) => r !== rule) : [...cur, rule]);
                    }} />
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      )}

      {data && tab === "retention" && (
        <Panel title="Data retention" icon={<Database size={15} />}>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {RETENTION.map(([name, label, help]) => (
              <SettingInput key={name} {...ctx} name={name} label={label} unit="days" help={help} integer />
            ))}
          </div>
          <p className="mt-4 text-xs text-faint">Cleanup runs hourly in small batches. Shortening retention frees space within the hour.</p>
        </Panel>
      )}

      {data && tab === "notifications" && <Notifications {...ctx} dirty={dirty} />}

      {tab === "maintenance" && <Maintenance />}
    </div>
  );
}

// ------------------------------------------------------------------ inputs
type Ctx = { data: SettingsData | null; draft: Draft; setDraft: (fn: (d: Draft) => Draft) => void };

function SourceBadge({ source, pending }: { source: string; pending?: boolean }) {
  if (pending) return <Badge tone="warning">unsaved</Badge>;
  return <Badge tone={source === "ui" ? "cyan" : source === "env" ? "violet" : "neutral"}>{source === "ui" ? "custom" : source}</Badge>;
}

function SettingInput({ data, draft, setDraft, name, label, unit, help, integer }: Ctx & {
  name: string; label: string; unit?: string; help?: ReactNode; integer?: boolean;
}) {
  const f = data!.fields[name];
  const pending = name in draft;
  const value = pending ? (draft[name] === null ? f.default : draft[name]) : f.value;
  const set = (v: string | null) => setDraft((d) => {
    const n = { ...d };
    if (v !== null && v !== "" && +v === +f.value) delete n[name];
    else n[name] = v;
    return n;
  });
  return (
    <Field label={<span className="flex items-center justify-between gap-2">{label}<SourceBadge source={f.source} pending={pending} /></span>}
      help={<>{help}{f.source !== "default" || pending ? <> · default {String(f.default)}</> : null}</>}>
      <div className="flex items-center gap-1.5">
        <div className="relative flex-1">
          <input className={clsx("input w-full pr-12", draft[name] === "" && "!border-crit/50")} type="number" min={0} step={integer ? 1 : "any"}
            value={value ?? ""} onChange={(e) => set(e.target.value)} />
          {unit && <span className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 font-mono text-[11px] text-faint">{unit}</span>}
        </div>
        {(f.source === "ui" && draft[name] !== null) && (
          <button className="btn btn-ghost !p-2" title="Reset to the env/default value" onClick={() => set(null)}><RotateCcw size={14} /></button>
        )}
      </div>
    </Field>
  );
}

function SecretInput({ data, draft, setDraft, name, label, placeholder }: Ctx & { name: string; label: string; placeholder: string }) {
  const f = data!.fields[name];
  const pending = name in draft;
  const saved = f.value === MASK;
  const set = (v: string | null) => setDraft((d) => ({ ...d, [name]: v }));
  const clear = () => setDraft((d) => {
    const n = { ...d };
    delete n[name];
    return n;
  });
  return (
    <Field label={<span className="flex items-center justify-between gap-2">{label}<SourceBadge source={f.source} pending={pending} /></span>}
      help={f.source === "ui" && f.default === MASK ? "Overrides the value set in the environment" : undefined}>
      <div className="flex items-center gap-1.5">
        <input className="input flex-1 font-mono text-xs" type="text" autoComplete="off" spellCheck={false}
          value={pending ? String(draft[name] ?? "") : ""}
          placeholder={pending && draft[name] === null ? "reset to environment value" : saved ? `${MASK}  (saved, type to replace)` : placeholder}
          onChange={(e) => set(e.target.value)} />
        {pending && <button className="btn btn-ghost !p-2" title="Undo" onClick={clear}><X size={14} /></button>}
        {!pending && saved && <button className="btn btn-ghost btn-danger !p-2" title="Remove" onClick={() => set("")}><Trash2 size={14} /></button>}
        {!pending && f.source === "ui" && (
          <button className="btn btn-ghost !p-2" title="Reset to the environment value" onClick={() => set(null)}><RotateCcw size={14} /></button>
        )}
      </div>
    </Field>
  );
}

// ----------------------------------------------------------- notifications
function Notifications(props: Ctx & { dirty: boolean }) {
  const { data, draft, setDraft, dirty } = props;
  const [testing, setTesting] = useState(false);
  const [results, setResults] = useState<Record<string, { ok: boolean; error?: string; status?: number }> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const sev = String(draft.notify_min_severity ?? data!.fields.notify_min_severity.value);

  const test = async () => {
    setTesting(true);
    setErr(null);
    setResults(null);
    try {
      setResults((await api<{ results: typeof results }>("/settings/test-notification", { method: "POST" })).results);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Panel title="Channels" icon={<BellRing size={15} />} className="lg:col-span-2">
        {data!.secrets_corrupt && (
          <div className="mb-3 rounded-lg border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
            Saved channel URLs can't be decrypted (NV_SECRET_KEY changed?). Re-enter them.
          </div>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          {CHANNELS.map(([name, label, ph]) => <SecretInput key={name} {...props} name={name} label={label} placeholder={ph} />)}
        </div>
        <p className="mt-4 text-xs text-faint">URLs and tokens are stored encrypted with NV_SECRET_KEY and never sent back to the browser.</p>
      </Panel>
      <div className="space-y-4">
        <Panel title="Minimum severity" icon={<Gauge size={15} />} delay={0.05}>
          <Segmented value={sev} onChange={(v) => setDraft((d) => ({ ...d, notify_min_severity: v }))}
            options={["info", "warning", "critical"].map((s) => ({ value: s, label: s }))} />
          <p className="mt-3 text-xs text-dim">Alerts below this severity show in the dashboard only. Maintenance-suppressed alerts are never sent.</p>
        </Panel>
        <Panel title="Test" icon={<Send size={15} />} delay={0.1}>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {data!.channels.length ? data!.channels.map((c) => <Badge key={c} tone="cyan">{c}</Badge>) : <span className="text-xs text-faint">No channel configured</span>}
          </div>
          <button className="btn btn-primary w-full justify-center" onClick={test} disabled={testing || dirty || !data!.channels.length}>
            {testing ? <Spinner size={14} /> : <Send size={15} />} Send test notification
          </button>
          {dirty && <p className="mt-2 text-xs text-warn">Save your changes first.</p>}
          {err && <p className="mt-2 text-xs text-crit">{err}</p>}
          {results && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-3 space-y-1.5">
              {Object.entries(results).map(([ch, r]) => (
                <div key={ch} className="flex items-center justify-between rounded-lg border border-edge bg-black/20 px-3 py-1.5 text-sm">
                  <span className="font-mono text-xs">{ch}</span>
                  {r.ok ? <Badge tone="ok"><Check size={10} /> delivered</Badge> : <Badge tone="critical" className="max-w-[60%] truncate">{r.error}</Badge>}
                </div>
              ))}
            </motion.div>
          )}
        </Panel>
      </div>
    </div>
  );
}

// ------------------------------------------------------------- maintenance
function toLocalInput(ts: number) {
  const d = new Date(ts * 1000);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
}

export function describeWindow(w: MaintenanceWindow) {
  if (w.kind === "once") return `${clock(w.starts_at!, true)} → ${clock(w.ends_at!, true)}`;
  const days = w.kind === "daily" ? "Daily" : w.weekdays.map((d) => WEEKDAYS[d]).join(", ");
  return `${days} at ${w.start_time} for ${duration(w.duration_min * 60)} (${w.tz})`;
}

function Maintenance() {
  const { data, reload } = useApi<{ items: MaintenanceWindow[] }>("/maintenance", 30000);
  const devices = useLive((s) => s.devices);
  const tz = useMemo(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC", []);
  const now = Date.now() / 1000;
  const [f, setF] = useState({
    name: "", device_id: "" as string, kind: "once" as MaintenanceWindow["kind"],
    start: toLocalInput(now), end: toLocalInput(now + 3600), start_time: "02:00", duration_min: 60, weekdays: [6] as number[],
  });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useTick(30000);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      const body = f.kind === "once"
        ? { starts_at: new Date(f.start).getTime() / 1000, ends_at: new Date(f.end).getTime() / 1000 }
        : { start_time: f.start_time, duration_min: f.duration_min, weekdays: f.weekdays };
      await api("/maintenance", { method: "POST", body: { name: f.name, kind: f.kind, tz, device_id: f.device_id ? +f.device_id : null, ...body } });
      setF((x) => ({ ...x, name: "" }));
      reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (w: MaintenanceWindow) => {
    if (!confirm(`Delete maintenance window "${w.name || describeWindow(w)}"?`)) return;
    await api(`/maintenance/${w.id}`, { method: "DELETE" });
    reload();
  };
  const quick = (mins: number) => {
    const t = Date.now() / 1000;
    setF((x) => ({ ...x, kind: "once", start: toLocalInput(t), end: toLocalInput(t + mins * 60) }));
  };
  const devList = Object.values(devices).sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Panel title="Schedule a window" icon={<Plus size={15} />} className="lg:col-span-2">
        <div className="space-y-4">
          <Field label="Name"><input className="input w-full" value={f.name} maxLength={128} placeholder="e.g. Firmware upgrade" onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Scope" help="A device's window also covers devices it manages (e.g. a UniFi controller's APs).">
            <select className="input w-full" value={f.device_id} onChange={(e) => setF({ ...f, device_id: e.target.value })}>
              <option value="">All devices</option>
              {devList.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </Field>
          <Segmented value={f.kind} onChange={(kind) => setF({ ...f, kind })}
            options={[{ value: "once", label: "One-off" }, { value: "daily", label: "Daily" }, { value: "weekly", label: "Weekly" }]} />
          {f.kind === "once" ? (
            <>
              <div className="flex flex-wrap gap-1.5">
                {[30, 60, 120, 240].map((m) => <button key={m} className="chip" onClick={() => quick(m)}>now + {m < 60 ? `${m}m` : `${m / 60}h`}</button>)}
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Starts"><input className="input w-full" type="datetime-local" value={f.start} onChange={(e) => setF({ ...f, start: e.target.value })} /></Field>
                <Field label="Ends"><input className="input w-full" type="datetime-local" value={f.end} onChange={(e) => setF({ ...f, end: e.target.value })} /></Field>
              </div>
            </>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Start time" help={tz}><input className="input w-full" type="time" value={f.start_time} onChange={(e) => setF({ ...f, start_time: e.target.value })} /></Field>
                <Field label="Duration (minutes)"><input className="input w-full" type="number" min={1} max={10080} value={f.duration_min} onChange={(e) => setF({ ...f, duration_min: +e.target.value })} /></Field>
              </div>
              {f.kind === "weekly" && (
                <div className="flex flex-wrap gap-1.5">
                  {WEEKDAYS.map((d, i) => (
                    <button key={d} className="chip" data-active={f.weekdays.includes(i)}
                      onClick={() => setF({ ...f, weekdays: f.weekdays.includes(i) ? f.weekdays.filter((x) => x !== i) : [...f.weekdays, i] })}>{d}</button>
                  ))}
                </div>
              )}
            </>
          )}
          {err && <div className="rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-xs text-crit">{err}</div>}
          <button className="btn btn-primary w-full justify-center" onClick={create} disabled={busy}>
            {busy ? <Spinner size={14} /> : <CalendarClock size={15} />} Schedule
          </button>
          <p className="text-xs text-faint">During a window alerts are still recorded (marked <span className="text-violet">maintenance</span>) but never notified. Problems that outlast the window alert normally.</p>
        </div>
      </Panel>

      <Panel title={`Windows · ${data?.items.length ?? 0}`} icon={<Wrench size={15} />} className="lg:col-span-3" delay={0.05}>
        {!data && <div className="grid h-24 place-items-center"><Spinner /></div>}
        {data && !data.items.length && <Empty icon={<CalendarClock size={28} />} title="No maintenance scheduled">Plan upgrades and reboots so they don't page anyone.</Empty>}
        <div className="space-y-2">
          <AnimatePresence initial={false}>
            {data?.items.map((w) => (
              <motion.div key={w.id} layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, x: 30 }}
                className={clsx("relative flex items-center gap-3 overflow-hidden rounded-xl border p-3",
                  w.active ? "border-violet/50 bg-violet/[0.06] shadow-[0_0_24px_-12px_#a78bfa]" : "border-edge bg-black/20")}>
                {w.active && <span className="absolute inset-y-0 left-0 w-1 bg-violet" />}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{w.name || "Maintenance"}</span>
                    {w.active ? <Badge tone="violet">active · {duration((w.active_until ?? now) - Date.now() / 1000)} left</Badge>
                      : w.next_start ? <Badge>next {clock(w.next_start, true)}</Badge> : <Badge tone="disabled">ended</Badge>}
                    <Badge tone="neutral">{w.kind}</Badge>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-dim">{describeWindow(w)}</div>
                  <div className="font-mono text-[11px] text-faint">
                    {w.device_id ? <Link className="text-cyan" to={`/devices/${w.device_id}`}>{devices[w.device_id]?.name ?? `device ${w.device_id}`}</Link> : "all devices"}
                    {w.created_by && ` · by ${w.created_by}`}
                  </div>
                </div>
                <button className="btn btn-ghost btn-danger !p-1.5" title="Delete" onClick={() => remove(w)}><Trash2 size={15} /></button>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </Panel>
    </div>
  );
}

/** Thin banner shown on every page while a maintenance window is running. */
export function MaintenanceBanner() {
  const { data } = useApi<{ items: MaintenanceWindow[] }>("/maintenance/active", 60000);
  const devices = useLive((s) => s.devices);
  const [hidden, setHidden] = useState<string>("");
  const items = data?.items ?? [];
  const sig = items.map((w) => w.id).join(",");
  const show = items.length > 0 && hidden !== sig;
  const until = Math.min(...items.map((w) => w.active_until ?? Infinity));
  return (
    <AnimatePresence>
      {show && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
          className="overflow-hidden border-b border-violet/30 bg-gradient-to-r from-violet/15 via-violet/5 to-transparent">
          <div className="flex items-center gap-3 px-4 py-2 text-sm md:px-6">
            <Wrench size={15} className="shrink-0 text-violet" />
            <span className="min-w-0 flex-1 truncate">
              <span className="font-mono text-[10.5px] tracking-widest text-violet uppercase">Maintenance</span>{" "}
              {items.map((w) => `${w.name || "window"} (${w.device_id ? devices[w.device_id]?.name ?? `#${w.device_id}` : "all devices"})`).join(", ")}
              <span className="text-dim"> · alerts suppressed{Number.isFinite(until) && ` until ${clock(until)}`}</span>
            </span>
            <Link to="/settings?tab=maintenance" className="text-xs text-dim hover:text-cyan">Manage</Link>
            <button className="text-faint hover:text-ink" title="Hide" onClick={() => setHidden(sig)}><X size={14} /></button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
