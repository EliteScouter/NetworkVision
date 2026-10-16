import clsx from "clsx";
import {
  Activity,
  AlertTriangle,
  Globe,
  HeartPulse,
  History,
  Lock,
  Pencil,
  Play,
  Plug,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { Sparkline } from "../components/charts";
import { useHistory } from "../components/HistoryExplorer";
import { Badge, CountUp, Drawer, Empty, Field, Kv, Panel, Segmented, Spinner, StatusDot, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { ago, clock, duration, fmtUptime, ms, uptimeColor } from "../lib/format";
import { useApi, useTick } from "../lib/hooks";
import type {
  CertInfo,
  ServiceConfig,
  ServiceIncident,
  ServiceItem,
  ServiceKind,
  ServicesResponse,
  ServiceStatus,
  ServiceTestResult,
} from "../lib/types";

const KIND_LABEL: Record<ServiceKind, string> = { http: "HTTP(S)", tcp: "TCP", dns: "DNS", tls: "TLS cert" };
const KIND_ICON: Record<ServiceKind, ReactNode> = {
  http: <Globe size={13} />, tcp: <Plug size={13} />, dns: <Search size={13} />, tls: <Lock size={13} />,
};
const STATUS_TONE: Record<ServiceStatus, string> = { up: "up", degraded: "degraded", down: "down", pending: "unknown", paused: "disabled" };
const DOT_STATUS: Record<ServiceStatus, string> = { up: "up", degraded: "degraded", down: "down", pending: "unknown", paused: "disabled" };

function target(s: Pick<ServiceItem, "kind" | "target" | "port">) {
  return s.kind === "http" || s.port == null ? s.target : `${s.target.includes(":") ? `[${s.target}]` : s.target}:${s.port}`;
}

export function UptimeBars({ bars, count = 30, height = 28 }: { bars: (number | null)[]; count?: number; height?: number }) {
  const shown = bars.slice(-count);
  const now = Date.now() / 1000;
  return (
    <div className="flex items-end gap-[2px]" style={{ height }} role="img"
      aria-label={`Daily uptime, last ${shown.length} days`}>
      {shown.map((p, i) => {
        const end = now - (shown.length - 1 - i) * 86400;
        const c = uptimeColor(p);
        return (
          <motion.span key={i} initial={{ scaleY: 0.2, opacity: 0 }} animate={{ scaleY: 1, opacity: 1 }}
            transition={{ delay: i * 0.008, duration: 0.25 }}
            title={`${new Date((end - 86400) * 1000).toLocaleDateString([], { month: "short", day: "2-digit" })} → ${clock(end, true).slice(0, 6)}: ${p == null ? "no data" : fmtUptime(p)}`}
            className="min-w-[2px] flex-1 origin-bottom rounded-[2px] transition-[filter] hover:brightness-150"
            style={{ height: "100%", background: p == null ? c : `linear-gradient(180deg, ${c}, ${c}aa)`,
              boxShadow: p != null && p < 99 ? `0 0 6px -1px ${c}` : undefined }} />
        );
      })}
    </div>
  );
}

function certTone(c: CertInfo, cfg: ServiceConfig) {
  if (!c.valid) return "critical";
  if (c.days_left < cfg.cert_crit_days) return "critical";
  if (c.days_left < cfg.cert_warn_days) return "warning";
  return "ok";
}

function CertBadge({ cert, cfg }: { cert: CertInfo | null; cfg: ServiceConfig }) {
  if (!cert) return null;
  const tone = certTone(cert, cfg);
  const Icon = tone === "ok" ? ShieldCheck : ShieldAlert;
  return (
    <Badge tone={tone} className="!normal-case">
      <Icon size={11} />
      {cert.valid ? `cert ${Math.max(0, Math.floor(cert.days_left))}d` : "cert invalid"}
    </Badge>
  );
}

function ServiceCard({ s, i, onOpen, onEdit, onCheck, checking }: {
  s: ServiceItem; i: number; onOpen: () => void; onEdit: () => void; onCheck: () => void; checking: boolean;
}) {
  const st = s.state;
  const color = { up: "#34d399", degraded: "#fbbf24", down: "#fb4d6d", pending: "#64748b", paused: "#334155" }[st.status];
  const openHistory = useHistory((x) => x.open);
  return (
    <motion.div layout initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.96 }}
      transition={{ delay: Math.min(i, 12) * 0.03 }}
      className={clsx("panel group relative flex flex-col gap-3 overflow-hidden p-4", !s.enabled && "opacity-60")}
      style={{ borderColor: st.status === "down" ? "#fb4d6d55" : st.status === "degraded" ? "#fbbf2440" : undefined,
        boxShadow: st.status === "down" ? "0 0 28px -10px #fb4d6d" : undefined }}>
      <div className="absolute -top-12 -right-12 h-28 w-28 rounded-full opacity-15 blur-2xl transition-opacity group-hover:opacity-30" style={{ background: color }} />
      <div className="flex items-start gap-3">
        <div className="pt-1.5"><StatusDot status={DOT_STATUS[st.status]} health={st.status === "down" ? "critical" : "ok"} size={9} /></div>
        <button type="button" onClick={onOpen} className="min-w-0 flex-1 text-left">
          <div className="truncate text-[15px] font-semibold hover:text-cyan">{s.name}</div>
          <div className="truncate font-mono text-[11px] text-faint">{target(s)}</div>
        </button>
        <div className="text-right">
          <div className="num text-lg leading-tight" style={{ color: st.status === "down" ? "#fb4d6d" : "#e6f1ff" }}>
            {st.status === "down" ? "DOWN" : ms(st.response_ms)}
          </div>
          <div className="font-mono text-[10px] text-faint">{st.last_ts ? ago(st.last_ts) : st.status === "paused" ? "paused" : "pending"}</div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone="neutral">{KIND_ICON[s.kind]}{KIND_LABEL[s.kind]}</Badge>
        <Badge tone={STATUS_TONE[st.status]}>{st.status}</Badge>
        <CertBadge cert={st.cert} cfg={s.config} />
        {s.tags.filter((t) => t !== "demo").slice(0, 2).map((t) => <Badge key={t} tone="violet">{t}</Badge>)}
      </div>

      <div>
        <UptimeBars bars={s.bars} count={30} />
        <div className="mt-1 flex justify-between font-mono text-[9.5px] tracking-wide text-faint">
          <span>30 DAYS AGO</span><span>{fmtUptime(s.uptime["30d"])} UPTIME</span><span>TODAY</span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-1 rounded-lg border border-edge/70 bg-black/20 px-2 py-1.5 text-center">
        {(["24h", "7d", "30d", "90d"] as const).map((w) => (
          <div key={w}>
            <div className="font-mono text-[9.5px] text-faint">{w}</div>
            <div className="num text-[12.5px]" style={{ color: s.uptime[w] == null ? undefined : uptimeColor(s.uptime[w]) }}>{fmtUptime(s.uptime[w])}</div>
          </div>
        ))}
      </div>

      <button type="button" className="block w-full text-left" title="Response time history"
        onClick={() => openHistory({ kind: "service", title: `${s.name} · response time`, unit: "ms", filters: { service_id: s.id },
          series: [{ key: "response_ms", label: "Response", color: "#22d3ee" }] })}>
        {st.spark.filter((v) => v != null).length >= 2
          ? <Sparkline data={st.spark} height={30} color={st.status === "down" ? "#fb4d6d" : "#22d3ee"} />
          : <div className="grid h-[30px] place-items-center font-mono text-[10px] text-faint">{st.status === "down" ? "no successful responses" : "collecting response times…"}</div>}
      </button>

      {(st.error || st.cert?.error) && st.status !== "up" && (
        <div className="flex items-start gap-1.5 rounded-md border border-crit/25 bg-crit/[0.06] px-2 py-1.5 text-[11.5px] text-crit/90">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          <span className="line-clamp-2">{st.error || st.cert?.error}</span>
        </div>
      )}

      <div className="mt-auto flex items-center justify-between border-t border-edge/60 pt-2">
        <span className="font-mono text-[10.5px] text-faint">every {duration(s.interval_s)}{st.incident_started ? ` · down ${duration(Date.now() / 1000 - st.incident_started)}` : ""}</span>
        <div className="flex gap-1">
          <button className="btn btn-ghost !p-1.5" title="Check now" onClick={onCheck} disabled={checking || !s.enabled}>
            {checking ? <Spinner size={13} /> : <Play size={14} />}
          </button>
          <button className="btn btn-ghost !p-1.5" title="Edit" onClick={onEdit}><Pencil size={14} /></button>
        </div>
      </div>
    </motion.div>
  );
}

// ------------------------------------------------------------------ form
type Draft = {
  id?: number; name: string; kind: ServiceKind; target: string; port: string; enabled: boolean;
  interval_s: number; timeout_s: number; tags: string; notes: string; config: ServiceConfig;
};

const DEFAULT_CFG: ServiceConfig = {
  fail_threshold: 3, slow_ms: null, expected_status: "200-399", keyword: "", method: "GET", follow_redirects: true,
  verify_tls: true, check_cert: true, record_type: "A", expected: [], sni: "", cert_warn_days: 21, cert_crit_days: 7,
};
const INTERVALS = [30, 60, 120, 300, 600, 1800, 3600];
const PLACEHOLDER: Record<ServiceKind, string> = {
  http: "https://cloud.example.com/status.php", tcp: "plex.example.com", dns: "cloud.example.com", tls: "mail.example.com",
};

function draftFrom(s?: ServiceItem): Draft {
  if (!s) return { name: "", kind: "http", target: "", port: "", enabled: true, interval_s: 60, timeout_s: 10, tags: "", notes: "", config: { ...DEFAULT_CFG } };
  return { id: s.id, name: s.name, kind: s.kind, target: s.target, port: s.port?.toString() ?? "", enabled: s.enabled,
    interval_s: s.interval_s, timeout_s: s.timeout_s, tags: s.tags.join(", "), notes: s.notes, config: { ...DEFAULT_CFG, ...s.config } };
}

function payload(d: Draft) {
  return {
    name: d.name, kind: d.kind, target: d.target.trim(), port: d.kind === "http" || d.kind === "dns" || !d.port ? null : +d.port,
    enabled: d.enabled, interval_s: d.interval_s, timeout_s: d.timeout_s, notes: d.notes,
    tags: d.tags.split(",").map((t) => t.trim()).filter(Boolean), config: d.config,
  };
}

function TestOutcome({ r }: { r: ServiceTestResult }) {
  const addrs = (r.detail.addresses as string[] | undefined) ?? [];
  return (
    <div className={clsx("rounded-lg border p-3 text-xs", r.ok ? "border-ok/40 bg-ok/10" : "border-crit/40 bg-crit/10")}>
      <div className={clsx("flex items-center gap-2 font-medium", r.ok ? "text-ok" : "text-crit")}>
        {r.ok ? <ShieldCheck size={14} /> : <AlertTriangle size={14} />}
        {r.ok ? `Reachable · ${ms(r.response_ms)}` : r.error}
      </div>
      <div className="mt-1.5 space-y-0.5 font-mono text-[11px] text-dim">
        {r.detail.status_code != null && <div>HTTP {String(r.detail.status_code)}{r.detail.redirects ? ` after ${String(r.detail.redirects)} redirect(s)` : ""}</div>}
        {addrs.length > 0 && <div>resolves to {addrs.join(", ")}</div>}
        {r.cert && <div>cert: {r.cert.valid ? "valid" : r.cert.error} · {Math.floor(r.cert.days_left)} days left · {r.cert.issuer}</div>}
      </div>
    </div>
  );
}

function ServiceForm({ initial, onClose, onSaved }: { initial: Draft; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState(initial);
  const [busy, setBusy] = useState<"save" | "test" | "delete" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [test, setTest] = useState<ServiceTestResult | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const c = d.config;
  const setC = (patch: Partial<ServiceConfig>) => setD({ ...d, config: { ...c, ...patch } });
  const isHttps = d.kind === "http" && d.target.trim().toLowerCase().startsWith("https://");

  const run = async (what: "save" | "test" | "delete") => {
    setBusy(what); setErr(null);
    try {
      if (what === "test") setTest(await api<ServiceTestResult>("/services/test", { method: "POST", body: payload(d) }));
      else if (what === "delete") { await api(`/services/${d.id}`, { method: "DELETE" }); onSaved(); onClose(); }
      else {
        await api(d.id ? `/services/${d.id}` : "/services", { method: d.id ? "PUT" : "POST", body: payload(d) });
        onSaved(); onClose();
      }
    } catch (e) { setErr((e as Error).message); } finally { setBusy(null); }
  };

  return (
    <div className="space-y-4">
      <Field label="Check type">
        <Segmented value={d.kind} onChange={(kind) => { setD({ ...d, kind, port: kind === "tls" && !d.port ? "443" : d.port }); setTest(null); }}
          options={(Object.keys(KIND_LABEL) as ServiceKind[]).map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
      </Field>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="sm:col-span-1"><Field label="Name">
          <input className="input" value={d.name} maxLength={128} placeholder="Nextcloud" onChange={(e) => setD({ ...d, name: e.target.value })} />
        </Field></div>
        <div className={d.kind === "tcp" || d.kind === "tls" ? "sm:col-span-1" : "sm:col-span-2"}>
          <Field label={d.kind === "http" ? "URL" : "Host"} help={d.kind === "http" ? "http:// or https:// only" : d.kind === "dns" ? "Hostname to resolve" : "Hostname or IP"}>
            <input className="input font-mono" value={d.target} placeholder={PLACEHOLDER[d.kind]} spellCheck={false}
              onChange={(e) => setD({ ...d, target: e.target.value })} />
          </Field>
        </div>
        {(d.kind === "tcp" || d.kind === "tls") && (
          <Field label="Port"><input className="input" type="number" min={1} max={65535} value={d.port} placeholder={d.kind === "tls" ? "443" : "22"}
            onChange={(e) => setD({ ...d, port: e.target.value })} /></Field>
        )}
      </div>

      {d.kind === "http" && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Field label="Expected status" help="e.g. 200-399, 204, 2xx">
            <input className="input font-mono" value={c.expected_status} onChange={(e) => setC({ expected_status: e.target.value })} />
          </Field>
          <Field label="Method">
            <select className="input" value={c.method} onChange={(e) => setC({ method: e.target.value as "GET" | "HEAD" })}>
              <option>GET</option><option>HEAD</option>
            </select>
          </Field>
          <Field label="Keyword" help="Must appear in the body (case-insensitive)">
            <input className="input" value={c.keyword} maxLength={256} disabled={c.method === "HEAD"} onChange={(e) => setC({ keyword: e.target.value })} />
          </Field>
          <div className="col-span-2 flex flex-wrap gap-x-5 gap-y-2 sm:col-span-3">
            <Toggle checked={c.follow_redirects} onChange={(v) => setC({ follow_redirects: v })} label="Follow redirects" />
            <Toggle checked={c.verify_tls} onChange={(v) => setC({ verify_tls: v })} label="Reject invalid certificates" />
            {isHttps && <Toggle checked={c.check_cert} onChange={(v) => setC({ check_cert: v })} label="Track certificate expiry" />}
          </div>
        </div>
      )}
      {d.kind === "dns" && (
        <div className="grid grid-cols-3 gap-3">
          <Field label="Record">
            <select className="input" value={c.record_type} onChange={(e) => setC({ record_type: e.target.value as ServiceConfig["record_type"] })}>
              <option>A</option><option>AAAA</option><option value="ANY">A + AAAA</option>
            </select>
          </Field>
          <div className="col-span-2"><Field label="Expected addresses" help="Optional. Every answer must be one of these - catches a stale or hijacked record.">
            <input className="input font-mono" value={c.expected.join(", ")} placeholder="203.0.113.42"
              onChange={(e) => setC({ expected: e.target.value.split(/[\s,]+/).filter(Boolean) })} />
          </Field></div>
        </div>
      )}
      {d.kind === "tls" && (
        <Field label="Server name (SNI)" help="Defaults to the host. The certificate must cover this name.">
          <input className="input font-mono" value={c.sni} placeholder={d.target || "mail.example.com"} onChange={(e) => setC({ sni: e.target.value })} />
        </Field>
      )}
      {(d.kind === "tls" || isHttps) && (
        <div className="grid grid-cols-2 gap-3">
          <Field label="Warn when cert expires in (days)">
            <input className="input" type="number" min={1} max={365} value={c.cert_warn_days} onChange={(e) => setC({ cert_warn_days: +e.target.value })} />
          </Field>
          <Field label="Critical below (days)">
            <input className="input" type="number" min={0} max={365} value={c.cert_crit_days} onChange={(e) => setC({ cert_crit_days: +e.target.value })} />
          </Field>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Field label="Check every">
          <select className="input" value={d.interval_s} onChange={(e) => setD({ ...d, interval_s: +e.target.value })}>
            {INTERVALS.map((s) => <option key={s} value={s}>{duration(s)}</option>)}
          </select>
        </Field>
        <Field label="Timeout (s)">
          <input className="input" type="number" min={1} max={60} value={d.timeout_s} onChange={(e) => setD({ ...d, timeout_s: +e.target.value })} />
        </Field>
        <Field label="Down after" help="consecutive failures">
          <input className="input" type="number" min={1} max={20} value={c.fail_threshold} onChange={(e) => setC({ fail_threshold: +e.target.value })} />
        </Field>
        <Field label="Slow above (ms)" help="blank = off">
          <input className="input" type="number" min={1} value={c.slow_ms ?? ""} onChange={(e) => setC({ slow_ms: e.target.value ? +e.target.value : null })} />
        </Field>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Tags" help="comma separated"><input className="input" value={d.tags} onChange={(e) => setD({ ...d, tags: e.target.value })} /></Field>
        <Field label="Notes"><input className="input" value={d.notes} maxLength={2000} onChange={(e) => setD({ ...d, notes: e.target.value })} /></Field>
      </div>
      <Toggle checked={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} label="Monitoring enabled" />

      {test && <TestOutcome r={test} />}
      {err && <div className="rounded-lg border border-crit/40 bg-crit/10 p-2.5 text-xs text-crit">{err}</div>}

      <div className="flex flex-wrap items-center gap-2 border-t border-edge pt-4">
        <button className="btn btn-primary" disabled={!!busy || !d.name || !d.target} onClick={() => run("save")}>
          {busy === "save" && <Spinner size={14} />}{d.id ? "Save changes" : "Add service"}
        </button>
        <button className="btn" disabled={!!busy || !d.target} onClick={() => run("test")}>
          {busy === "test" ? <Spinner size={14} /> : <Activity size={14} />}Test now
        </button>
        <div className="flex-1" />
        {d.id && (confirmDel ? (
          <>
            <span className="text-xs text-dim">Delete with all history?</span>
            <button className="btn btn-danger" disabled={!!busy} onClick={() => run("delete")}>{busy === "delete" && <Spinner size={14} />}Delete</button>
            <button className="btn btn-ghost" onClick={() => setConfirmDel(false)}>Cancel</button>
          </>
        ) : <button className="btn btn-ghost text-crit" onClick={() => setConfirmDel(true)}><Trash2 size={14} />Delete</button>)}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ detail
function ServiceDetail({ id, onEdit }: { id: number; onEdit: (s: ServiceItem) => void }) {
  const { data } = useApi<ServiceItem & { incidents: ServiceIncident[] }>(`/services/${id}`, 15000);
  const openHistory = useHistory((x) => x.open);
  if (!data) return <div className="grid h-40 place-items-center"><Spinner size={22} /></div>;
  const st = data.state, cert = st.cert;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={STATUS_TONE[st.status]}>{st.status}</Badge>
        <Badge tone="neutral">{KIND_ICON[data.kind]}{KIND_LABEL[data.kind]}</Badge>
        <span className="truncate font-mono text-xs text-dim">{target(data)}</span>
        <div className="flex-1" />
        <button className="btn" onClick={() => openHistory({ kind: "service", title: `${data.name} · response time`, unit: "ms",
          filters: { service_id: data.id }, series: [{ key: "response_ms", label: "Response", color: "#22d3ee" }] })}><History size={14} />Response history</button>
        <button className="btn" onClick={() => onEdit(data)}><Pencil size={14} />Edit</button>
      </div>

      <div>
        <div className="hud-label mb-2">Uptime · 90 days</div>
        <UptimeBars bars={data.bars} count={90} height={36} />
        <div className="mt-3 grid grid-cols-4 gap-2">
          {(["24h", "7d", "30d", "90d"] as const).map((w) => (
            <div key={w} className="rounded-lg border border-edge bg-black/20 p-2 text-center">
              <div className="hud-label">{w}</div>
              <div className="num mt-0.5 text-lg" style={{ color: data.uptime[w] == null ? undefined : uptimeColor(data.uptime[w]) }}>{fmtUptime(data.uptime[w])}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <div className="hud-label mb-1">Last check</div>
          <Kv k="When" v={st.last_ts ? `${clock(st.last_ts)} (${ago(st.last_ts)})` : "—"} />
          <Kv k="Response" v={ms(st.response_ms)} />
          <Kv k="Last success" v={st.last_ok_ts ? ago(st.last_ok_ts) : "never"} />
          <Kv k="Result" v={st.error || "OK"} />
          {st.detail.status_code != null && <Kv k="HTTP status" v={String(st.detail.status_code)} />}
          {Array.isArray(st.detail.addresses) && <Kv k="Resolves to" v={(st.detail.addresses as string[]).join(", ")} />}
        </div>
        <div>
          <div className="hud-label mb-1">Certificate</div>
          {cert ? (
            <>
              <Kv k="Status" v={<span className={cert.valid ? "text-ok" : "text-crit"}>{cert.valid ? "valid" : cert.error}</span>} />
              <Kv k="Expires" v={`${new Date(cert.not_after * 1000).toLocaleDateString()} (${Math.floor(cert.days_left)} d)`} />
              <Kv k="Issuer" v={cert.issuer} />
              <Kv k="Subject" v={cert.subject} />
              <Kv k="Names" v={<span title={cert.sans.join("\n")}>{cert.sans.slice(0, 3).join(", ")}{cert.sans.length > 3 ? ` +${cert.sans.length - 3}` : ""}</span>} />
            </>
          ) : <div className="py-2 text-xs text-faint">{st.cert_error || (data.kind === "http" || data.kind === "tls" ? "Not read yet." : "Not applicable for this check type.")}</div>}
        </div>
      </div>

      <div>
        <div className="hud-label mb-2">Incidents</div>
        {data.incidents.length === 0 ? <div className="text-xs text-faint">No outages recorded.</div> : (
          <div className="space-y-1.5">
            {data.incidents.map((inc) => (
              <div key={inc.id} className={clsx("flex items-center gap-3 rounded-lg border px-3 py-2 text-xs",
                inc.ongoing ? "border-crit/40 bg-crit/10" : "border-edge bg-black/20")}>
                <span className={clsx("h-2 w-2 shrink-0 rounded-full", inc.ongoing ? "animate-pulse bg-crit" : "bg-faint")} />
                <span className="w-32 shrink-0 font-mono text-dim">{clock(inc.started_at, true).slice(0, 12)}</span>
                <span className="num w-16 shrink-0">{duration(inc.duration_s)}</span>
                <span className="min-w-0 flex-1 truncate text-dim">{inc.error}</span>
                {inc.ongoing && <Badge tone="down">ongoing</Badge>}
              </div>
            ))}
          </div>
        )}
      </div>
      {data.notes && <div className="rounded-lg border border-edge bg-black/20 p-3 text-xs text-dim">{data.notes}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ page
export default function ServicesPage() {
  const { data, reload, setData } = useApi<ServicesResponse>("/services", 15000);
  const [editing, setEditing] = useState<Draft | null>(null);
  const [detail, setDetail] = useState<number | null>(null);
  const [checking, setChecking] = useState<Set<number>>(new Set());
  const [filter, setFilter] = useState<"all" | "issues">("all");
  useTick(10000);

  const items = useMemo(() => {
    const rank: Record<ServiceStatus, number> = { down: 0, degraded: 1, pending: 2, up: 3, paused: 4 };
    const all = [...(data?.services ?? [])].sort((a, b) => rank[a.state.status] - rank[b.state.status] || a.name.localeCompare(b.name));
    return filter === "issues" ? all.filter((s) => s.state.status === "down" || s.state.status === "degraded") : all;
  }, [data, filter]);

  useEffect(() => {
    if (!detail || data?.services.some((s) => s.id === detail)) return;
    setDetail(null);
  }, [data, detail]);

  const checkNow = async (id: number) => {
    setChecking((c) => new Set(c).add(id));
    try {
      const it = await api<ServiceItem>(`/services/${id}/check`, { method: "POST" });
      setData((d) => (d ? { ...d, services: d.services.map((s) => (s.id === id ? it : s)) } : d));
    } catch { /* shown on next refresh */ } finally {
      setChecking((c) => { const n = new Set(c); n.delete(id); return n; });
    }
  };

  if (!data) return <div className="grid h-64 place-items-center"><Spinner size={26} /></div>;
  const sm = data.summary;
  const avg30 = (() => {
    const v = data.services.map((s) => s.uptime["30d"]).filter((x): x is number => x != null);
    return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null;
  })();
  const detailItem = data.services.find((s) => s.id === detail);

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Services up", tone: sm.down ? "#fb4d6d" : "#34d399", icon: HeartPulse,
            value: <><CountUp value={sm.up + sm.degraded} /><span className="text-base text-dim"> / {sm.total - sm.paused}</span></>,
            sub: <>{sm.down ? <span className="text-crit">{sm.down} down</span> : "none down"} · {sm.degraded} degraded{sm.paused ? ` · ${sm.paused} paused` : ""}</> },
          { label: "Avg uptime · 30d", tone: uptimeColor(avg30), icon: Activity, value: <span className="num">{fmtUptime(avg30)}</span>, sub: "across all services" },
          { label: "Certificates", tone: sm.certs_expiring ? "#fbbf24" : "#34d399", icon: ShieldCheck,
            value: <span className="num">{sm.soonest_cert ? `${Math.max(0, Math.floor(sm.soonest_cert.days_left))}d` : "—"}</span>,
            sub: sm.soonest_cert ? <>soonest: {sm.soonest_cert.name}{sm.certs_expiring ? ` · ${sm.certs_expiring} expiring` : ""}</> : "no TLS checks yet" },
        ].map((k, i) => (
          <motion.div key={k.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="panel relative overflow-hidden p-4">
            <div className="absolute -top-10 -right-10 h-28 w-28 rounded-full opacity-20 blur-2xl" style={{ background: k.tone }} />
            <div className="flex items-center justify-between"><span className="hud-label">{k.label}</span><k.icon size={15} style={{ color: k.tone }} /></div>
            <div className="mt-2 text-[26px] leading-none font-semibold">{k.value}</div>
            <div className="mt-2 truncate text-xs text-dim">{k.sub}</div>
          </motion.div>
        ))}
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}
          className="panel flex flex-col justify-between gap-3 p-4">
          <span className="hud-label">Checked from this NetworkVision host</span>
          <div className="flex flex-wrap items-center gap-2">
            <button className="btn btn-primary" onClick={() => setEditing(draftFrom())}><Plus size={15} />Add service</button>
            <Segmented value={filter} onChange={setFilter} options={[{ value: "all", label: "All" }, { value: "issues", label: "Issues" }]} />
          </div>
        </motion.div>
      </div>

      {data.services.length === 0 ? (
        <Panel title="Services" icon={<HeartPulse size={15} />}>
          <Empty icon={<HeartPulse size={30} />} title="No services monitored yet">
            Add the websites and ports you expose (Nextcloud, Plex, Vaultwarden, a mail server…) to track uptime, response time and certificate expiry.
            <div className="mt-3"><button className="btn btn-primary" onClick={() => setEditing(draftFrom())}><Plus size={15} />Add your first service</button></div>
          </Empty>
        </Panel>
      ) : items.length === 0 ? (
        <Panel><Empty icon={<ShieldCheck size={28} />} title="No issues">Every service is up.</Empty></Panel>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
          <AnimatePresence initial={false}>
            {items.map((s, i) => (
              <ServiceCard key={s.id} s={s} i={i} checking={checking.has(s.id) || s.state.running}
                onOpen={() => setDetail(s.id)} onEdit={() => setEditing(draftFrom(s))} onCheck={() => checkNow(s.id)} />
            ))}
          </AnimatePresence>
        </div>
      )}

      <Drawer open={!!editing} onClose={() => setEditing(null)} width={680}
        title={editing?.id ? `Edit ${editing.name}` : "Add service"}>
        {editing && <ServiceForm key={editing.id ?? "new"} initial={editing} onClose={() => setEditing(null)} onSaved={reload} />}
      </Drawer>
      <Drawer open={detail != null && !editing} onClose={() => setDetail(null)} width={760}
        title={<span className="flex items-center gap-2">{detailItem && <StatusDot status={DOT_STATUS[detailItem.state.status]} size={9} />}{detailItem?.name ?? "Service"}</span>}>
        {detail != null && <ServiceDetail id={detail} onEdit={(s) => setEditing(draftFrom(s))} />}
      </Drawer>
    </div>
  );
}
