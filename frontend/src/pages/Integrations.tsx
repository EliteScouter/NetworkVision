import clsx from "clsx";
import {
  CheckCircle2,
  ChevronLeft,
  Database,
  KeyRound,
  Pencil,
  Plug,
  Plus,
  Radio,
  Settings2,
  ShieldAlert,
  Trash2,
  XCircle,
  Zap,
} from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { DeviceIcon, ROLE_LABEL } from "../components/DeviceIcon";
import { Badge, Drawer, Empty, Field, Kv, Panel, Segmented, Spinner, StatusDot, Toggle } from "../components/ui";
import { api } from "../lib/api";
import { ago } from "../lib/format";
import { useApi } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { DeviceDetail, FieldSpec, Integration, Meta } from "../lib/types";

const MASK = "••••••••";

interface FormState {
  id?: number;
  kind: string;
  name: string;
  host: string;
  role: string;
  enabled: boolean;
  poll_interval: string;
  tags: string;
  location: string;
  notes: string;
  ping: boolean;
  syslog_aliases: string;
  values: Record<string, unknown>;
}

type TestResult = {
  ok: boolean; reachable: boolean; error: string | null; elapsed_ms: number; facts: Record<string, unknown>;
  metrics: Record<string, number>; interfaces: number; neighbors: number; gateways: number; children: number; logs: number; sections: string[];
};

function DynamicField({ f, value, onChange }: { f: FieldSpec; value: unknown; onChange: (v: unknown) => void }) {
  if (f.type === "bool") return <Toggle checked={!!value} onChange={onChange} label={f.label} />;
  return (
    <Field label={<>{f.label}{f.required && <span className="text-crit"> *</span>}{f.secret && <KeyRound size={10} className="ml-1 inline text-violet" />}</>} help={f.help}>
      {f.type === "select" ? (
        <select className="input" value={String(value ?? f.default ?? "")} onChange={(e) => onChange(e.target.value)}>
          {f.options?.map((o) => <option key={o}>{o}</option>)}
        </select>
      ) : (
        <input className="input font-mono" type={f.type === "password" && !(String(value ?? "").startsWith("env:")) ? "password" : f.type === "number" ? "number" : "text"}
          value={String(value ?? "")} placeholder={f.placeholder || (f.default != null ? String(f.default) : "")}
          onFocus={(e) => f.secret && value === MASK && e.target.select()}
          onChange={(e) => onChange(f.type === "number" ? (e.target.value === "" ? "" : Number(e.target.value)) : e.target.value)}
          autoComplete="off" spellCheck={false} />
      )}
    </Field>
  );
}

function DeviceForm({ integrations, roles, initial, onSaved, onBack }: {
  integrations: Integration[]; roles: string[]; initial: FormState; onSaved: () => void; onBack?: () => void;
}) {
  const [f, setF] = useState<FormState>(initial);
  const [test, setTest] = useState<TestResult | null>(null);
  const [busy, setBusy] = useState<"" | "test" | "save">("");
  const [err, setErr] = useState<string | null>(null);
  const spec = integrations.find((i) => i.kind === f.kind);

  const payload = () => {
    const config: Record<string, unknown> = { ping: f.ping };
    const secrets: Record<string, unknown> = {};
    if (f.syslog_aliases.trim()) config.syslog_aliases = f.syslog_aliases.split(",").map((s) => s.trim()).filter(Boolean);
    spec?.fields.forEach((fs) => {
      const v = f.values[fs.key];
      if (v === undefined) return;
      (fs.secret ? secrets : config)[fs.key] = v;
    });
    return {
      name: f.name, kind: f.kind, role: f.role, host: f.host, enabled: f.enabled,
      poll_interval: f.poll_interval ? Number(f.poll_interval) : null, config, secrets,
      tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean), location: f.location, notes: f.notes,
    };
  };

  const runTest = async () => {
    setBusy("test"); setErr(null); setTest(null);
    try {
      setTest(await api<TestResult>("/devices/test", { method: "POST", body: payload(), query: { device_id: f.id } }));
    } catch (e) { setErr((e as Error).message); } finally { setBusy(""); }
  };
  const save = async () => {
    setBusy("save"); setErr(null);
    try {
      await api(f.id ? `/devices/${f.id}` : "/devices", { method: f.id ? "PUT" : "POST", body: payload() });
      onSaved();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(""); }
  };

  return (
    <div className="space-y-5">
      {onBack && <button className="flex items-center gap-1 text-sm text-dim hover:text-cyan" onClick={onBack}><ChevronLeft size={15} /> Choose another integration</button>}
      {spec && (
        <div className="rounded-xl border border-cyan/25 bg-cyan/5 p-3">
          <div className="font-medium">{spec.label} <span className="text-xs text-dim">· {spec.vendor}</span></div>
          <div className="mt-0.5 text-xs text-dim">{spec.description}</div>
        </div>
      )}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Display name *"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="pf-edge" /></Field>
        <Field label="Host / IP *" help="Hostname or IP only - no http://"><input className="input font-mono" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} placeholder="10.0.0.1" /></Field>
        <Field label="Role">
          <select className="input" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
            {roles.map((r) => <option key={r} value={r}>{ROLE_LABEL[r] ?? r}</option>)}
          </select>
        </Field>
        <Field label="Poll interval (s)" help="Blank = global default"><input className="input" type="number" min={5} value={f.poll_interval} onChange={(e) => setF({ ...f, poll_interval: e.target.value })} /></Field>
      </div>

      <div className="space-y-4 rounded-xl border border-edge bg-black/20 p-4">
        <div className="hud-label flex items-center gap-2"><Plug size={12} /> Connection</div>
        <div className="grid gap-4 sm:grid-cols-2">
          {spec?.fields.map((fs) => (
            <div key={fs.key} className={clsx(fs.type === "bool" && "self-end pb-2")}>
              <DynamicField f={fs} value={f.values[fs.key]} onChange={(v) => setF({ ...f, values: { ...f.values, [fs.key]: v } })} />
            </div>
          ))}
        </div>
        <div className="flex items-start gap-2 rounded-lg border border-violet/25 bg-violet/5 p-2.5 text-xs text-dim">
          <KeyRound size={14} className="mt-0.5 shrink-0 text-violet" />
          <span>Secrets are encrypted at rest and never sent back to the browser. Prefer <code className="text-violet">env:VARIABLE_NAME</code> to keep them
            entirely in your Portainer stack environment (variables starting with <code>NV_</code> are blocked).</span>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Tags" help="Comma separated"><input className="input" value={f.tags} onChange={(e) => setF({ ...f, tags: e.target.value })} placeholder="core, rack" /></Field>
        <Field label="Location"><input className="input" value={f.location} onChange={(e) => setF({ ...f, location: e.target.value })} placeholder="Rack / Office / Garage" /></Field>
        <Field label="Syslog aliases" help="Extra hostnames/IPs this device sends syslog from"><input className="input font-mono" value={f.syslog_aliases} onChange={(e) => setF({ ...f, syslog_aliases: e.target.value })} /></Field>
        <div className="flex flex-col justify-end gap-3 pb-1">
          <Toggle checked={f.ping} onChange={(v) => setF({ ...f, ping: v })} label="Also ping for latency / loss" />
          <Toggle checked={f.enabled} onChange={(v) => setF({ ...f, enabled: v })} label="Enabled" />
        </div>
      </div>
      <Field label="Notes"><textarea className="input min-h-16" value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></Field>

      {test && (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
          className={clsx("rounded-xl border p-3 text-sm", test.ok ? "border-ok/40 bg-ok/5" : test.reachable ? "border-warn/40 bg-warn/5" : "border-crit/40 bg-crit/5")}>
          <div className="flex items-center gap-2 font-medium">
            {test.ok ? <CheckCircle2 size={16} className="text-ok" /> : <XCircle size={16} className={test.reachable ? "text-warn" : "text-crit"} />}
            {test.ok ? "Connection successful" : test.reachable ? "Reachable, but the integration reported a problem" : "Connection failed"}
            <span className="ml-auto font-mono text-xs text-faint">{test.elapsed_ms} ms</span>
          </div>
          {test.error && <div className="mt-1 text-xs break-all text-dim">{test.error}</div>}
          {test.reachable && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {[["interfaces", test.interfaces], ["gateways", test.gateways], ["neighbors", test.neighbors], ["discovered devices", test.children], ["log lines", test.logs]]
                .filter(([, n]) => n).map(([k, n]) => <Badge key={k as string} tone="cyan">{n} {k}</Badge>)}
              {test.sections.map((s) => <Badge key={s} tone="violet">{s}</Badge>)}
              {Boolean(test.facts.model) && <Badge>{String(test.facts.model)} {String(test.facts.version ?? "")}</Badge>}
            </div>
          )}
        </motion.div>
      )}
      {err && <div className="rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-sm text-crit">{err}</div>}

      <div className="flex justify-end gap-2 border-t border-edge pt-4">
        <button className="btn" onClick={runTest} disabled={!!busy || !f.host}>{busy === "test" ? <Spinner size={14} /> : <Zap size={15} />} Test connection</button>
        <button className="btn btn-primary" onClick={save} disabled={!!busy || !f.name || !f.host}>{busy === "save" ? <Spinner size={14} /> : <CheckCircle2 size={15} />} {f.id ? "Save changes" : "Add device"}</button>
      </div>
    </div>
  );
}

const SYSLOG_GUIDES: [string, string][] = [
  ["pfSense", "Status › System Logs › Settings › Remote Logging Options → enable, Remote log server = <host>:514, contents: Everything."],
  ["OPNsense", "System › Settings › Logging › Remote → add destination: transport UDP(4), hostname <host>, port 514, all applications/levels."],
  ["UniFi Network", "Settings › CyberSecure/System › Traffic Logging (Activity Logging / SIEM Server) → Syslog server <host> port 514."],
  ["HP ProCurve / Aruba", "configure → logging <host> udp 514 → logging severity info → write memory"],
  ["TP-Link managed", "Maintenance › Logs › Remote Log → Server IP <host>, UDP port 514, severity level 6 (info)."],
  ["Linux / Proxmox / TrueNAS", "rsyslog: *.* @<host>:514   (TrueNAS: System › Advanced › Syslog server)"],
];

export default function IntegrationsPage({ meta }: { meta: Meta | null }) {
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState<"devices" | "syslog" | "system">("devices");
  const { data: info } = useApi<{ integrations: Integration[]; roles: string[] }>("/integrations");
  const { data: list, reload } = useApi<{ devices: (DeviceDetail & { config: Record<string, unknown> })[] }>("/devices", 15000);
  const live = useLive((s) => s.devices);
  const [drawer, setDrawer] = useState<null | { mode: "pick" } | { mode: "form"; initial: FormState }>(null);

  const blank = (kind: string): FormState => {
    const spec = info?.integrations.find((i) => i.kind === kind);
    return {
      kind, name: "", host: "", role: spec?.default_role ?? "other", enabled: true, poll_interval: "", tags: "", location: "", notes: "",
      ping: true, syslog_aliases: "",
      values: Object.fromEntries((spec?.fields ?? []).filter((f) => f.default != null).map((f) => [f.key, f.default])),
    };
  };

  const openEdit = async (id: number) => {
    const d = await api<DeviceDetail>(`/devices/${id}`);
    const cfg = d.config ?? {};
    setDrawer({
      mode: "form",
      initial: {
        id: d.id, kind: d.kind, name: d.name, host: d.host, role: d.role, enabled: d.enabled,
        poll_interval: d.poll_interval ? String(d.poll_interval) : "", tags: d.tags.join(", "), location: d.location, notes: d.notes ?? "",
        ping: cfg.ping !== false, syslog_aliases: ((cfg.syslog_aliases as string[]) ?? []).join(", "),
        values: { ...Object.fromEntries(Object.entries(cfg).filter(([k]) => !["ping", "syslog_aliases", "name_locked"].includes(k))), ...d.secrets },
      },
    });
  };

  useEffect(() => {
    if (!info) return;
    if (params.get("add")) setDrawer({ mode: "pick" });
    const e = params.get("edit");
    if (e) openEdit(Number(e));
    if (params.get("add") || e) setParams({}, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info]);

  const top = useMemo(() => (list?.devices ?? []).filter((d) => d.parent_id == null), [list]);
  const childCount = (id: number) => (list?.devices ?? []).filter((d) => d.parent_id === id).length;
  const remove = async (id: number, name: string) => {
    if (!confirm(`Remove ${name}? Its metrics, alerts and discovered child devices are deleted too.`)) return;
    await api(`/devices/${id}`, { method: "DELETE" });
    reload();
  };
  const host = typeof location !== "undefined" ? location.hostname : "<networkvision-host>";

  return (
    <div className="mx-auto max-w-[1400px] space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={tab} onChange={setTab} options={[
          { value: "devices", label: "Integrations" }, { value: "syslog", label: "Syslog setup" }, { value: "system", label: "System" },
        ]} />
        {tab === "devices" && <button className="btn btn-primary ml-auto" onClick={() => setDrawer({ mode: "pick" })}><Plus size={15} /> Add integration</button>}
      </div>

      {tab === "devices" && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {!top.length && <div className="panel md:col-span-2 xl:col-span-3"><Empty icon={<Plug size={30} />} title="Nothing connected yet">Add your firewall, UniFi controller and switches to bring them into one pane of glass.</Empty></div>}
          {top.map((d, i) => {
            const st = live[d.id] ?? d;
            const spec = info?.integrations.find((x) => x.kind === d.kind);
            return (
              <motion.div key={d.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }} className="panel p-4">
                <div className="flex items-start gap-3">
                  <div className="grid h-10 w-10 place-items-center rounded-xl border border-edge bg-black/30 text-cyan"><DeviceIcon role={d.role} size={19} /></div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2"><span className="truncate font-semibold">{d.name}</span><StatusDot status={st.status} health={st.health} size={7} /></div>
                    <div className="truncate font-mono text-[11px] text-faint">{spec?.label ?? d.kind} · {d.host}</div>
                  </div>
                  {!d.enabled && <Badge tone="disabled">disabled</Badge>}
                </div>
                {st.error && <div className="mt-3 truncate rounded-md border border-warn/30 bg-warn/5 px-2 py-1 text-xs text-warn" title={st.error}>{st.error}</div>}
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {Object.entries(d.secrets ?? {}).map(([k, v]) => (
                    <Badge key={k} tone={String(v).startsWith("env:") ? "violet" : "neutral"}><KeyRound size={9} /> {k}{String(v).startsWith("env:") && ` ← ${String(v).slice(4)}`}</Badge>
                  ))}
                  {childCount(d.id) > 0 && <Badge tone="cyan">{childCount(d.id)} discovered</Badge>}
                </div>
                <div className="mt-3 flex items-center justify-between border-t border-edge pt-3">
                  <span className="font-mono text-[11px] text-faint">polled {ago(st.last_poll)}{st.poll_ms != null && ` · ${st.poll_ms.toFixed(0)}ms`}</span>
                  <div className="flex gap-1">
                    <button className="btn btn-ghost !p-1.5" title="Edit" onClick={() => openEdit(d.id)}><Pencil size={15} /></button>
                    <button className="btn btn-ghost btn-danger !p-1.5" title="Remove" onClick={() => remove(d.id, d.name)}><Trash2 size={15} /></button>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}

      {tab === "syslog" && (
        <Panel title="Centralize every log" icon={<Radio size={15} />}>
          <p className="mb-4 text-sm text-dim">
            NetworkVision listens for syslog on <span className="font-mono text-cyan">UDP{meta?.syslog.tcp ? " + TCP" : ""} {meta?.syslog.port ?? 5514}</span> inside
            the container — publish it as <span className="font-mono text-cyan">514</span> on the host (see docker-compose). Lines are matched to devices by source IP, hostname or the
            aliases you configure, and anything critical raises an alert automatically.
          </p>
          <div className="grid gap-3 md:grid-cols-2">
            {SYSLOG_GUIDES.map(([v, g]) => (
              <div key={v} className="rounded-xl border border-edge bg-black/20 p-3">
                <div className="mb-1 font-medium">{v}</div>
                <div className="font-mono text-xs leading-relaxed text-dim">{g.replaceAll("<host>", host)}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {tab === "system" && meta && (
        <div className="grid gap-4 md:grid-cols-2">
          <Panel title="Runtime" icon={<Settings2 size={15} />}>
            <Kv k="Version" v={meta.version} />
            <Kv k="Demo mode" v={meta.demo_mode ? "on" : "off"} />
            <Kv k="Default poll interval" v={`${meta.poll_interval}s`} />
            <Kv k="Syslog" v={meta.syslog.enabled ? `port ${meta.syslog.port}${meta.syslog.tcp ? " udp+tcp" : " udp"}` : "disabled"} />
            <Kv k="Log lines received" v={meta.logs.received.toLocaleString()} />
            <Kv k="Dropped (backpressure)" v={meta.logs.dropped} />
            <Kv k="Live dashboards" v={meta.ws_clients} />
            <Kv k="Notifications" v={meta.notifications ? "configured" : "none"} />
          </Panel>
          <Panel title="Storage" icon={<Database size={15} />}>
            <Kv k="Database" v={meta.database} />
            <Kv k="Metric retention" v={`${meta.retention.metrics_days} days`} />
            <Kv k="Log retention" v={`${meta.retention.logs_days} days`} />
          </Panel>
          <Panel title="Alert thresholds" icon={<ShieldAlert size={15} />} className="md:col-span-2">
            <div className="grid gap-x-8 sm:grid-cols-2">
              {Object.entries(meta.thresholds).map(([k, v]) => <Kv key={k} k={k.replace(/_/g, " ")} v={v} />)}
            </div>
            <p className="mt-3 text-xs text-faint">Thresholds are set with <code>NV_ALERT_*</code> environment variables — see .env.example.</p>
          </Panel>
        </div>
      )}

      <Drawer open={!!drawer} onClose={() => setDrawer(null)} width={760}
        title={drawer?.mode === "form" ? (drawer.initial.id ? `Edit ${drawer.initial.name}` : "New integration") : "Add an integration"}>
        {drawer?.mode === "pick" && (
          <div className="grid gap-3 sm:grid-cols-2">
            {info?.integrations.map((it) => (
              <button key={it.kind} onClick={() => setDrawer({ mode: "form", initial: blank(it.kind) })}
                className="group rounded-xl border border-edge bg-black/20 p-4 text-left transition hover:-translate-y-0.5 hover:border-cyan/50 hover:shadow-[0_0_24px_-8px_#22d3ee]">
                <div className="flex items-center gap-2">
                  <DeviceIcon role={it.default_role} size={18} className="text-cyan" />
                  <span className="font-medium">{it.label}</span>
                </div>
                <div className="mt-0.5 font-mono text-[10.5px] tracking-wider text-faint uppercase">{it.vendor}</div>
                <div className="mt-2 text-xs leading-relaxed text-dim">{it.description}</div>
              </button>
            ))}
          </div>
        )}
        {drawer?.mode === "form" && info && (
          <DeviceForm key={drawer.initial.id ?? drawer.initial.kind} integrations={info.integrations} roles={info.roles} initial={drawer.initial}
            onBack={drawer.initial.id ? undefined : () => setDrawer({ mode: "pick" })}
            onSaved={() => { setDrawer(null); reload(); }} />
        )}
      </Drawer>
    </div>
  );
}
