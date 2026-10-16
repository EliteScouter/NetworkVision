import clsx from "clsx";
import { BellOff, Save, SlidersHorizontal, X } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api } from "../lib/api";
import { useApi } from "../lib/hooks";
import type { AlertTuning } from "../lib/types";
import { Badge, Field, Panel, Spinner, Toggle } from "./ui";

const OVERRIDES: [string, string, string][] = [
  ["cpu", "CPU", "%"], ["mem", "Memory", "%"], ["temp", "Temp", "°C"], ["latency_ms", "Latency", "ms"],
  ["loss_pct", "Loss", "%"], ["if_util", "Port util", "%"], ["if_errors", "Port errors", "/min"],
];

type Globals = { rules: Record<string, string>; thresholds: Record<string, number> };

/** Shared state for the tuning panel and the per-port mute buttons on the device page. */
export function useAlertTuning(deviceId: number) {
  const { data, setData } = useApi<AlertTuning>(`/alert-tuning/${deviceId}`);
  const save = async (next: AlertTuning) => {
    const r = await api<AlertTuning>(`/alert-tuning/${deviceId}`, { method: "PUT", body: next });
    setData(r);
    return r;
  };
  const toggleInterface = (name: string) => {
    if (!data) return;
    const muted = data.muted_interfaces.includes(name);
    return save({ ...data, muted_interfaces: muted ? data.muted_interfaces.filter((i) => i !== name) : [...data.muted_interfaces, name] });
  };
  return { tuning: data, save, toggleInterface };
}

export function AlertTuningPanel({ tuning, save }: { tuning: AlertTuning | null; save: (t: AlertTuning) => Promise<AlertTuning> }) {
  const { data: globals } = useApi<Globals>("/alert-tuning");
  const [draft, setDraft] = useState<AlertTuning | null>(tuning);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setDraft(tuning), [tuning]);
  if (!draft || !globals) return <Panel title="Alert tuning" icon={<SlidersHorizontal size={15} />}><div className="grid h-16 place-items-center"><Spinner /></div></Panel>;

  const dirty = JSON.stringify(draft) !== JSON.stringify(tuning);
  const commit = async (next: AlertTuning) => {
    setBusy(true);
    setErr(null);
    try {
      await save(next);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const setTh = (k: string, v: string) => {
    const th = { ...draft.thresholds };
    if (v === "") delete th[k];
    else th[k] = +v;
    setDraft({ ...draft, thresholds: th });
  };

  return (
    <Panel title="Alert tuning" icon={<SlidersHorizontal size={15} />}
      actions={draft.muted ? <Badge tone="warning"><BellOff size={10} /> muted</Badge> : undefined}>
      <div className="space-y-4">
        <Toggle checked={draft.muted} onChange={(muted) => commit({ ...draft, muted })} label="Mute every alert for this device" />

        <div className={clsx("space-y-4 transition-opacity", draft.muted && "pointer-events-none opacity-40")}>
          <div>
            <div className="hud-label mb-2">Threshold overrides</div>
            <div className="grid grid-cols-2 gap-2">
              {OVERRIDES.map(([k, label, unit]) => (
                <Field key={k} label={label}>
                  <div className="relative">
                    <input className={clsx("input w-full pr-10 !py-1.5 text-sm", draft.thresholds[k] != null && "!border-cyan/50")} type="number" min={0} step="any"
                      placeholder={String(globals.thresholds[k] ?? "")} value={draft.thresholds[k] ?? ""} onChange={(e) => setTh(k, e.target.value)} />
                    <span className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 font-mono text-[10px] text-faint">{unit}</span>
                  </div>
                </Field>
              ))}
            </div>
            <p className="mt-1.5 text-[11px] text-faint">Empty = global value (<Link to="/settings" className="text-dim hover:text-cyan">Settings</Link>).</p>
          </div>

          <div>
            <div className="hud-label mb-2">Rules on this device</div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(globals.rules).map(([rule, label]) => {
                const off = draft.disabled_rules.includes(rule);
                return (
                  <button key={rule} className="chip" data-active={!off} title={off ? "Disabled for this device" : "Enabled"}
                    onClick={() => setDraft({ ...draft, disabled_rules: off ? draft.disabled_rules.filter((r) => r !== rule) : [...draft.disabled_rules, rule] })}>
                    <span className={clsx(off && "line-through opacity-60")}>{label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div>
            <div className="hud-label mb-2">Muted ports</div>
            {!draft.muted_interfaces.length && <p className="text-xs text-faint">None. Use the bell on a port row to ignore a port that is expected to be down.</p>}
            <div className="flex flex-wrap gap-1.5">
              {draft.muted_interfaces.map((i) => (
                <Badge key={i} tone="warning">
                  <BellOff size={10} /> {i}
                  <button className="ml-0.5 hover:text-ink" title="Unmute" onClick={() => setDraft({ ...draft, muted_interfaces: draft.muted_interfaces.filter((x) => x !== i) })}><X size={10} /></button>
                </Badge>
              ))}
            </div>
          </div>
        </div>

        {err && <div className="text-xs text-crit">{err}</div>}
        {dirty && (
          <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} className="flex justify-end gap-2">
            <button className="btn" onClick={() => setDraft(tuning)}>Discard</button>
            <button className="btn btn-primary" onClick={() => commit(draft)} disabled={busy}>{busy ? <Spinner size={14} /> : <Save size={14} />} Save</button>
          </motion.div>
        )}
      </div>
    </Panel>
  );
}
