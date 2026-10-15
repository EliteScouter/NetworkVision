import clsx from "clsx";
import { animate, AnimatePresence, motion } from "motion/react";
import { X } from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import { deviceColor } from "../lib/format";

export function Panel({
  title,
  icon,
  actions,
  children,
  className,
  bodyClass,
  brackets = true,
  delay = 0,
}: {
  title?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
  brackets?: boolean;
  delay?: number;
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 14, filter: "blur(4px)" }}
      animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      transition={{ duration: 0.45, delay, ease: [0.2, 0.7, 0.2, 1] }}
      className={clsx("panel flex min-w-0 flex-col", brackets && "panel-brackets", className)}
    >
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-2">
          <div className="flex min-w-0 items-center gap-2">
            {icon && <span className="text-cyan">{icon}</span>}
            <h2 className="hud-label truncate !text-[11px] !text-ink/80">{title}</h2>
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx("min-h-0 flex-1 px-4 pb-4", bodyClass)}>{children}</div>
    </motion.section>
  );
}

/** Animated number that counts toward its new value. */
export function CountUp({ value, format = (n) => Math.round(n).toLocaleString(), className }: {
  value: number;
  format?: (n: number) => string;
  className?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const prev = useRef(0);
  useEffect(() => {
    const from = prev.current;
    prev.current = value;
    const ctrl = animate(from, value, {
      duration: 0.9,
      ease: [0.2, 0.7, 0.2, 1],
      onUpdate: (v) => ref.current && (ref.current.textContent = format(v)),
    });
    return () => ctrl.stop();
  }, [value, format]);
  return <span ref={ref} className={clsx("num", className)}>{format(value)}</span>;
}

export function StatusDot({ status, health = "ok", size = 8, pulse = true }: {
  status: string;
  health?: string;
  size?: number;
  pulse?: boolean;
}) {
  const color = deviceColor(status, health);
  const alive = pulse && (status === "down" || health === "critical" || health === "warning" || status === "degraded");
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      {alive && (
        <span className="absolute inset-0 animate-pulse-ring rounded-full" style={{ background: color }} />
      )}
      <span
        className="relative inline-flex rounded-full"
        style={{ width: size, height: size, background: color, boxShadow: `0 0 ${size}px ${color}` }}
      />
    </span>
  );
}

const BADGE: Record<string, string> = {
  critical: "border-crit/40 bg-crit/10 text-crit",
  warning: "border-warn/40 bg-warn/10 text-warn",
  info: "border-info/40 bg-info/10 text-info",
  ok: "border-ok/40 bg-ok/10 text-ok",
  up: "border-ok/40 bg-ok/10 text-ok",
  down: "border-crit/40 bg-crit/10 text-crit",
  degraded: "border-warn/40 bg-warn/10 text-warn",
  unknown: "border-faint/40 bg-faint/10 text-dim",
  disabled: "border-faint/40 bg-faint/10 text-faint",
  neutral: "border-edge bg-white/[0.02] text-dim",
  violet: "border-violet/40 bg-violet/10 text-violet",
  cyan: "border-cyan/40 bg-cyan/10 text-cyan",
};

export function Badge({ tone = "neutral", children, className }: { tone?: string; children: ReactNode; className?: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10.5px] uppercase tracking-wider",
        BADGE[tone] ?? BADGE.neutral,
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Meter({ value, max = 100, color, className }: { value: number | null | undefined; max?: number; color?: string; className?: string }) {
  const v = value == null ? 0 : Math.max(0, Math.min(1, value / max));
  const c = color ?? (v > 0.9 ? "#fb4d6d" : v > 0.75 ? "#fbbf24" : "#22d3ee");
  return (
    <div className={clsx("h-1.5 overflow-hidden rounded-full bg-white/5", className)}>
      <motion.div
        className="h-full rounded-full"
        initial={false}
        animate={{ width: `${v * 100}%` }}
        transition={{ type: "spring", stiffness: 120, damping: 20 }}
        style={{ background: `linear-gradient(90deg, ${c}88, ${c})`, boxShadow: `0 0 10px ${c}66` }}
      />
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center">
      {icon && <div className="text-faint">{icon}</div>}
      <div className="text-sm font-medium text-ink/80">{title}</div>
      {children && <div className="max-w-md text-xs text-dim">{children}</div>}
    </div>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: ReactNode }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm select-none">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={clsx(
          "relative h-5 w-9 rounded-full border transition-colors",
          checked ? "border-cyan/60 bg-cyan/25" : "border-edge bg-white/5",
        )}
      >
        <motion.span
          layout
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
          className={clsx("absolute top-0.5 h-3.5 w-3.5 rounded-full", checked ? "right-0.5 bg-cyan shadow-[0_0_10px_#22d3ee]" : "left-0.5 bg-dim")}
        />
      </button>
      {label && <span className="text-dim">{label}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="relative inline-flex rounded-lg border border-edge bg-black/30 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={clsx(
            "relative z-10 rounded-md px-2.5 py-1 font-mono text-[11px] tracking-wide transition-colors",
            value === o.value ? "text-ink" : "text-dim hover:text-ink",
          )}
        >
          {value === o.value && (
            <motion.span
              layoutId={`seg-${options.map((x) => x.value).join("")}`}
              className="absolute inset-0 -z-10 rounded-md border border-cyan/40 bg-cyan/15"
              transition={{ type: "spring", stiffness: 400, damping: 32 }}
            />
          )}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Drawer({ open, onClose, title, children, width = 720 }: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    const fn = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", fn);
    return () => window.removeEventListener("keydown", fn);
  }, [open, onClose]);
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />
          <motion.aside
            role="dialog"
            aria-modal="true"
            className="panel fixed top-0 right-0 bottom-0 z-50 flex max-w-full flex-col !rounded-none !rounded-l-2xl"
            style={{ width }}
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 260, damping: 30 }}
          >
            <header className="flex items-center justify-between border-b border-edge px-5 py-4">
              <div className="min-w-0 text-base font-semibold">{title}</div>
              <button className="btn btn-ghost !p-1.5" onClick={onClose} aria-label="Close">
                <X size={18} />
              </button>
            </header>
            <div className="min-h-0 flex-1 overflow-y-auto p-5">{children}</div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

export function Field({ label, help, children }: { label: ReactNode; help?: ReactNode; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="hud-label block">{label}</span>
      {children}
      {help && <span className="block text-[11.5px] leading-snug text-faint">{help}</span>}
    </label>
  );
}

export function Kv({ k, v }: { k: ReactNode; v: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-edge/50 py-1.5 text-sm last:border-0">
      <span className="text-dim">{k}</span>
      <span className="truncate text-right font-mono text-[12.5px] text-ink/90">{v ?? "—"}</span>
    </div>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <span
      className="inline-block animate-spin rounded-full border-2 border-cyan/20 border-t-cyan"
      style={{ width: size, height: size }}
    />
  );
}
