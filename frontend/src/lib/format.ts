export function bps(v: number | null | undefined, digits = 1): string {
  if (v == null || !isFinite(v)) return "—";
  const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0;
  let n = Math.abs(v);
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : digits)} ${units[i]}`;
}

export function bpsParts(v: number | null | undefined): [string, string] {
  const [n, u] = bps(v).split(" ");
  return [n, u ?? ""];
}

export function bytes(v: number | null | undefined): string {
  if (v == null || !isFinite(v)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let n = Math.abs(v);
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function speed(mbps: number | null | undefined): string {
  if (!mbps) return "—";
  return mbps >= 1000 ? `${+(mbps / 1000).toFixed(1)}G` : `${mbps}M`;
}

export function pct(v: number | null | undefined, digits = 0): string {
  return v == null ? "—" : `${v.toFixed(digits)}%`;
}

export function ms(v: number | null | undefined): string {
  if (v == null) return "—";
  return v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const s = Math.floor(seconds);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${s}s`;
}

export function ago(ts: number | null | undefined): string {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 5) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  return `${duration(s)} ago`;
}

export function clock(ts: number, withDate = false): string {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString([], { hour12: false });
  return withDate ? `${d.toLocaleDateString([], { month: "short", day: "2-digit" })} ${t}` : t;
}

export const SEV_NAMES = ["EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"];

export function sevColor(sev: number): string {
  if (sev <= 2) return "text-crit";
  if (sev === 3) return "text-[#ff7a90]";
  if (sev === 4) return "text-warn";
  if (sev === 5) return "text-sky";
  if (sev === 6) return "text-dim";
  return "text-faint";
}

export function utilColor(u: number | null | undefined): string {
  if (u == null) return "#22d3ee";
  if (u >= 80) return "#fb4d6d";
  if (u >= 50) return "#fbbf24";
  if (u >= 20) return "#a78bfa";
  return "#22d3ee";
}

export const STATUS_COLOR: Record<string, string> = {
  up: "#34d399",
  degraded: "#fbbf24",
  down: "#fb4d6d",
  unknown: "#64748b",
  disabled: "#334155",
};

export const HEALTH_COLOR: Record<string, string> = {
  ok: "#34d399",
  info: "#60a5fa",
  warning: "#fbbf24",
  critical: "#fb4d6d",
};

/** One color that represents a device: down beats everything, then alert health. */
export function deviceColor(status: string, health: string): string {
  if (status === "down") return STATUS_COLOR.down;
  if (status === "unknown" || status === "disabled") return STATUS_COLOR[status];
  if (health === "critical") return HEALTH_COLOR.critical;
  if (health === "warning" || status === "degraded") return HEALTH_COLOR.warning;
  return STATUS_COLOR.up;
}
