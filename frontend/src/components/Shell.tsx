import clsx from "clsx";
import {
  Bell,
  Gauge,
  Gauge as GaugeIcon,
  LogOut,
  type LucideIcon,
  Network,
  Plug,
  ScrollText,
  Search,
  Server,
  Users,
  Wifi,
  X,
} from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router";
import { api } from "../lib/api";
import { useTick } from "../lib/hooks";
import { useLive } from "../lib/store";
import type { DeviceSummary } from "../lib/types";
import { DeviceIcon } from "./DeviceIcon";
import { HistoryExplorerHost } from "./HistoryExplorer";
import { StatusDot } from "./ui";

const NAV: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/", label: "Command Center", icon: GaugeIcon },
  { to: "/topology", label: "Topology", icon: Network },
  { to: "/devices", label: "Devices", icon: Server },
  { to: "/clients", label: "Clients", icon: Users },
  { to: "/wifi", label: "WiFi", icon: Wifi },
  { to: "/speedtest", label: "Speedtest", icon: Gauge },
  { to: "/logs", label: "Logs", icon: ScrollText },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/integrations", label: "Integrations", icon: Plug },
];

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" className="shrink-0">
      <defs>
        <linearGradient id="nv-logo" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#a78bfa" />
        </linearGradient>
      </defs>
      <path d="M6 32c6-11 15-17 26-17s20 6 26 17c-6 11-15 17-26 17S12 43 6 32z" fill="none" stroke="url(#nv-logo)" strokeWidth="3.5" />
      <circle cx="32" cy="32" r="9" fill="none" stroke="url(#nv-logo)" strokeWidth="3.5" />
      <circle cx="32" cy="32" r="3.5" fill="#22d3ee">
        <animate attributeName="opacity" values="1;0.35;1" dur="2.4s" repeatCount="indefinite" />
      </circle>
    </svg>
  );
}

function Background() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(1200px_600px_at_15%_-10%,rgba(34,211,238,0.10),transparent_60%),radial-gradient(900px_600px_at_100%_0%,rgba(167,139,250,0.10),transparent_60%),radial-gradient(800px_500px_at_50%_120%,rgba(244,114,182,0.06),transparent_60%)]" />
      <div className="bg-grid absolute inset-0" />
      <div className="absolute inset-x-0 top-0 h-40 animate-scan bg-gradient-to-b from-transparent via-cyan/[0.035] to-transparent" />
    </div>
  );
}

function Toasts() {
  const toasts = useLive((s) => s.toasts);
  const dismiss = useLive((s) => s.dismissToast);
  const nav = useNavigate();
  const tone: Record<string, string> = { critical: "#fb4d6d", warning: "#fbbf24", info: "#60a5fa", ok: "#34d399" };
  return (
    <div className="fixed top-4 right-4 z-[60] flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      <AnimatePresence initial={false}>
        {toasts.map((t) => (
          <motion.div
            key={t.id}
            layout
            initial={{ opacity: 0, x: 60, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 60, transition: { duration: 0.2 } }}
            className="panel cursor-pointer overflow-hidden !rounded-xl p-3 pl-4"
            style={{ boxShadow: `0 0 30px -10px ${tone[t.severity]}` }}
            onClick={() => {
              if (t.deviceId) nav(`/devices/${t.deviceId}`);
              dismiss(t.id);
            }}
          >
            <span className="absolute inset-y-0 left-0 w-1" style={{ background: tone[t.severity] }} />
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="font-mono text-[10px] tracking-widest uppercase" style={{ color: tone[t.severity] }}>
                  {t.severity === "ok" ? "resolved" : t.severity}
                </div>
                <div className="truncate text-sm font-medium">{t.title}</div>
                {t.detail && <div className="truncate text-xs text-dim">{t.detail}</div>}
              </div>
              <button className="text-faint hover:text-ink" onClick={(e) => { e.stopPropagation(); dismiss(t.id); }}>
                <X size={14} />
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const devices = useLive((s) => s.devices);
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const nav = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (open) {
      setQ("");
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  type Item = { key: string; label: string; hint: string; run: () => void; icon: ReactNode; status?: DeviceSummary };
  const items = useMemo((): Item[] => {
    const t = q.toLowerCase().trim();
    const pages: Item[] = NAV.map((n) => ({ key: n.to, label: n.label, hint: "page", run: () => nav(n.to), icon: <n.icon size={16} /> }));
    const devs: Item[] = Object.values(devices).map((d) => ({
      key: `d${d.id}`, label: d.name, hint: `${d.host} · ${d.model || d.role}`, run: () => nav(`/devices/${d.id}`),
      icon: <DeviceIcon role={d.role} size={16} />, status: d,
    }));
    const extra: Item[] = t ? [{ key: "logsearch", label: `Search logs for “${q}”`, hint: "logs", run: () => nav(`/logs?q=${encodeURIComponent(q)}`), icon: <ScrollText size={16} /> }] : [];
    const all = [...pages, ...devs];
    return (t ? all.filter((i) => `${i.label} ${i.hint}`.toLowerCase().includes(t)) : all).slice(0, 12).concat(extra);
  }, [q, devices, nav]);

  const run = (i: number) => {
    items[i]?.run();
    onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-[70] flex items-start justify-center bg-black/60 pt-[12vh] backdrop-blur-sm"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
          <motion.div className="panel panel-brackets w-[620px] max-w-[calc(100vw-2rem)] overflow-hidden"
            initial={{ y: -20, scale: 0.97 }} animate={{ y: 0, scale: 1 }} exit={{ y: -10, scale: 0.98 }}
            onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center gap-3 border-b border-edge px-4 py-3">
              <Search size={18} className="text-cyan" />
              <input ref={inputRef} value={q} onChange={(e) => { setQ(e.target.value); setIdx(0); }}
                onKeyDown={(e) => {
                  if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); }
                  if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
                  if (e.key === "Enter") run(idx);
                  if (e.key === "Escape") onClose();
                }}
                placeholder="Jump to a device, page, or search logs…"
                className="flex-1 bg-transparent text-[15px] outline-none placeholder:text-faint" />
              <kbd className="rounded border border-edge px-1.5 font-mono text-[10px] text-faint">ESC</kbd>
            </div>
            <ul className="max-h-[50vh] overflow-y-auto p-2">
              {items.map((it, i) => (
                <li key={it.key}>
                  <button onMouseEnter={() => setIdx(i)} onClick={() => run(i)}
                    className={clsx("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm",
                      i === idx ? "bg-cyan/10 text-ink" : "text-dim")}>
                    <span className={i === idx ? "text-cyan" : ""}>{it.icon}</span>
                    <span className="flex-1 truncate">{it.label}</span>
                    {it.status && <StatusDot status={it.status.status} health={it.status.health} pulse={false} />}
                    <span className="truncate font-mono text-[11px] text-faint">{it.hint}</span>
                  </button>
                </li>
              ))}
              {!items.length && <li className="px-3 py-6 text-center text-sm text-faint">Nothing matches.</li>}
            </ul>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function UtcClock() {
  useTick(1000);
  const d = new Date();
  return (
    <div className="hidden text-right leading-tight lg:block">
      <div className="num text-sm text-ink">{d.toLocaleTimeString([], { hour12: false })}</div>
      <div className="font-mono text-[10px] tracking-wider text-faint">
        UTC {d.toISOString().slice(11, 19)}
      </div>
    </div>
  );
}

export function Shell({ children, user, demo }: { children: ReactNode; user: string | null; demo: boolean }) {
  const loc = useLocation();
  const connected = useLive((s) => s.connected);
  const alerts = useLive((s) => s.alerts);
  const devices = useLive((s) => s.devices);
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    const fn = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
      if (e.key === "/" && !(e.target as HTMLElement).closest("input,textarea,select")) {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", fn);
    return () => window.removeEventListener("keydown", fn);
  }, []);

  const critical = Object.values(alerts).filter((a) => a.severity === "critical").length;
  const warning = Object.values(alerts).filter((a) => a.severity === "warning").length;
  const down = Object.values(devices).filter((d) => d.status === "down" && d.enabled).length;
  const title = NAV.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)))?.label ?? "NetworkVision";

  const logout = async () => {
    await api("/auth/logout", { method: "POST" }).catch(() => {});
    location.href = "/login";
  };

  return (
    <div className="flex h-full">
      <Background />
      <aside className="group/side relative z-20 flex w-[68px] shrink-0 flex-col border-r border-edge/70 bg-abyss/70 backdrop-blur-xl transition-[width] duration-300 hover:w-[230px] max-md:hidden">
        <div className="flex h-16 items-center gap-3 overflow-hidden px-[18px]">
          <Logo />
          <span className="grad-text text-lg font-bold tracking-tight whitespace-nowrap opacity-0 transition-opacity duration-300 group-hover/side:opacity-100">
            NetworkVision
          </span>
        </div>
        <nav className="mt-2 flex flex-1 flex-col gap-1 px-3">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"}
              className={({ isActive }) => clsx(
                "relative flex h-11 items-center gap-3 overflow-hidden rounded-xl px-[11px] text-sm transition-colors",
                isActive ? "text-ink" : "text-dim hover:bg-white/[0.03] hover:text-ink")}>
              {({ isActive }) => (
                <>
                  {isActive && (
                    <motion.span layoutId="nav-active" className="absolute inset-0 rounded-xl border border-cyan/35 bg-gradient-to-r from-cyan/15 to-violet/10"
                      transition={{ type: "spring", stiffness: 380, damping: 32 }} />
                  )}
                  <n.icon size={20} className={clsx("relative shrink-0", isActive && "text-cyan drop-shadow-[0_0_6px_#22d3ee]")} />
                  <span className="relative whitespace-nowrap opacity-0 transition-opacity duration-300 group-hover/side:opacity-100">{n.label}</span>
                  {n.to === "/alerts" && critical + warning > 0 && (
                    <span className={clsx("absolute top-1.5 left-7 grid h-4 min-w-4 place-items-center rounded-full px-1 font-mono text-[9.5px] font-bold text-void",
                      critical ? "bg-crit shadow-[0_0_10px_#fb4d6d]" : "bg-warn")}>
                      {critical + warning}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <button onClick={logout} title="Sign out"
          className="m-3 flex h-10 items-center gap-3 overflow-hidden rounded-xl px-[11px] text-sm text-dim hover:text-ink">
          <LogOut size={18} className="shrink-0" />
          <span className="truncate whitespace-nowrap opacity-0 transition-opacity group-hover/side:opacity-100">{user ?? "Sign out"}</span>
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-4 border-b border-edge/70 bg-void/60 px-4 backdrop-blur-xl md:px-6">
          <div className="md:hidden"><Logo size={26} /></div>
          <div className="min-w-0">
            <div className="hud-label hidden sm:block">NetworkVision // NOC</div>
            <h1 className="truncate text-lg font-semibold tracking-tight">{title}</h1>
          </div>
          {demo && <span className="hidden rounded-md border border-magenta/40 bg-magenta/10 px-2 py-0.5 font-mono text-[10px] tracking-widest text-magenta sm:inline">DEMO DATA</span>}
          <button onClick={() => setPalette(true)}
            className="ml-auto flex h-9 w-full max-w-sm items-center gap-2 rounded-xl border border-edge bg-black/30 px-3 text-sm text-faint transition hover:border-cyan/40 max-sm:max-w-[40px] max-sm:px-2.5">
            <Search size={15} className="shrink-0" />
            <span className="flex-1 truncate text-left max-sm:hidden">Search devices, logs…</span>
            <kbd className="rounded border border-edge px-1.5 font-mono text-[10px] max-sm:hidden">Ctrl K</kbd>
          </button>
          <div className="flex items-center gap-4">
            {(down > 0 || critical > 0) && (
              <NavLink to="/alerts" className="hidden items-center gap-2 rounded-lg border border-crit/40 bg-crit/10 px-2.5 py-1 font-mono text-[11px] text-crit md:flex">
                <span className="h-1.5 w-1.5 animate-blink rounded-full bg-crit" />
                {down > 0 ? `${down} DOWN` : `${critical} CRITICAL`}
              </NavLink>
            )}
            <div className="flex items-center gap-2" title={connected ? "Live stream connected" : "Reconnecting…"}>
              <StatusDot status={connected ? "up" : "down"} size={7} pulse={!connected} />
              <span className={clsx("font-mono text-[10.5px] tracking-widest", connected ? "text-ok" : "text-crit")}>
                {connected ? "LIVE" : "OFFLINE"}
              </span>
            </div>
            <UtcClock />
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto pb-20 md:pb-0">
          <AnimatePresence mode="wait">
            <motion.div key={loc.pathname.split("/")[1]} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }} className="h-full">
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
        {/* mobile bottom nav */}
        <nav className="fixed inset-x-0 bottom-0 z-20 flex justify-around border-t border-edge bg-abyss/90 py-2 backdrop-blur-xl md:hidden">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className={({ isActive }) => clsx("p-2", isActive ? "text-cyan" : "text-dim")}>
              <n.icon size={20} />
            </NavLink>
          ))}
        </nav>
      </div>
      <Toasts />
      <HistoryExplorerHost />
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
    </div>
  );
}
