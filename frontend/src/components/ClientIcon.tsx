import {
  Camera,
  Cpu,
  Gamepad2,
  HelpCircle,
  Laptop,
  Lightbulb,
  type LucideIcon,
  Printer,
  Router,
  Server,
  Smartphone,
  Speaker,
  Tablet,
  Tv,
  Watch,
} from "lucide-react";

export const CATEGORY: Record<string, { icon: LucideIcon; label: string }> = {
  phone: { icon: Smartphone, label: "Phone" },
  tablet: { icon: Tablet, label: "Tablet" },
  computer: { icon: Laptop, label: "Computer" },
  tv: { icon: Tv, label: "TV / streamer" },
  speaker: { icon: Speaker, label: "Speaker" },
  console: { icon: Gamepad2, label: "Console" },
  camera: { icon: Camera, label: "Camera" },
  printer: { icon: Printer, label: "Printer" },
  iot: { icon: Lightbulb, label: "Smart home" },
  watch: { icon: Watch, label: "Wearable" },
  server: { icon: Server, label: "Server" },
  network: { icon: Router, label: "Network gear" },
  unknown: { icon: HelpCircle, label: "Other" },
};

export function ClientIcon({ category, size = 16, className }: { category: string; size?: number; className?: string }) {
  const Icon = CATEGORY[category]?.icon ?? Cpu;
  return <Icon size={size} className={className} />;
}

/** Four signal bars, coloured by quality (dBm). */
export function SignalBars({ signal, size = 14 }: { signal: number | null | undefined; size?: number }) {
  if (signal == null) return <span className="text-faint">—</span>;
  const level = signal >= -60 ? 4 : signal >= -67 ? 3 : signal >= -75 ? 2 : 1;
  const color = level >= 4 ? "#34d399" : level === 3 ? "#22d3ee" : level === 2 ? "#fbbf24" : "#fb4d6d";
  return (
    <span className="inline-flex items-end gap-[2px]" style={{ height: size }} title={`${signal} dBm`}>
      {[1, 2, 3, 4].map((b) => (
        <span key={b} className="w-[3px] rounded-sm" style={{
          height: `${b * 25}%`, background: b <= level ? color : "#1e2d4d", boxShadow: b <= level ? `0 0 5px ${color}88` : undefined,
        }} />
      ))}
    </span>
  );
}

export const BAND_COLOR: Record<string, string> = { "2.4": "#fbbf24", "5": "#22d3ee", "6": "#a78bfa" };

export function BandBadge({ band }: { band?: string | null }) {
  if (!band) return null;
  const c = BAND_COLOR[band] ?? "#7f8fb0";
  return (
    <span className="inline-flex items-center rounded border px-1 font-mono text-[10px]" style={{ color: c, borderColor: `${c}55`, background: `${c}14` }}>
      {band} GHz
    </span>
  );
}
