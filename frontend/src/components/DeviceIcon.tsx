import {
  Boxes,
  Cloud,
  Cpu,
  Database,
  HardDrive,
  type LucideIcon,
  Network,
  Radio,
  Router,
  Server,
  ShieldCheck,
  Wifi,
} from "lucide-react";

export const ROLE_ICON: Record<string, LucideIcon> = {
  firewall: ShieldCheck,
  router: Router,
  switch: Network,
  ap: Wifi,
  controller: Boxes,
  server: Server,
  nas: Database,
  hypervisor: Cpu,
  iot: Radio,
  internet: Cloud,
  other: HardDrive,
};

export const ROLE_LABEL: Record<string, string> = {
  firewall: "Firewall",
  router: "Router",
  switch: "Switch",
  ap: "Access point",
  controller: "Controller",
  server: "Server",
  nas: "Storage",
  hypervisor: "Hypervisor",
  iot: "IoT",
  internet: "Internet",
  other: "Other",
};

export function DeviceIcon({ role, size = 18, className }: { role: string; size?: number; className?: string }) {
  const Icon = ROLE_ICON[role] ?? HardDrive;
  return <Icon size={size} className={className} />;
}
