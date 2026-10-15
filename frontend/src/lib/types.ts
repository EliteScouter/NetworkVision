export type Status = "up" | "down" | "degraded" | "unknown" | "disabled";
export type Health = "ok" | "info" | "warning" | "critical";
export type Severity = "info" | "warning" | "critical";

export interface DeviceSummary {
  id: number;
  name: string;
  kind: string;
  role: string;
  host: string;
  parent_id: number | null;
  enabled: boolean;
  status: Status;
  health: Health;
  error: string | null;
  last_poll: number | null;
  last_ok: number | null;
  poll_ms: number | null;
  metrics: Record<string, number>;
  rx_bps: number;
  tx_bps: number;
  vendor: string;
  model: string;
  version: string;
  tags: string[];
  location: string;
  ports_up: number;
  ports_total: number;
  alert_counts: Partial<Record<Severity, number>>;
  spark: [number, number | null, number | null][];
}

export interface Iface {
  name: string;
  alias: string;
  index: number | null;
  oper_up: boolean | null;
  admin_up: boolean | null;
  speed_mbps: number | null;
  media: string;
  mac: string;
  vlan: string;
  is_uplink: boolean;
  poe_w: number | null;
  rx_bps: number | null;
  tx_bps: number | null;
  util_pct: number | null;
  errors_per_min: number;
  rx_pps: number | null;
  tx_pps: number | null;
  flaps_10m: number;
  extra: Record<string, unknown>;
  history: [number, number | null, number | null][];
}

export interface Gateway {
  name: string;
  address: string;
  up: boolean | null;
  latency_ms: number | null;
  loss_pct: number | null;
  detail: string;
}

export interface Neighbor {
  local_port: string;
  remote_name: string;
  remote_port: string;
  remote_mac: string;
  remote_ip: string;
  protocol: string;
}

export interface Section {
  id: string;
  title: string;
  columns: string[];
  rows: unknown[][];
  kind: "table" | "kv";
}

export interface DeviceDetail extends DeviceSummary {
  facts: Record<string, unknown>;
  interfaces: Iface[];
  neighbors: Neighbor[];
  gateways: Gateway[];
  sections: Section[];
  history: [number, number | null, number | null, number | null, number | null, number | null][];
  config: Record<string, unknown>;
  secrets: Record<string, string>;
  poll_interval: number | null;
  external_id: string | null;
  notes: string;
  children: DeviceSummary[];
}

export interface Alert {
  id: number;
  key: string;
  device_id: number | null;
  device_name: string | null;
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  started_at: number;
  last_seen_at: number;
  resolved_at: number | null;
  acknowledged_at: number | null;
  acknowledged_by: string;
  count: number;
}

export interface LogItem {
  id?: number;
  ts: number;
  device_id: number | null;
  device?: string | null;
  host: string;
  severity: number;
  facility: string;
  app: string;
  message: string;
  source: string;
}

export interface FieldSpec {
  key: string;
  label: string;
  type: "text" | "number" | "password" | "bool" | "select";
  secret: boolean;
  required: boolean;
  default: unknown;
  options: string[] | null;
  placeholder: string;
  help: string;
}

export interface Integration {
  kind: string;
  label: string;
  vendor: string;
  description: string;
  default_role: string;
  discovers_children: boolean;
  fields: FieldSpec[];
}

export interface TopoNode extends Omit<Partial<DeviceSummary>, "id"> {
  id: string;
  device_id: number | null;
  name: string;
  role: string;
  status: Status;
  health: Health;
  x: number | null;
  y: number | null;
  clients?: number | null;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  source_port: string;
  target_port: string;
  kind: "lldp" | "uplink" | "manual" | "description" | "wan";
  label: string;
  link_id: number | null;
  speed_mbps?: number | null;
  rx_bps?: number | null;
  tx_bps?: number | null;
  util_pct?: number | null;
  errors_per_min?: number;
  status: "up" | "down";
}

export interface Topology {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

export interface Overview {
  ts: number;
  devices: { total: number; up: number; degraded: number; down: number; unknown: number };
  alerts: { total: number; critical: number; warning: number; info: number };
  wan: {
    rx_bps: number;
    tx_bps: number;
    gateways: (Gateway & { device: string })[];
    history: [number, number | null, number | null][];
  };
  clients: number;
  throughput_bps: number;
  ports: { up: number; total: number; errors: number };
  logs_per_min: number;
  top_talkers: {
    device_id: number;
    device: string;
    ifname: string;
    alias: string;
    rx_bps: number;
    tx_bps: number;
    util_pct: number | null;
    speed_mbps: number | null;
  }[];
  recent_alerts: Alert[];
}

export interface Meta {
  version: string;
  demo_mode: boolean;
  poll_interval: number;
  syslog: { enabled: boolean; port: number; tcp: boolean };
  database: string;
  notifications: boolean;
  ws_clients: number;
  logs: { received: number; dropped: number };
  collectors: string[];
  retention: { metrics_days: number; logs_days: number };
  thresholds: Record<string, number>;
}
