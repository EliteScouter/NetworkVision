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
  /** Opened during a maintenance window: recorded, not notified. */
  suppressed?: boolean;
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
    gateways: (Gateway & { device: string; device_id?: number })[];
    history: [number, number | null, number | null][];
    primary: { device_id: number; device: string; ifname: string } | null;
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
  maintenance?: MaintenanceWindow[];
}

// ----------------------------------------------------------------- settings
export interface SettingField {
  value: string | number;
  /** The env var (or built-in) value that applies when the UI value is reset. */
  default: string | number;
  source: "default" | "env" | "ui";
  secret: boolean;
}

export interface SettingsData {
  fields: Record<string, SettingField>;
  disabled_rules: string[];
  rules: Record<string, string>;
  channels: string[];
  secrets_corrupt: boolean;
}

export interface AlertTuning {
  device_id: number;
  muted: boolean;
  disabled_rules: string[];
  muted_interfaces: string[];
  thresholds: Record<string, number>;
}

export interface MaintenanceWindow {
  id: number;
  name: string;
  device_id: number | null;
  kind: "once" | "daily" | "weekly";
  starts_at: number | null;
  ends_at: number | null;
  start_time: string;
  duration_min: number;
  weekdays: number[];
  tz: string;
  enabled: boolean;
  created_by: string;
  created_at: number;
  active: boolean;
  active_until: number | null;
  next_start: number | null;
}

// ------------------------------------------------------------------ history
export type HistoryKind = "device" | "interface" | "gateway" | "radio" | "speedtest";

export interface HistoryTarget {
  kind: HistoryKind;
  title: string;
  /** Filters for the series (device_id, ifname, name, radio). */
  filters?: Record<string, string | number>;
  /** Which columns to plot and how. */
  series: { key: string; label: string; color: string }[];
  unit: "bps" | "pct" | "ms" | "count" | "raw";
}

export interface HistoryResponse {
  kind: HistoryKind;
  since: number;
  until: number;
  resolution: "raw" | "hourly";
  columns: string[];
  points: (number | null)[][];
  peaks: (number | null)[][];
  stats: Record<string, { min: number | null; avg: number | null; max: number | null; p95: number | null; last: number | null; total_bytes?: number | null }>;
  samples: number;
}

// ------------------------------------------------------------------ clients
export interface Client {
  mac: string;
  display_name: string;
  name?: string;
  hostname?: string;
  ip?: string;
  ipv6?: string[];
  vendor?: string;
  network?: string;
  vlan?: number | null;
  category: string;
  online: boolean;
  wired?: boolean;
  is_guest?: boolean;
  fixed_ip?: boolean;
  uplink_mac?: string;
  uplink_name?: string;
  uplink_device_id?: number;
  sw_port?: number | null;
  wired_rate_mbps?: number | null;
  ssid?: string;
  bssid?: string;
  band?: string | null;
  radio_proto?: string | null;
  standard?: string | null;
  channel?: number | null;
  channel_width?: number | null;
  signal?: number | null;
  rssi?: number | null;
  noise?: number | null;
  snr?: number | null;
  tx_rate_mbps?: number | null;
  rx_rate_mbps?: number | null;
  nss?: number | null;
  retries_pct?: number | null;
  satisfaction?: number | null;
  satisfaction_reason?: unknown;
  anomalies?: unknown;
  powersave?: boolean | null;
  fast_roaming?: boolean | null;
  mlo?: boolean | null;
  down_bps?: number;
  up_bps?: number;
  down_bytes?: number | null;
  up_bytes?: number | null;
  uptime_s?: number | null;
  assoc_time?: number | null;
  first_seen?: number | null;
  last_seen?: number | null;
  idle_s?: number | null;
  dhcp_end?: number | null;
  lease?: { state: string; interface: string; expires: unknown };
  sources: string[];
  via: string[];
  history?: [number, number, number][];
}

export interface ClientsResponse {
  clients: Client[];
  counts: {
    total: number; online: number; offline: number; wired: number; wireless: number;
    by_band: Record<string, number>; by_network: Record<string, number>; by_category: Record<string, number>;
  };
}

// --------------------------------------------------------------------- wifi
export interface Radio {
  name: string; band: string; channel: number | null; width: number | null; tx_power: number | null; tx_power_mode?: string;
  min_tx_power?: number | null; max_tx_power?: number | null;
  utilization: number | null; self_rx: number; self_tx: number; interference: number | null;
  clients: number | null; satisfaction: number | null; retries_pct: number | null; dfs: boolean; standard: string | null;
}
export interface Vap {
  ssid: string; bssid: string; band: string | null; channel: number | null; clients: number | null;
  satisfaction: number | null; avg_signal: number | null; tx_bytes: number | null; rx_bytes: number | null; is_guest: boolean;
}
export interface AccessPoint {
  mac: string; name: string; model: string; ip: string; online: boolean; uptime_s: number | null; version: string;
  satisfaction: number | null; clients: number | null; device_id: number | null; controller: string;
  uplink: { name: string; port: number | null; speed: number | null; type: string | null };
  radios: Radio[]; vaps: Vap[];
}
export interface Ssid {
  id: string; name: string; enabled: boolean; security: string; wpa_mode?: string; hidden: boolean; guest: boolean;
  bands: string[]; network: string; fast_roaming: boolean; pmf: string; mlo: boolean; l2_isolation: boolean;
  clients: number; clients_by_band: Record<string, number>; satisfaction: number | null;
}
export interface Neighbor {
  bssid: string; ssid: string; band: string | null; channel: number | null; width: number | null; signal: number | null;
  security: string; seen_by: string; last_seen: number | null; is_rogue: boolean; vendor: string;
}
export interface WifiResponse {
  controllers: { id: number; name: string; updated: number }[];
  aps: AccessPoint[];
  ssids: Ssid[];
  neighbors: Neighbor[];
  clients: Client[];
  summary: {
    aps_total: number; aps_online: number; clients: number; ssids: number; satisfaction: number | null; avg_signal: number | null;
    busiest_radio: Radio | null; neighbors: number; by_band: Record<string, number>; by_standard: Record<string, number>;
    by_signal: Record<string, number>; channel_load: Record<string, Record<string, number>>;
  };
}

// ---------------------------------------------------------------- speedtest
export interface SpeedResult {
  id: number; ts: number; engine: string; trigger: string; server: string; isp: string; public_ip: string;
  download_bps: number | null; upload_bps: number | null; latency_ms: number | null; jitter_ms: number | null;
  loaded_latency_ms: number | null; bytes_used: number | null; duration_s: number | null; error: string;
}
export interface SpeedSettings {
  enabled: boolean; interval_min: number; duration_s: number; streams: number;
  expected_down_mbps: number | null; expected_up_mbps: number | null; alert_pct: number;
}
export interface SpeedStatus {
  settings: SpeedSettings; engine: string; running: boolean; progress: SpeedProgress | Record<string, never>;
  next_run: number | null; last: SpeedResult | null; recent: SpeedResult[];
}
export interface SpeedProgress { state?: string; phase?: string; mbps?: number; progress?: number; result?: SpeedResult }
