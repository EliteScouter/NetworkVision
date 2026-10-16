import { create } from "zustand";
import { api } from "./api";
import type { Alert, DeviceSummary, LogItem, SecEvent, SpeedProgress } from "./types";

export interface Toast {
  id: number;
  severity: "info" | "warning" | "critical" | "ok";
  title: string;
  detail?: string;
  deviceId?: number | null;
}

interface LiveState {
  connected: boolean;
  lastMessage: number;
  devices: Record<number, DeviceSummary>;
  alerts: Record<number, Alert>;
  alertsLoaded: boolean;
  logs: LogItem[];
  logsPaused: boolean;
  security: SecEvent[];
  toasts: Toast[];
  speed: SpeedProgress | null;
  setSpeed: (p: SpeedProgress | null) => void;
  setConnected: (c: boolean) => void;
  setDevices: (list: DeviceSummary[]) => void;
  loadAlerts: () => Promise<void>;
  applyAlert: (event: string, a: Alert) => void;
  addLogs: (items: LogItem[]) => void;
  setLogsPaused: (p: boolean) => void;
  addSecurity: (items: SecEvent[]) => void;
  pushToast: (t: Omit<Toast, "id">) => void;
  dismissToast: (id: number) => void;
}

const MAX_LOGS = 600;
let toastSeq = 1;

export const useLive = create<LiveState>((set, get) => ({
  connected: false,
  lastMessage: 0,
  devices: {},
  alerts: {},
  alertsLoaded: false,
  logs: [],
  logsPaused: false,
  security: [],
  toasts: [],
  speed: null,
  setSpeed: (speed) => set({ speed }),
  setConnected: (connected) => set({ connected }),
  setDevices: (list) => set({ devices: Object.fromEntries(list.map((d) => [d.id, d])), lastMessage: Date.now() }),
  loadAlerts: async () => {
    const r = await api<{ items: Alert[] }>("/alerts", { query: { state: "active" } });
    set({ alerts: Object.fromEntries(r.items.map((a) => [a.id, a])), alertsLoaded: true });
  },
  applyAlert: (event, a) => {
    const alerts = { ...get().alerts };
    if (event === "resolved") delete alerts[a.id];
    else alerts[a.id] = a;
    set({ alerts });
    if (event === "opened" && a.severity !== "info") {
      get().pushToast({ severity: a.severity, title: a.title, detail: a.detail, deviceId: a.device_id });
    } else if (event === "resolved" && a.severity === "critical") {
      get().pushToast({ severity: "ok", title: `Resolved: ${a.title}`, deviceId: a.device_id });
    }
  },
  addLogs: (items) => {
    if (get().logsPaused || !items.length) return;
    const next = [...items].reverse().concat(get().logs);
    set({ logs: next.length > MAX_LOGS ? next.slice(0, MAX_LOGS) : next });
  },
  setLogsPaused: (logsPaused) => set({ logsPaused }),
  addSecurity: (items) => {
    if (!items.length) return;
    const next = [...items].reverse().concat(get().security);
    set({ security: next.length > 400 ? next.slice(0, 400) : next });
  },
  pushToast: (t) => {
    const id = toastSeq++;
    set({ toasts: [...get().toasts.slice(-4), { ...t, id }] });
    setTimeout(() => get().dismissToast(id), t.severity === "critical" ? 12000 : 7000);
  },
  dismissToast: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
}));

// ----------------------------------------------------------------- websocket
let socket: WebSocket | null = null;
let retry = 0;
let pingTimer: number | undefined;
let stopped = false;

export function connectLive(): () => void {
  stopped = false;
  const open = () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${proto}://${location.host}/api/ws`);
    socket.onopen = () => {
      retry = 0;
      useLive.getState().setConnected(true);
      pingTimer = window.setInterval(() => socket?.readyState === 1 && socket.send("ping"), 25000);
    };
    socket.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      const s = useLive.getState();
      if (msg.type === "state") s.setDevices(msg.devices);
      else if (msg.type === "alert") s.applyAlert(msg.event, msg.alert);
      else if (msg.type === "logs") s.addLogs(msg.items);
      else if (msg.type === "speedtest") s.setSpeed(msg);
      else if (msg.type === "security") s.addSecurity(msg.items);
    };
    socket.onclose = () => {
      window.clearInterval(pingTimer);
      useLive.getState().setConnected(false);
      if (stopped) return;
      retry = Math.min(retry + 1, 6);
      window.setTimeout(open, 500 * 2 ** retry);
    };
  };
  open();
  return () => {
    stopped = true;
    window.clearInterval(pingTimer);
    socket?.close();
  };
}
