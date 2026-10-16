import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router";
import { Shell } from "./components/Shell";
import { Spinner } from "./components/ui";
import { api, setUnauthorizedHandler } from "./lib/api";
import { connectLive, useLive } from "./lib/store";
import type { Meta } from "./lib/types";
import AlertsPage from "./pages/Alerts";
import ClientsPage from "./pages/Clients";
import DeviceDetailPage from "./pages/DeviceDetail";
import DevicesPage from "./pages/Devices";
import DhcpPage from "./pages/Dhcp";
import IntegrationsPage from "./pages/Integrations";
import LoginPage from "./pages/Login";
import LogsPage from "./pages/Logs";
import OverviewPage from "./pages/Overview";
import SecurityPage from "./pages/Security";
import SpeedtestPage from "./pages/Speedtest";
import TopologyPage from "./pages/Topology";
import WifiPage from "./pages/Wifi";

type Me = { user: string | null; auth_disabled: boolean; configured: boolean };

function Authed({ me }: { me: Me }) {
  const [meta, setMeta] = useState<Meta | null>(null);
  useEffect(() => {
    const stop = connectLive();
    useLive.getState().loadAlerts().catch(() => {});
    api<Meta>("/meta").then(setMeta).catch(() => {});
    return stop;
  }, []);
  return (
    <Shell user={me.user} demo={!!meta?.demo_mode}>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DeviceDetailPage />} />
        <Route path="/clients" element={<ClientsPage />} />
        <Route path="/wifi" element={<WifiPage />} />
        <Route path="/speedtest" element={<SpeedtestPage />} />
        <Route path="/security" element={<SecurityPage />} />
        <Route path="/dhcp" element={<DhcpPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/integrations" element={<IntegrationsPage meta={meta} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const nav = useNavigate();

  const refresh = () => api<Me>("/auth/me").then(setMe).catch(() => setMe({ user: null, auth_disabled: false, configured: true }));
  useEffect(() => {
    refresh();
    setUnauthorizedHandler(() => {
      setMe((m) => (m ? { ...m, user: null } : m));
      nav("/login");
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!me) {
    return (
      <div className="grid h-full place-items-center">
        <Spinner size={28} />
      </div>
    );
  }
  return (
    <Routes>
      <Route
        path="/login"
        element={me.user ? <Navigate to="/" replace /> : <LoginPage configured={me.configured} onLogin={refresh} />}
      />
      <Route path="/*" element={me.user ? <Authed me={me} /> : <Navigate to="/login" replace />} />
    </Routes>
  );
}
