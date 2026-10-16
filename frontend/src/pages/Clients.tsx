import clsx from "clsx";
import { ArrowDownUp, Cable, ExternalLink, Search, Users, Wifi, X } from "lucide-react";
import { motion } from "motion/react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { Sparkline } from "../components/charts";
import { BAND_COLOR, BandBadge, CATEGORY, ClientIcon, SignalBars } from "../components/ClientIcon";
import { Badge, Drawer, Empty, Kv, Meter, Panel, Spinner } from "../components/ui";
import { ago, bps, bytes, clock, duration } from "../lib/format";
import { useApi, useLocalState } from "../lib/hooks";
import type { Client, ClientsResponse } from "../lib/types";

type SortKey = "name" | "ip" | "signal" | "traffic" | "usage" | "satisfaction" | "seen";

function ipKey(ip?: string) {
  return (ip ?? "").split(".").map((n) => n.padStart(3, "0")).join(".");
}

function Stat({ label, value, sub, color }: { label: string; value: React.ReactNode; sub?: React.ReactNode; color?: string }) {
  return (
    <div className="panel p-3.5">
      <div className="hud-label">{label}</div>
      <div className="num mt-1 text-2xl font-semibold" style={{ color }}>{value}</div>
      {sub && <div className="mt-1 text-[11px] text-dim">{sub}</div>}
    </div>
  );
}

function ClientDrawer({ mac, onClose }: { mac: string | null; onClose: () => void }) {
  const { data: c } = useApi<Client>(mac ? `/clients/${encodeURIComponent(mac)}` : null, 5000);
  const hist = c?.history ?? [];
  return (
    <Drawer open={!!mac} onClose={onClose} width={640}
      title={c ? <span className="flex items-center gap-2"><ClientIcon category={c.category} size={18} className="text-cyan" />{c.display_name}</span> : "Client"}>
      {!c ? <div className="grid h-40 place-items-center"><Spinner /></div> : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={c.online ? "up" : "unknown"}>{c.online ? "online" : "offline"}</Badge>
            <Badge tone="cyan">{c.wired ? "wired" : "wireless"}</Badge>
            {c.band && <BandBadge band={c.band} />}
            {c.standard && <Badge tone="violet">{c.standard}</Badge>}
            {c.is_guest && <Badge tone="warning">guest</Badge>}
            {c.fixed_ip && <Badge>fixed IP</Badge>}
            <span className="ml-auto font-mono text-[11px] text-faint">via {c.via.join(", ")}</span>
          </div>

          {c.online && (
            <div className="rounded-xl border border-edge bg-black/20 p-3">
              <div className="mb-1 flex justify-between text-xs">
                <span className="text-cyan">↓ {bps(c.down_bps)}</span><span className="hud-label">live traffic</span><span className="text-magenta">↑ {bps(c.up_bps)}</span>
              </div>
              <Sparkline data={hist.map((p) => p[1] + p[2])} height={46} />
            </div>
          )}

          <section>
            <div className="hud-label mb-1">Identity</div>
            <Kv k="Name" v={c.name || "—"} />
            <Kv k="Hostname" v={c.hostname || "—"} />
            <Kv k="Device type" v={CATEGORY[c.category]?.label ?? c.category} />
            <Kv k="Vendor" v={c.vendor || "—"} />
            <Kv k="MAC" v={c.mac} />
            <Kv k="IP address" v={c.ip || "—"} />
            {!!c.ipv6?.length && <Kv k="IPv6" v={c.ipv6.join(", ")} />}
            <Kv k="Network" v={`${c.network || "—"}${c.vlan != null ? ` (VLAN ${c.vlan})` : ""}`} />
          </section>

          <section>
            <div className="hud-label mb-1">Connection</div>
            {c.wired ? (
              <>
                <Kv k="Switch" v={c.uplink_device_id ? <Link to={`/devices/${c.uplink_device_id}`} className="text-cyan">{c.uplink_name}</Link> : c.uplink_name || "—"} />
                <Kv k="Port" v={c.sw_port ?? "—"} />
                <Kv k="Link speed" v={c.wired_rate_mbps ? `${c.wired_rate_mbps >= 1000 ? c.wired_rate_mbps / 1000 + " Gbps" : c.wired_rate_mbps + " Mbps"}` : "—"} />
              </>
            ) : (
              <>
                <Kv k="Access point" v={c.uplink_device_id ? <Link to={`/devices/${c.uplink_device_id}`} className="text-cyan">{c.uplink_name}</Link> : c.uplink_name || "—"} />
                <Kv k="SSID" v={c.ssid || "—"} />
                <Kv k="Band / channel" v={c.band ? `${c.band} GHz · ch ${c.channel ?? "?"}${c.channel_width ? ` · ${c.channel_width} MHz` : ""}` : "—"} />
                <Kv k="Signal" v={c.signal != null ? <span className="inline-flex items-center gap-2"><SignalBars signal={c.signal} />{c.signal} dBm</span> : "—"} />
                <Kv k="Noise / SNR" v={c.noise != null ? `${c.noise} dBm · SNR ${c.snr ?? "?"} dB` : "—"} />
                <Kv k="Link rate ↓ / ↑" v={c.tx_rate_mbps ? `${c.tx_rate_mbps.toFixed(0)} / ${c.rx_rate_mbps?.toFixed(0) ?? "?"} Mbps` : "—"} />
                <Kv k="Spatial streams" v={c.nss ? `${c.nss}×${c.nss} MIMO` : "—"} />
                <Kv k="Retries" v={c.retries_pct != null ? `${c.retries_pct.toFixed(1)}%` : "—"} />
                <Kv k="Power save / 802.11r / MLO" v={[c.powersave ? "yes" : "no", c.fast_roaming ? "yes" : "no", c.mlo ? "yes" : "no"].join(" / ")} />
              </>
            )}
          </section>

          {c.satisfaction != null && (
            <section>
              <div className="hud-label mb-2">Experience</div>
              <div className="flex items-center gap-3">
                <Meter value={c.satisfaction} className="flex-1" color={c.satisfaction >= 80 ? "#34d399" : c.satisfaction >= 50 ? "#fbbf24" : "#fb4d6d"} />
                <span className="num text-sm">{c.satisfaction.toFixed(0)}%</span>
              </div>
            </section>
          )}

          <section>
            <div className="hud-label mb-1">Activity</div>
            <Kv k="Downloaded / uploaded" v={`${bytes(c.down_bytes)} / ${bytes(c.up_bytes)}`} />
            <Kv k="Connected for" v={c.online ? duration(c.uptime_s) : "—"} />
            <Kv k="First seen" v={c.first_seen ? clock(c.first_seen, true) : "—"} />
            <Kv k="Last seen" v={c.online ? "now" : ago(c.last_seen)} />
            {c.idle_s != null && c.online && <Kv k="Idle" v={duration(c.idle_s)} />}
          </section>

          {c.lease && (
            <section>
              <div className="hud-label mb-1">DHCP lease</div>
              <Kv k="State" v={c.lease.state || "—"} />
              <Kv k="Interface" v={c.lease.interface || "—"} />
              <Kv k="Expires" v={String(c.lease.expires ?? "—")} />
            </section>
          )}

          <div className="flex flex-wrap gap-2 border-t border-edge pt-4">
            {c.ip && <Link to={`/logs?q=${encodeURIComponent(c.ip)}`} className="btn"><ExternalLink size={14} /> Logs for {c.ip}</Link>}
            <Link to={`/logs?q=${encodeURIComponent(c.mac)}`} className="btn"><ExternalLink size={14} /> Logs for MAC</Link>
          </div>
        </div>
      )}
    </Drawer>
  );
}

export default function ClientsPage() {
  const { data, loading } = useApi<ClientsResponse>("/clients", 5000);
  const [q, setQ] = useState("");
  const [status, setStatus] = useLocalState<"online" | "offline" | "all">("clients-status", "online");
  const [conn, setConn] = useLocalState<string[]>("clients-conn", []);
  const [network, setNetwork] = useLocalState("clients-net", "");
  const [ssid, setSsid] = useLocalState("clients-ssid", "");
  const [uplink, setUplink] = useLocalState("clients-uplink", "");
  const [cats, setCats] = useLocalState<string[]>("clients-cats", []);
  const [sort, setSort] = useLocalState<{ key: SortKey; dir: 1 | -1 }>("clients-sort", { key: "traffic", dir: -1 });
  const [open, setOpen] = useState<string | null>(null);

  const all = data?.clients ?? [];
  const options = useMemo(() => ({
    networks: [...new Set(all.map((c) => c.network).filter(Boolean))].sort() as string[],
    ssids: [...new Set(all.map((c) => c.ssid).filter(Boolean))].sort() as string[],
    uplinks: [...new Set(all.map((c) => c.uplink_name).filter(Boolean))].sort() as string[],
    cats: [...new Set(all.map((c) => c.category))].sort(),
  }), [all]);

  const list = useMemo(() => {
    const t = q.toLowerCase().trim();
    const filtered = all.filter((c) =>
      (status === "all" || (status === "online") === c.online) &&
      (!conn.length || conn.some((k) => (k === "wired" ? c.wired : !c.wired && c.band === k))) &&
      (!network || c.network === network) && (!ssid || c.ssid === ssid) && (!uplink || c.uplink_name === uplink) &&
      (!cats.length || cats.includes(c.category)) &&
      (!t || [c.display_name, c.hostname, c.ip, c.mac, c.vendor, c.network, c.ssid, c.uplink_name].join(" ").toLowerCase().includes(t)));
    const val = (c: Client): number | string => {
      switch (sort.key) {
        case "name": return c.display_name.toLowerCase();
        case "ip": return ipKey(c.ip);
        case "signal": return c.signal ?? -999;
        case "traffic": return (c.down_bps ?? 0) + (c.up_bps ?? 0);
        case "usage": return (c.down_bytes ?? 0) + (c.up_bytes ?? 0);
        case "satisfaction": return c.satisfaction ?? -1;
        case "seen": return c.online ? Infinity : c.last_seen ?? 0;
      }
    };
    return filtered.sort((a, b) => {
      const [x, y] = [val(a), val(b)];
      return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
    });
  }, [all, q, status, conn, network, ssid, uplink, cats, sort]);

  const counts = data?.counts;
  const toggle = (arr: string[], set: (v: string[]) => void, v: string) => set(arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);
  const th = (key: SortKey, label: string, cls?: string) => (
    <th className={clsx("cursor-pointer hover:text-ink", cls)} onClick={() => setSort({ key, dir: sort.key === key ? (-sort.dir as 1 | -1) : -1 })}>
      <span className="inline-flex items-center gap-1">{label}{sort.key === key && <ArrowDownUp size={11} className="text-cyan" />}</span>
    </th>
  );
  const totalDown = list.reduce((s, c) => s + (c.down_bps ?? 0), 0);
  const totalUp = list.reduce((s, c) => s + (c.up_bps ?? 0), 0);

  return (
    <div className="mx-auto max-w-[1800px] space-y-4 p-4 md:p-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Online" value={counts?.online ?? "—"} sub={`${counts?.offline ?? 0} offline (30 days)`} color="#34d399" />
        <Stat label="Wireless" value={counts?.wireless ?? "—"} sub={<span className="flex gap-2">{Object.entries(counts?.by_band ?? {}).sort().map(([b, n]) => <span key={b} style={{ color: BAND_COLOR[b] }}>{b} GHz {n}</span>)}</span>} />
        <Stat label="Wired" value={counts?.wired ?? "—"} sub="switch-attached" />
        <Stat label="Live download" value={bps(totalDown)} sub="sum of shown clients" color="#22d3ee" />
        <Stat label="Live upload" value={bps(totalUp)} sub="sum of shown clients" color="#f472b6" />
      </div>

      <div className="panel space-y-3 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex min-w-[240px] flex-1 items-center gap-2 rounded-xl border border-edge bg-black/30 px-3">
            <Search size={15} className="text-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name, IP, MAC, vendor, SSID…"
              className="h-9 flex-1 bg-transparent text-sm outline-none placeholder:text-faint" />
            {q && <button onClick={() => setQ("")} className="text-faint hover:text-ink"><X size={14} /></button>}
          </div>
          {(["online", "offline", "all"] as const).map((s) => (
            <button key={s} className="chip" data-active={status === s} onClick={() => setStatus(s)}>{s}</button>
          ))}
          <span className="mx-1 h-5 w-px bg-edge" />
          <button className="chip" data-active={conn.includes("wired")} onClick={() => toggle(conn, setConn, "wired")}><Cable size={12} /> wired</button>
          {["2.4", "5", "6"].map((b) => (
            <button key={b} className="chip" data-active={conn.includes(b)} onClick={() => toggle(conn, setConn, b)}><Wifi size={12} style={{ color: BAND_COLOR[b] }} /> {b} GHz</button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select className="input !w-auto !py-1.5" value={network} onChange={(e) => setNetwork(e.target.value)}>
            <option value="">All networks</option>{options.networks.map((n) => <option key={n}>{n}</option>)}
          </select>
          <select className="input !w-auto !py-1.5" value={ssid} onChange={(e) => setSsid(e.target.value)}>
            <option value="">All SSIDs</option>{options.ssids.map((n) => <option key={n}>{n}</option>)}
          </select>
          <select className="input !w-auto !py-1.5" value={uplink} onChange={(e) => setUplink(e.target.value)}>
            <option value="">All APs / switches</option>{options.uplinks.map((n) => <option key={n}>{n}</option>)}
          </select>
          {options.cats.map((c) => (
            <button key={c} className="chip" data-active={cats.includes(c)} onClick={() => toggle(cats, setCats, c)}>
              <ClientIcon category={c} size={12} /> {CATEGORY[c]?.label ?? c}
            </button>
          ))}
          <span className="ml-auto font-mono text-xs text-faint">{list.length} of {all.length}</span>
        </div>
      </div>

      <Panel title="Clients" icon={<Users size={15} />} bodyClass="!p-0" brackets={false}>
        {loading && !data ? <div className="grid h-40 place-items-center"><Spinner /></div> : !list.length ? (
          <Empty icon={<Users size={30} />} title="No clients match">Clients come from your UniFi controller and firewall DHCP leases.</Empty>
        ) : (
          <div className="max-h-[calc(100vh-24rem)] min-h-[300px] overflow-auto">
            <table className="table-hud min-w-[1250px]">
              <thead><tr>
                {th("name", "Client")}{th("ip", "IP")}<th>Network</th><th>Connection</th><th>AP / switch</th>
                {th("signal", "Signal")}{th("traffic", "Live ↓ / ↑")}{th("usage", "Data used")}{th("satisfaction", "Experience")}{th("seen", "Uptime / seen")}
              </tr></thead>
              <tbody>
                {list.map((c, i) => (
                  <motion.tr key={c.mac} initial={i < 40 ? { opacity: 0 } : false} animate={{ opacity: 1 }} transition={{ delay: Math.min(i, 40) * 0.008 }}
                    className={clsx("cursor-pointer", !c.online && "opacity-55")} onClick={() => setOpen(c.mac)}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <span className={clsx("grid h-7 w-7 shrink-0 place-items-center rounded-lg border", c.online ? "border-cyan/30 bg-cyan/10 text-cyan" : "border-edge text-faint")}>
                          <ClientIcon category={c.category} size={14} />
                        </span>
                        <div className="min-w-0">
                          <div className="truncate font-medium">{c.display_name}</div>
                          <div className="truncate font-mono text-[10.5px] text-faint">{c.vendor || c.mac}</div>
                        </div>
                      </div>
                    </td>
                    <td className="font-mono text-xs">{c.ip || "—"}</td>
                    <td className="text-xs text-dim">{c.network || "—"}{c.vlan != null && <span className="text-faint"> · {c.vlan}</span>}</td>
                    <td className="text-xs">
                      {c.wired ? <span className="inline-flex items-center gap-1.5 text-dim"><Cable size={12} /> port {c.sw_port ?? "?"}</span>
                        : <span className="inline-flex items-center gap-1.5"><BandBadge band={c.band} /><span className="truncate text-dim">{c.ssid}</span></span>}
                    </td>
                    <td className="max-w-[160px] truncate text-xs text-dim">{c.uplink_name || "—"}</td>
                    <td>{c.wired ? <span className="text-faint">—</span> : (
                      <span className="inline-flex items-center gap-2"><SignalBars signal={c.signal} /><span className="num text-[11px] text-dim">{c.signal ?? ""}</span>
                        {c.standard && <span className="font-mono text-[10px] text-violet/80">{c.standard.replace("Wi-Fi ", "WiFi")}</span>}</span>
                    )}</td>
                    <td className="num text-xs">{c.online ? <><span className="text-cyan">{bps(c.down_bps)}</span> <span className="text-faint">/</span> <span className="text-magenta">{bps(c.up_bps)}</span></> : "—"}</td>
                    <td className="num text-xs text-dim">{bytes((c.down_bytes ?? 0) + (c.up_bytes ?? 0))}</td>
                    <td className="w-32">{c.satisfaction != null ? (
                      <div className="flex items-center gap-2"><Meter value={c.satisfaction} className="flex-1"
                        color={c.satisfaction >= 80 ? "#34d399" : c.satisfaction >= 50 ? "#fbbf24" : "#fb4d6d"} /><span className="num w-8 text-right text-[11px]">{c.satisfaction.toFixed(0)}</span></div>
                    ) : <span className="text-faint">—</span>}</td>
                    <td className="font-mono text-[11px] text-dim">{c.online ? duration(c.uptime_s) : ago(c.last_seen)}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <ClientDrawer mac={open} onClose={() => setOpen(null)} />
    </div>
  );
}
