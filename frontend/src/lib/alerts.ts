import type { Alert } from "./types";

/** Short human names for alert rules (shared by the Alerts page and the alert detail drawer). */
export const RULE_LABEL: Record<string, string> = {
  device_down: "Device down", poll_error: "Integration error", high_cpu: "High CPU", high_mem: "High memory",
  high_temp: "Temperature", high_latency: "Latency", packet_loss: "Packet loss", gateway_down: "Gateway down",
  gateway_loss: "Gateway loss", gateway_latency: "Gateway latency", port_flapping: "Port flapping", port_down: "Link down",
  port_errors: "Port errors", port_saturated: "Saturation", firmware_update: "Firmware", log_event: "Critical log",
  sec_bruteforce: "Brute force", sec_login_after_failures: "Possible breach", sec_portscan: "Port scan", sec_ids: "IDS",
  sec_wan_spike: "WAN spike", dhcp_ip_conflict: "IP conflict", dhcp_duplicate_hostname: "Duplicate hostname",
  dhcp_address_hopping: "Address hopping", dhcp_multiple_servers: "Multiple DHCP servers",
  dhcp_failover: "DHCP failover unhealthy", dhcp_config_drift: "DHCP config drift", dhcp_scope_full: "DHCP scope nearly full",
  dhcp_bad_address: "DHCP BAD_ADDRESS", dhcp_static_in_pool: "Static IP in DHCP pool", dhcp_server_overlap: "Overlapping DHCP servers",
  dhcp_reservation_mismatch: "Reservation mismatch", dhcp_reserved_other: "Reserved IP used by another device", dhcp_unauthorized: "DHCP server not authorized",
  dhcp_dns_down: "DNS server not answering", dhcp_dns_ad_records: "DC records missing", dhcp_dns_external: "External DNS failing",
  dhcp_dns_events: "DNS Server log errors", dhcp_dns_mismatch: "DC records differ", dhcp_dns_insecure_updates: "Nonsecure DNS updates",
  dhcp_dns_stale: "Stale DNS records", dhcp_dns_ptr: "PTR mismatch", dhcp_rogue_server: "Rogue DHCP",
  dhcp_nak_storm: "DHCPNAK storm", dhcp_new_device: "New device",
  speedtest_failed: "Speed test", speedtest_slow: "Slow internet",
  service_down: "Service down", service_slow: "Service slow", cert_expiring: "Certificate expiring", cert_invalid: "Certificate invalid",
};

/** Where an alert's evidence lives, derived from its key (rule:device:subject) and device. */
export function alertLinks(a: Alert): { to: string; label: string }[] {
  const out: { to: string; label: string }[] = [];
  const [ns, kind, subject] = a.key.split(":");
  const fw = (ip: string) => `/firewall?range=24h&f=${encodeURIComponent(JSON.stringify({ chips: [{ field: "src", value: ip }], q: "", hideNoise: false }))}`;
  if (ns === "dhcp") out.push({ to: "/dhcp", label: "Open DHCP insights" });
  if (ns === "sec") {
    out.push({ to: "/security", label: "Open Security" });
    if (["brute", "breach", "scan"].includes(kind) && subject) out.push({ to: fw(subject), label: `Firewall log for ${subject}` });
  }
  if (ns === "svc") out.push({ to: "/services", label: "Open Services" });
  if (ns === "log") out.push({ to: a.device_id ? `/logs?device=${a.device_id}` : "/logs", label: "Open logs" });
  if (a.rule.startsWith("speedtest")) out.push({ to: "/speedtest", label: "Open Speed test" });
  if (a.device_id) out.push({ to: `/devices/${a.device_id}`, label: `Open ${a.device_name ?? "device"}` });
  return out;
}

/** Engines pack lists into the detail as "summary — item; item; item". */
export function splitDetail(detail: string): { text: string; items: string[] } {
  const i = detail.indexOf(" — ");
  if (i < 0 || !detail.slice(i + 3).includes("; ")) return { text: detail, items: [] };
  return { text: detail.slice(0, i), items: detail.slice(i + 3).split("; ").filter(Boolean) };
}
