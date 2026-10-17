<div align="center">

# NetworkVision

**One futuristic pane of glass for your whole network.**
pfSense · OPNsense · UniFi · HP ProCurve · TP-Link · Windows DHCP · anything SNMP · syslog from everything.

</div>

---

Tired of opening five web UIs to figure out why the network is slow? NetworkVision polls all your
gear, receives everyone's syslog, builds a **live animated topology**, and raises **alerts** when
something goes wrong. It ships as a single Docker container that drops straight into Portainer.

## Features

- **Command Center**: a health score, WAN throughput, internet latency, clients, an alert feed, a device matrix, top talkers and a live event stream.
- **Live topology**: discovered from LLDP, UniFi uplinks, port descriptions and WAN interfaces. Links glow by utilization, packets flow at speeds tied to real traffic, and down links pulse red. You can drag nodes to pin them.
- **Device deep dive**: a switch faceplate with port LEDs, a per-port traffic/error/flap/PoE/SFP table, CPU/mem/temp/latency history, gateways, neighbors, and vendor config (firewall rules, DHCP leases, VLANs, services, clients, firmware).
- **Clients**: every device on the network from UniFi plus pfSense/OPNsense DHCP, merged by MAC. Signal, link rates, Wi-Fi standard, AP or switch port, retries, experience score, data used, DHCP lease, live traffic, and known-offline devices from the last 30 days. Auto-classified as phone, TV, IoT, camera and so on.
- **WiFi dashboard**: per-AP radio health with airtime rings (your traffic vs. interference), channel and width, TX power, retries, SSIDs, band/standard/signal mix, clients needing attention, and a **channel map** of your radios against every neighbouring network.
- **History explorer**: click any chart for 1h to 1y or a custom range, drag to zoom, peaks overlay, min/avg/max/p95, data moved, and CSV export. Hourly rollups keep long ranges fast.
- **Speed test**: built-in (Cloudflare's speed-test network, no binary). Download, upload, latency, jitter and **bufferbloat** (latency under load). Scheduled (hourly by default) or on demand, with history and a "slower than expected" alert.
- **Services (uptime)**: watch the things you host: HTTP(S) (status codes, keyword, redirects), TCP ports, DNS answers and TLS certificates (days left, issuer, name match). Status-page style 90-day uptime bars, 24h/7d/30d/90d uptime, response-time sparklines and history, an incident log, and alerts for down, slow, expiring (<21 / <7 days) and invalid certificates.
- **Log explorer**: a built-in syslog receiver (UDP + TCP, RFC 3164/5424) plus logs pulled from device APIs. You get a severity histogram, full-text search with `-exclusions`, filters, and live tail.
- **Firewall explorer**: pfSense / OPNsense `filterlog` (syslog or API) parsed into searchable events with friendly interface names (igb0.20 → HOME) and rule descriptions (tracker → "pfB_Top_v4 auto rule"). Live tail, click-to-filter IPs/ports/rules, CIDR search, a zoomable pass/block timeline, top blocked sources, ports, rules and interfaces. Optionally count but skip storing pass traffic or multicast noise.
- **Alerts**: device down, gateway down/loss/latency, high CPU/mem/temp, link down, port flapping, port errors, saturation, critical syslog, and firmware updates. Alerts are debounced and auto-resolve. You can ack or resolve them, and route them to Discord, Slack, ntfy, or any webhook.
- **Security**: firewall logs, SSH / firewall-GUI / OpenVPN / web logins and Suricata/Snort alerts become one picture: top attacking IPs, targeted ports and services, an attack timeline, origin countries, a live threat feed and a per-IP drilldown. Detects **brute force**, **port scans**, **logins that succeed after a brute force** (critical), **IDS hits** and **spikes in blocked WAN traffic**.
- **DHCP**: correlates DHCP leases (pfSense/OPNsense) with UniFi clients from the shared client inventory and finds **IP conflicts**, **duplicate hostnames**, **devices hopping addresses**, **multiple / rogue DHCP servers**, NAK storms, and **brand-new devices** joining the network.
- **Fast filtering everywhere**, plus a `Ctrl+K` command palette.
- **Demo mode** gives you a full simulated homelab to explore before connecting anything.

## Supported integrations

| Integration | How | What you get |
|---|---|---|
| **pfSense** | [pfSense REST API](https://pfrest.org) package (v2), API key | CPU/mem/temp/disk, interfaces, gateways (latency/loss), DHCP leases, services, firewall rules, system + firewall logs |
| **OPNsense** | Native API (key + secret) | CPU/mem/temp, interfaces, gateways, DHCP (ISC/Kea), services, firmware status, logs |
| **UniFi Network** (Cloud Key Gen1/Gen2/+, UDM, UCG, self-hosted) | Local account or API key | Auto-discovers every switch/AP/gateway: ports, PoE, SFP, uplinks, clients, WAN health, alarms, events, networks |
| **SNMP v2c / v3** | Standard MIBs + vendor fallbacks | Interfaces, traffic, errors, CPU, memory, temperature, VLANs, LLDP neighbors. Covers HP ProCurve/Aruba, managed TP-Link, UniFi switches, Cisco, MikroTik, Linux, Synology |
| **TP-Link Easy Smart** (TL-SG108E…) *(experimental)* | Read-only web UI | Port link/speed, packet & error counters, VLANs |
| **Windows Server DHCP** | WinRM / PowerShell (read-only) | Scopes & utilization, leases, reservations, BAD_ADDRESS, failover state, config drift between failover partners, static IPs inside pools, overlapping DHCP servers |
| **Ping / TCP** | ICMP with TCP fallback | Up/down, latency, loss for anything with an IP |
| **Syslog** | UDP/TCP 514 → container 5514 | Every log line from every device, matched by IP/hostname |

## Quick start (Portainer)

1. **Stacks → Add stack**, then paste [`docker-compose.yml`](docker-compose.yml) or use *Repository* and point it at this repo.
2. Under **Environment variables**, set at least:
   ```
   NV_SECRET_KEY=<output of: openssl rand -base64 48>
   NV_ADMIN_PASSWORD=<a strong password>
   ```
   Want to look around first? Add `NV_DEMO_MODE=true`.
3. Deploy, then open `http://<docker-host>:8080`.
4. Go to **Integrations → Add integration** and connect your gear. Hit **Test connection** before saving.
5. Point every device's remote syslog at `<docker-host>:514`. The *Syslog setup* tab has per-vendor instructions.

### Keeping secrets out of the database

Any credential field accepts `env:VARIABLE_NAME`. Define the variable in your Portainer stack (and in the
`environment:` list of the compose file), and NetworkVision reads it at poll time. Nothing is stored. Values typed
directly are Fernet-encrypted at rest with a key derived from `NV_SECRET_KEY`, and they are never sent back to the browser.
Variables starting with `NV_` can't be referenced, so NetworkVision's own secrets stay private.

### Two-factor authentication (MFA)

Go to **Integrations → Security → Set up authenticator** and scan the QR code with any TOTP app (Google Authenticator,
Authy, 1Password, Bitwarden, KeePassXC…). Save the 10 one-time recovery codes. After that, signing in needs your
password **and** a code. Turning MFA on or off signs out every other session.

- Prefer config-as-code? Set `NV_ADMIN_TOTP_SECRET` (base32) instead. MFA is then always on.
- Lost your phone *and* your recovery codes? Set `NV_MFA_RESET=true`, restart, sign in, remove the variable and enroll again.

### KeePass integration

Keep device credentials in KeePass instead of NetworkVision:

1. Create a **dedicated** `.kdbx` (KeePass / KeePassXC) holding only the credentials NetworkVision needs.
2. Copy it to the Docker host and mount it read-only (see the commented volume in `docker-compose.yml`).
3. Set `NV_KEEPASS_FILE`, plus `NV_KEEPASS_PASSWORD` and/or `NV_KEEPASS_KEYFILE`.
4. In any credential field click the 🔑 button, or type a reference:
   | Reference | Resolves to |
   |---|---|
   | `kp:Network/pfSense` | the entry's password |
   | `kp:Network/UniFi#username` | its username |
   | `kp:Network/pfSense#api_key` | a custom string field |

Values are read at poll time and never stored or shown. When you update the file (e.g. Syncthing, a scheduled copy),
NetworkVision reloads it and reconnects with the rotated credentials automatically.

### Database

SQLite in the `/data` volume is the zero-setup default, and it handles a homelab comfortably. To use an existing
MariaDB/MySQL instead:

```sql
CREATE DATABASE networkvision CHARACTER SET utf8mb4;
CREATE USER 'networkvision'@'%' IDENTIFIED BY '...';
GRANT ALL ON networkvision.* TO 'networkvision'@'%';
```
```
NV_DB_DRIVER=mariadb
NV_DB_HOST=10.0.0.20
NV_DB_PASSWORD=...
```
Tables are created automatically on first start.

**Moving existing data from SQLite to MariaDB:** before switching `NV_DB_DRIVER`, copy everything (devices, credentials,
history, logs, alerts, MFA state) with the built-in tool, run inside the container:

```bash
docker exec -e NV_DB_HOST=10.0.0.20 -e NV_DB_PASSWORD=... networkvision python -m app.tools.migrate_db
```

It creates the schema, refuses to overwrite a non-empty target, copies in small transactions and verifies row counts.
Keep the same `NV_SECRET_KEY`, because stored credentials are encrypted with it.

**MariaDB Galera clusters** are supported. NetworkVision uses `READ COMMITTED`, retries certification
conflicts and node failovers, writes logs in small batches, and purges expired data in small chunks so
retention never produces a giant write set. Point `NV_DB_HOST` at a single writer: your MaxScale / ProxySQL /
HAProxy endpoint, or one fixed node. That avoids multi-master write conflicts entirely.

## Per-device setup notes

- **pfSense**: install the REST API package (System → Package Manager, or see pfrest.org), then create a key under *System → REST API → Keys*, ideally for a read-only user.
- **OPNsense**: *System → Access → Users*. Create a user with read-only privileges (Diagnostics, Status, Dashboard, Firmware) and generate an API key. Use the key and secret.
- **UniFi**: create a **local** read-only admin, not a UI.com SSO account. Use the controller IP (Cloud Key Gen2 = UniFi OS, port 443). The site id is usually `default`.
- **HP ProCurve**: `snmp-server community "<community>" restricted` and `lldp run` (on by default). Use the SNMP integration.
- **TP-Link managed (JetStream/Omada)**: enable SNMP. Use the SNMP integration.
- **TP-Link Easy Smart (TL-SG108E)**: no SNMP exists, so use the *Easy Smart* integration (read-only scraping). These switches allow only one web session at a time.
- **Windows Server DHCP**: add *each* DHCP server (both failover partners) so their configuration can be compared.
  1. Create a plain domain account (e.g. `svc-networkvision`) and add it to **DHCP Users** and **Remote Management Users** on each server. No admin rights are needed.
  2. Enable WinRM over HTTPS (port 5986), e.g. `winrm quickconfig -transport:https` with a certificate from your CA, and allow 5986 from the Docker host. HTTP (5985) also works and is still encrypted by NTLM.
  3. Put the password in the stack env (e.g. `WINDHCP_PASSWORD`) and enter `env:WINDHCP_PASSWORD` in the integration form, with the user as `DOMAIN\svc-networkvision`.

### Services (uptime monitoring)

*Services* checks your self-hosted sites and ports on their own interval (default 60 s) and records every result, so the
history explorer and uptime figures work like every other chart. A service is only marked **down** after *N*
consecutive failures (default 3), which opens an incident and a critical alert; the next success closes both.

| Check | What it verifies |
|---|---|
| HTTP(S) | Status code in range (`200-399`, `204`, `2xx,401`...), optional keyword in the body, response time; redirects optional. HTTPS certificates are read hourly for expiry alerts. |
| TCP | The port accepts a connection (SSH, Plex, game servers, SMTP...). |
| DNS | The name resolves (system resolver), and optionally *only* to the addresses you expect - catches a stale or hijacked record. |
| TLS cert | Handshake, chain validity, the certificate covers the name (SAN), days until expiry. Works for any TLS port (443, 465, 993, 8443...). |

Only `http://` / `https://` URLs and plain hostnames/IPs are accepted as targets.

**Check from outside, too.** These checks run from the NetworkVision host, i.e. from *inside* your network. That is
great for "is the app up and is its certificate valid", but it cannot see what visitors see: NAT reflection or split DNS
can make a service look healthy internally while the port-forward is broken, and an ISP outage takes NetworkVision
offline along with everything else. Pair it with a free external probe (Uptime Kuma on a cheap VPS, UptimeRobot,
Healthchecks.io, or Better Stack) pointed at the same public URLs, and point the DNS check at your public hostname with
your WAN IP as the expected address.

**Topology tip:** if a switch port description names a device (e.g. `Proxmox-01`), NetworkVision draws the link automatically.

## Security monitoring: what to enable

NetworkVision only sees what your devices log. To watch attacks against services you expose through pfSense:

1. **Send pfSense's logs to NetworkVision.** *Status → System Logs → Settings → Remote Logging Options*: enable
   remote logging, set the remote server to `<docker-host>:514`, and select *Everything* (or at least *Firewall
   Events*, *System Events* and *VPN*).
2. **Log the default block rules.** In the same settings page, check *Log packets matched from the default block
   rules*. That gives you the internet background noise: who is knocking, and on which ports.
3. **Log your port forwards.** For every NAT port forward, open its **associated WAN firewall rule** (*Firewall →
   Rules → WAN*), and under *Extra Options* tick **Log packets that are handled by this rule**. Pass rules are not
   logged by default, so without this you can't see who actually reaches the exposed service.
4. **Log your explicit WAN block rules** the same way (and any pfBlockerNG rules you want to see).
5. **Send the logs of the services themselves.** The firewall only sees connections, not passwords. To catch
   failed logins, forward the syslog of the hosts behind the port forwards:
   - SSH servers: rsyslog `*.* @<docker-host>:514` (sshd logs to `auth`)
   - Reverse proxies (nginx / Traefik / Caddy / HAProxy): send **access logs** to syslog. Bursts of 401/403 count
     as failed logins. nginx example: `access_log syslog:server=<docker-host>:514,tag=nginx combined;`
   - OpenVPN on pfSense is covered by step 1.
6. **Optional IDS.** Install Suricata or Snort on pfSense/OPNsense, enable *Send alerts to system log*, and every
   alert shows up with its signature and priority. Priority 1 alerts are critical.
7. **Optional GeoIP.** Create a free MaxMind account, then set `NV_GEOIP_LICENSE_KEY`. The GeoLite2 Country
   database is downloaded into the data volume and refreshed weekly.

**Tuning:** internet scanners hit every public IP all day, so scans that were **completely blocked** are recorded
and shown but don't raise alerts unless `NV_SEC_SCAN_ALERT_BLOCKED=true`. Scans from **inside** your network (a
compromised IoT device, say) and scans that got anything through always alert. Put trusted scanners (your
vulnerability scanner, monitoring) in `NV_SEC_IGNORE_IPS`. All thresholds are listed under `NV_SEC_*` in
[`.env.example`](.env.example).

## DHCP insights

These checks work automatically once pfSense/OPNsense (leases) and/or UniFi (clients) are connected. For the
"multiple DHCP servers" check, also forward the DHCP server logs (`dhcpd`, `dnsmasq`, Kea) to syslog. Mark the
devices you recognize as **Known** on the *DHCP* page. "New device" alerts start after a learning period
(`NV_DHCP_LEARNING_HOURS`, default 1 hour), so your existing devices don't each raise one.

## Configuration

Everything is configured with `NV_*` environment variables. See [`.env.example`](.env.example) for the full,
documented list: auth, database, retention, alert thresholds and notifications.

| Variable | Default | |
|---|---|---|
| `NV_SECRET_KEY` | *(required)* | Signs sessions, encrypts stored credentials |
| `NV_ADMIN_PASSWORD` / `NV_ADMIN_PASSWORD_HASH` | | Dashboard login (bcrypt hash preferred) |
| `NV_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `NV_TRUSTED_PROXY_HEADER` | | e.g. `Remote-User` for Authelia/Authentik forward-auth |
| `NV_POLL_INTERVAL` | `15` | Seconds between polls |
| `NV_DB_DRIVER` | `sqlite` | `sqlite` or `mariadb` |
| `NV_DEMO_MODE` | `false` | Simulated homelab |

### Settings in the UI

Alert thresholds, rules, retention and notification channels can also be changed live under
**Settings**, without a redeploy. Precedence, lowest to highest:

1. built-in default
2. `NV_*` environment variable
3. value saved in the UI

Each field shows where its value comes from (`default`, `env` or `custom`). **Reset** deletes the
saved value so the env var (or the default) applies again. Values are stored in the `settings`
table; webhook URLs and the ntfy token are encrypted with `NV_SECRET_KEY` and are never sent back
to the browser. **Send test notification** posts to every configured channel and shows the
result of each one.

**Alert tuning** (on each device's page):

- mute every alert for a device, or only individual ports (the bell on a port row), e.g. a port
  that is expected to be down
- turn individual rules off for that device (rules can also be turned off globally in Settings)
- override thresholds for that device. An empty field means the global value applies.

**Maintenance windows** (Settings › Maintenance) are one-off, daily or weekly, and apply to one
device or to all of them. A device's window also covers the devices it manages, such as a UniFi
controller's APs. During a window, alerts are still recorded but marked *maintenance*: they are
not notified, don't change device health and don't pop up toasts. A banner shows while a window
is active. If a problem is still there when the window ends, the alert becomes a normal alert
and is notified then. Recurring windows use the browser's time zone and follow DST.

## Architecture

```
 ┌───────────── container ──────────────────────────────────────────┐
 │  FastAPI (uvicorn)                                               │
 │   ├─ collectors/  pfSense · OPNsense · UniFi · SNMP · TP-Link ·  │
 │   │               Ping · Demo   → normalized Snapshot            │
 │   ├─ poller       one asyncio task per integration               │
 │   ├─ state        live rates (32/64-bit wrap safe), histories    │
 │   ├─ alerts       debounced rules → DB + Discord/Slack/ntfy      │
 │   ├─ syslog       UDP/TCP receiver → batched log pipeline        │
 │   ├─ topology     LLDP + uplinks + descriptions + manual links   │
 │   └─ REST + WebSocket ─────────────► React SPA (Vite, Tailwind,  │
 │                                       Motion, d3-force)          │
 └──────────── SQLite (/data)  or  external MariaDB ────────────────┘
```

Adding an integration means writing one file: subclass `Collector`, declare its form `fields`, and return a
`Snapshot`. See [`backend/app/collectors/base.py`](backend/app/collectors/base.py).

## Development

```bash
# backend
cd backend && python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
NV_DEMO_MODE=true NV_ADMIN_PASSWORD=dev uvicorn app.main:app --reload --port 8080
pytest && ruff check app tests

# frontend (proxies /api to :8080)
cd frontend && npm install && npm run dev
```

## Security

The dashboard needs authentication unless you explicitly disable it. Credentials are encrypted at rest or kept in
env vars, and the container runs as non-root with all capabilities dropped. See [SECURITY.md](SECURITY.md) to report
a vulnerability.

## License

[MIT](LICENSE)
