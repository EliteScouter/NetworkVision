<div align="center">

# NetworkVision

**One futuristic pane of glass for your whole network.**
pfSense · OPNsense · UniFi · HP ProCurve · TP-Link · anything SNMP · syslog from everything.

</div>

---

Tired of opening five web UIs to figure out why the network is slow? NetworkVision polls all your
gear, receives everyone's syslog, builds a **live animated topology**, and raises **alerts** when
something goes wrong. It ships as a single Docker container that drops straight into Portainer.

## Features

- **Command Center**: a health score, WAN throughput, internet latency, clients, an alert feed, a device matrix, top talkers and a live event stream.
- **Live topology**: discovered from LLDP, UniFi uplinks, port descriptions and WAN interfaces. Links glow by utilization, packets flow at speeds tied to real traffic, and down links pulse red. You can drag nodes to pin them.
- **Device deep dive**: a switch faceplate with port LEDs, a per-port traffic/error/flap/PoE/SFP table, CPU/mem/temp/latency history, gateways, neighbors, and vendor config (firewall rules, DHCP leases, VLANs, services, clients, firmware).
- **Log explorer**: a built-in syslog receiver (UDP + TCP, RFC 3164/5424) plus logs pulled from device APIs. You get a severity histogram, full-text search with `-exclusions`, filters, and live tail.
- **Alerts**: device down, gateway down/loss/latency, high CPU/mem/temp, link down, port flapping, port errors, saturation, critical syslog, and firmware updates. Alerts are debounced and auto-resolve. You can ack or resolve them, and route them to Discord, Slack, ntfy, or any webhook.
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

**Topology tip:** if a switch port description names a device (e.g. `Proxmox-01`), NetworkVision draws the link automatically.

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
