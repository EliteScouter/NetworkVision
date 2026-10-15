"""Seeds a simulated homelab when NV_DEMO_MODE=true and the database is empty."""

from __future__ import annotations

import logging

from sqlalchemy import func, select

from .db import sessionmaker
from .models import Device, Link

log = logging.getLogger("networkvision.demo")

DEMO_DEVICES = [
    # name, profile, role, host, location, extra config
    ("pf-edge", "pfsense", "firewall", "10.0.0.1", "Rack", {}),
    ("opn-lab", "opnsense", "firewall", "10.0.50.1", "Proxmox-01 (VM)", {}),
    ("UniFi Cloud Key", "unifi", "controller", "10.0.0.5", "Rack", {}),
    ("Access-SW1", "procurve", "switch", "10.0.0.11", "Rack", {}),
    ("Desk-SW", "tplink", "switch", "10.0.0.12", "Office", {}),
    ("Garage-SW", "tplink", "switch", "10.0.0.13", "Garage", {}),
    ("Proxmox-01", "host", "hypervisor", "10.0.0.31", "Rack", {"demo_model": "Dell R730xd"}),
    ("Proxmox-02", "host", "hypervisor", "10.0.0.32", "Rack", {"demo_model": "Minisforum MS-01"}),
    ("TrueNAS", "host", "nas", "10.0.0.40", "Rack", {"demo_model": "TrueNAS SCALE"}),
    ("Portainer", "host", "server", "10.0.0.50", "Proxmox-02 (VM)", {"demo_model": "Docker host"}),
]


async def seed_demo() -> None:
    async with sessionmaker()() as db:
        if (await db.execute(select(func.count(Device.id)))).scalar():
            return
        rows = {}
        for name, profile, role, host, location, extra in DEMO_DEVICES:
            d = Device(name=name, kind="demo", role=role, host=host, location=location, tags=["demo"],
                       config={"profile": profile, "demo_name": name, **extra}, facts={})
            db.add(d)
            rows[name] = d
        await db.flush()
        db.add(Link(a_device_id=rows["opn-lab"].id, a_port="WAN", b_device_id=rows["Proxmox-01"].id,
                    b_port="vmbr0", label="virtio bridge"))
        db.add(Link(a_device_id=rows["Portainer"].id, a_port="eth0", b_device_id=rows["Proxmox-02"].id,
                    b_port="vmbr0", label="virtio bridge"))
        await db.commit()
    log.info("Demo mode: seeded %d simulated devices", len(DEMO_DEVICES))
