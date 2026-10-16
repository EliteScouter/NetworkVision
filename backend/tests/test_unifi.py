"""UniFi controller: internet health must not false-alarm behind a third-party gateway."""

import httpx

from app.collectors.unifi import UnifiCollector


def _unifi(devices: list[dict], www: dict) -> UnifiCollector:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/auth/login":
            return httpx.Response(200, json={}, headers={"x-csrf-token": "t"})
        path = req.url.path.split("/api/s/default/", 1)[-1]
        data = {"stat/device": devices, "stat/health": [www, {"subsystem": "lan", "status": "ok"}]}.get(path, [])
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": data})

    c = UnifiCollector("192.0.2.5", {"site": "default"}, {"username": "nv", "password": "pw"})
    c._client = httpx.AsyncClient(base_url=c.base_url, transport=httpx.MockTransport(handler))
    return c


SWITCH = {"type": "usw", "mac": "aa:bb:cc:dd:ee:01", "name": "Core", "state": 1, "port_table": []}
GATEWAY = {"type": "udm", "mac": "aa:bb:cc:dd:ee:02", "name": "UDM", "state": 1, "port_table": []}


async def test_third_party_gateway_reports_no_internet_gateway():
    c = _unifi([SWITCH], {"subsystem": "www", "status": "unknown"})
    snap = await c.collect()
    assert snap.gateways == []  # pfSense/OPNsense own the internet; no bogus "down"


async def test_unifi_gateway_internet_health():
    c = _unifi([SWITCH, GATEWAY], {"subsystem": "www", "status": "ok", "latency": 12, "drops": 3,
                                   "xput_down": 940.1, "xput_up": 38.2})
    gw = (await c.collect()).gateways[0]
    assert gw.up is True and gw.latency_ms == 12
    assert gw.loss_pct is None  # drops is a count, never treated as a percentage
    assert "940.1" in gw.detail and "3 connectivity drops" in gw.detail


async def test_unifi_gateway_internet_error_is_down():
    c = _unifi([GATEWAY], {"subsystem": "www", "status": "error"})
    assert (await c.collect()).gateways[0].up is False
