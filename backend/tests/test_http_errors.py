"""Unexpected HTTP replies must produce actionable error messages."""

import httpx
import pytest

from app.collectors.base import CollectorError
from app.collectors.opnsense import OpnSenseCollector


def _collector(handler) -> OpnSenseCollector:
    c = OpnSenseCollector("192.0.2.1", {"scheme": "https", "port": 443}, {"api_key": "k", "api_secret": "s"})
    c._client = httpx.AsyncClient(base_url=c.base_url, transport=httpx.MockTransport(handler), follow_redirects=False)
    return c


async def test_redirect_explains_scheme_or_port():
    c = _collector(lambda req: httpx.Response(302, headers={"location": "https://192.0.2.1:8443/"}))
    with pytest.raises(CollectorError, match=r"redirected \(HTTP 302\) to https://192.0.2.1:8443/.*scheme or port"):
        await c.collect()


async def test_html_login_page_is_described():
    page = "<!doctype html><html><head><title>Login | OPNsense</title></head><body>Username Password</body></html>"
    c = _collector(lambda req: httpx.Response(200, text=page, headers={"content-type": "text/html; charset=utf-8"}))
    with pytest.raises(CollectorError) as e:
        await c.collect()
    msg = str(e.value)
    assert "HTTP 200, content-type text/html" in msg
    assert "'Login | OPNsense'" in msg and "web login page" in msg


async def test_other_web_server_is_described():
    page = "<html><head><title>Welcome to nginx!</title></head><body>hi</body></html>"
    c = _collector(lambda req: httpx.Response(200, text=page, headers={"content-type": "text/html"}))
    with pytest.raises(CollectorError, match="another web server"):
        await c.collect()


def _opnsense(style: str):
    """Fake OPNsense that only knows one naming style; returns (handler, list of requested paths)."""
    seen: list[str] = []
    data = {
        "diagnostics/system/system_information": {"name": "opn-lab", "versions": ["OPNsense 26.7.2"]},
        "diagnostics/system/system_resources": {"memory": {"total": "8000", "used": "2000"}},
        "routes/gateway/status": {"items": [{"name": "WAN_GW", "status": "none", "delay": "1.5 ms", "loss": "0.0 %"}]},
    }
    if style == "camel":
        data = {k.replace("system_information", "systemInformation").replace("system_resources", "systemResources"): v
                for k, v in data.items()}

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/api/")
        seen.append(path)
        if path in data:
            return httpx.Response(200, json=data[path])
        return httpx.Response(400, json={"message": f"action {path.rsplit('/', 1)[-1]} not found", "status": 400})

    return handler, seen


@pytest.mark.parametrize("style", ["snake", "camel"])
async def test_opnsense_handles_both_api_naming_styles(style):
    handler, seen = _opnsense(style)
    c = _collector(handler)
    snap = await c.collect()
    assert snap.facts["hostname"] == "opn-lab" and snap.facts["version"] == "OPNsense 26.7.2"
    assert snap.metrics["mem"] == 25.0
    assert snap.gateways[0].name == "WAN_GW" and snap.gateways[0].latency_ms == 1.5
    # The working style is remembered, so a second poll doesn't retry the wrong names.
    seen.clear()
    await c.collect()
    wrong = "systemResources" if style == "snake" else "system_resources"
    assert not any(wrong in p for p in seen)


async def test_pfsense_caches_slow_endpoints():
    from app.collectors.pfsense import PfSenseCollector

    hits: dict[str, int] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/api/v2/")
        hits[path] = hits.get(path, 0) + 1
        data = {"status/system": {"cpu_usage": 5}, "status/interfaces": [{"descr": "WAN", "status": "up", "inbytes": 1}]}
        return httpx.Response(200, json={"data": data.get(path, [])})

    c = PfSenseCollector("192.0.2.1", {"scheme": "https", "port": 443}, {"api_key": "k"})
    c._client = httpx.AsyncClient(base_url=c.base_url, transport=httpx.MockTransport(handler))
    for _ in range(3):
        await c.collect()
    assert hits["status/system"] == 3 and hits["status/interfaces"] == 3  # fresh every poll
    assert hits["firewall/rules"] == 1 and hits["status/dhcp_server/leases"] == 1  # cached


async def test_geoip_rejected_key_is_reported(monkeypatch, tmp_path):
    import httpx

    from app.services import geoip as g

    real = httpx.AsyncClient
    monkeypatch.setattr(g.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(lambda r: httpx.Response(401)), **kw))
    monkeypatch.setenv("NV_GEOIP_DB", str(tmp_path / "x.mmdb"))
    gi = g.GeoIP()
    assert await gi._download("0" * 32) is False
    assert "HTTP 401" in gi.error and "_mmk" in gi.error
    assert "0" * 32 not in gi.error  # never echo the key
