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
