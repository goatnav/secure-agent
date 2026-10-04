import httpx
import pytest
from app.api import app

async def test_facade_forwards_bytes_and_only_permitted_headers(monkeypatch):
    seen = []
    original = httpx.AsyncClient
    def upstream(request):
        seen.append(request)
        assert request.content == b'{"tenant":"acme"}'
        assert request.headers.get("authorization") == "Bearer demo"
        assert "x-worker-secret" not in request.headers
        assert request.url.path == "/v1/auth/login"
        return httpx.Response(200, json={"ok":True})
    monkeypatch.setattr(httpx,"AsyncClient",lambda **kwargs: original(transport=httpx.MockTransport(upstream),**kwargs))
    async with original(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
        result=await client.post("/v1/auth/login",content=b'{"tenant":"acme"}',headers={"Authorization":"Bearer demo","X-Worker-Secret":"must-not-forward"})
        assert result.status_code==200 and result.json()=={"ok":True}
        assert result.headers["cache-control"]=="no-store"
        assert len(seen)==1

async def test_facade_hides_internal_and_bounds_request_size():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test") as client:
        assert (await client.post("/internal/runs/claim",json={})).status_code==404
        assert (await client.post("/v1/%2e%2e/internal/runs/claim",json={})).status_code==404
        assert (await client.post("/v1/runs/../../internal/runs/claim",json={})).status_code==404
        assert (await client.post("/v1/runs",content=b'x'*17000)).status_code==413
