"""Same-origin browser facade. The gateway remains the authorization authority."""
import os
import re
import httpx
from fastapi import FastAPI, Request, Response

app = FastAPI(title="SecureAgent API", version="1.0.0")
GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:8080")

@app.get("/healthz")
async def health():
    return {"status": "ok"}

@app.api_route("/v1/{path:path}", methods=["GET", "POST"])
async def proxy(path: str, request: Request):
    # Fixed destination and path prefix: the browser cannot reach /internal or choose an upstream.
    static = {("POST", "auth/login"), ("GET", "me"), ("GET", "runs"),
              ("POST", "runs"), ("GET", "approvals"), ("GET", "audit"),
              ("GET", "tools"), ("POST", "tools/execute")}
    dynamic = ((request.method == "GET" and re.fullmatch(r"runs/[a-f0-9]{32}", path)) or
               (request.method == "POST" and re.fullmatch(r"runs/[a-f0-9]{32}/cancel", path)) or
               (request.method == "POST" and re.fullmatch(r"approvals/[a-f0-9]{32}/decision", path)))
    if (request.method, path) not in static and not dynamic:
        return Response('{"error":"route not found"}', status_code=404, media_type="application/json")
    if len(request.url.query) > 1000:
        return Response(status_code=400)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 16384:
            return Response(status_code=413)
    headers = {k: v for k, v in request.headers.items()
               if k.lower() in {"authorization", "content-type", "x-tenant-id", "traceparent"}}
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
            result = await client.request(request.method, f"{GATEWAY}/v1/{path}",
                                          headers=headers, content=bytes(body))
        return Response(result.content, status_code=result.status_code,
                        media_type="application/json", headers={"Cache-Control": "no-store"})
    except httpx.HTTPError:
        return Response('{"error":"gateway unavailable"}', status_code=503,
                        media_type="application/json")
