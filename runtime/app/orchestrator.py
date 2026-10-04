import asyncio
import httpx
from opentelemetry import trace, propagate
from .providers import provider
from .models import Report

tracer = trace.get_tracer("secureagent.runtime")

class Gateway:
    def __init__(self, base: str, token: str):
        self.client = httpx.AsyncClient(base_url=base, timeout=10,
                                       headers={"Authorization": f"Bearer {token}"})

    async def post(self, path: str, body: dict) -> dict:
        headers = {}
        propagate.inject(headers)
        response = await self.client.post(path, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def tool(self, name: str, args: dict, key: str) -> dict:
        with tracer.start_as_current_span("tool.request", attributes={"tool.name": name}):
            for attempt in range(3):
                try:
                    return await self.post("/v1/tools/execute", {"tool": name, "arguments": args, "idempotency_key": key})
                except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                    transient = isinstance(exc, httpx.TransportError) or exc.response.status_code in (502, 503, 504)
                    if name == "identity.disable" or not transient or attempt == 2:
                        raise
                    await asyncio.sleep(0.2 * 2 ** attempt)
        raise RuntimeError("unreachable")

async def investigate(gateway: Gateway, run: dict, model=None):
    """Finite workflow: five reads, one model assessment, at most one mutation proposal."""
    parent = propagate.extract({"traceparent": run.get("traceparent", "")})
    with tracer.start_as_current_span("investigation", context=parent, attributes={"run.id": run["id"]}):
        identity_id = run["identity_id"]
        # A persisted report is a recovery checkpoint: never repeat an uncertain paid call.
        if run.get("report"):
            report = Report.model_validate(run["report"])
            if report.recommend_disable:
                await gateway.tool("identity.disable", {"identity_id": identity_id}, "containment")
            return
        evidence, references = {}, set()
        async def read(name, args, key):
            output = await gateway.tool(name, args, key)
            references.update(output["references"])
            return output["data"]
        evidence["events"] = await read("siem.search", {"identity_id": identity_id}, "events")
        identity = await read("identity.read", {"identity_id": identity_id}, "identity")
        evidence["asset"] = await read("asset.lookup", {"asset_id": identity["asset_id"]}, "asset")
        indicator = next((event["indicator"] for event in evidence["events"] if event.get("indicator")), "indicator-7")
        evidence["threat"] = await read("threat.lookup", {"indicator": indicator}, "threat")
        evidence["guidance"] = await read("guidance.read", {"policy_id": "SEC-IR-01"}, "guidance")
        await gateway.post("/internal/model/reserve", {"idempotency_key": "assessment"})
        with tracer.start_as_current_span("model.assessment") as span:
            report, usage = await (model or provider()).assess(evidence, references)
            span.set_attribute("model.total_tokens", usage["total_tokens"])
            span.set_attribute("model.provider", usage["provider"])
        if identity.get("disabled"):
            report.recommend_disable = False
            report.summary = "Identity is already contained. Evidence review completed."
        await gateway.post("/internal/runs/result", {"report": report.model_dump(), "usage": usage})
        if report.recommend_disable:
            await gateway.tool("identity.disable", {"identity_id": identity_id}, "containment")
