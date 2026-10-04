import asyncio
import logging
import os
import socket
import httpx
from redis.asyncio import Redis
from redis.exceptions import ResponseError
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from .orchestrator import Gateway, investigate

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

def setup_telemetry():
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        tp = TracerProvider(resource=Resource.create({"service.name": "secureagent-worker"}))
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(tp)

async def process(base: str, job: dict):
    async with httpx.AsyncClient(timeout=10) as client:
        claim = await client.post(f"{base}/internal/runs/claim", json=job,
                                 headers={"X-Worker-Secret": os.environ["WORKER_SECRET"]})
    if claim.status_code in (404, 409, 410):
        return
    claim.raise_for_status()
    data = claim.json()
    gateway = Gateway(base, data["token"])
    try:
        await asyncio.wait_for(investigate(gateway, data["run"]), timeout=70)
    except Exception:
        # No request/response bodies or provider errors are written to logs.
        logging.warning("Investigation failed for run %s", job["run"])
        try:
            await gateway.post("/internal/runs/result", {"error": "runtime failure"})
        except httpx.HTTPError:
            logging.warning("Run result unavailable; lease recovery will handle run %s", job["run"])
    finally:
        await gateway.client.aclose()

async def main():
    setup_telemetry()
    redis = Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    base = os.getenv("GATEWAY_URL", "http://localhost:8080")
    stream, group, consumer = "agent-runs", "runtime", socket.gethostname()
    try:
        await redis.xgroup_create(stream, group, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    logging.info("Worker ready")
    try:
        while True:
            # Recover entries abandoned by dead workers. DB leases fence stale credentials.
            claimed = await redis.xautoclaim(stream, group, consumer, min_idle_time=95000, start_id="0-0", count=10)
            entries = claimed[1]
            if not entries:
                messages = await redis.xreadgroup(group, consumer, {stream: ">"}, count=1, block=3000)
                entries = messages[0][1] if messages else []
            for entry_id, job in entries:
                try:
                    await process(base, {"tenant": job["tenant"], "run": job["run"]})
                    await redis.xack(stream, group, entry_id)
                    await redis.xdel(stream, entry_id)
                except httpx.HTTPError:
                    logging.warning("Gateway unavailable; retaining pending entry")
                    await asyncio.sleep(2)
    finally:
        await redis.aclose()
        trace.get_tracer_provider().shutdown() if hasattr(trace.get_tracer_provider(), "shutdown") else None

if __name__ == "__main__":
    asyncio.run(main())
