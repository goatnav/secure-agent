"""Measure gateway-only HTTP latency. No model request occurs in this workload."""
import argparse
import asyncio
import json
import os
import platform
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import httpx

async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base",default="http://localhost:8080")
    p.add_argument("--requests",type=int,default=200)
    p.add_argument("--concurrency",type=int,default=20)
    p.add_argument("--output",default="results/benchmark.json")
    p.add_argument("--label",default="local-compose")
    args=p.parse_args()
    if args.requests<1 or args.concurrency<1:
        p.error("requests and concurrency must be positive")
    latencies=[];statuses=Counter(); semaphore=asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(base_url=args.base,timeout=30,limits=httpx.Limits(max_connections=args.concurrency)) as client:
        login=await client.post("/v1/auth/login",json={"tenant":"acme","username":"analyst","password":os.getenv("DEMO_PASSWORD","secureagent-demo")})
        login.raise_for_status();headers={"Authorization":"Bearer "+login.json()["token"]}
        async def request():
            async with semaphore:
                started=time.perf_counter()
                try:
                    response=await client.get("/v1/runs",headers=headers)
                    statuses[str(response.status_code)]+=1
                except httpx.HTTPError:
                    statuses["transport_error"]+=1
                latencies.append((time.perf_counter()-started)*1000)
        started=time.perf_counter()
        await asyncio.gather(*(request() for _ in range(args.requests)))
        elapsed=time.perf_counter()-started
    ordered=sorted(latencies)
    def percentile(q): return ordered[min(len(ordered)-1,int((len(ordered)-1)*q))]
    result={"at":datetime.now(timezone.utc).isoformat(),"label":args.label,
            "workload":"GET /v1/runs authenticated; no model calls","hardware":{"os":platform.platform(),"cpu":platform.processor(),"logical_cpus":os.cpu_count()},
            "requests":args.requests,"concurrency":args.concurrency,"elapsed_seconds":elapsed,"requests_per_second":args.requests/elapsed,
            "latency_ms":{"p50":percentile(.5),"p95":percentile(.95),"p99":percentile(.99)},"statuses":dict(statuses),
            "limitations":"Includes network and transaction latency. Rate-limited responses are included; this is not tool or model throughput."}
    output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))

if __name__=="__main__": asyncio.run(main())
