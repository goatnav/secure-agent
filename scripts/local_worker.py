"""Ephemeral native preview worker; never a Redis/persistence substitute."""
import asyncio
import os
import sys
from pathlib import Path
import httpx

root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/"runtime"))
from app.worker import process

async def main():
    for line in (root/".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key,value=line.split("=",1)
            if key in {"WORKER_SECRET","DEMO_PASSWORD","MODEL_PROVIDER","OPENAI_API_KEY","OPENAI_MODEL"}:
                os.environ.setdefault(key,value)
    base=os.getenv("GATEWAY_URL","http://localhost:8080")
    async with httpx.AsyncClient(base_url=base,timeout=15) as client:
        tokens={}
        for tenant in ("acme","orbit"):
            r=await client.post("/v1/auth/login",json={"tenant":tenant,"username":"analyst","password":os.getenv("DEMO_PASSWORD","secureagent-demo")});r.raise_for_status();tokens[tenant]=r.json()["token"]
        print("Ephemeral preview worker ready; no Redis delivery or durable recovery.",flush=True)
        while True:
            for tenant,token in list(tokens.items()):
                response=await client.get("/v1/runs",headers={"Authorization":"Bearer "+token})
                if response.status_code==429:
                    await asyncio.sleep(10)
                    continue
                if response.status_code==401:
                    r=await client.post("/v1/auth/login",json={"tenant":tenant,"username":"analyst","password":os.getenv("DEMO_PASSWORD","secureagent-demo")});r.raise_for_status();tokens[tenant]=r.json()["token"];continue
                response.raise_for_status()
                for run in response.json():
                    if run["state"]=="queued": await process(base,{"tenant":tenant,"run":run["id"]})
            await asyncio.sleep(5)

if __name__=="__main__":asyncio.run(main())
