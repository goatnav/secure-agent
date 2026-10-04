"""Reproducible HTTP acceptance walkthrough, with no credential logging."""
import argparse
import json
import os
import time
from pathlib import Path
import httpx

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:3000")
    parser.add_argument("--decision", choices=["approve", "reject"], default="approve")
    args = parser.parse_args()
    client = httpx.Client(base_url=args.base, timeout=30)
    password = os.getenv("DEMO_PASSWORD", "secureagent-demo")
    def login(tenant, username):
        result = client.post("/v1/auth/login", json={"tenant":tenant,"username":username,"password":password})
        result.raise_for_status()
        return {"Authorization": "Bearer " + result.json()["token"]}
    analyst, approver, orbit = login("acme","analyst"), login("acme","approver"), login("orbit","analyst")
    created = client.post("/v1/runs", headers=analyst, json={"identity_id":"employee-438"})
    created.raise_for_status()
    run_id = created.json()["id"]
    assert client.get(f"/v1/runs/{run_id}", headers=orbit).status_code == 404
    assert client.get("/v1/runs", headers={**analyst,"X-Tenant-ID":"orbit"}).status_code == 403
    for _ in range(90):
        response = client.get(f"/v1/runs/{run_id}", headers=analyst)
        response.raise_for_status()
        run = response.json()
        if run["state"] in ("awaiting_approval","completed","failed"):
            break
        time.sleep(1)
    assert run["state"] != "failed", run.get("error")
    assert run.get("report",{}).get("findings"), "No evidence-backed report"
    if run["state"] == "awaiting_approval":
        approval = run["approval_id"]
        path = f"/v1/approvals/{approval}/decision"
        assert client.post(path, headers=analyst,json={"decision":"approve"}).status_code == 403
        for _ in range(2):
            result = client.post(path,headers=approver,json={"decision":args.decision})
            result.raise_for_status()
        assert client.get(f"/v1/runs/{run_id}",headers=analyst).json()["state"] == "completed"
    else:
        assert run["state"] == "completed", "Investigation timed out"
    audit = client.get("/v1/audit",headers=analyst).json()
    assert any(event["decision"] == "deny" for event in audit)
    print(json.dumps({"run":run_id,"status":"passed","checks":["tenant isolation","tenant spoofing denied","cited report","independent approval or already-contained identity","idempotent decision","denial audit"]},indent=2))
    client.close()

if __name__ == "__main__":
    main()
