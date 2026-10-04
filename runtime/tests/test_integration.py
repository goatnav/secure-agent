"""Runs against actual app-role PostgreSQL and the Compose gateway/worker."""
import os
import time
import httpx
import psycopg
import pytest

pytestmark = pytest.mark.skipif(not os.getenv("APP_DATABASE_URL"), reason="requires Compose verification profile")

def test_postgres_enforces_rls_and_append_only_audit():
    with psycopg.connect(os.environ["APP_DATABASE_URL"]) as conn:
        with conn.cursor() as c:
            c.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user")
            assert c.fetchone() == (False, False)
            c.execute("SELECT count(*) FROM identities")
            assert c.fetchone()[0] == 0  # No tenant context defaults to deny.
            c.execute("SELECT set_config('app.tenant_id','acme',true)")
            c.execute("SELECT DISTINCT tenant_id FROM identities")
            assert c.fetchall() == [("acme",)]
            c.execute("SELECT count(*) FROM identities WHERE tenant_id='orbit'")
            assert c.fetchone()[0] == 0
            c.execute("SELECT body->>'disable_count' FROM identities WHERE id='employee-438'")
            count = c.fetchone()[0]
            assert count in (None, "1"), "duplicate containment executed"
    for sql in ("UPDATE audit_events SET body=body", "DELETE FROM audit_events", "UPDATE policies SET body=body"):
        with psycopg.connect(os.environ["APP_DATABASE_URL"]) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql)
    with psycopg.connect(os.environ["APP_DATABASE_URL"]) as conn:
        conn.execute("SELECT set_config('app.tenant_id','acme',true)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO identities(tenant_id,id,body) VALUES('orbit','injected','{\"id\":\"injected\"}')")

def test_queued_investigation_is_processed_with_tenant_evidence():
    with httpx.Client(base_url=os.getenv("GATEWAY_URL","http://localhost:8080"),timeout=15) as client:
        password = os.getenv("DEMO_PASSWORD","secureagent-demo")
        login = client.post("/v1/auth/login",json={"tenant":"orbit","username":"analyst","password":password})
        login.raise_for_status(); headers={"Authorization":"Bearer "+login.json()["token"]}
        created = client.post("/v1/runs",headers=headers,json={"identity_id":"employee-438"})
        created.raise_for_status();rid=created.json()["id"]
        for _ in range(60):
            r=client.get(f"/v1/runs/{rid}",headers=headers);r.raise_for_status();run=r.json()
            if run["state"] in ("awaiting_approval","completed","failed"): break
            time.sleep(1)
        assert run["state"] == "awaiting_approval", run
        event_refs=[ref for finding in run["report"]["findings"] for ref in finding["references"] if ref.startswith("EVT-")]
        assert event_refs and all(ref.startswith("EVT-orbit-") for ref in event_refs)
        path=f"/v1/approvals/{run['approval_id']}/decision"
        assert client.post(path,headers=headers,json={"decision":"approve"}).status_code==403
        login=client.post("/v1/auth/login",json={"tenant":"orbit","username":"approver","password":password});login.raise_for_status()
        decision=client.post(path,headers={"Authorization":"Bearer "+login.json()["token"]},json={"decision":"reject"})
        decision.raise_for_status();assert decision.json()["state"]=="rejected"
