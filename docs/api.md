# HTTP interfaces

Browser clients use `http://localhost:3000/v1`. Direct gateway access is `http://localhost:8080/v1`. All routes except login require `Authorization: Bearer <JWT>`. Optional `X-Tenant-ID` must match the authenticated tenant. Internal routes cannot be forwarded by the FastAPI browser facade.

| Method / path | Principal | Input / behavior |
|---|---|---|
| POST `/v1/auth/login` | Public, rate-limited | `{"tenant":"acme","username":"analyst","password":"…"}`; returns token, tenant, role, username |
| GET `/v1/me` | Authenticated | Current signed principal |
| POST `/v1/runs` | Analyst | `{"identity_id":"employee-438"}`; returns durable queued run (201) |
| GET `/v1/runs` | Human | Latest 200 tenant-scoped runs |
| GET `/v1/runs/{id}` | Human or bound worker | Run, state, evidence, report, usage, budgets, approval reference |
| POST `/v1/runs/{id}/cancel` | Original analyst | Cancels executable run; terminal runs conflict |
| GET `/v1/approvals` | Human | Tenant-scoped pending and decided approvals |
| POST `/v1/approvals/{id}/decision` | Independent approver | `{"decision":"approve"}` or `reject`; revalidates and commits action atomically |
| GET `/v1/audit` | Human | Latest 200 tenant-scoped sanitized audit events |
| GET `/v1/tools` | Authenticated | Static typed tool registry |
| POST `/v1/tools/execute` | Bound, actively leased worker | Tool, exactly one typed argument, run-local idempotency key |
| POST `/internal/runs/claim` | Trusted worker service | `X-Worker-Secret`; `{"tenant":"acme","run":"…"}`; returns 5-minute run/agent/lease JWT |
| POST `/internal/model/reserve` | Bound worker | `{"idempotency_key":"assessment"}`; server-computed conservative reservation |
| POST `/internal/runs/result` | Bound worker | Validated `report` + sanitized `usage`, or non-sensitive failure marker |
| GET `/healthz` | Local infrastructure | Process liveness |
| GET `/metrics` | Local infrastructure | Prometheus-format request latency histogram |

Example worker tool request:

```json
{
  "tool": "siem.search",
  "arguments": {"identity_id": "employee-438"},
  "idempotency_key": "events"
}
```

Allowed reads return `{"decision":"allow","data":…, "references":[…]}`. Mutation proposals return 202 with `{"decision":"approval_required","approval_id":"…"}`. A changed request under an existing key is denied. Calls without a valid active worker lease cannot execute tools.

Reports contain `summary`, `findings` (`severity`, `summary`, `references`), `timeline`, and `recommend_disable`. All finding references must have been retrieved through this run. Report structure is bounded and validated in Python and Go. State transitions are `queued → running → awaiting_approval → completed` or `running → completed`; failure/cancellation can terminate active runs. Expired pending approvals fail the run. Rejecting a proposal completes the run with `remediation=rejected`.

Errors use `{"error":"…"}`: 400 malformed schema, 401 invalid credentials, 403 policy/binding/role/budget denial, 404 tenant-scoped missing record, 409 state/idempotent decision conflict, 410 exhausted claim, 429 rate limit, and 503 unavailable storage or limiter. Raw upstream/provider exception text is not exposed.
