# Security and reliability boundaries

## Threat model

Untrusted actors include authenticated analysts requesting forbidden actions, model output, poisoned retrieved guidance, forged tokens, malicious tool arguments, cross-tenant identifiers, duplicate queue deliveries, and stale workers. The gateway is the authorization boundary. Database administrators, the gateway signing key, the worker service credential, and host/container administrators are trusted.

A model proposes a report and a containment recommendation. It cannot authenticate as an approver, modify policies, select another tenant, bypass the gateway, or execute a mutation. Model assessment occurs in a fixed workflow, rather than an unrestricted autonomous tool loop. Strict output schemas and valid evidence IDs constrain structure and grounding; they do not prove a model's conclusions are correct. Humans review containment recommendations.

## Enforcement

JWT verification fixes HS256, issuer, audience, expiry, role, and worker binding. Tenant identity comes from signed claims; conflicting headers are rejected and audited. The app's SQL queries explicitly include tenant IDs, and forced PostgreSQL RLS supplies a second boundary. Transaction-local `set_config` prevents pooled connections leaking tenant context.

Every registered operation requires an explicit policy grant. Deletion and unknown tools are denied. Identity reads and disablement are bound to the investigated identity; asset, threat, and guidance reads remain tenant-scoped under the agent's grants. Tool arguments accept only one named identifier and reject extra fields. Redis errors fail closed. Rate limits use atomic fixed windows, not a token bucket; bursts can cross window boundaries.

Approvals bind to persisted canonical argument hashes and an independently persisted proposed action. The gateway checks the active agent policy, original requester, run state, action, tenant, and expiration at execution time. Simulated identity disablement and its execution/audit records use the same transaction, serialized per tenant. This exactly-once property applies to the local database mutation. A future external IAM integration must add remote idempotency or reconciliation for uncertain outcomes; a database transaction alone cannot provide that guarantee.

Audit rows are append-only for the application role. PostgreSQL superusers can still alter them. This is not a cryptographic or externally anchored tamper-proof ledger. Audit arguments contain validated identifiers only, and telemetry avoids model text, tool bodies, login passwords, tokens, and API keys. Unauthenticated token failures have no trustworthy tenant and return 401 without a tenant audit entry; infrastructure logs should be used for production authentication monitoring.

The gateway app role can initialize policies but cannot update existing policy versions. There is no public policy-management API. Changes require an administrator to insert a new version and update the agent's active version; pending approvals pinned to old versions will fail revalidation. The worker service secret can mint credentials for any seeded run and is a trusted service credential, not a tenant-specific user credential. Compose gives the worker neither JWT signing keys nor database credentials; model credentials are available only to the worker. The verification container receives only the app-role database credential.

## Recovery

Run creation is durable before stream dispatch. The dispatcher re-enqueues executable runs when their dispatch/lease interval permits. Enqueue can precede a failed database commit, so delivery is at least once. Redis Streams retains unacknowledged entries for reclaim. Claims serialize in PostgreSQL, allow three attempts within the elapsed-time budget, and fence stale worker credentials.

Read outputs are cached by a run-local idempotency key bound to tool and canonical arguments. A persisted assessment is a checkpoint, so a recovering worker can propose containment without paying for another assessment. If a worker dies during a paid model call before saving the report, the consumed reservation prevents another call; recovery fails the run safely and the user may create a new run. No automatic mutation retry occurs on transport uncertainty. A committed pending approval remains durable even if the worker never receives its response.

Cancellation invalidates worker execution and pending approval execution through run-state checks. Investigation timeouts become failed runs. Approvals expire after one hour independently of the five-minute investigation budget. The dispatcher marks expired approvals and their runs accordingly.

## Operational limitations

Local demo authentication lacks SSO, password rotation, refresh/revocation, and TLS termination. JWTs stay in dashboard memory, with a one-hour user lifetime. Exposed ports bind loopback; service-to-service network access is trusted. Redis and PostgreSQL credentials and network hardening must change for a shared deployment. Do not connect real identity services using this demo configuration.

Security decisions serialize per tenant, and list endpoints show at most the latest 200 records without pagination. This is intentionally modest capacity, not a high-scale claim. Jaeger uses ephemeral storage. HTTP histograms use status labels, without sensitive identifiers. Model input projection strips unknown fields and common secret patterns; it is defense in depth for synthetic data, not a comprehensive enterprise DLP system. Cost reservations use operator-supplied price estimates and are not guaranteed actual billing caps.
