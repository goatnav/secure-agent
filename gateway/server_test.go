package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	s       *Server
	handler http.Handler
	clock   time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{clock: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	store := NewMemory()
	if e := seed(store, "test-password"); e != nil {
		t.Fatal(e)
	}
	f.s = &Server{store: store, config: Config{JWTSecret: strings.Repeat("j", 32), WorkerSecret: strings.Repeat("w", 32), MaxTools: 25, MaxTokens: 20000, MaxCost: .5, ReservationCost: .218, Timeout: 300, Rate: 10000}, limiter: &localLimiter{counts: map[string]int{}}, now: func() time.Time { return f.clock }}
	f.handler = f.s.Handler()
	return f
}
func (f *fixture) token(tenant, role string) string {
	return sign(Claims{Sub: role, Tenant: tenant, Role: role, Iss: "secureagent", Aud: "gateway", Iat: f.clock.Unix(), Exp: f.clock.Add(time.Hour).Unix()}, f.s.config.JWTSecret)
}
func (f *fixture) request(method, path, token string, body any, headers map[string]string) (int, any) {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	var out any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}
func requireStatus(t *testing.T, got, want int, body any) {
	t.Helper()
	if got != want {
		t.Fatalf("status %d want %d: %#v", got, want, body)
	}
}
func (f *fixture) run(t *testing.T) (string, string) {
	t.Helper()
	status, b := f.request("POST", "/v1/runs", f.token("acme", "analyst"), Record{"identity_id": "employee-438"}, nil)
	requireStatus(t, status, 201, b)
	rid := str(Record(b.(map[string]any)), "id")
	status, b = f.request("POST", "/internal/runs/claim", "", Record{"tenant": "acme", "run": rid}, map[string]string{"X-Worker-Secret": f.s.config.WorkerSecret})
	requireStatus(t, status, 200, b)
	return rid, str(Record(b.(map[string]any)), "token")
}
func (f *fixture) tool(token, name string, args Record, key string) (int, any) {
	return f.request("POST", "/v1/tools/execute", token, Record{"tool": name, "arguments": args, "idempotency_key": key}, nil)
}
func (f *fixture) row(t *testing.T, tenant, table, id string) Record {
	t.Helper()
	var row Record
	e := f.s.store.Tenant(context.Background(), tenant, func(tx Tx) error { var e error; row, e = tx.Get(table, id); return e })
	if e != nil {
		t.Fatal(e)
	}
	return row
}
func (f *fixture) edit(t *testing.T, table, id string, fn func(Record)) {
	t.Helper()
	e := f.s.store.Tenant(context.Background(), "acme", func(tx Tx) error {
		r, e := tx.Get(table, id)
		if e != nil {
			return e
		}
		fn(r)
		return tx.Put(table, id, r)
	})
	if e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) approval(t *testing.T) (string, string) {
	rid, token := f.run(t)
	status, b := f.tool(token, "identity.disable", Record{"identity_id": "employee-438"}, "containment")
	requireStatus(t, status, 202, b)
	return rid, str(Record(b.(map[string]any)), "approval_id")
}

func TestAuthentication(t *testing.T) {
	f := setup(t)
	status, b := f.request("POST", "/v1/auth/login", "", Record{"tenant": "acme", "username": "analyst", "password": "test-password"}, nil)
	requireStatus(t, status, 200, b)
	for _, token := range []string{"", f.token("acme", "analyst") + "x", sign(Claims{Sub: "analyst", Tenant: "acme", Role: "analyst", Iss: "wrong", Aud: "gateway", Exp: f.clock.Add(time.Hour).Unix()}, f.s.config.JWTSecret), sign(Claims{Sub: "analyst", Tenant: "acme", Role: "analyst", Iss: "secureagent", Aud: "gateway", Exp: f.clock.Unix()}, f.s.config.JWTSecret)} {
		status, b = f.request("GET", "/v1/runs", token, nil, nil)
		requireStatus(t, status, 401, b)
	}
	status, b = f.request("POST", "/v1/auth/login", "", Record{"tenant": "acme", "username": "analyst", "password": "wrong"}, nil)
	requireStatus(t, status, 401, b)
}
func TestTenantBoundaries(t *testing.T) {
	f := setup(t)
	rid, token := f.run(t)
	status, b := f.request("GET", "/v1/runs/"+rid, f.token("orbit", "analyst"), nil, nil)
	requireStatus(t, status, 404, b)
	status, b = f.request("GET", "/v1/runs", f.token("acme", "analyst"), nil, map[string]string{"X-Tenant-ID": "orbit"})
	requireStatus(t, status, 403, b)
	status, b = f.tool(token, "siem.search", Record{"identity_id": "employee-438"}, "events")
	requireStatus(t, status, 200, b)
	events := obj(Record(b.(map[string]any)), "data")
	_ = events
	data := b.(map[string]any)["data"].([]any)
	for _, v := range data {
		if !strings.Contains(v.(map[string]any)["id"].(string), "acme") {
			t.Fatal("cross tenant event")
		}
	}
}
func TestDenyByDefaultAndSchemas(t *testing.T) {
	cases := []struct {
		name string
		args Record
		key  string
		want int
	}{
		{"identity.delete", Record{"identity_id": "employee-438"}, "delete", 403},
		{"get_all_credentials", Record{}, "exfil", 403},
		{"siem.search", Record{"identity_id": "employee-438", "tenant": "orbit"}, "invalid", 403},
		{"siem.search", Record{"identity_id": "' OR 1=1"}, "sql", 403},
		{"identity.disable", Record{"identity_id": "employee-999"}, "lateral", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name+tc.key, func(t *testing.T) {
			f := setup(t)
			_, token := f.run(t)
			status, b := f.tool(token, tc.name, tc.args, tc.key)
			requireStatus(t, status, tc.want, b)
			status, b = f.request("GET", "/v1/audit", f.token("acme", "analyst"), nil, nil)
			requireStatus(t, status, 200, b)
			found := false
			for _, row := range b.([]any) {
				if row.(map[string]any)["decision"] == "deny" {
					found = true
				}
			}
			if !found {
				t.Fatal("denial missing from audit")
			}
		})
	}
	f := setup(t)
	status, b := f.tool(f.token("acme", "analyst"), "identity.read", Record{"identity_id": "employee-438"}, "human")
	requireStatus(t, status, 403, b)
}
func TestIdempotencyAndToolBudget(t *testing.T) {
	f := setup(t)
	rid, token := f.run(t)
	for i := 0; i < 2; i++ {
		status, b := f.tool(token, "siem.search", Record{"identity_id": "employee-438"}, "events")
		requireStatus(t, status, 200, b)
	}
	if num(f.row(t, "acme", "runs", rid), "tool_calls") != 1 {
		t.Fatal("duplicate read spent budget")
	}
	status, b := f.tool(token, "identity.read", Record{"identity_id": "employee-438"}, "events")
	requireStatus(t, status, 403, b)
	f.s.config.MaxTools = 1
	status, b = f.tool(token, "identity.read", Record{"identity_id": "employee-438"}, "identity")
	requireStatus(t, status, 403, b)
}
func TestApprovalExactlyOnce(t *testing.T) {
	f := setup(t)
	rid, aid := f.approval(t)
	status, b := f.request("POST", "/v1/approvals/"+aid+"/decision", f.token("acme", "analyst"), Record{"decision": "approve"}, nil)
	requireStatus(t, status, 403, b)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, b := f.request("POST", "/v1/approvals/"+aid+"/decision", f.token("acme", "approver"), Record{"decision": "approve"}, nil)
			if status != 200 {
				t.Errorf("concurrent decision: %d %#v", status, b)
			}
		}()
	}
	wg.Wait()
	identity := f.row(t, "acme", "identities", "employee-438")
	if identity["disabled"] != true || num(identity, "disable_count") != 1 {
		t.Fatal("mutation not exactly once")
	}
	if str(f.row(t, "acme", "runs", rid), "state") != "completed" {
		t.Fatal("run not completed")
	}
}
func TestApprovalBindingAndExpiry(t *testing.T) {
	for _, scenario := range []string{"self", "expiry", "arguments", "policy", "cancel", "cross-tenant"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			rid, aid := f.approval(t)
			tenant := "acme"
			switch scenario {
			case "self":
				f.edit(t, "approvals", aid, func(a Record) { a["requester"] = "approver" })
			case "expiry":
				f.clock = f.clock.Add(2 * time.Hour)
			case "arguments":
				f.edit(t, "approvals", aid, func(a Record) { a["arguments"] = Record{"identity_id": "employee-999"} })
			case "policy":
				f.edit(t, "agents", "incident-response", func(a Record) { a["policy_version"] = "v2" })
			case "cancel":
				status, b := f.request("POST", "/v1/runs/"+rid+"/cancel", f.token("acme", "analyst"), Record{}, nil)
				requireStatus(t, status, 200, b)
			case "cross-tenant":
				tenant = "orbit"
			}
			status, b := f.request("POST", "/v1/approvals/"+aid+"/decision", f.token(tenant, "approver"), Record{"decision": "approve"}, nil)
			want := 403
			if scenario == "cross-tenant" {
				want = 404
			}
			requireStatus(t, status, want, b)
			if f.row(t, "acme", "identities", "employee-438")["disabled"] != false {
				t.Fatal("unsafe mutation")
			}
		})
	}
}
func TestApprovalRejection(t *testing.T) {
	f := setup(t)
	_, aid := f.approval(t)
	status, b := f.request("POST", "/v1/approvals/"+aid+"/decision", f.token("acme", "approver"), Record{"decision": "reject"}, nil)
	requireStatus(t, status, 200, b)
	if f.row(t, "acme", "identities", "employee-438")["disabled"] != false {
		t.Fatal("rejected mutation executed")
	}
}
func TestLeaseRecoveryAndFencing(t *testing.T) {
	f := setup(t)
	rid, old := f.run(t)
	status, b := f.request("POST", "/internal/runs/claim", "", Record{"tenant": "acme", "run": rid}, map[string]string{"X-Worker-Secret": f.s.config.WorkerSecret})
	requireStatus(t, status, 409, b)
	f.clock = f.clock.Add(91 * time.Second)
	status, b = f.request("POST", "/internal/runs/claim", "", Record{"tenant": "acme", "run": rid}, map[string]string{"X-Worker-Secret": f.s.config.WorkerSecret})
	requireStatus(t, status, 200, b)
	fresh := str(Record(b.(map[string]any)), "token")
	status, b = f.tool(old, "siem.search", Record{"identity_id": "employee-438"}, "old")
	requireStatus(t, status, 403, b)
	status, b = f.tool(fresh, "siem.search", Record{"identity_id": "employee-438"}, "fresh")
	requireStatus(t, status, 200, b)
}
func TestModelAndElapsedBudgets(t *testing.T) {
	f := setup(t)
	_, token := f.run(t)
	f.s.config.MaxTokens = 100
	status, b := f.request("POST", "/internal/model/reserve", token, Record{"idempotency_key": "assessment"}, nil)
	requireStatus(t, status, 403, b)
	f.s.config.MaxTokens = 20000
	f.s.config.MaxCost = .01
	status, b = f.request("POST", "/internal/model/reserve", token, Record{"idempotency_key": "assessment"}, nil)
	requireStatus(t, status, 403, b)
	f.s.config.MaxCost = .5
	status, b = f.request("POST", "/internal/model/reserve", token, Record{"idempotency_key": "assessment"}, nil)
	requireStatus(t, status, 200, b)
	status, b = f.request("POST", "/internal/model/reserve", token, Record{"idempotency_key": "assessment"}, nil)
	requireStatus(t, status, 403, b)
	f.s.config.Timeout = 60
	f.clock = f.clock.Add(61 * time.Second)
	status, b = f.tool(token, "siem.search", Record{"identity_id": "employee-438"}, "expired")
	requireStatus(t, status, 403, b)
}
func TestGroundingRejectsInventedReferences(t *testing.T) {
	f := setup(t)
	_, token := f.run(t)
	report := Report{Summary: "Injected", Findings: []Finding{{Severity: "high", Summary: "Invented", References: []string{"OTHER-TENANT"}}}, Timeline: []string{}, RecommendDisable: true}
	status, b := f.request("POST", "/internal/runs/result", token, Record{"report": report}, nil)
	requireStatus(t, status, 403, b)
}

func TestMalformedToolRequestIsAudited(t *testing.T) {
	f := setup(t)
	_, token := f.run(t)
	status, b := f.request("POST", "/v1/tools/execute", token, Record{"tool": "identity.read", "arguments": Record{"identity_id": "employee-438"}, "idempotency_key": "schema", "override_policy": true}, nil)
	requireStatus(t, status, 400, b)
	status, b = f.request("GET", "/v1/audit", f.token("acme", "analyst"), nil, nil)
	requireStatus(t, status, 200, b)
	found := false
	for _, v := range b.([]any) {
		row := Record(v.(map[string]any))
		if str(row, "outcome") == "invalid request schema" {
			found = true
		}
	}
	if !found {
		t.Fatal("schema denial was not audited")
	}
}

func TestWorkerImpersonationAndBinding(t *testing.T) {
	f := setup(t)
	rid, token := f.run(t)
	status, b := f.request("POST", "/internal/runs/claim", "", Record{"tenant": "acme", "run": rid}, map[string]string{"X-Worker-Secret": "forged"})
	requireStatus(t, status, 401, b)
	c, e := verify(token, f.s.config.JWTSecret, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	c.Run = "another-run"
	status, b = f.tool(sign(c, f.s.config.JWTSecret), "identity.read", Record{"identity_id": "employee-438"}, "impersonation")
	requireStatus(t, status, 403, b)
}
func TestTransactionRollbackAndAppendOnlyAudit(t *testing.T) {
	s := NewMemory()
	e := s.Tenant(context.Background(), "acme", func(tx Tx) error { _ = tx.Insert("identities", "test", Record{}); return errors.New("rollback") })
	if e == nil {
		t.Fatal("expected error")
	}
	_ = s.Tenant(context.Background(), "acme", func(tx Tx) error {
		if _, e := tx.Get("identities", "test"); e != errMissing {
			t.Fatal("failed transaction committed")
		}
		if e := tx.Put("audit_events", "a", Record{}); e == nil {
			t.Fatal("audit mutable")
		}
		return nil
	})
}

type brokenLimiter struct{}

func (brokenLimiter) Allow(context.Context, string, int) (bool, error) {
	return false, errors.New("redis down")
}
func TestRateLimitFailsClosed(t *testing.T) {
	f := setup(t)
	f.s.config.Rate = 1
	for _, want := range []int{200, 429} {
		status, b := f.request("GET", "/v1/runs", f.token("acme", "analyst"), nil, nil)
		requireStatus(t, status, want, b)
	}
	f.s.limiter = brokenLimiter{}
	status, b := f.request("GET", "/v1/runs", f.token("acme", "analyst"), nil, nil)
	requireStatus(t, status, 503, b)
}
