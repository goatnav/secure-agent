package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

type Limiter interface {
	Allow(context.Context, string, int) (bool, error)
}
type localLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	minute int64
}

func (l *localLimiter) Allow(ctx context.Context, key string, max int) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	minute := time.Now().Unix() / 60
	if l.minute != minute {
		l.minute = minute
		l.counts = map[string]int{}
	}
	l.counts[key]++
	return l.counts[key] <= max, nil
}

type Config struct {
	JWTSecret, WorkerSecret            string
	MaxTools, MaxTokens, Timeout, Rate int
	MaxCost, ReservationCost           float64
}
type Server struct {
	store   Store
	limiter Limiter
	config  Config
	now     func() time.Time
}
type response struct {
	code int
	body any
}
type contextKey struct{}

func id() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func str(r Record, key string) string { s, _ := r[key].(string); return s }
func num(r Record, key string) float64 {
	switch n := r[key].(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}
func obj(r Record, key string) Record {
	switch v := r[key].(type) {
	case Record:
		return v
	case map[string]any:
		return Record(v)
	}
	return Record{}
}
func jsonHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func write(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := parseBody(w, r, out); err != nil {
		write(w, 400, Record{"error": "invalid request schema"})
		return false
	}
	return true
}
func parseBody(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errors.New("invalid request schema")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid request body")
	}
	return nil
}
func (s *Server) audit(tx Tx, c Claims, r *http.Request, tool, decision, outcome string, args Record, approval string) error {
	// Only validated identifiers are passed as args, never raw request bodies, credentials or model text.
	traceID := trace.SpanContextFromContext(r.Context()).TraceID().String()
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("tenant.id", c.Tenant), attribute.String("run.id", c.Run), attribute.String("tool.name", tool), attribute.String("policy.decision", decision), attribute.String("operation.outcome", outcome))
	return tx.Insert("audit_events", id(), Record{"at": s.now().UTC().Format(time.RFC3339Nano), "actor": c.Sub, "tenant": c.Tenant, "run": c.Run, "tool": tool, "decision": decision, "outcome": outcome, "arguments": args, "approval": approval, "trace_id": traceID})
}
func (s *Server) transact(w http.ResponseWriter, r *http.Request, c Claims, f func(Tx) (response, error)) {
	out := response{}
	e := s.store.Tenant(r.Context(), c.Tenant, func(tx Tx) error { var e error; out, e = f(tx); return e })
	if e != nil {
		write(w, 503, Record{"error": "storage unavailable"})
		return
	}
	write(w, out.code, out.body)
}
func (s *Server) deny(tx Tx, c Claims, r *http.Request, tool, reason string, args Record) (response, error) {
	e := s.audit(tx, c, r, tool, "deny", reason, args, "")
	return response{403, Record{"error": reason}}, e
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	meter := &metrics{requests: map[string]*metricValue{}}
	mux.HandleFunc("GET /metrics", meter.serve)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { write(w, 200, Record{"status": "ok"}) })
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /internal/runs/claim", s.claim)
	mux.Handle("GET /v1/me", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(contextKey{}).(Claims)
		write(w, 200, Record{"username": c.Sub, "tenant": c.Tenant, "role": c.Role})
	})))
	mux.Handle("POST /v1/runs", s.auth(http.HandlerFunc(s.createRun)))
	mux.Handle("GET /v1/runs", s.auth(http.HandlerFunc(s.list("runs"))))
	mux.Handle("GET /v1/runs/{id}", s.auth(http.HandlerFunc(s.getRun)))
	mux.Handle("POST /v1/runs/{id}/cancel", s.auth(http.HandlerFunc(s.cancel)))
	mux.Handle("GET /v1/approvals", s.auth(http.HandlerFunc(s.list("approvals"))))
	mux.Handle("POST /v1/approvals/{id}/decision", s.auth(http.HandlerFunc(s.decide)))
	mux.Handle("GET /v1/audit", s.auth(http.HandlerFunc(s.list("audit_events"))))
	mux.Handle("GET /v1/tools", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { write(w, 200, toolRegistry) })))
	mux.Handle("POST /v1/tools/execute", s.auth(http.HandlerFunc(s.execute)))
	mux.Handle("POST /internal/model/reserve", s.auth(http.HandlerFunc(s.reserve)))
	mux.Handle("POST /internal/runs/result", s.auth(http.HandlerFunc(s.result)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("secureagent/gateway").Start(parent, "http.request")
		defer span.End()
		span.SetAttributes(attribute.String("http.request.method", r.Method))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		started := time.Now()
		measured := &measuredWriter{ResponseWriter: w}
		mux.ServeHTTP(measured, r.WithContext(ctx))
		meter.observe(measured.status, time.Since(started))
		span.SetAttributes(attribute.Int("http.response.status_code", measured.status))
	})
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, e := verify(token, s.config.JWTSecret, s.now())
		if e != nil {
			write(w, 401, Record{"error": "invalid credentials"})
			return
		}
		if tenant := r.Header.Get("X-Tenant-ID"); tenant != "" && tenant != c.Tenant {
			s.transact(w, r, c, func(tx Tx) (response, error) {
				return s.deny(tx, c, r, "http.request", "tenant header mismatch", Record{})
			})
			return
		}
		allowed, e := s.limiter.Allow(r.Context(), c.Tenant+":"+c.Sub, s.config.Rate)
		if e != nil {
			write(w, 503, Record{"error": "rate limiter unavailable"})
			return
		}
		if !allowed {
			s.transact(w, r, c, func(tx Tx) (response, error) {
				e := s.audit(tx, c, r, "http.request", "deny", "rate limit", Record{}, "")
				return response{429, Record{"error": "rate limit exceeded"}}, e
			})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, c)))
	})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tenant   string `json:"tenant"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) > 128 || len(in.Username) > 64 || (in.Tenant != "acme" && in.Tenant != "orbit") {
		write(w, 401, Record{"error": "invalid credentials"})
		return
	}
	// Tenant-wide login limit avoids trusting proxy headers or attacker-selected usernames.
	ok, e := s.limiter.Allow(r.Context(), "login:"+in.Tenant, 30)
	if e != nil {
		write(w, 503, Record{"error": "rate limiter unavailable"})
		return
	}
	if !ok {
		write(w, 429, Record{"error": "login rate limit exceeded"})
		return
	}
	c := Claims{Tenant: in.Tenant, Sub: in.Username}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		u, e := tx.Get("users", in.Username)
		if e != nil && e != errMissing {
			return response{}, e
		}
		if e != nil || bcrypt.CompareHashAndPassword([]byte(str(u, "password_hash")), []byte(in.Password)) != nil {
			c.Sub = "anonymous"
			e = s.audit(tx, c, r, "auth.login", "deny", "invalid credentials", Record{}, "")
			return response{401, Record{"error": "invalid credentials"}}, e
		}
		c.Role = str(u, "role")
		c.Iss = "secureagent"
		c.Aud = "gateway"
		c.Iat = s.now().Unix()
		c.Exp = s.now().Add(time.Hour).Unix()
		e = s.audit(tx, c, r, "auth.login", "allow", "authenticated", Record{}, "")
		return response{200, Record{"token": sign(c, s.config.JWTSecret), "tenant": c.Tenant, "role": c.Role, "username": c.Sub}}, e
	})
}
func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	var in struct {
		Identity string `json:"identity_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		if c.Role != "analyst" {
			return s.deny(tx, c, r, "run.create", "analyst role required", Record{})
		}
		if _, e := tx.Get("identities", in.Identity); e == errMissing {
			return response{404, Record{"error": "identity not found"}}, nil
		} else if e != nil {
			return response{}, e
		}
		a, e := tx.Get("agents", "incident-response")
		if e != nil {
			return response{}, e
		}
		rid := id()
		traceCarrier := propagation.MapCarrier{}
		otel.GetTextMapPropagator().Inject(r.Context(), traceCarrier)
		run := Record{"identity_id": in.Identity, "requester": c.Sub, "agent": "incident-response", "policy_version": str(a, "policy_version"), "state": "queued", "created_at": s.now().UTC().Format(time.RFC3339Nano), "created_unix": s.now().Unix(), "tool_calls": 0, "tokens_reserved": 0, "cost_reserved": 0, "evidence": []string{}, "attempts": 0, "lease_until": 0}
		run["traceparent"] = traceCarrier["traceparent"]
		if e = tx.Insert("runs", rid, run); e != nil {
			return response{}, e
		}
		c.Run = rid
		e = s.audit(tx, c, r, "run.create", "allow", "queued", Record{"identity_id": in.Identity}, "")
		run["id"] = rid
		return response{201, run}, e
	})
}
func (s *Server) list(table string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := r.Context().Value(contextKey{}).(Claims)
		s.transact(w, r, c, func(tx Tx) (response, error) {
			if c.Role == "worker" {
				return s.deny(tx, c, r, "records.list", "human role required", Record{})
			}
			rows, e := tx.List(table)
			sort.Slice(rows, func(i, j int) bool {
				return str(rows[i], "at")+str(rows[i], "created_at") > str(rows[j], "at")+str(rows[j], "created_at")
			})
			if len(rows) > 200 {
				rows = rows[:200]
			}
			return response{200, rows}, e
		})
	}
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	s.transact(w, r, c, func(tx Tx) (response, error) {
		if c.Role == "worker" && c.Run != r.PathValue("id") {
			return s.deny(tx, c, r, "run.read", "run credential mismatch", Record{})
		}
		row, e := tx.Get("runs", r.PathValue("id"))
		if e == errMissing {
			return response{404, Record{"error": "run not found"}}, nil
		}
		if e != nil {
			return response{}, e
		}
		return response{200, row}, nil
	})
}
func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	s.transact(w, r, c, func(tx Tx) (response, error) {
		run, e := tx.Get("runs", r.PathValue("id"))
		if e == errMissing {
			return response{404, Record{"error": "run not found"}}, nil
		}
		if e != nil {
			return response{}, e
		}
		if c.Role != "analyst" || c.Sub != str(run, "requester") {
			return s.deny(tx, c, r, "run.cancel", "requester required", Record{})
		}
		state := str(run, "state")
		if state == "completed" || state == "failed" {
			return response{409, Record{"error": "run is terminal"}}, nil
		}
		run["state"] = "cancelled"
		e = tx.Put("runs", str(run, "id"), run)
		if e != nil {
			return response{}, e
		}
		c.Run = str(run, "id")
		e = s.audit(tx, c, r, "run.cancel", "allow", "cancelled", Record{}, "")
		return response{200, run}, e
	})
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	// This service credential can mint run-scoped credentials, but cannot execute tools itself.
	if !constantEqual(r.Header.Get("X-Worker-Secret"), s.config.WorkerSecret) {
		write(w, 401, Record{"error": "invalid worker credentials"})
		return
	}
	var in struct {
		Tenant string `json:"tenant"`
		Run    string `json:"run"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Tenant != "acme" && in.Tenant != "orbit" {
		write(w, 400, Record{"error": "unknown tenant"})
		return
	}
	c := Claims{Tenant: in.Tenant, Sub: "runtime", Role: "worker", Run: in.Run, Agent: "incident-response"}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		run, e := tx.Get("runs", in.Run)
		if e == errMissing {
			return response{404, Record{"error": "run not found"}}, nil
		}
		if e != nil {
			return response{}, e
		}
		state := str(run, "state")
		if state != "queued" && state != "running" {
			return response{409, Record{"error": "run not executable"}}, nil
		}
		if num(run, "lease_until") > float64(s.now().Unix()) {
			return response{409, Record{"error": "run already leased"}}, nil
		}
		if s.expired(run) || num(run, "attempts") >= 3 {
			run["state"] = "failed"
			run["error"] = "runtime recovery or time budget exhausted"
			e = tx.Put("runs", in.Run, run)
			return response{410, Record{"error": "run exhausted"}}, e
		}
		c.Lease = id()
		c.Iss = "secureagent"
		c.Aud = "gateway"
		c.Iat = s.now().Unix()
		c.Exp = s.now().Add(5 * time.Minute).Unix()
		run["lease"] = c.Lease
		run["lease_until"] = s.now().Add(90 * time.Second).Unix()
		run["state"] = "running"
		run["attempts"] = num(run, "attempts") + 1
		if e = tx.Put("runs", in.Run, run); e != nil {
			return response{}, e
		}
		e = s.audit(tx, c, r, "run.claim", "allow", "running", Record{}, "")
		return response{200, Record{"token": sign(c, s.config.JWTSecret), "run": run}}, e
	})
}
func constantEqual(a, b string) bool {
	if b == "" {
		return false
	}
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
func (s *Server) expired(run Record) bool {
	return s.now().Unix()-int64(num(run, "created_unix")) >= int64(s.config.Timeout)
}
func (s *Server) workerRun(tx Tx, c Claims) (Record, error) {
	if c.Role != "worker" {
		return nil, errors.New("worker role required")
	}
	run, e := tx.Get("runs", c.Run)
	if e != nil {
		return nil, e
	}
	if str(run, "state") != "running" || str(run, "lease") != c.Lease || num(run, "lease_until") <= float64(s.now().Unix()) {
		return nil, errors.New("inactive run lease")
	}
	if s.expired(run) {
		return nil, errors.New("elapsed-time budget exhausted")
	}
	return run, nil
}
func (s *Server) reserve(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	var in struct {
		Key string `json:"idempotency_key"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		run, e := s.workerRun(tx, c)
		if e != nil {
			return s.deny(tx, c, r, "model.reserve", e.Error(), Record{})
		}
		if in.Key != "assessment" {
			return s.deny(tx, c, r, "model.reserve", "invalid reservation", Record{})
		}
		// Never reuse a model reservation after worker recovery: a provider call might already have spent it.
		if _, ok := run["model_reserved"]; ok {
			return s.deny(tx, c, r, "model.reserve", "model reservation already consumed", Record{})
		}
		if num(run, "tokens_reserved")+18200 > float64(s.config.MaxTokens) || num(run, "cost_reserved")+s.config.ReservationCost > s.config.MaxCost {
			return s.deny(tx, c, r, "model.reserve", "model budget exhausted", Record{})
		}
		run["tokens_reserved"] = num(run, "tokens_reserved") + 18200
		run["cost_reserved"] = num(run, "cost_reserved") + s.config.ReservationCost
		run["model_reserved"] = true
		if e = tx.Put("runs", c.Run, run); e != nil {
			return response{}, e
		}
		e = s.audit(tx, c, r, "model.reserve", "allow", "budget reserved", Record{}, "")
		return response{200, Record{"reserved": true}}, e
	})
}

type ToolSpec struct {
	Argument string `json:"argument"`
	Mutation bool   `json:"mutation"`
}

var toolRegistry = map[string]ToolSpec{"siem.search": {"identity_id", false}, "identity.read": {"identity_id", false}, "asset.lookup": {"asset_id", false}, "threat.lookup": {"indicator", false}, "guidance.read": {"policy_id", false}, "identity.disable": {"identity_id", true}}

type toolRequest struct {
	Tool      string `json:"tool"`
	Arguments Record `json:"arguments"`
	Key       string `json:"idempotency_key"`
}

func validIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (s *Server) policy(tx Tx, run Record, tool string) (string, error) {
	agent, e := tx.Get("agents", str(run, "agent"))
	if e != nil {
		return "deny", e
	}
	if active, _ := agent["active"].(bool); !active || str(agent, "policy_version") != str(run, "policy_version") {
		return "deny", nil
	}
	p, e := tx.Get("policies", str(run, "policy_version"))
	if e != nil {
		return "deny", e
	}
	decision := str(obj(p, "permissions"), tool)
	if decision != "allow" && decision != "approval" {
		decision = "deny"
	}
	return decision, nil
}
func (s *Server) execute(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	var in toolRequest
	if parseBody(w, r, &in) != nil {
		s.transact(w, r, c, func(tx Tx) (response, error) {
			e := s.audit(tx, c, r, "tool.execute", "deny", "invalid request schema", Record{}, "")
			return response{400, Record{"error": "invalid request schema"}}, e
		})
		return
	}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		run, e := s.workerRun(tx, c)
		if e != nil {
			return s.deny(tx, c, r, "tool.execute", e.Error(), Record{})
		}
		spec, known := toolRegistry[in.Tool]
		if !known {
			return s.deny(tx, c, r, "tool.execute", "tool not registered", Record{})
		}
		if len(in.Arguments) != 1 || !validIdentifier(str(in.Arguments, spec.Argument)) || !validIdentifier(in.Key) {
			return s.deny(tx, c, r, in.Tool, "invalid tool arguments", Record{})
		}
		args := Record{spec.Argument: str(in.Arguments, spec.Argument)}
		binding := jsonHash(Record{"tool": in.Tool, "arguments": args})
		executionID := c.Run + "-" + in.Key
		if existing, e := tx.Get("tool_executions", executionID); e == nil {
			if str(existing, "binding") != binding {
				return s.deny(tx, c, r, in.Tool, "idempotency key binding mismatch", args)
			}
			return response{200, obj(existing, "response")}, nil
		} else if e != errMissing {
			return response{}, e
		}
		if num(run, "tool_calls") >= float64(s.config.MaxTools) {
			return s.deny(tx, c, r, in.Tool, "tool budget exhausted", args)
		}
		run["tool_calls"] = num(run, "tool_calls") + 1
		if e = tx.Put("runs", c.Run, run); e != nil {
			return response{}, e
		}
		decision, e := s.policy(tx, run, in.Tool)
		if e != nil {
			return response{}, e
		}
		if decision == "deny" {
			return s.deny(tx, c, r, in.Tool, "policy denied", args)
		}
		// Target binding contains model-suggested lateral movement within the tenant too.
		if spec.Argument == "identity_id" && str(args, "identity_id") != str(run, "identity_id") {
			return s.deny(tx, c, r, in.Tool, "identity outside investigation", args)
		}
		if spec.Mutation {
			if decision != "approval" {
				return s.deny(tx, c, r, in.Tool, "mutation requires approval policy", args)
			}
			identity, e := tx.Get("identities", str(args, "identity_id"))
			if e == errMissing {
				return response{404, Record{"error": "identity not found"}}, nil
			}
			if e != nil {
				return response{}, e
			}
			if disabled, _ := identity["disabled"].(bool); disabled {
				return response{409, Record{"error": "identity already disabled"}}, nil
			}
			aid := id()
			action := Record{"run": c.Run, "tool": in.Tool, "arguments": args, "binding": binding, "requester": str(run, "requester"), "policy_version": str(run, "policy_version"), "expires_unix": s.now().Add(time.Hour).Unix(), "state": "pending", "created_at": s.now().UTC().Format(time.RFC3339Nano)}
			if e = tx.Insert("proposed_actions", aid, action); e != nil {
				return response{}, e
			}
			if e = tx.Insert("approvals", aid, action); e != nil {
				return response{}, e
			}
			run["state"] = "awaiting_approval"
			run["approval_id"] = aid
			if e = tx.Put("runs", c.Run, run); e != nil {
				return response{}, e
			}
			out := Record{"decision": "approval_required", "approval_id": aid}
			if e = tx.Insert("tool_executions", executionID, Record{"run": c.Run, "tool": in.Tool, "binding": binding, "response": out}); e != nil {
				return response{}, e
			}
			e = s.audit(tx, c, r, in.Tool, "approval_required", "pending", args, aid)
			return response{202, out}, e
		}
		output, refs, e := readTool(tx, in.Tool, args)
		if e == errMissing {
			ae := s.audit(tx, c, r, in.Tool, "allow", "not found", args, "")
			return response{404, Record{"error": "evidence not found"}}, ae
		}
		if e != nil {
			return response{}, e
		}
		evidence := stringList(run["evidence"])
		evidence = append(evidence, refs...)
		run["evidence"] = evidence
		if e = tx.Put("runs", c.Run, run); e != nil {
			return response{}, e
		}
		out := Record{"decision": "allow", "data": output, "references": refs}
		if e = tx.Insert("tool_executions", executionID, Record{"run": c.Run, "tool": in.Tool, "binding": binding, "response": out}); e != nil {
			return response{}, e
		}
		e = s.audit(tx, c, r, in.Tool, "allow", "executed", args, "")
		return response{200, out}, e
	})
}
func stringList(v any) []string {
	out := []string{}
	switch a := v.(type) {
	case []any:
		for _, s := range a {
			if x, ok := s.(string); ok {
				out = append(out, x)
			}
		}
	case []string:
		out = append(out, a...)
	}
	return out
}
func readTool(tx Tx, tool string, args Record) (any, []string, error) {
	table, key := "", ""
	switch tool {
	case "siem.search":
		rows, e := tx.List("events")
		out := []Record{}
		refs := []string{}
		for _, v := range rows {
			if str(v, "identity_id") == str(args, "identity_id") {
				out = append(out, v)
				refs = append(refs, str(v, "id"))
			}
		}
		sort.Slice(out, func(i, j int) bool { return str(out[i], "timestamp") < str(out[j], "timestamp") })
		return out, refs, e
	case "identity.read":
		table, key = "identities", "identity_id"
	case "asset.lookup":
		table, key = "assets", "asset_id"
	case "threat.lookup":
		table, key = "threat_intel", "indicator"
	case "guidance.read":
		table, key = "guidance", "policy_id"
	}
	row, e := tx.Get(table, str(args, key))
	if e != nil {
		return nil, nil, e
	}
	return row, []string{str(row, "id")}, nil
}
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	var in struct {
		Decision string `json:"decision"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Decision != "approve" && in.Decision != "reject" {
		write(w, 400, Record{"error": "decision must be approve or reject"})
		return
	}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		a, e := tx.Get("approvals", r.PathValue("id"))
		if e == errMissing {
			return response{404, Record{"error": "approval not found"}}, nil
		}
		if e != nil {
			return response{}, e
		}
		c.Run = str(a, "run")
		args := obj(a, "arguments")
		if c.Role != "approver" || c.Sub == str(a, "requester") {
			return s.deny(tx, c, r, "approval.decision", "independent approver required", Record{})
		}
		if str(a, "state") != "pending" {
			if str(a, "decision") == in.Decision && str(a, "decider") == c.Sub {
				return response{200, a}, nil
			}
			return response{409, Record{"error": "approval already decided"}}, nil
		}
		run, e := tx.Get("runs", c.Run)
		if e != nil {
			return response{}, e
		}
		decision, e := s.policy(tx, run, str(a, "tool"))
		if e != nil {
			return response{}, e
		}
		action, e := tx.Get("proposed_actions", str(a, "id"))
		if e != nil {
			return response{}, e
		}
		expected := jsonHash(Record{"tool": str(a, "tool"), "arguments": args})
		if str(run, "state") != "awaiting_approval" || str(run, "approval_id") != str(a, "id") || str(a, "policy_version") != str(run, "policy_version") || str(a, "requester") != str(run, "requester") || str(a, "binding") != expected || str(action, "binding") != expected || jsonHash(obj(action, "arguments")) != jsonHash(args) || str(a, "tool") != "identity.disable" || str(args, "identity_id") != str(run, "identity_id") || decision != "approval" || num(a, "expires_unix") <= float64(s.now().Unix()) {
			return s.deny(tx, c, r, "approval.decision", "approval binding, expiry or policy invalid", Record{})
		}
		outcome := "rejected"
		if in.Decision == "approve" {
			identity, e := tx.Get("identities", str(args, "identity_id"))
			if e != nil {
				return response{}, e
			}
			identity["disabled"] = true
			identity["disable_count"] = num(identity, "disable_count") + 1
			if e = tx.Put("identities", str(identity, "id"), identity); e != nil {
				return response{}, e
			}
			if e = tx.Insert("tool_executions", "mutation-"+str(a, "id"), Record{"run": c.Run, "tool": "identity.disable", "binding": expected, "approval": str(a, "id"), "response": Record{"disabled": true}}); e != nil {
				return response{}, e
			}
			outcome = "executed"
		}
		a["state"] = outcome
		a["decision"] = in.Decision
		a["decider"] = c.Sub
		action["state"] = outcome
		run["state"] = "completed"
		run["remediation"] = outcome
		if e = tx.Put("approvals", str(a, "id"), a); e != nil {
			return response{}, e
		}
		if e = tx.Put("proposed_actions", str(a, "id"), action); e != nil {
			return response{}, e
		}
		if e = tx.Put("runs", c.Run, run); e != nil {
			return response{}, e
		}
		e = s.audit(tx, c, r, "identity.disable", in.Decision, outcome, args, str(a, "id"))
		return response{200, a}, e
	})
}

type Finding struct {
	Severity   string   `json:"severity"`
	Summary    string   `json:"summary"`
	References []string `json:"references"`
}
type Report struct {
	Summary          string    `json:"summary"`
	Findings         []Finding `json:"findings"`
	Timeline         []string  `json:"timeline"`
	RecommendDisable bool      `json:"recommend_disable"`
}

func validateReport(report Report, run Record) error {
	if len(report.Summary) == 0 || len(report.Summary) > 2000 || len(report.Findings) == 0 || len(report.Findings) > 10 || len(report.Timeline) > 30 {
		return errors.New("invalid report bounds")
	}
	allowed := map[string]bool{}
	for _, ref := range stringList(run["evidence"]) {
		allowed[ref] = true
	}
	for _, f := range report.Findings {
		if f.Severity != "low" && f.Severity != "medium" && f.Severity != "high" {
			return errors.New("invalid severity")
		}
		if len(f.Summary) == 0 || len(f.Summary) > 1000 || len(f.References) == 0 || len(f.References) > 20 {
			return errors.New("invalid finding")
		}
		for _, ref := range f.References {
			if !allowed[ref] {
				return errors.New("ungrounded citation")
			}
		}
	}
	for _, line := range report.Timeline {
		if len(line) > 500 {
			return errors.New("invalid timeline")
		}
	}
	return nil
}
func (s *Server) result(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(contextKey{}).(Claims)
	var in struct {
		Report *Report `json:"report"`
		Error  string  `json:"error"`
		Usage  *struct {
			Provider     string `json:"provider"`
			TotalTokens  int    `json:"total_tokens"`
			InputTokens  int    `json:"input_tokens"`
			OutputTokens int    `json:"output_tokens"`
		} `json:"usage"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.transact(w, r, c, func(tx Tx) (response, error) {
		run, e := s.workerRun(tx, c)
		if e != nil {
			return s.deny(tx, c, r, "run.result", e.Error(), Record{})
		}
		if in.Error != "" {
			run["state"] = "failed"
			run["error"] = "runtime failed; inspect trace and retry with a new run"
		} else {
			if in.Report == nil || validateReport(*in.Report, run) != nil {
				return s.deny(tx, c, r, "run.result", "invalid or ungrounded report", Record{})
			}
			if run["model_reserved"] != true || in.Usage == nil || in.Usage.TotalTokens < 0 || in.Usage.InputTokens < 0 || in.Usage.OutputTokens < 0 || (in.Usage.Provider != "mock" && in.Usage.Provider != "openai") {
				return s.deny(tx, c, r, "run.result", "invalid model usage or missing reservation", Record{})
			}
			if float64(in.Usage.TotalTokens) > num(run, "tokens_reserved") {
				run["state"] = "failed"
				run["error"] = "provider exceeded token reservation"
			} else {
				run["report"] = in.Report
				run["usage"] = in.Usage
				if !in.Report.RecommendDisable {
					run["state"] = "completed"
				}
			}
		}
		if e = tx.Put("runs", c.Run, run); e != nil {
			return response{}, e
		}
		e = s.audit(tx, c, r, "run.result", "allow", str(run, "state"), Record{}, "")
		return response{200, run}, e
	})
}

func (s *Server) dispatch(ctx context.Context, q Queue) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, tenant := range tenants {
				_ = s.store.Tenant(ctx, tenant, func(tx Tx) error {
					runs, e := tx.List("runs")
					if e != nil {
						return e
					}
					for _, run := range runs {
						state := str(run, "state")
						if state == "awaiting_approval" {
							a, e := tx.Get("approvals", str(run, "approval_id"))
							if e != nil {
								return e
							}
							if num(a, "expires_unix") <= float64(s.now().Unix()) {
								a["state"] = "expired"
								run["state"] = "failed"
								run["error"] = "approval expired"
								if e = tx.Put("approvals", str(a, "id"), a); e != nil {
									return e
								}
								if e = tx.Put("runs", str(run, "id"), run); e != nil {
									return e
								}
							}
							continue
						}
						if state != "queued" && state != "running" {
							continue
						}
						if s.expired(run) {
							run["state"] = "failed"
							run["error"] = "elapsed-time budget exhausted"
							if e = tx.Put("runs", str(run, "id"), run); e != nil {
								return e
							}
							continue
						}
						if num(run, "lease_until") > float64(s.now().Unix()) || num(run, "dispatched_at")+30 > float64(s.now().Unix()) {
							continue
						}
						if e = q.Enqueue(ctx, tenant, str(run, "id")); e != nil {
							return e
						}
						run["dispatched_at"] = s.now().Unix()
						if e = tx.Put("runs", str(run, "id"), run); e != nil {
							return e
						}
					}
					return nil
				})
			}
		}
	}
}
func envInt(value string, fallback int) int {
	n, e := strconv.Atoi(value)
	if e != nil || n < 1 {
		return fallback
	}
	return n
}
