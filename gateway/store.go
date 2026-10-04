package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errMissing = errors.New("not found")
var tables = map[string]bool{"users": true, "agents": true, "policies": true, "runs": true, "approvals": true, "proposed_actions": true, "tool_executions": true, "audit_events": true, "identities": true, "events": true, "assets": true, "threat_intel": true, "guidance": true}

type Record map[string]any
type Tx interface {
	Get(string, string) (Record, error)
	List(string) ([]Record, error)
	Put(string, string, Record) error
	Insert(string, string, Record) error
}
type Store interface {
	Tenant(context.Context, string, func(Tx) error) error
}

// The memory implementation uses the same transaction semantics for deterministic tests.
type Memory struct {
	mu   sync.Mutex
	data map[string]map[string]map[string]Record
}

func NewMemory() *Memory { return &Memory{data: map[string]map[string]map[string]Record{}} }
func clone(r Record) Record {
	b, _ := json.Marshal(r)
	var out Record
	_ = json.Unmarshal(b, &out)
	return out
}

type memTx struct{ data map[string]map[string]Record }

func (m *Memory) Tenant(ctx context.Context, tenant string, f func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := map[string]map[string]Record{}
	for t, rows := range m.data[tenant] {
		d[t] = map[string]Record{}
		for id, r := range rows {
			d[t][id] = clone(r)
		}
	}
	if err := f(&memTx{d}); err != nil {
		return err
	}
	m.data[tenant] = d
	return nil
}
func (t *memTx) Get(table, id string) (Record, error) {
	r, ok := t.data[table][id]
	if !ok {
		return nil, errMissing
	}
	return clone(r), nil
}
func (t *memTx) List(table string) ([]Record, error) {
	out := []Record{}
	for _, r := range t.data[table] {
		out = append(out, clone(r))
	}
	return out, nil
}
func (t *memTx) Put(table, id string, r Record) error {
	if table == "audit_events" {
		return errors.New("audit is append-only")
	}
	return t.save(table, id, r, false)
}
func (t *memTx) Insert(table, id string, r Record) error { return t.save(table, id, r, true) }
func (t *memTx) save(table, id string, r Record, insert bool) error {
	if !tables[table] {
		return errors.New("invalid table")
	}
	if t.data[table] == nil {
		t.data[table] = map[string]Record{}
	}
	if _, ok := t.data[table][id]; ok && insert {
		return errors.New("duplicate")
	}
	r = clone(r)
	r["id"] = id
	t.data[table][id] = r
	return nil
}

type Postgres struct{ pool *pgxpool.Pool }
type pgTx struct {
	tx     pgx.Tx
	ctx    context.Context
	tenant string
}

func NewPostgres(ctx context.Context, url string) (*Postgres, error) {
	p, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Postgres{p}, nil
}
func (p *Postgres) Tenant(ctx context.Context, tenant string, f func(Tx) error) error {
	tx, e := p.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		return e
	}
	// Serialize security decisions per tenant. This simple MVP trades throughput for clear atomicity.
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant); e != nil {
		return e
	}
	if e = f(&pgTx{tx, ctx, tenant}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (t *pgTx) Get(table, id string) (Record, error) {
	if !tables[table] {
		return nil, errors.New("invalid table")
	}
	var b []byte
	e := t.tx.QueryRow(t.ctx, fmt.Sprintf("SELECT body FROM %s WHERE tenant_id=$1 AND id=$2", table), t.tenant, id).Scan(&b)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, errMissing
	}
	if e != nil {
		return nil, e
	}
	var r Record
	e = json.Unmarshal(b, &r)
	return r, e
}
func (t *pgTx) List(table string) ([]Record, error) {
	if !tables[table] {
		return nil, errors.New("invalid table")
	}
	rows, e := t.tx.Query(t.ctx, fmt.Sprintf("SELECT body FROM %s WHERE tenant_id=$1 ORDER BY id", table), t.tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var r Record
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (t *pgTx) Put(table, id string, r Record) error {
	if table == "audit_events" {
		return errors.New("audit is append-only")
	}
	return t.save(table, id, r, false)
}
func (t *pgTx) Insert(table, id string, r Record) error { return t.save(table, id, r, true) }
func (t *pgTx) save(table, id string, r Record, insert bool) error {
	if !tables[table] {
		return errors.New("invalid table")
	}
	r = clone(r)
	r["id"] = id
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	q := fmt.Sprintf("INSERT INTO %s(tenant_id,id,body) VALUES($1,$2,$3)", table)
	if !insert {
		q += " ON CONFLICT(tenant_id,id) DO UPDATE SET body=excluded.body"
	}
	_, e = t.tx.Exec(t.ctx, q, t.tenant, id, b)
	return e
}
