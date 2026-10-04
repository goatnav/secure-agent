import React, { useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  Activity,
  FileCheck2,
  ScrollText,
  ArrowUpRight,
  LockKeyhole,
  LogOut,
  Plus,
  Search,
  Check,
  X,
  Circle,
  Layers3,
} from "./icons";

type Session = {
  token: string;
  tenant: string;
  role: string;
  username: string;
};
type Finding = { severity: string; summary: string; references: string[] };
type Run = {
  id: string;
  state: string;
  identity_id: string;
  created_at: string;
  tool_calls: number;
  tokens_reserved: number;
  cost_reserved: number;
  usage?: { total_tokens: number; provider: string };
  error?: string;
  remediation?: string;
  report?: { summary: string; findings: Finding[]; timeline: string[] };
};
type Approval = {
  id: string;
  run: string;
  tool: string;
  state: string;
  requester: string;
  arguments: Record<string, string>;
  expires_unix: number;
};
type Audit = {
  id: string;
  at: string;
  actor: string;
  tool: string;
  decision: string;
  outcome: string;
  trace_id: string;
  run: string;
};
async function api<T>(
  path: string,
  token?: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/v1/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
const short = (id: string) => id.slice(0, 8);
const date = (value: string) =>
  new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
function Badge({ state }: { state: string }) {
  return (
    <span className={`badge ${state}`}>
      <Circle size={7} fill="currentColor" />
      {state.replaceAll("_", " ")}
    </span>
  );
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null); // Credentials live only in memory.
  const sessionRef = useRef<Session | null>(session);
  sessionRef.current = session;
  const [tenant, setTenant] = useState("acme"),
    [role, setRole] = useState("analyst"),
    [password, setPassword] = useState("");
  const [view, setView] = useState("Investigations"),
    [runs, setRuns] = useState<Run[]>([]),
    [approvals, setApprovals] = useState<Approval[]>([]),
    [audit, setAudit] = useState<Audit[]>([]);
  const [selected, setSelected] = useState<string | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [showForm, setShowForm] = useState(false),
    [identity, setIdentity] = useState("employee-438");
  const [query, setQuery] = useState("");
  const refresh = async (s: Session) => {
    const [r, a, events] = await Promise.all([
      api<Run[]>("runs", s.token),
      api<Approval[]>("approvals", s.token),
      api<Audit[]>("audit", s.token),
    ]);
    if (sessionRef.current?.token !== s.token) return;
    setRuns(r);
    setApprovals(a);
    setAudit(events);
  };
  useEffect(() => {
    if (!session) return;
    let active = true;
    const poll = async () => {
      try {
        if (active) await refresh(session);
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    };
    void poll();
    const timer = setInterval(poll, 4000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [session]);
  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const login = (event: React.FormEvent) => {
    event.preventDefault();
    void act(async () => {
      const s = await api<Session>("auth/login", undefined, {
        tenant,
        username: role,
        password,
      });
      sessionRef.current = s;
      setSession(s);
      setPassword("");
      setSelected(null);
    });
  };
  const newRun = (event: React.FormEvent) => {
    event.preventDefault();
    if (!session) return;
    void act(async () => {
      const run = await api<Run>("runs", session.token, {
        identity_id: identity,
      });
      setSelected(run.id);
      setShowForm(false);
      await refresh(session);
    });
  };
  const decide = (id: string, decision: string) => {
    if (!session) return;
    void act(async () => {
      await api(`approvals/${id}/decision`, session.token, { decision });
      await refresh(session);
    });
  };
  const pending = approvals.filter((a) => a.state === "pending"),
    current = runs.find((r) => r.id === selected);
  if (!session)
    return (
      <div className="login">
        <div className="login-story">
          <div className="brand">
            <ShieldCheck /> SecureAgent <span>PLATFORM</span>
          </div>
          <div className="story-copy">
            <span className="eyebrow">GOVERNED INTELLIGENCE</span>
            <h1>
              Investigate freely.
              <br />
              Act deliberately.
            </h1>
            <p>
              A secure execution layer for security agents.
              <br />
              Every tool call checked. Every action accountable.
            </p>
            <div className="login-controls">
              <span>
                <LockKeyhole size={16} /> Tenant isolation
              </span>
              <span>
                <FileCheck2 size={16} /> Human approvals
              </span>
            </div>
          </div>
          <small>LOCAL DEMO · SYNTHETIC ENTERPRISE DATA</small>
        </div>
        <div className="login-form">
          <form onSubmit={login}>
            <span className="eyebrow">WORKSPACE ACCESS</span>
            <h2>Sign in to your workspace</h2>
            <p>Use a seeded analyst or approver account.</p>
            <label>
              Tenant
              <select
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
              >
                <option value="acme">Acme Security</option>
                <option value="orbit">Orbit Security</option>
              </select>
            </label>
            <label>
              Account
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="analyst">Analyst</option>
                <option value="approver">Approver</option>
              </select>
            </label>
            <label>
              Demo password
              <input
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            <button className="primary" disabled={busy}>
              Enter workspace <ArrowUpRight size={17} />
            </button>
            <small>
              Default demo password: secureagent-demo.
              <br />
              Use your configured value if changed.
            </small>
          </form>
        </div>
      </div>
    );
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck /> SecureAgent
        </div>
        <div className="workspace">
          <span className="workspace-icon">
            {session.tenant.slice(0, 1).toUpperCase()}
          </span>
          <div>
            {session.tenant === "acme" ? "Acme Security" : "Orbit Security"}
            <small>Isolated workspace</small>
          </div>
          <LockKeyhole size={14} />
        </div>
        <span className="nav-label">OPERATIONS</span>
        <nav>
          {[
            ["Investigations", Activity],
            ["Approvals", FileCheck2],
            ["Audit trail", ScrollText],
          ].map(([name, Icon]) => (
            <button
              key={name as string}
              className={view === name ? "active" : ""}
              onClick={() => {
                setView(name as string);
                setSelected(null);
                setQuery("");
              }}
            >
              <Icon size={18} />
              {name as string}
              {name === "Approvals" && pending.length > 0 && (
                <span className="count">{pending.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="security-note">
          <ShieldCheck size={20} />
          <strong>Policy enforcement active</strong>
          <p>
            Tools are governed by policy v1. Containment requires independent
            approval.
          </p>
          <span className="status-dot" /> Default deny
        </div>
        <div className="user">
          <div className="avatar">
            {session.username.slice(0, 1).toUpperCase()}
          </div>
          <div>
            {session.username}
            <small>{session.role}</small>
          </div>
          <button
            aria-label="Sign out"
            onClick={() => {
              sessionRef.current = null;
              setSession(null);
              setRuns([]);
              setApprovals([]);
              setAudit([]);
              setError("");
            }}
          >
            <LogOut size={17} />
          </button>
        </div>
      </aside>
      <main>
        <header>
          <span>
            Workspace <span className="slash">/</span> {view}
          </span>
          <div>
            <span className="demo">SYNTHETIC DATA</span>
            <span className="tenant-label">
              <LockKeyhole size={13} />
              {session.tenant}
            </span>
            <button
              className="mobile-signout"
              aria-label="Sign out"
              onClick={() => {
                sessionRef.current = null;
                setSession(null);
                setRuns([]);
                setApprovals([]);
                setAudit([]);
                setError("");
              }}
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>
        <div className="content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">SECURITY OPERATIONS</span>
              <h1>{current ? `Investigation ${short(current.id)}` : view}</h1>
              <p>
                {view === "Investigations"
                  ? "Evidence-led investigation. Policy-controlled response."
                  : view === "Approvals"
                    ? "Review proposed actions before they change an identity."
                    : "A record of decisions across your workspace."}
              </p>
            </div>
            {view === "Investigations" && session.role === "analyst" && (
              <button
                className="primary"
                onClick={() => setShowForm(!showForm)}
              >
                <Plus size={16} />
                New investigation
              </button>
            )}
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
          {showForm && (
            <form className="new-run" onSubmit={newRun}>
              <label>
                Identity ID
                <input
                  required
                  value={identity}
                  onChange={(e) => setIdentity(e.target.value)}
                  maxLength={80}
                />
              </label>
              <p>Query seeded login events and propose a governed response.</p>
              <button className="primary" disabled={busy}>
                Investigate <ArrowUpRight size={16} />
              </button>
            </form>
          )}
          <div className="stats">
            <div>
              <span>
                Total investigations <Activity size={16} />
              </span>
              <strong>{runs.length.toString().padStart(2, "0")}</strong>
              <small>In this tenant</small>
            </div>
            <div>
              <span>
                Awaiting approval <FileCheck2 size={16} />
              </span>
              <strong>{pending.length.toString().padStart(2, "0")}</strong>
              <small>Independent review required</small>
            </div>
            <div>
              <span>
                Policy denials <ShieldCheck size={16} />
              </span>
              <strong>
                {audit
                  .filter((a) => a.decision === "deny")
                  .length.toString()
                  .padStart(2, "0")}
              </strong>
              <small>Across the latest 200 events</small>
            </div>
            <div>
              <span>
                Execution boundary <Layers3 size={16} />
              </span>
              <strong className="small-stat">
                Enforced <span className="status-dot" />
              </strong>
              <small>Gateway · policy v1</small>
            </div>
          </div>
          {view === "Investigations" &&
            (current ? (
              <>
                <button className="back" onClick={() => setSelected(null)}>
                  ← All investigations
                </button>
                <section className="panel detail">
                  <div className="panel-heading">
                    <h2>Investigation overview</h2>
                    <Badge state={current.state} />
                  </div>
                  <div className="detail-meta">
                    <span>
                      IDENTITY<strong>{current.identity_id}</strong>
                    </span>
                    <span>
                      TOOL CALLS<strong>{current.tool_calls} / 25</strong>
                    </span>
                    <span>
                      PROVIDER TOKENS
                      <strong>
                        {current.usage?.total_tokens ?? "Pending"}
                      </strong>
                    </span>
                    <span>
                      RESERVED BUDGET
                      <strong>${current.cost_reserved.toFixed(3)}</strong>
                    </span>
                  </div>
                  {current.error && (
                    <div className="error">{current.error}</div>
                  )}
                  {current.report ? (
                    <>
                      <h3>{current.report.summary}</h3>
                      {current.report.findings.map((f, i) => (
                        <div className="finding" key={i}>
                          <Badge state={f.severity} />
                          <p>{f.summary}</p>
                          <div className="references">
                            {f.references.map((ref) => (
                              <code key={ref}>{ref}</code>
                            ))}
                          </div>
                        </div>
                      ))}
                      <h3>Evidence timeline</h3>
                      <ol className="timeline">
                        {current.report.timeline.map((line, i) => (
                          <li key={i}>{line}</li>
                        ))}
                      </ol>
                    </>
                  ) : (
                    <div className="empty">
                      <Activity />
                      <h3>Investigation in progress</h3>
                      <p>
                        The bounded workflow is gathering evidence. This view
                        updates automatically.
                      </p>
                    </div>
                  )}
                  {current.remediation && (
                    <p className="remediation">
                      Containment outcome: {current.remediation}
                    </p>
                  )}
                  {session.role === "analyst" &&
                    !["completed", "failed", "cancelled"].includes(
                      current.state,
                    ) && (
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() =>
                          void act(async () => {
                            await api(
                              `runs/${current.id}/cancel`,
                              session.token,
                              {},
                            );
                            await refresh(session);
                          })
                        }
                      >
                        Cancel investigation
                      </button>
                    )}
                </section>
              </>
            ) : (
              <section className="panel">
                <div className="panel-heading">
                  <h2>
                    Recent investigations <span>{runs.length}</span>
                  </h2>
                  <div className="search">
                    <Search size={15} />
                    <input
                      aria-label="Filter investigations"
                      placeholder="Search identity or run"
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                    />
                  </div>
                </div>
                {runs.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>INVESTIGATION</th>
                          <th>IDENTITY</th>
                          <th>STATUS</th>
                          <th>TOOLS</th>
                          <th>CREATED</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {runs
                          .filter((r) =>
                            `${r.id} ${r.identity_id}`.includes(query),
                          )
                          .map((run) => (
                            <tr key={run.id}>
                              <td>
                                <button
                                  className="run-link"
                                  onClick={() => setSelected(run.id)}
                                >
                                  <Activity size={16} />
                                  {short(run.id)}
                                </button>
                              </td>
                              <td>{run.identity_id}</td>
                              <td>
                                <Badge state={run.state} />
                              </td>
                              <td>{run.tool_calls}</td>
                              <td className="muted">{date(run.created_at)}</td>
                              <td>
                                <button
                                  className="icon-button"
                                  aria-label={`Open investigation ${short(run.id)}`}
                                  onClick={() => setSelected(run.id)}
                                >
                                  <ArrowUpRight size={16} />
                                </button>
                              </td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty">
                    <Activity />
                    <h3>Your first investigation starts here</h3>
                    <p>
                      Investigate employee-438 to trace a suspicious login
                      sequence.
                    </p>
                  </div>
                )}
                <div className="panel-footer">
                  <span className="status-dot" />
                  Tenant-scoped results{" "}
                  <span>Auto-refresh every 4 seconds</span>
                </div>
              </section>
            ))}
          {view === "Approvals" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>
                  Action review <span>{pending.length} pending</span>
                </h2>
                <span className="muted">Two-person control</span>
              </div>
              {approvals.length ? (
                approvals.map((a) => (
                  <div className="approval" key={a.id}>
                    <div className="approval-symbol">
                      <LockKeyhole size={20} />
                    </div>
                    <div>
                      <h3>{a.tool}</h3>
                      <p>
                        {a.arguments.identity_id} · Run {short(a.run)}
                      </p>
                      <small>
                        Requested by {a.requester} · Expires{" "}
                        {new Date(a.expires_unix * 1000).toLocaleString()}
                      </small>
                    </div>
                    <Badge state={a.state} />
                    {a.state === "pending" && session.role === "approver" && (
                      <div className="approval-buttons">
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() => decide(a.id, "reject")}
                        >
                          <X size={15} />
                          Reject
                        </button>
                        <button
                          className="primary"
                          disabled={busy}
                          onClick={() => decide(a.id, "approve")}
                        >
                          <Check size={15} />
                          Approve & execute
                        </button>
                      </div>
                    )}
                    {a.state === "pending" && session.role !== "approver" && (
                      <small>Sign in as an approver to review</small>
                    )}
                  </div>
                ))
              ) : (
                <div className="empty">
                  <FileCheck2 />
                  <h3>No actions waiting for review</h3>
                  <p>
                    Agents can investigate automatically. Containment comes here
                    first.
                  </p>
                </div>
              )}
            </section>
          )}
          {view === "Audit trail" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>
                  Decision ledger <span>{audit.length}</span>
                </h2>
                <span className="muted">Append-only for application roles</span>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>TIME</th>
                      <th>ACTOR</th>
                      <th>ACTION</th>
                      <th>DECISION</th>
                      <th>OUTCOME</th>
                      <th>TRACE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.map((a) => (
                      <tr key={a.id}>
                        <td className="muted">{date(a.at)}</td>
                        <td>{a.actor}</td>
                        <td>
                          <code>{a.tool}</code>
                        </td>
                        <td>
                          <Badge state={a.decision} />
                        </td>
                        <td>{a.outcome}</td>
                        <td>
                          <code title={a.trace_id}>{short(a.trace_id)}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
          <footer>
            <ShieldCheck size={13} />
            SecureAgent Platform{" "}
            <span>All actions pass through the governed execution layer.</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
