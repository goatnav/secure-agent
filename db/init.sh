#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE secureagent_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOBYPASSRLS;
CREATE TABLE tenants (id text PRIMARY KEY);
INSERT INTO tenants VALUES ('acme'),('orbit');
GRANT SELECT ON tenants TO secureagent_app;
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['users','agents','policies','runs','approvals','proposed_actions','tool_executions','audit_events','identities','events','assets','threat_intel','guidance'] LOOP
  EXECUTE format('CREATE TABLE %I (tenant_id text NOT NULL REFERENCES tenants(id), id text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(tenant_id,id), CHECK(body->>''id''=id))',t);
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',t);
  IF t = 'audit_events' THEN
   EXECUTE format('GRANT SELECT,INSERT ON %I TO secureagent_app',t);
  ELSE
   EXECUTE format('GRANT SELECT,INSERT,UPDATE ON %I TO secureagent_app',t);
  END IF;
 END LOOP;
END $$;
-- Policy versions cannot be edited through application credentials.
REVOKE UPDATE ON policies FROM secureagent_app;
CREATE INDEX runs_state ON runs(tenant_id,(body->>'state'));
CREATE INDEX events_identity ON events(tenant_id,(body->>'identity_id'));
CREATE INDEX audit_time ON audit_events(tenant_id,(body->>'at'));
SQL
