CREATE TABLE IF NOT EXISTS app_migrations (
  name text PRIMARY KEY, digest text NOT NULL, applied timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_tasks (
  id uuid PRIMARY KEY, name text NOT NULL, idempotency_key text NOT NULL,
  input jsonb NOT NULL, actor jsonb NOT NULL,
  state text NOT NULL DEFAULT 'queued', attempts integer NOT NULL DEFAULT 0,
  available timestamptz NOT NULL DEFAULT now(), lease_until timestamptz,
  lease_token uuid, result jsonb, error text,
  created timestamptz NOT NULL DEFAULT now(), updated timestamptz NOT NULL DEFAULT now(),
  UNIQUE(name,idempotency_key)
);
CREATE INDEX IF NOT EXISTS app_tasks_dispatch ON app_tasks(state,available,lease_until);
