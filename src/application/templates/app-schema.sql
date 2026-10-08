CREATE TABLE IF NOT EXISTS app_records (
    id uuid PRIMARY KEY,
    kind text NOT NULL,
    data jsonb NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    updated timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_records_kind ON app_records(kind);
CREATE UNIQUE INDEX IF NOT EXISTS app_identity_provider_subject ON app_records((data->>'provider'),(data->>'subject')) WHERE kind='identities';
DROP INDEX IF EXISTS app_identity_subject;
CREATE TABLE IF NOT EXISTS app_sessions (
    digest text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES app_records(id),
    expires timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS app_preview_codes (
    digest text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES app_records(id),
    challenge text NOT NULL,
    expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS app_preview_codes_expires ON app_preview_codes(expires);
CREATE TABLE IF NOT EXISTS app_magic_links (
    digest text PRIMARY KEY,
    email text NOT NULL,
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_magic_links_expires ON app_magic_links(expires);
CREATE TABLE IF NOT EXISTS app_magic_requests (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email_digest text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_magic_requests_created ON app_magic_requests(created);
CREATE INDEX IF NOT EXISTS app_magic_requests_email ON app_magic_requests(email_digest,created);
CREATE TABLE IF NOT EXISTS app_google_states (
    digest text PRIMARY KEY,
    verifier text NOT NULL,
    client_id text NOT NULL,
    expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS app_google_states_expires ON app_google_states(expires);
ALTER TABLE app_google_states ADD COLUMN IF NOT EXISTS next text;
CREATE TABLE IF NOT EXISTS app_integration_secrets (
    provider text PRIMARY KEY,
    client_secret text,
    access_token text,
    refresh_token text,
    expires timestamptz,
    updated timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_integration_states (
    digest text PRIMARY KEY,
    provider text NOT NULL,
    user_id uuid NOT NULL REFERENCES app_records(id) ON DELETE CASCADE,
    next text,
    expires timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS app_integration_states_expires ON app_integration_states(expires);
CREATE TABLE IF NOT EXISTS app_uploads (
    id uuid PRIMARY KEY,
    kind text NOT NULL,
    field text NOT NULL,
    user_id uuid,
    name text NOT NULL,
    size bigint NOT NULL,
    content_type text NOT NULL,
    store text NOT NULL,
    key text,
    oid oid,
    state text NOT NULL DEFAULT 'pending',
    expires timestamptz NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS app_uploads_expires ON app_uploads(expires);
