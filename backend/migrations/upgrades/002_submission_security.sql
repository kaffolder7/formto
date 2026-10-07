ALTER TABLE forms
  ADD COLUMN submission_mode TEXT NOT NULL DEFAULT 'public' CHECK (submission_mode IN ('public', 'private', 'legacy')),
  ADD COLUMN security_configured BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN security_revision INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN allowed_origins JSONB NOT NULL DEFAULT '[]',
  ADD COLUMN hosted_enabled BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN turnstile_site_key TEXT,
  ADD COLUMN turnstile_secret_encrypted TEXT,
  ADD COLUMN submission_key_hash TEXT,
  ADD COLUMN submission_key_prefix TEXT,
  ADD COLUMN submission_key_created_at TIMESTAMPTZ,
  ADD COLUMN fields JSONB NOT NULL DEFAULT '[{"name":"name","label":"Name","type":"text","required":true,"maxLength":200},{"name":"email","label":"Email","type":"email","required":true,"maxLength":254},{"name":"message","label":"Message","type":"textarea","required":true,"maxLength":10000}]',
  ADD COLUMN daily_submission_limit INTEGER NOT NULL DEFAULT 500 CHECK (daily_submission_limit BETWEEN 1 AND 1000000),
  ADD COLUMN daily_notification_limit INTEGER NOT NULL DEFAULT 100 CHECK (daily_notification_limit BETWEEN 0 AND 1000000);

-- Only forms present at upgrade receive compatibility mode. New forms default to public.
-- Preserve activation, endpoints, hosted pages, and existing integrations until owner opt-in.
UPDATE forms SET submission_mode = 'legacy', hosted_enabled = true,
  fields = jsonb_set(fields, '{2,required}', 'false');

ALTER TABLE submissions ADD COLUMN notification_status TEXT NOT NULL DEFAULT 'legacy';

CREATE TABLE form_daily_usage (
  form_id UUID NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
  day DATE NOT NULL,
  submissions INTEGER NOT NULL DEFAULT 0,
  notifications INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (form_id, day)
);

CREATE TABLE submission_rate_limits (
  key TEXT PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL
);
CREATE INDEX submission_rate_limits_expiry ON submission_rate_limits(window_start);
