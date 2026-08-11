-- support screen sharing: who opened a live view of a counter, when, and against which site.
-- Append-only and deliberately unlinked from counters: an audit trail has to outlive the thing
-- it describes being edited or deleted.
CREATE TABLE IF NOT EXISTS support_sessions (
  id            bigserial PRIMARY KEY,
  opened_at     timestamptz NOT NULL DEFAULT now(),
  counter_id    text,
  pi_serial     text,
  pharmacy_code text,
  actor         text,
  minutes       int
);
CREATE INDEX IF NOT EXISTS support_sessions_opened_idx ON support_sessions (opened_at DESC);
