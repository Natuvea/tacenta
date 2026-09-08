-- Session expiry (decision record 0043): a session token is valid only until
-- its expires_at. The in-memory store already enforces this; this brings the
-- Postgres store to parity. Revocation (0044) needs no schema change — it is a
-- delete from this table.
--
-- The column is NOT NULL; existing rows, if any, take a now() default so the
-- alter succeeds, and real inserts set
-- expires_at = now() + the session TTL explicitly.
alter table sessions
    add column if not exists expires_at timestamptz not null default now();

-- Validation filters on expires_at, so index it alongside the primary-key
-- lookup on token_hash.
create index if not exists sessions_expires_at_idx on sessions (expires_at);
