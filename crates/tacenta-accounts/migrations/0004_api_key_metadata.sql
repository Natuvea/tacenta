-- API-key metadata for rotation (decision record 0048). A key row was just its
-- hash and tenant; add a non-secret prefix so a tenant can recognise a key in a
-- list and revoke it by prefix, an optional label, and a creation time. The
-- prefix is the first 12 characters of the key (`tct_` plus eight hex); the full
-- key is still never stored. Keys created before this migration have a null
-- prefix (it cannot be derived from the hash) and a created_at of now().
alter table api_keys add column if not exists key_prefix text;
alter table api_keys add column if not exists label      text;
alter table api_keys add column if not exists created_at timestamptz not null default now();

-- Listing a tenant's keys filters by tenant_id; index it.
create index if not exists api_keys_tenant_id_idx on api_keys (tenant_id);
