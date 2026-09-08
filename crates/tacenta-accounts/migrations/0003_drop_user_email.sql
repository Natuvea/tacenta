-- Users sign up without an email — only tenants have one. Drop the users.email
-- column; this also drops the per-tenant email uniqueness constraint
-- (users_tenant_email_key), which depended on it. Users remain unique by
-- (tenant_id, username), the primary key. No data migration is needed.
alter table users drop column if exists email;
