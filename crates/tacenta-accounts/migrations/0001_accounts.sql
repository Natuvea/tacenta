-- The account model as relational tables. Uniqueness — global for tenants,
-- per-tenant for users — is enforced by database constraints, the durable-store
-- form of the in-memory store's index maps (decision records 0033, 0039).
-- Passwords are argon2id hashes; API keys and session tokens are stored only as
-- their SHA-256 digest. Constraints are named so the store can map a unique
-- violation back to the field that collided.

create table if not exists tenants (
    id            text        primary key,
    username      text        not null,
    email         text        not null,
    password_hash text        not null,
    created_at    timestamptz not null default now(),
    constraint tenants_username_key unique (username),
    constraint tenants_email_key unique (email)
);

create table if not exists api_keys (
    key_hash   bytea primary key,
    tenant_id  text  not null references tenants (id) on delete cascade
);

create table if not exists users (
    tenant_id     text        not null references tenants (id) on delete cascade,
    username      text        not null,
    email         text        not null,
    password_hash text        not null,
    created_at    timestamptz not null default now(),
    constraint users_pkey primary key (tenant_id, username),
    constraint users_tenant_email_key unique (tenant_id, email)
);

create table if not exists sessions (
    token_hash bytea       primary key,
    tenant_id  text        not null,
    username   text        not null,
    created_at timestamptz not null default now(),
    constraint sessions_user_fkey
        foreign key (tenant_id, username)
        references users (tenant_id, username)
        on delete cascade
);
