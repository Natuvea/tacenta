-- A completed lifecycle mutation is keyed by an opaque 32-byte client retry
-- key. Request and result are canonical bounded account-inventory encodings;
-- the application verifies them before accepting either on every read.
create table if not exists account_inventory_mutations (
    tenant_id       text  not null,
    username        text  not null,
    idempotency_key bytea not null check (octet_length(idempotency_key) = 32),
    request         bytea not null,
    result          bytea not null,
    constraint account_inventory_mutations_pkey
        primary key (tenant_id, username, idempotency_key),
    constraint account_inventory_mutations_user_fkey
        foreign key (tenant_id, username)
        references users (tenant_id, username)
        on delete cascade
);
