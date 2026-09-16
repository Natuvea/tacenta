-- The canonical state from which the hosted inventory issuer signs device
-- statements. The bytea payload is decoded and validated by tacenta-accounts
-- on every read and write; keeping it as one row makes the inventory mutation
-- atomic with its generation check, and preserves the exact bounded v1 model.
create table if not exists account_device_inventories (
    tenant_id text  not null,
    username  text  not null,
    state     bytea not null,
    constraint account_device_inventories_pkey primary key (tenant_id, username),
    constraint account_device_inventories_user_fkey
        foreign key (tenant_id, username)
        references users (tenant_id, username)
        on delete cascade
);
