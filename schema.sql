create table if not exists keys (
    id            varchar(36) primary key,
    prefix        varchar(16) not null unique,
    key_hash      text        not null,
    tier          varchar(8)  not null,
    note          varchar(120) not null default '',
    hwid          varchar(64),
    revoked       boolean     not null default false,
    created_at    timestamptz not null default now(),
    expires_at    timestamptz not null,
    last_seen_at  timestamptz,
    last_ip       varchar(64) not null default '',
    use_count     integer     not null default 0
);

create index if not exists ix_keys_prefix   on keys (prefix);
create index if not exists ix_keys_hwid     on keys (hwid);
create index if not exists ix_keys_expires  on keys (expires_at);

create table if not exists audit (
    id       serial primary key,
    at       timestamptz not null default now(),
    actor    varchar(64) not null default '',
    action   varchar(48) not null,
    key_id   varchar(36) not null default '',
    detail   varchar(240) not null default ''
);

create index if not exists ix_audit_at     on audit (at);
create index if not exists ix_audit_action on audit (action);
create index if not exists ix_audit_key    on audit (key_id);

alter table keys enable row level security;
alter table audit enable row level security;
