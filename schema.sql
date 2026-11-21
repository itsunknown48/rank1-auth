create table if not exists keys (
    id            varchar(36) primary key,
    prefix        varchar(16) not null unique,
    key_hash      text        not null,
    key_sealed    text,
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

create table if not exists payloads (
    id         serial primary key,
    version    varchar(32) not null default '',
    url        text        not null,
    sha256     varchar(64) not null,
    key_b64    varchar(64) not null,
    nonce_b64  varchar(32) not null,
    size       integer     not null default 0,
    active     boolean     not null default true,
    created_at timestamptz not null default now()
);

create index if not exists ix_payloads_active on payloads (active);

create table if not exists loaders (
    id         serial primary key,
    version    varchar(32) not null,
    url        text        not null default '',
    sha256     varchar(64) not null,
    size       integer     not null default 0,
    notes      varchar(240) not null default '',
    mandatory  boolean     not null default false,
    active     boolean     not null default true,
    created_at timestamptz not null default now()
);

create index if not exists ix_loaders_active on loaders (active);

alter table keys enable row level security;
alter table audit enable row level security;
alter table payloads enable row level security;
alter table loaders enable row level security;
