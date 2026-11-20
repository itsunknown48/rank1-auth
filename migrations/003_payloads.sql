-- existing deployments only: payload release table

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

alter table payloads enable row level security;
