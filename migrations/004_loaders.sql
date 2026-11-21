create table if not exists loaders (
    id serial primary key,
    version varchar(32) not null,
    url text not null default '',
    sha256 varchar(64) not null,
    size integer not null default 0,
    notes varchar(240) not null default '',
    mandatory boolean not null default false,
    active boolean not null default true,
    created_at timestamptz not null default now()
);
create index if not exists ix_loaders_active on loaders (active);
alter table loaders enable row level security;
