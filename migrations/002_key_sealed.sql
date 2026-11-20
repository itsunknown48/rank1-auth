-- existing deployments only: adds the sealed-copy column used by the panel's reveal

alter table keys add column if not exists key_sealed text;

-- keys issued before this migration cannot be revealed (only their argon2 hash exists).
-- delete and reissue them if you need the plaintext back.
