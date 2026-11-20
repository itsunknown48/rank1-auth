# Rank1 Auth Backend

FastAPI + Postgres (Supabase) + Redis (Upstash). Issues Ed25519 JWT sessions for a
license key, binds the key to one machine, and hands out the AES key for the encrypted
overlay blob only after a valid auth.

## Layout

```
app/config.py        env settings
app/db.py            SQLAlchemy models: keys, audit
app/keyformat.py     RANK-XXXX-XXXX-XXXX-XXXX generation + normalisation
app/security.py      argon2id hashing, Ed25519 JWT, Redis session/kill-switch
app/deps.py          DB session, admin guard, live-session guard
app/schemas.py       request/response models
app/routers/auth.py      /v1/auth /v1/heartbeat /v1/revoke-self
app/routers/payload.py   /v1/payload
app/routers/admin.py     /v1/admin/*
schema.sql           tables for Supabase
smoke_test.py        full endpoint walk against SQLite
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | liveness |
| GET | `/v1/pubkey` | none | Ed25519 public key for the loader |
| POST | `/v1/auth` | none | `{key, hwid, version}` -> token |
| POST | `/v1/heartbeat` | bearer | rotate token, keep session alive |
| POST | `/v1/revoke-self` | bearer | burn the calling key |
| POST | `/v1/payload` | bearer | AES key + url for the sealed overlay |
| GET | `/v1/payload/blob` | bearer | backend-hosted sealed overlay |
| POST | `/v1/admin/payload` | admin | register a sealed release |
| GET | `/v1/admin/payloads` | admin | release history |
| POST | `/v1/admin/payload-disable` | admin | stop serving a payload |
| POST | `/v1/admin/issue` | admin | `{tier, count, note}` -> plaintext keys |
| GET | `/v1/admin/keys` | admin | `status`, `q`, `limit`, `offset` |
| POST | `/v1/admin/revoke` | admin | `{key_prefix, reason}` |
| POST | `/v1/admin/unrevoke` | admin | `{key_prefix}` |
| POST | `/v1/admin/reset-hwid` | admin | `{key_prefix}` |
| POST | `/v1/admin/extend` | admin | `{key_prefix, days | tier}` |
| DELETE | `/v1/admin/key` | admin | `?key_prefix=` |
| GET | `/v1/admin/stats` | admin | counters + kill-switch state |
| GET | `/v1/admin/audit` | admin | last N audit rows |
| POST | `/v1/admin/purge-expired` | admin | drop keys expired > 30 days |
| POST | `/v1/admin/kill-switch` | admin | `{on}` global lockout |

Admin auth is the `X-Admin-Secret` header compared with `hmac.compare_digest`.

## Key format

```
RANK-7Q4M-XB2K-9HVP-T3ZD
```

Alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (Crockford base32, no I/L/O/U).
`prefix` = `RANK-` + first group, stored as the lookup handle. The full key is only
stored as an argon2id hash. Tiers: `1d 3d 7d 10d 30d`.

## Token

EdDSA (Ed25519) JWT, no library-specific extras:

```
{sub, hwid, tier, iat, exp, jti, iss="rank1", aud="loader"}
```

Lifetime `TOKEN_TTL_SECONDS` (default 600). Every heartbeat rotates the token and
marks the previous `jti` dead in Redis, so a captured token dies within one minute.

## Local run

```bash
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
copy .env.example .env
python tools/gen_secrets.py     # paste ADMIN_SECRET + ED25519_SEED_B64 into .env
uvicorn app.main:app --reload --port 8000
python smoke_test.py            # 40 checks, sqlite, no network
```

## Supabase setup

1. Create the project, then **SQL Editor -> New query -> paste `schema.sql` -> Run**.
2. **Project Settings -> Database -> Connection string -> URI**, append `?sslmode=require`.
3. Put that URI in `DATABASE_URL`. If the host is `...pooler.supabase.com`, port `6543`
   is the transaction pooler (better for serverless, needs `?pgbouncer=true`); port
   `5432` is the session pooler, which is what Railway wants here.
4. RLS is enabled and no policies exist, so the anon key cannot read keys or audit.

## Railway deploy

```bash
railway init
railway variables set DATABASE_URL="postgresql://..." REDIS_URL="rediss://..." \
  ADMIN_SECRET="..." JWT_SEED_B64="..." \
  PUBLIC_BASE_URL="https://rank1-auth-production.up.railway.app"
railway up
```

`railway.json` pins the Nixpacks build, `uvicorn` start, and `/health` check.

## Redis keys

```
rank1:sess:<jti>     key_id | "dead"   TTL = token lifetime
rank1:kill           "1"               global kill switch
```

With `REDIS_URL` empty the process falls back to an in-memory dict — fine for a
single local dev instance, useless across Railway replicas.

## Payload publishing

Sealed with AES-256-GCM, registered in the DB so it can rotate without a redeploy.

```bash
# backend serves the blob itself (rank1-overlay.bin committed next to app/)
python tools/publish_payload.py ../../1_run/Rank1Overlay.exe --local --version 1.0.0

# or a GitHub Release asset
GITHUB_TOKEN=ghp_x GITHUB_REPO=you/rank1-release \
RANK1_API=https://rank1-auth-production.up.railway.app ADMIN_SECRET=... \
python tools/publish_payload.py ../../1_run/Rank1Overlay.exe --version 1.0.1
```

`POST /v1/admin/payload` deactivates every older release, so `/v1/payload` always
returns the newest one. `POST /v1/admin/payload-disable` serves nothing and the loader
fails closed. The encrypted blob is safe to publish anywhere — without the key and
nonce from a live session it is noise.
