import sys

import redis

url = sys.argv[1].strip() if len(sys.argv) > 1 else ""
if not url:
    raise SystemExit("usage: redis_ping.py <rediss://...>")

scheme = url.split("://", 1)[0] if "://" in url else "(none)"
host = url.split("@")[-1] if "@" in url else url
has_pass = bool(url.split("@")[0].split(":", 1)[-1]) if "@" in url else False

print(f"scheme  {scheme}")
print(f"host    {host}")
print(f"pass    {'present' if has_pass else 'MISSING'}")

r = redis.Redis.from_url(url, decode_responses=True, socket_timeout=5)
print(f"ping    {r.ping()}")
r.set("rank1:probe", "1", ex=30)
print(f"get     {r.get('rank1:probe')}")
r.delete("rank1:probe")
print("ok")
