from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
os.environ.setdefault("DATABASE_URL", "sqlite:///./smoke.db")
os.environ.setdefault("ADMIN_SECRET", "smoke-secret")
os.environ.setdefault("payload".upper() + "_URL", "https://example.invalid/rank1-overlay.bin")
os.environ.setdefault("PAYLOAD_SHA256", "0" * 64)
os.environ.setdefault("PAYLOAD_KEY_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("PAYLOAD_NONCE_B64", "AAAAAAAAAAAAAAAA")
os.environ.setdefault("PAYLOAD_VERSION", "1.0.0")

db_file = ROOT / "smoke.db"
if db_file.exists():
    db_file.unlink()
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

ADMIN = {"X-Admin-Secret": "smoke-secret"}
HWID = "a" * 32
failures: list[str] = []


def check(label: str, condition: bool, extra: str = "") -> None:
    print(("  PASS  " if condition else "  FAIL  ") + label + (f"  [{extra}]" if extra else ""))
    if not condition:
        failures.append(label)


with TestClient(app) as client:
    print("health")
    check("health ok", client.get("/health").json().get("ok") is True)

    print("admin issue")
    r = client.post("/v1/admin/issue", json={"tier": "30d", "count": 2, "note": "smoke"}, headers=ADMIN)
    check("issue 200", r.status_code == 200, str(r.status_code))
    keys = r.json()["keys"]
    check("two keys", len(keys) == 2, str(len(keys)))
    plain = keys[0]["key"]
    check("key shape", plain.startswith("RANK-") and plain.count("-") == 4, plain)
    check("prefix shape", keys[0]["key_prefix"].startswith("RANK-"), keys[0]["key_prefix"])

    print("bad tier")
    check("bad tier 400", client.post("/v1/admin/issue", json={"tier": "99d"}, headers=ADMIN).status_code == 400)

    print("admin auth")
    check("no secret 401", client.post("/v1/admin/issue", json={"tier": "1d"}).status_code == 401)

    print("auth")
    r = client.post("/v1/auth", json={"key": plain, "hwid": HWID, "version": "1.0.0"})
    check("auth 200", r.status_code == 200, r.text[:120])
    body = r.json()
    token = body["token"]
    check("ttl 600", body["ttl"] == 600, str(body["ttl"]))
    check("tier 30d", body["tier"] == "30d", body["tier"])
    check("expires_at set", body["expires_at"].endswith("Z"), body["expires_at"])
    bearer = {"Authorization": f"Bearer {token}"}

    print("auth again same hwid")
    check("same hwid 200", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 200)

    print("auth other hwid")
    r = client.post("/v1/auth", json={"key": plain, "hwid": "b" * 32})
    check("hwid mismatch 409", r.status_code == 409, str(r.status_code))

    print("auth lower case key")
    check("case-insensitive", client.post("/v1/auth", json={"key": plain.lower(), "hwid": HWID}).status_code == 200)

    print("malformed")
    check("junk 400", client.post("/v1/auth", json={"key": "RANK-ZZZZ", "hwid": HWID}).status_code == 400)
    check("unknown prefix 404", client.post("/v1/auth", json={"key": "RANK-0000-0000-0000-0000", "hwid": HWID}).status_code == 404)

    print("heartbeat")
    r = client.post("/v1/heartbeat", headers=bearer)
    check("heartbeat 200", r.status_code == 200, r.text[:120])
    new_token = r.json()["token"]
    check("token rotated", new_token != token)
    check("old token dead", client.post("/v1/heartbeat", headers=bearer).status_code == 403)
    bearer = {"Authorization": f"Bearer {new_token}"}

    print("payload")
    r = client.post("/v1/payload", headers=bearer)
    check("payload 200", r.status_code == 200, r.text[:120])
    check("payload url", r.json()["url"].startswith("https://"), r.json()["url"])

    print("payload without token")
    check("payload 401", client.post("/v1/payload").status_code == 401)

    print("payload publish")
    release = {
        "url": "https://github.com/o/r/releases/download/t/rank1-overlay-9.9.9.bin",
        "sha256": "a" * 64,
        "key_b64": "k" * 44,
        "nonce_b64": "n" * 16,
        "size": 1234,
        "version": "9.9.9",
    }
    r = client.post("/v1/admin/payload", headers=ADMIN, json=release)
    check("publish 200", r.status_code == 200, r.text[:160])
    check("publish overrides env", client.post("/v1/payload", headers=bearer).json()["version"] == "9.9.9")
    check("publish listed", client.get("/v1/admin/payloads", headers=ADMIN).json()["items"][0]["version"] == "9.9.9")
    check("publish rejected without secret", client.post("/v1/admin/payload", json=release).status_code == 401)

    r2 = dict(release, version="9.9.10")
    client.post("/v1/admin/payload", headers=ADMIN, json=r2)
    items = client.get("/v1/admin/payloads", headers=ADMIN).json()["items"]
    check("only one active", sum(1 for i in items if i["active"]) == 1, str([i["active"] for i in items]))
    check("newest wins", client.post("/v1/payload", headers=bearer).json()["version"] == "9.9.10")

    check("payload-disable 200", client.post("/v1/admin/payload-disable", headers=ADMIN).status_code == 200)
    check("env fallback after disable", client.post("/v1/payload", headers=bearer).json()["version"] == "1.0.0")

    print("keys list")
    r = client.get("/v1/admin/keys", headers=ADMIN)
    check("list 200", r.status_code == 200)
    check("list has 2", r.json()["total"] == 2, str(r.json()["total"]))
    check("hwid bound", any(item["hwid"] == HWID for item in r.json()["items"]))

    print("stats")
    s = client.get("/v1/admin/stats", headers=ADMIN).json()
    check("stats active 2", s["active"] == 2, str(s["active"]))
    check("stats bound 1", s["hwid_bound"] == 1, str(s["hwid_bound"]))

    print("reset hwid")
    handle = keys[0]["key_prefix"]
    check("reset 200", client.post("/v1/admin/reset-hwid", json={"key_prefix": handle}, headers=ADMIN).status_code == 200)
    check("old token still hwid-mismatched", client.post("/v1/heartbeat", headers=bearer).status_code == 403)

    print("extend")
    r = client.post("/v1/admin/extend", json={"key_prefix": handle, "days": 5}, headers=ADMIN)
    check("extend 200", r.status_code == 200, r.text[:120])

    print("reveal")
    r = client.get(f"/v1/admin/reveal?key_prefix={handle}", headers=ADMIN)
    check("reveal 200", r.status_code == 200, r.text[:120])
    check("reveal returns the exact key", r.json().get("key") == plain, str(r.json())[:80])
    check("reveal rejected without secret", client.get(f"/v1/admin/reveal?key_prefix={handle}").status_code == 401)

    print("revoke")
    r = client.post("/v1/auth", json={"key": plain, "hwid": HWID})
    check("re-auth 200", r.status_code == 200, r.text[:120])
    bearer2 = {"Authorization": f"Bearer {r.json()['token']}"}
    check("revoke 200", client.post("/v1/admin/revoke", json={"key_prefix": handle, "reason": "smoke"}, headers=ADMIN).status_code == 200)
    check("auth after revoke 403", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 403)

    print("unrevoke")
    check("unrevoke 200", client.post("/v1/admin/unrevoke", json={"key_prefix": handle}, headers=ADMIN).status_code == 200)
    check("auth restored 200", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 200)

    print("kill switch")
    check("kill on", client.post("/v1/admin/kill-switch", json={"on": True}, headers=ADMIN).status_code == 200)
    check("auth blocked 403", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 403)
    check("kill off", client.post("/v1/admin/kill-switch", json={"on": False}, headers=ADMIN).status_code == 200)
    check("auth back 200", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 200)

    print("audit")
    a = client.get("/v1/admin/audit", headers=ADMIN).json()["items"]
    check("audit populated", len(a) >= 5, str(len(a)))
    check("audit has issue", any(x["action"] == "issue" for x in a))

    print("delete")
    check("delete 200", client.delete(f"/v1/admin/key?key_prefix={handle}", headers=ADMIN).status_code == 200)
    check("auth after delete 404", client.post("/v1/auth", json={"key": plain, "hwid": HWID}).status_code == 404)

print()
if failures:
    print(f"FAILED {len(failures)}: " + ", ".join(failures))
    sys.exit(1)
print("ALL CHECKS PASSED")
