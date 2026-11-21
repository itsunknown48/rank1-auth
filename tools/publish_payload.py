from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GITHUB_API = "https://api.github.com"


def seal(source: Path) -> tuple[bytes, bytes, bytes, str]:
    plain = source.read_bytes()
    key = os.urandom(32)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plain, None)
    digest = hashlib.sha256(sealed).hexdigest()
    return sealed, key, nonce, digest


def call(method: str, url: str, headers: dict, body: bytes | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def gh_release(token: str, repo: str, tag: str) -> dict:
    headers = gh_headers(token)
    status, body = call("GET", f"{GITHUB_API}/repos/{repo}/releases/tags/{tag}", headers)
    if status == 200:
        return json.loads(body)
    if status != 404:
        raise SystemExit(f"github release lookup failed: {status} {body[:200]!r}")
    payload = json.dumps(
        {"tag_name": tag, "name": tag, "draft": False, "prerelease": False, "body": "Rank1 overlay payload"}
    ).encode()
    status, body = call(
        "POST", f"{GITHUB_API}/repos/{repo}/releases", {**headers, "Content-Type": "application/json"}, payload
    )
    if status not in (200, 201):
        raise SystemExit(f"github release create failed: {status} {body[:200]!r}")
    return json.loads(body)


def gh_upload(token: str, repo: str, release: dict, asset_name: str, data: bytes) -> str:
    headers = gh_headers(token)
    for asset in release.get("assets", []):
        if asset["name"] == asset_name:
            call("DELETE", f"{GITHUB_API}/repos/{repo}/releases/assets/{asset['id']}", headers)
    upload_url = release["upload_url"].split("{", 1)[0]
    status, body = call(
        "POST",
        f"{upload_url}?name={asset_name}",
        {**headers, "Content-Type": "application/octet-stream"},
        data,
    )
    if status not in (200, 201):
        raise SystemExit(f"github asset upload failed: {status} {body[:200]!r}")
    return json.loads(body)["browser_download_url"]


def register(api: str, secret: str, descriptor: dict) -> dict:
    status, body = call(
        "POST",
        f"{api.rstrip('/')}/v1/admin/payload",
        {"X-Admin-Secret": secret, "Content-Type": "application/json"},
        json.dumps(descriptor).encode(),
    )
    if status != 200:
        raise SystemExit(f"backend rejected the payload: {status} {body[:200]!r}")
    return json.loads(body)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("overlay", type=Path)
    ap.add_argument("--version", default="", help="release label, e.g. 1.0.1")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPO", ""), help="owner/repo")
    ap.add_argument("--tag", default="", help="release tag, defaults to rank1-overlay-<version>")
    ap.add_argument("--api", default=os.environ.get("RANK1_API", ""))
    ap.add_argument("--no-upload", action="store_true", help="seal only, print the descriptors")
    ap.add_argument(
        "--local",
        action="store_true",
        help="serve the blob from the backend itself (no GitHub)",
    )
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--descriptor", type=Path, default=None, help="write the sealed descriptor json")
    ap.add_argument("--register-only", type=Path, default=None, help="register an existing descriptor json")
    args = ap.parse_args()

    secret = os.environ.get("ADMIN_SECRET", "")
    api = args.api or os.environ.get("RANK1_API", "")

    if args.register_only:
        descriptor = json.loads(args.register_only.read_text())
        if not secret or not api:
            raise SystemExit("RANK1_API / ADMIN_SECRET must be set to register")
        result = register(api, secret, descriptor)
        print(f"active  release #{result['id']} {result['version']} {result['sha256'][:12]}")
        return 0

    if not args.overlay.is_file():
        raise SystemExit(f"not found: {args.overlay}")

    version = args.version or "0.0.0"
    sealed, key, nonce, digest = seal(args.overlay)
    out = args.out or Path(f"rank1-overlay-{version}.bin")
    if args.local:
        out = Path(__file__).resolve().parent.parent / "rank1-overlay.bin"
    out.write_bytes(sealed)

    print(f"plain   {args.overlay}  {args.overlay.stat().st_size} bytes")
    print(f"sealed  {out}  {len(sealed)} bytes")
    print(f"sha256  {digest}")

    descriptor = {
        "sha256": digest,
        "key_b64": base64.b64encode(key).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "size": len(sealed),
        "version": version,
        "url": "",
    }

    token = os.environ.get("GITHUB_TOKEN", "")
    tag = args.tag or f"rank1-overlay-{version}"

    if args.descriptor:
        args.descriptor.write_text(json.dumps(descriptor, indent=2))
        print(f"desc    {args.descriptor}")

    if args.local:
        print(f"blob    {out}")
        if not secret or not api:
            print()
            print("RANK1_API / ADMIN_SECRET not set, register manually:")
            print(json.dumps(descriptor, indent=2))
            return 0
        result = register(api, secret, descriptor)
        print(f"active  release #{result['id']} {result['version']} {result['sha256'][:12]}")
        return 0

    if args.no_upload or not token or not args.repo:
        print()
        print("manual upload:")
        print(f"  gh release create {tag} {out} --repo {args.repo or '<owner/repo>'} --title {tag}")
        print("  then register with url = the asset's browser_download_url")
        print()
        print(json.dumps(descriptor, indent=2))
        return 0

    asset = f"rank1-overlay-{version}.bin"
    release = gh_release(token, args.repo, tag)
    descriptor["url"] = gh_upload(token, args.repo, release, asset, sealed)
    print(f"upload  {descriptor['url']}")

    if not secret or not api:
        print()
        print("RANK1_API / ADMIN_SECRET not set, register manually:")
        print(json.dumps(descriptor, indent=2))
        return 0

    result = register(api, secret, descriptor)
    print(f"active  release #{result['id']} {result['version']} {result['sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
