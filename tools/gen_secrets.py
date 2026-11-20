from __future__ import annotations

import base64
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric import ec


def main() -> None:
    seed = secrets.token_bytes(32)
    key = ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    nums = key.public_key().public_numbers()
    raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

    print("ADMIN_SECRET=" + secrets.token_hex(32))
    print("JWT_SEED_B64=" + base64.b64encode(seed).decode())
    print()
    print("# loader public key (x||y, base64):")
    print("PUBKEY_B64=" + base64.b64encode(raw).decode())

    out = sys.argv[1] if len(sys.argv) > 1 else ""
    if out:
        lines = ["#ifndef RANK1_PUBKEY_H", "#define RANK1_PUBKEY_H", "", "static const unsigned char g_auth_pubkey[64] = {"]
        for row in range(0, 64, 12):
            chunk = ", ".join(f"0x{b:02x}" for b in raw[row:row + 12])
            lines.append("    " + chunk + ",")
        lines += ["};", "", "#endif", ""]
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines))
        print(f"# wrote {out}")


if __name__ == "__main__":
    main()
