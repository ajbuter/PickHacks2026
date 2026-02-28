#!/usr/bin/env python3
"""
hash_credential.py
──────────────────
Reads a W3C Verifiable Credential JSON-LD file and produces its Keccak-256
hash — the same hash that gets stored on-chain in the IdentityRegistry contract.

Usage:
    python3 hash_credential.py [path_to_credential.jsonld]

Dependencies:
    pip install pycryptodome   # (or pysha3, or web3)
"""

import json
import sys
import os

# ── Keccak-256 implementation (tries multiple libraries) ────────────────────


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of *data*."""
    # Try 1: web3 (most common in Ethereum dev)
    try:
        from web3 import Web3

        return Web3.keccak(data)
    except ImportError:
        pass

    # Try 2: pycryptodome
    try:
        from Crypto.Hash import keccak

        h = keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
    except ImportError:
        pass

    # Try 3: pysha3
    try:
        import sha3

        h = sha3.keccak_256()
        h.update(data)
        return h.digest()
    except ImportError:
        pass

    print(
        "ERROR: No Keccak-256 library found.\n"
        "Install one of: web3, pycryptodome, pysha3\n"
        "  pip install web3\n"
        "  pip install pycryptodome\n"
        "  pip install pysha3",
        file=sys.stderr,
    )
    sys.exit(1)


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    # Default credential path
    default_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "credentials",
        "government_id.jsonld",
    )
    credential_path = sys.argv[1] if len(sys.argv) > 1 else default_path

    if not os.path.isfile(credential_path):
        print(f"File not found: {credential_path}", file=sys.stderr)
        sys.exit(1)

    # Read and canonicalize (compact JSON, sorted keys, no extra whitespace)
    with open(credential_path, "r", encoding="utf-8") as f:
        credential = json.load(f)

    canonical = json.dumps(credential, sort_keys=True, separators=(",", ":"))
    canonical_bytes = canonical.encode("utf-8")

    digest = keccak256(canonical_bytes)
    hex_hash = "0x" + digest.hex()

    print("=" * 72)
    print("  W3C Verifiable Credential  →  Keccak-256 Hash")
    print("=" * 72)
    print(f"  Source file : {credential_path}")
    print(f"  Byte length: {len(canonical_bytes)}")
    print(f"  Keccak-256 : {hex_hash}")
    print("=" * 72)
    print()
    print("Use this hash as the `idHash` parameter when calling")
    print("IdentityRegistry.registerIdentity(citizenAddress, idHash)")
    print()

    return hex_hash


if __name__ == "__main__":
    main()
