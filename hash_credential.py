#!/usr/bin/env python3
"""
hash_credential.py
──────────────────
Upload, verify, and hash W3C Verifiable Credential JSON-LD files against
the on-chain IdentityRegistry contract (Hyperledger Besu / Keccak-256).

Usage:
    python3 hash_credential.py upload [credential.jsonld] [--contract 0x...]
    python3 hash_credential.py verify <contract_address> [credential.jsonld] [--citizen 0x...]
    python3 hash_credential.py hash   [credential.jsonld]

    Running with no arguments defaults to 'upload' (legacy behaviour).

Programmatic API:
    from hash_credential import upload_credential, verify_credential

    result = upload_credential("cred.jsonld")
    ok     = verify_credential("cred.jsonld", result["contract_address"])

Dependencies:
    pip install web3   # (or pycryptodome / pysha3 for hashing only)
"""

import json
import sys
import os
from web3 import Web3


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

    print(
        "ERROR: No Keccak-256 library found.\n"
        "Install one of: web3, pycryptodome, pysha3\n"
        "  pip install web3\n"
        "  pip install pycryptodome\n"
        "  pip install pysha3",
        file=sys.stderr,
    )
    sys.exit(1)


# ── Helpers ──────────────────────────────────────────────────────────────────


BESU_URL = "http://127.0.0.1:8545"
CHAIN_ID = 1337
ACCOUNT_ADDRESS = Web3.to_checksum_address("0x2001c163af2de54de00e254b4f35be7b96ba7fd2")
PRIVATE_KEY = "0x29eb1571081de6590941526036b80f63da5ce5c6c797b604f7a6bf9497ea857b"

ABI_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sol-bin", "IdentityRegistry.abi"
)
BIN_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sol-bin", "IdentityRegistry.bin"
)


def read_str(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def _get_w3() -> Web3:
    """Return a connected Web3 instance pointing at the local Besu node."""
    w3 = Web3(Web3.HTTPProvider(BESU_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Failed to connect to Besu node at {BESU_URL}")
    return w3


def hash_credential(credential_path: str) -> tuple[str, bytes]:
    """
    Read a .jsonld credential, canonicalize it, and return
    (hex_hash_string, raw_bytes32).
    """
    if not os.path.isfile(credential_path):
        raise FileNotFoundError(f"Credential file not found: {credential_path}")

    with open(credential_path, "r", encoding="utf-8") as f:
        credential = json.load(f)

    canonical = json.dumps(credential, sort_keys=True, separators=(",", ":"))
    canonical_bytes = canonical.encode("utf-8")

    digest = keccak256(canonical_bytes)
    hex_hash = "0x" + digest.hex()
    return hex_hash, bytes.fromhex(hex_hash[2:])


def _load_contract_abi():
    return json.loads(read_str(ABI_PATH))


def _deploy_contract(w3: Web3) -> str:
    """Deploy a fresh IdentityRegistry contract and return its address."""
    abi = _load_contract_abi()
    bytecode = read_str(BIN_PATH)

    factory = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)

    deploy_tx = factory.constructor().build_transaction(
        {
            "from": ACCOUNT_ADDRESS,
            "nonce": nonce,
            "gas": 3_000_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": CHAIN_ID,
        }
    )

    signed = w3.eth.account.sign_transaction(deploy_tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract_address = receipt["contractAddress"]
    if contract_address is None:
        raise RuntimeError("Deployment failed — no contract address in receipt.")
    print(f"  Contract deployed at: {contract_address}")
    return str(contract_address)


# ── Public API ───────────────────────────────────────────────────────────────


def upload_credential(
    credential_path: str,
    citizen_address: str | None = None,
    contract_address: str | None = None,
) -> dict:
    """
    Upload (register) a .jsonld credential to the blockchain.

    1. Hash the credential file with Keccak-256.
    2. If no contract_address is given, deploy a new IdentityRegistry.
    3. Call registerIdentity(citizen, idHash) on the contract.

    Parameters
    ----------
    credential_path : str
        Path to the .jsonld credential file.
    citizen_address : str, optional
        Ethereum address of the citizen. Defaults to ACCOUNT_ADDRESS.
    contract_address : str, optional
        Address of an already-deployed IdentityRegistry. If omitted a new
        contract is deployed first.

    Returns
    -------
    dict with keys: hex_hash, contract_address, tx_hash, block_number
    """
    w3 = _get_w3()
    hex_hash, id_hash_bytes = hash_credential(credential_path)
    citizen = (
        Web3.to_checksum_address(citizen_address)
        if citizen_address
        else ACCOUNT_ADDRESS
    )

    print("=" * 72)
    print("  W3C Verifiable Credential  →  Upload to Blockchain")
    print("=" * 72)
    print(f"  Source file : {credential_path}")
    print(f"  Keccak-256 : {hex_hash}")
    print(f"  Citizen     : {citizen}")
    print()

    # Deploy if needed
    if contract_address is None:
        contract_address = _deploy_contract(w3)
    else:
        contract_address = Web3.to_checksum_address(contract_address)

    abi = _load_contract_abi()
    checksum_addr = Web3.to_checksum_address(contract_address)
    contract = w3.eth.contract(address=checksum_addr, abi=abi)
    nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)

    register_tx = contract.functions.registerIdentity(
        citizen, id_hash_bytes
    ).build_transaction(
        {
            "from": ACCOUNT_ADDRESS,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": CHAIN_ID,
        }
    )

    signed = w3.eth.account.sign_transaction(register_tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"  Identity registered! Tx: {tx_hash.hex()}")
    print(f"  Block number: {receipt['blockNumber']}")
    print("=" * 72)
    print()

    return {
        "hex_hash": hex_hash,
        "contract_address": contract_address,
        "tx_hash": tx_hash.hex(),
        "block_number": receipt["blockNumber"],
    }


def verify_credential(
    credential_path: str,
    contract_address: str,
    citizen_address: str | None = None,
) -> bool:
    """
    Verify that a .jsonld credential exists on the blockchain.

    Hashes the local credential file and calls verifyIdentity() on the
    deployed IdentityRegistry to check whether the on-chain hash matches.

    Parameters
    ----------
    credential_path : str
        Path to the .jsonld credential file to verify.
    contract_address : str
        Address of the deployed IdentityRegistry contract.
    citizen_address : str, optional
        Ethereum address of the citizen. Defaults to ACCOUNT_ADDRESS.

    Returns
    -------
    bool – True if the credential hash is registered on-chain for the citizen.
    """
    w3 = _get_w3()
    hex_hash, id_hash_bytes = hash_credential(credential_path)
    citizen = (
        Web3.to_checksum_address(citizen_address)
        if citizen_address
        else ACCOUNT_ADDRESS
    )

    print("=" * 72)
    print("  W3C Verifiable Credential  →  Blockchain Verification")
    print("=" * 72)
    print(f"  Source file       : {credential_path}")
    print(f"  Keccak-256       : {hex_hash}")
    print(f"  Citizen          : {citizen}")
    print(f"  Contract         : {contract_address}")
    print()

    abi = _load_contract_abi()
    checksum_contract = Web3.to_checksum_address(contract_address)
    contract = w3.eth.contract(address=checksum_contract, abi=abi)

    # Check registration status
    is_registered = contract.functions.isRegistered(citizen).call()
    if not is_registered:
        print("  ✗ Citizen address is NOT registered on-chain.")
        print("=" * 72)
        return False

    # Verify the hash matches
    matches = contract.functions.verifyIdentity(citizen, id_hash_bytes).call()
    stored_hash = "0x" + contract.functions.getIdentity(citizen).call().hex()

    if matches:
        print("  ✓ Credential VERIFIED — on-chain hash matches the local file.")
    else:
        print("  ✗ Credential MISMATCH — on-chain hash does NOT match.")
        print(f"    On-chain hash : {stored_hash}")
        print(f"    Local hash    : {hex_hash}")

    print("=" * 72)
    return matches


# ── Main (CLI) ───────────────────────────────────────────────────────────────


def main():
    """
    CLI entry-point.

    Usage:
        python3 hash_credential.py upload [credential.jsonld] [--contract 0x...]
        python3 hash_credential.py verify <contract_address> [credential.jsonld] [--citizen 0x...]
        python3 hash_credential.py hash   [credential.jsonld]   (just print the hash)

    Defaults to 'upload' when called with no arguments (legacy behaviour).
    """
    default_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "credentials",
        "government_id.jsonld",
    )

    args = sys.argv[1:]

    # ── Determine sub-command ────────────────────────────────────────────
    command = "upload"  # default for backward compatibility
    if args and args[0] in ("upload", "verify", "hash"):
        command = args.pop(0)

    # ── Parse remaining flags ────────────────────────────────────────────
    credential_path = default_path
    contract_addr = None
    citizen_addr = None

    i = 0
    positional = []
    while i < len(args):
        if args[i] == "--contract" and i + 1 < len(args):
            contract_addr = args[i + 1]
            i += 2
        elif args[i] == "--citizen" and i + 1 < len(args):
            citizen_addr = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1

    # For 'verify', the first positional is the contract address (required)
    if command == "verify":
        if not contract_addr:
            if not positional:
                print(
                    "Usage: hash_credential.py verify <contract_address> [credential.jsonld]",
                    file=sys.stderr,
                )
                sys.exit(1)
            contract_addr = positional.pop(0)

    if positional:
        credential_path = positional[0]

    # ── Execute ──────────────────────────────────────────────────────────
    if command == "hash":
        hex_hash, _ = hash_credential(credential_path)
        print("=" * 72)
        print("  W3C Verifiable Credential  →  Keccak-256 Hash")
        print("=" * 72)
        print(f"  Source file : {credential_path}")
        print(f"  Keccak-256 : {hex_hash}")
        print("=" * 72)
        return hex_hash

    elif command == "upload":
        result = upload_credential(credential_path, citizen_addr, contract_addr)
        return result["hex_hash"]

    elif command == "verify":
        assert contract_addr is not None  # guarded above
        ok = verify_credential(credential_path, contract_addr, citizen_addr)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
