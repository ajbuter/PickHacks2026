#!/usr/bin/env python3
"""
api.py
──────
FastAPI service for registering arbitrary JSON identity documents on the
Hyperledger Besu blockchain and verifying their existence.

Run:
    uvicorn api:app --reload --port 8000

Endpoints:
    POST /register    – Hash arbitrary JSON, store the hash on-chain.
    POST /verify      – Check whether the JSON's hash exists on-chain.
"""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from web3 import Web3

from hash_credential import (
    ACCOUNT_ADDRESS,
    ABI_PATH,
    BIN_PATH,
    CHAIN_ID,
    PRIVATE_KEY,
    _get_w3,
    _load_contract_abi,
    keccak256,
    read_str,
)

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Identity Registry API",
    description="Register and verify arbitrary JSON identity documents on-chain.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory default contract address (set after first deploy) ─────────────
_default_contract: str | None = None


# ── Request / Response models ────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    """Body for POST /register."""

    document: dict[str, Any] = Field(
        ..., description="Arbitrary JSON document to register on-chain."
    )
    citizen_address: str | None = Field(
        None,
        description="Ethereum address of the citizen. Defaults to the server account.",
    )
    contract_address: str | None = Field(
        None,
        description="Existing IdentityRegistry address. If omitted, a new contract is deployed.",
    )


class RegisterResponse(BaseModel):
    keccak256_hash: str
    contract_address: str
    tx_hash: str
    block_number: int
    citizen_address: str


class VerifyRequest(BaseModel):
    """Body for POST /verify."""

    document: dict[str, Any] = Field(
        ..., description="The JSON document to verify against the chain."
    )
    contract_address: str | None = Field(
        None,
        description="IdentityRegistry address. If omitted, uses the last deployed contract.",
    )
    citizen_address: str | None = Field(
        None,
        description="Citizen address to check. Defaults to the server account.",
    )


class VerifyResponse(BaseModel):
    verified: bool
    keccak256_hash: str
    on_chain_hash: str | None = None
    contract_address: str
    citizen_address: str


# ── Helpers ──────────────────────────────────────────────────────────────────


def _hash_json(document: dict) -> tuple[str, bytes]:
    """Canonicalize a dict and return (hex_hash, raw_bytes32)."""
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    digest = keccak256(canonical.encode("utf-8"))
    hex_hash = "0x" + digest.hex()
    return hex_hash, bytes.fromhex(hex_hash[2:])


def _deploy_contract(w3: Web3) -> str:
    """Deploy a new IdentityRegistry and return its address."""
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

    addr = receipt["contractAddress"]
    if addr is None:
        raise RuntimeError("Deployment failed — no contract address in receipt.")
    return str(addr)


# ── Endpoints ────────────────────────────────────────────────────────────────


@app.post("/register", response_model=RegisterResponse)
def register_identity(body: RegisterRequest):
    """
    Hash an arbitrary JSON document (Keccak-256) and register the hash
    on the IdentityRegistry smart contract.

    If no `contract_address` is provided, a new contract is deployed
    automatically and its address is returned.
    """
    global _default_contract

    try:
        w3 = _get_w3()
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    hex_hash, id_hash_bytes = _hash_json(body.document)
    citizen = (
        Web3.to_checksum_address(body.citizen_address)
        if body.citizen_address
        else ACCOUNT_ADDRESS
    )

    # Resolve contract address
    contract_address = body.contract_address or _default_contract
    if contract_address is None:
        contract_address = _deploy_contract(w3)
        _default_contract = contract_address
    else:
        contract_address = Web3.to_checksum_address(contract_address)

    # Register the hash on-chain
    abi = _load_contract_abi()
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=abi
    )
    nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)

    tx = contract.functions.registerIdentity(citizen, id_hash_bytes).build_transaction(
        {
            "from": ACCOUNT_ADDRESS,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": CHAIN_ID,
        }
    )

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return RegisterResponse(
        keccak256_hash=hex_hash,
        contract_address=contract_address,
        tx_hash=tx_hash.hex(),
        block_number=receipt["blockNumber"],
        citizen_address=citizen,
    )


@app.post("/verify", response_model=VerifyResponse)
def verify_identity(body: VerifyRequest):
    """
    Hash an arbitrary JSON document and check whether that hash is
    registered on-chain for the given citizen address.
    """
    global _default_contract

    contract_address = body.contract_address or _default_contract
    if contract_address is None:
        raise HTTPException(
            status_code=400,
            detail="No contract_address provided and no contract has been deployed yet.",
        )

    try:
        w3 = _get_w3()
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    hex_hash, id_hash_bytes = _hash_json(body.document)
    citizen = (
        Web3.to_checksum_address(body.citizen_address)
        if body.citizen_address
        else ACCOUNT_ADDRESS
    )
    contract_address = Web3.to_checksum_address(contract_address)

    abi = _load_contract_abi()
    contract = w3.eth.contract(address=contract_address, abi=abi)

    # Check registration
    is_registered = contract.functions.isRegistered(citizen).call()
    if not is_registered:
        return VerifyResponse(
            verified=False,
            keccak256_hash=hex_hash,
            on_chain_hash=None,
            contract_address=contract_address,
            citizen_address=citizen,
        )

    # Compare hashes
    matches = contract.functions.verifyIdentity(citizen, id_hash_bytes).call()
    stored_hash = "0x" + contract.functions.getIdentity(citizen).call().hex()

    return VerifyResponse(
        verified=matches,
        keccak256_hash=hex_hash,
        on_chain_hash=stored_hash,
        contract_address=contract_address,
        citizen_address=citizen,
    )


# ── Example: full lifecycle demo ────────────────────────────────────────────

if __name__ == "__main__":
    """
    Run this file directly to see a complete example:
      1. Register a citizen's identity document on-chain.
      2. Save the document as a .jsonId file.
      3. Verify the .jsonId against the blockchain (should PASS).
      4. Verify a fake/tampered .jsonId (should FAIL).

    Prerequisites:
      - Besu node running on http://127.0.0.1:8545
      - Contract ABI + BIN in sol-bin/

    Usage:
      python api.py
    """
    import pprint
    import tempfile

    SEPARATOR = "=" * 60

    # ── Step 1: Create a citizen identity document ──────────────────────
    citizen_id_document = {
        "type": "GovernmentID",
        "citizen": {
            "firstName": "Jane",
            "lastName": "Doe",
            "dateOfBirth": "1990-05-15",
            "nationalId": "AB-1234567",
        },
        "issuer": "Department of National Identity",
        "issuedDate": "2025-01-10",
        "expiryDate": "2035-01-10",
        "country": "Examplestan",
    }

    print(SEPARATOR)
    print("STEP 1 — Citizen identity document")
    print(SEPARATOR)
    pprint.pprint(citizen_id_document)

    # ── Step 2: Register the document on-chain ──────────────────────────
    print(f"\n{SEPARATOR}")
    print("STEP 2 — Register identity on the blockchain")
    print(SEPARATOR)

    w3 = _get_w3()
    hex_hash, id_hash_bytes = _hash_json(citizen_id_document)
    contract_addr = _deploy_contract(w3)

    abi = _load_contract_abi()
    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_addr), abi=abi)
    nonce = w3.eth.get_transaction_count(ACCOUNT_ADDRESS)

    tx = contract.functions.registerIdentity(
        ACCOUNT_ADDRESS, id_hash_bytes
    ).build_transaction(
        {
            "from": ACCOUNT_ADDRESS,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": w3.eth.gas_price,
            "chainId": CHAIN_ID,
        }
    )
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"  Keccak-256 hash : {hex_hash}")
    print(f"  Contract address: {contract_addr}")
    print(f"  TX hash         : {tx_hash.hex()}")
    print(f"  Block number    : {receipt['blockNumber']}")

    # ── Step 3: Generate the .jsonId file ───────────────────────────────
    print(f"\n{SEPARATOR}")
    print("STEP 3 — Generate .jsonId credential file")
    print(SEPARATOR)

    json_id = {
        "document": citizen_id_document,
        "blockchain": {
            "network": "Hyperledger Besu (local)",
            "chainId": CHAIN_ID,
            "contractAddress": contract_addr,
            "citizenAddress": ACCOUNT_ADDRESS,
            "keccak256Hash": hex_hash,
            "txHash": tx_hash.hex(),
            "blockNumber": receipt["blockNumber"],
        },
    }

    json_id_path = os.path.join(tempfile.gettempdir(), "jane_doe.jsonId")
    with open(json_id_path, "w") as f:
        json.dump(json_id, f, indent=2)

    print(f"  Saved to: {json_id_path}")
    print("  Contents:")
    print(json.dumps(json_id, indent=2))

    # ── Step 4: Verify the REAL .jsonId ─────────────────────────────────
    print(f"\n{SEPARATOR}")
    print("STEP 4 — Verify the REAL .jsonId  ✓  (expect: PASS)")
    print(SEPARATOR)

    with open(json_id_path) as f:
        loaded = json.load(f)

    verify_hash, verify_bytes = _hash_json(loaded["document"])
    is_registered = contract.functions.isRegistered(ACCOUNT_ADDRESS).call()
    matches = contract.functions.verifyIdentity(ACCOUNT_ADDRESS, verify_bytes).call()
    stored_hash = "0x" + contract.functions.getIdentity(ACCOUNT_ADDRESS).call().hex()

    print(f"  Submitted hash : {verify_hash}")
    print(f"  On-chain hash  : {stored_hash}")
    print(f"  Is registered  : {is_registered}")
    print(f"  Hashes match   : {matches}")
    print(f"  ➜ Verification : {'✅ PASSED' if matches else '❌ FAILED'}")

    # ── Step 5: Verify a FAKE / tampered .jsonId ────────────────────────
    print(f"\n{SEPARATOR}")
    print("STEP 5 — Verify a FAKE .jsonId  ✗  (expect: FAIL)")
    print(SEPARATOR)

    fake_document = {
        "type": "GovernmentID",
        "citizen": {
            "firstName": "John",
            "lastName": "Fakerson",
            "dateOfBirth": "2000-01-01",
            "nationalId": "ZZ-9999999",
        },
        "issuer": "Totally Legit ID Bureau",
        "issuedDate": "2025-06-01",
        "expiryDate": "2035-06-01",
        "country": "Fakeland",
    }

    fake_hash, fake_bytes = _hash_json(fake_document)
    fake_matches = contract.functions.verifyIdentity(ACCOUNT_ADDRESS, fake_bytes).call()

    print(f"  Fake hash      : {fake_hash}")
    print(f"  On-chain hash  : {stored_hash}")
    print(f"  Hashes match   : {fake_matches}")
    print(f"  ➜ Verification : {'✅ PASSED' if fake_matches else '❌ FAILED'}")

    print(f"\n{SEPARATOR}")
    print("DEMO COMPLETE")
    print(SEPARATOR)
