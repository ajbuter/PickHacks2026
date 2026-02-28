# Hackathon City — Private Ethereum Identity Network

A self-hosted, private Ethereum network using **Hyperledger Besu** with **Clique (Proof-of-Authority)** consensus. Designed for a Government Authority to manage citizen identity hashes on-chain.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Government Authority                   │
│                                                         │
│  ┌───────────────┐    ┌──────────────────────────────┐  │
│  │  Besu Node    │    │  IdentityRegistry Contract   │  │
│  │  (Clique PoA) │◄──►│  mapping(addr => bytes32)    │  │
│  │  Port 8545    │    │  onlyOwner: registerIdentity │  │
│  └───────────────┘    └──────────────────────────────┘  │
│         ▲                                               │
│         │ JSON-RPC                                      │
└─────────┼───────────────────────────────────────────────┘
          │
    ┌─────┴──────┐
    │  Verifier  │  curl / web3.js / web3.py
    │  (Public)  │  eth_call → getIdentity / verifyIdentity
    └────────────┘
```

### Two Layers of Security

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Chain** | Clique `extraData` signer list in `genesis.json` | Only the Government Node can mine/seal blocks |
| **Contract** | `onlyOwner` modifier in Solidity | Only the Government's private key can write ID hashes |

## Prerequisites

- **Docker** & **Docker Compose** (v2 plugin or standalone)
- **jq** — JSON processor (`apt install jq` / `brew install jq`)
- **Python 3.8+** (for the credential hashing script)
- One of: `web3` / `pycryptodome` / `pysha3` Python packages

## Quick Start

```bash
# 1. Clone and enter the project
cd hackathon-city

# 2. Run the bootstrap script
chmod +x setup.sh
./setup.sh

# 3. Verify the node is running
curl -s -X POST \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545
```

## Project Structure

```
hackathon-city/
├── setup.sh                        # Bootstrap: keygen → patch genesis → start
├── genesis.json                    # Clique PoA genesis (patched by setup.sh)
├── docker-compose.yml              # Besu container definition
├── contracts/
│   └── IdentityRegistry.sol        # On-chain identity registry
├── credentials/
│   └── government_id.jsonld        # Sample W3C Verifiable Credential
├── hash_credential.py              # Keccak-256 hasher for credentials
└── data/                           # Besu data directory (created by setup.sh)
    ├── key                         # Node private key (KEEP SECRET)
    └── node-address                # Derived Ethereum address
```

## File Details

### `genesis.json`
Clique PoA genesis configuration:
- **Chain ID:** 1337
- **Block period:** 5 seconds
- **Gas limit:** Effectively unlimited (for dev flexibility)
- **Signer:** Automatically patched by `setup.sh` into `extraData`

### `docker-compose.yml`
Runs Besu with:
- JSON-RPC HTTP on port **8545**
- JSON-RPC WebSocket on port **8546**
- APIs: `ETH, NET, CLIQUE, WEB3, ADMIN, DEBUG, TXPOOL`
- Mining enabled with zero gas price (permissioned network)

### `contracts/IdentityRegistry.sol`
| Function | Access | Description |
|----------|--------|-------------|
| `registerIdentity(address, bytes32)` | `onlyOwner` | Store a citizen's ID hash |
| `revokeIdentity(address)` | `onlyOwner` | Remove a citizen's ID hash |
| `getIdentity(address)` | Public | Look up a citizen's hash |
| `verifyIdentity(address, bytes32)` | Public | Check if hash matches |
| `transferOwnership(address)` | `onlyOwner` | Transfer authority |

### `hash_credential.py`
```bash
# Hash the sample credential
python3 hash_credential.py

# Hash a custom credential
python3 hash_credential.py /path/to/credential.jsonld
```

## Deployment Workflow

### 1. Start the Network
```bash
./setup.sh
```

### 2. Deploy the Contract
Use **Remix IDE**, **Hardhat**, or **Foundry**. Example with `curl` and a pre-compiled contract:

```bash
# Using web3.py
from web3 import Web3
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))

# Load the Government Authority's private key (from data/key)
# Deploy IdentityRegistry...
```

### 3. Register an Identity
```bash
# Hash the credential
python3 hash_credential.py credentials/government_id.jsonld

# Call registerIdentity(citizenAddress, idHash) via web3
```

### 4. Verify an Identity (The "Verification API")
```bash
# Anyone can verify by calling the contract via JSON-RPC:
curl -X POST \
  --data '{
    "jsonrpc":"2.0",
    "method":"eth_call",
    "params":[{
      "to": "CONTRACT_ADDRESS",
      "data": "0x..."
    }],
    "id":1
  }' \
  http://localhost:8545
```

## Operations

```bash
# View logs
docker compose logs -f besu-node

# Stop the network
docker compose down

# Restart
docker compose up -d

# Check signer status
curl -s -X POST \
  --data '{"jsonrpc":"2.0","method":"clique_getSigners","params":["latest"],"id":1}' \
  http://localhost:8545
```

## Security Notes

- **`data/key`** is the Government Authority's private key. Protect it accordingly.
- The JSON-RPC API is bound to `0.0.0.0` for development. In production, restrict via firewall or bind to `127.0.0.1`.
- The `--host-allowlist=*` flag should be tightened for production use.
- Consider adding TLS termination (e.g., nginx reverse proxy) in front of port 8545.
