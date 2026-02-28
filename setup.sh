#!/usr/bin/env bash
# ============================================================================
#  setup.sh — Bootstrap a private Hyperledger Besu network (Clique / PoA)
# ============================================================================
#  This script:
#    1. Generates a node key + Ethereum address for the Government Authority.
#    2. Patches genesis.json and docker-compose.yml with the real address.
#    3. Starts the Besu container via Docker Compose.
#
#  Prerequisites: docker, docker-compose (or docker compose plugin), jq, sed
#
#  Usage:
#    chmod +x setup.sh && ./setup.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/data"
GENESIS_FILE="${SCRIPT_DIR}/genesis.json"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
BESU_IMAGE="hyperledger/besu:latest"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*" >&2; }

# ── Pre-flight checks ───────────────────────────────────────────────────────

for cmd in docker jq sed; do
  if ! command -v "$cmd" &>/dev/null; then
    err "Required command '$cmd' not found. Please install it."
    exit 1
  fi
done

# Check for docker compose (plugin) or docker-compose (standalone)
if docker compose version &>/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
else
  err "Neither 'docker compose' plugin nor 'docker-compose' found."
  exit 1
fi

info "Using compose command: ${DOCKER_COMPOSE}"

# ── Step 1: Generate Node Key & Address ──────────────────────────────────────

if [ -f "${DATA_DIR}/key" ]; then
  info "Existing node key found in ${DATA_DIR}/key"
  info "Re-using existing key. Delete ${DATA_DIR}/key to regenerate."
else
  info "Generating new node key..."
  mkdir -p "${DATA_DIR}"

  # Run Besu in a throwaway container to generate the key pair
  docker run --rm \
    -v "${DATA_DIR}:/opt/besu/data" \
    "${BESU_IMAGE}" \
    --data-path=/opt/besu/data \
    public-key export-address \
    --to=/opt/besu/data/node-address

  ok "Node key generated."
fi

# Read the address (strip 0x prefix if present, lowercase)
if [ -f "${DATA_DIR}/node-address" ]; then
  NODE_ADDRESS=$(cat "${DATA_DIR}/node-address" | tr -d '[:space:]')
else
  # Fallback: derive address from key using Besu
  docker run --rm \
    -v "${DATA_DIR}:/opt/besu/data" \
    "${BESU_IMAGE}" \
    --data-path=/opt/besu/data \
    public-key export-address \
    --to=/opt/besu/data/node-address
  NODE_ADDRESS=$(cat "${DATA_DIR}/node-address" | tr -d '[:space:]')
fi

# Normalise: remove 0x prefix for extraData embedding
ADDR_NO_PREFIX="${NODE_ADDRESS#0x}"
ADDR_WITH_PREFIX="0x${ADDR_NO_PREFIX}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Government Authority Address: ${GREEN}${ADDR_WITH_PREFIX}${NC}${BOLD}  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 2: Patch genesis.json ──────────────────────────────────────────────

info "Patching genesis.json with signer address..."

# Build the correct Clique extraData field:
#   32 bytes vanity (64 hex zeros)
#   + 20 bytes signer address (40 hex chars)
#   + 65 bytes seal signature (130 hex zeros)
VANITY="0000000000000000000000000000000000000000000000000000000000000000"
SEAL="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
EXTRA_DATA="0x${VANITY}${ADDR_NO_PREFIX}${SEAL}"

# Create patched genesis using jq for correctness
jq --arg addr "${ADDR_WITH_PREFIX}" --arg extra "${EXTRA_DATA}" '
  .extraData = $extra |
  .alloc = { ($addr): .alloc[keys[0]] }
' "${GENESIS_FILE}" > "${GENESIS_FILE}.tmp" && mv "${GENESIS_FILE}.tmp" "${GENESIS_FILE}"

ok "genesis.json updated."

# ── Step 3: Patch docker-compose.yml ─────────────────────────────────────────

info "Patching docker-compose.yml with miner coinbase..."
sed -i.bak "s/SIGNER_ADDRESS_PLACEHOLDER/${ADDR_WITH_PREFIX}/g" "${COMPOSE_FILE}"
rm -f "${COMPOSE_FILE}.bak"
ok "docker-compose.yml updated."

# ── Step 4: Fix data directory permissions ──────────────────────────────────

info "Setting data directory permissions..."
chmod -R 777 "${DATA_DIR}"
ok "Permissions set."

# ── Step 5: Start the network ────────────────────────────────────────────────

info "Starting the Besu node..."
cd "${SCRIPT_DIR}"
${DOCKER_COMPOSE} up -d

echo ""
ok "Government Authority Besu node is running!"
echo ""
echo -e "${BOLD}  JSON-RPC HTTP  :${NC} http://localhost:8545"
echo -e "${BOLD}  JSON-RPC WS    :${NC} ws://localhost:8546"
echo -e "${BOLD}  Authority Addr :${NC} ${ADDR_WITH_PREFIX}"
echo ""
echo -e "${CYAN}  Quick health check:${NC}"
echo '    curl -s -X POST --data '"'"'{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'"'"' http://localhost:8545'
echo ""
echo -e "${CYAN}  View logs:${NC}"
echo "    ${DOCKER_COMPOSE} logs -f besu-node"
echo ""
echo -e "${CYAN}  Stop the network:${NC}"
echo "    ${DOCKER_COMPOSE} down"
echo ""

# Save the address to a file for other scripts to use
echo "${ADDR_WITH_PREFIX}" > "${SCRIPT_DIR}/.government-address"
ok "Address saved to .government-address"
