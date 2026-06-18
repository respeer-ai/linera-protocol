#!/bin/bash

set -euo pipefail

# Restart the existing respeer RPC and faucet containers without rebuilding images
# or creating new wallets. This script intentionally reuses the wallet state from
# the existing sibling linera-protocol-respeer checkout.

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
DEFAULT_RESPEER_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)/linera-protocol-respeer
RESPEER_DIR=${RESPEER_DIR:-$DEFAULT_RESPEER_DIR}
RESPEER_DOCKER_DIR=${RESPEER_DOCKER_DIR:-$RESPEER_DIR/docker}
WALLET_DIR=${WALLET_DIR:-$RESPEER_DIR/output/wallet}
LINERA_IMAGE=${LINERA_IMAGE:-linera-respeer}

function require_file() {
    local path=$1
    if [ ! -f "$path" ]; then
        echo "Required file not found: $path" >&2
        exit 1
    fi
}

function require_dir() {
    local path=$1
    if [ ! -d "$path" ]; then
        echo "Required directory not found: $path" >&2
        exit 1
    fi
}

function require_wallet() {
    local name=$1
    local dir=$WALLET_DIR/$name

    require_dir "$dir"
    require_file "$dir/wallet.json"
    require_file "$dir/keystore.json"
    require_dir "$dir/client.db"
}

require_file "$RESPEER_DOCKER_DIR/docker-compose-rpc.yml"
require_file "$RESPEER_DOCKER_DIR/docker-compose-faucet-shard.yml"
require_file "$RESPEER_DOCKER_DIR/rpc-entrypoint.sh"
require_file "$RESPEER_DOCKER_DIR/faucet-shard-entrypoint.sh"
require_file "$RESPEER_DOCKER_DIR/faucet-entrypoint.sh"
require_wallet rpc
require_wallet faucet
require_dir "$WALLET_DIR/faucet-depositor"

cd "$RESPEER_DOCKER_DIR"

docker stop rpc faucet >/dev/null 2>&1 || true
docker rm rpc faucet >/dev/null 2>&1 || true

LINERA_IMAGE=$LINERA_IMAGE docker compose -f docker-compose-rpc.yml up --wait
LINERA_IMAGE=$LINERA_IMAGE docker compose -f docker-compose-faucet-shard.yml up --wait

docker ps -a --filter name='^/(rpc|faucet)$' --format '{{.Names}} {{.Image}} {{.Status}} {{.Ports}}'
