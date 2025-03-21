#!/bin/bash

LAN_IP=$( hostname -I | awk '{print $1}' )

NUM_VALIDATORS=1
RUN_VALIDATORS=1
SHARDS_PER_VALIDATOR=4
GIT_COMMIT=main
COMPILE=1

options="s:n:c:C:R:"

while getopts $options opt; do
  case ${opt} in
    n) NUM_VALIDATORS=${OPTARG} ;;
    s) SHARDS_PER_VALIDATOR=${OPTARG} ;;
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    R) RUN_VALIDATORS=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/validator.toml.j2"

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/local"
mkdir -p $OUTPUT_DIR

# All validator config will be put here
VALIDATOR_DIR="${OUTPUT_DIR}/validator"
mkdir -p $VALIDATOR_DIR

# All generated config files will be put here
CONFIG_DIR="${OUTPUT_DIR}/config"
mkdir -p $CONFIG_DIR

# Wallet directory
WALLET_DIR="${OUTPUT_DIR}/wallet"
mkdir -p $WALLET_DIR

# Source code directory
SOURCE_DIR="${OUTPUT_DIR}/source"
mkdir -p $SOURCE_DIR

if [ "x$COMPILE" = "x1" ]; then
    # Install official linera for genesis cluster
    cd $SOURCE_DIR
    rm linera-protocol -rf
    git clone https://github.com/linera-io/linera-protocol.git
    cd linera-protocol

    git checkout $GIT_COMMIT

    # Get latest commit to avoid compilation for the same version
    LATEST_COMMIT=`git rev-parse HEAD`
    LATEST_COMMIT=${LATEST_COMMIT:0:10}
    INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}'`

    if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
        cargo install --path linera-service --features storage-service
        cargo install --path linera-storage-service --features storage-service
    fi
fi

cd $SCRIPT_DIR/..

# Make sure to clean up child processes on exit.
trap 'kill $(jobs -p)' EXIT

## Generate validator configuration from template
VALIDATOR_FILES=()
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    mkdir -p $VALIDATOR_DIR/$i

    # Generate validator configure of i
    echo "{
        \"validator\": {
            \"config_path\": \"$VALIDATOR_DIR/$i/server.json\",
            \"host\": \"$LAN_IP\",
            \"port\": $((19100 + i * 2)),
            \"metrics_port\": $((20100 + i * 2)),
            \"pyroscope_host\": \"$LAN_IP\",
            \"pyroscope_port\": $((4040 + i * 2)),
            \"internal_host\": \"$LAN_IP\",
            \"internal_port\": $((21100 + i * 2))
        },
        \"shards\": {
            \"shard_1\": {
                \"host\": \"$LAN_IP\",
                \"port\": $((22100 + i * 2)),
                \"metrics_port\": $((23100 + i * 2)),
                \"pyroscope_host\": \"$LAN_IP\",
                \"pyroscope_port\": $((24140 + i * 2))
          },
            \"shard_2\": {
                \"host\": \"$LAN_IP\",
                \"port\": $((25100 + i * 2)),
                \"metrics_port\": $((26100 + i * 2)),
                \"pyroscope_host\": \"$LAN_IP\",
                \"pyroscope_port\": $((27140 + i * 2))
            },
            \"shard_3\": {
                \"host\": \"$LAN_IP\",
                \"port\": $((28100 + i * 2)),
                \"metrics_port\": $((29100 + i * 2)),
                \"pyroscope_host\": \"$LAN_IP\",
                \"pyroscope_port\": $((30140 + i * 2))
            },
            \"shard_4\": {
                \"host\": \"$LAN_IP\",
                \"port\": $((31100 + i * 2)),
                \"metrics_port\": $((32100 + i * 2)),
                \"pyroscope_host\": \"$LAN_IP\",
                \"pyroscope_port\": $((33140 + i * 2))
            }
        }
    }" > $VALIDATOR_DIR/$i/validator.json

    jinja -d $VALIDATOR_DIR/$i/validator.json $TEMPLATE_FILE > $VALIDATOR_DIR/$i/validator.toml

    VALIDATOR_FILES+=("$VALIDATOR_DIR/$i/validator.toml")
done

# Generate committee
linera-server generate --validators "${VALIDATOR_FILES[@]}" --committee $CONFIG_DIR/committee.json

# Clean wallet
rm $WALLET_DIR/wallet_{1,2}.json $WALLET_DIR/client_{1,2}.db -rf

# Create configuration files for 10 user chains.
# * Private chain states are stored in one local wallet `wallet_1.json`.
# * `genesis.json` will contain the initial balances of chains as well as the initial committee.
linera --wallet $WALLET_DIR/wallet_1.json --storage rocksdb:$WALLET_DIR/client_1.db create-genesis-config 2 --genesis $CONFIG_DIR/genesis.json --initial-funding 100000000 --committee $CONFIG_DIR/committee.json

# Initialize the second wallet.
linera --wallet $WALLET_DIR/wallet_2.json --storage rocksdb:$WALLET_DIR/client_2.db wallet init --genesis $CONFIG_DIR/genesis.json

# Find free port for service
while true; do
    PORT=$(shuf -i 2000-65000 -n 1)
    if ! lsof -i:$PORT >/dev/null; then
        break
    fi
done

ENDPOINT="127.0.0.1:$PORT"

# Run Storage Service Server
linera-storage-server memory --endpoint "$ENDPOINT" &
SERVER_PID=$!
sleep 2  # Wait a moment to ensure the server starts properly
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Failed to start linera-storage-server. Exiting."
    exit 1
fi

STORAGE="service:tcp:$ENDPOINT:linera"

# Start servers and create initial chains in DB
for I in $(seq 0 $((RUN_VALIDATORS - 1)))
do
    linera-proxy $VALIDATOR_DIR/$I/server.json --storage $STORAGE --genesis $CONFIG_DIR/genesis.json &

    for J in $(seq 0 $((SHARDS_PER_VALIDATOR - 1)))
    do
        linera-server initialize --storage $STORAGE --genesis $CONFIG_DIR/genesis.json
    done
    for J in $(seq 0 $((SHARDS_PER_VALIDATOR - 1)))
    do
        linera-server run --storage $STORAGE --server $VALIDATOR_DIR/$I/server.json --shard "$J" --genesis $CONFIG_DIR/genesis.json &
    done
done

sleep 3;

# Create second wallet with unassigned key.
OWNER=$(linera --wallet $WALLET_DIR/wallet_2.json --storage rocksdb:$WALLET_DIR/client_2.db keygen)

# Open chain on behalf of wallet 2.
EFFECT_AND_CHAIN=$(linera --wallet $WALLET_DIR/wallet_1.json --storage rocksdb:$WALLET_DIR/client_1.db open-chain --owner "$OWNER")
EFFECT=$(echo "$EFFECT_AND_CHAIN" | sed -n '1 p')

# Assign newly created chain to unassigned key.
linera --wallet $WALLET_DIR/wallet_2.json --storage rocksdb:$WALLET_DIR/client_2.db assign --owner "$OWNER" --message-id "$EFFECT"

# Run a faucet on wallet_1 which has enough balance
linera --wallet $WALLET_DIR/wallet_1.json --storage rocksdb:$WALLET_DIR/client_1.db faucet --amount 10

read
