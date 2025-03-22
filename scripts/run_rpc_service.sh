#!/bin/bash

####
## E.g. ./run_rpc_service.sh -f http://172.16.31.73:8080 -C 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=https://faucet.testnet-archimedes.linera.io
COMPILE=1
GIT_COMMIT=main
CREATE_WALLET=1
CHAIN_OWNER_COUNT=4

options="f:c:C:W:"

while getopts $options opt; do
  case ${opt} in
    f) FAUCET_URL=${OPTARG} ;;
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TEMPLATE_FILE=${SCRIPT_DIR}/../configuration/template/nginx.conf.j2

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/local"
mkdir -p $OUTPUT_DIR

# Generate config
CONFIG_DIR="${OUTPUT_DIR}/config"
mkdir -p $CONFIG_DIR

# Wallet directory
WALLET_DIR="${OUTPUT_DIR}/wallet"
mkdir -p $WALLET_DIR

cd $SCRIPT_DIR/..

if [ "x$COMPILE" = "x1" ]; then
    # Get latest commit to avoid compilation for the same version
    LATEST_COMMIT=`git rev-parse HEAD`
    LATEST_COMMIT=${LATEST_COMMIT:0:10}
    INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}' | awk '{print $1}'`

    if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
        cargo install --path linera-service --features storage-service,disable-native-rpc,enable-wallet-rpc
        cargo install --path linera-storage-service --features storage-service
    fi
fi

# Make sure to clean up child processes on exit.
trap 'kill $(jobs -p)' EXIT

RPC_WALLET=$WALLET_DIR/rpc

if [ ! -d ${RPC_WALLET} ]; then
    CREATE_WALLET=1
fi

function create_rpc_wallet() {
    rm -rf $WALLET_DIR/rpc
    mkdir -p $WALLET_DIR/rpc

    # Init wallet from faucet
    linera --wallet $WALLET_DIR/rpc/wallet.json \
           --storage rocksdb://$WALLET_DIR/rpc/client.db \
           wallet init \
           --faucet $FAUCET_URL
}

# Create rpc wallet
if [ "x$CREATE_WALLET" = "x1" ]; then
    create_rpc_wallet
fi

function generate_rpc_nginx_conf() {
    endpoint=rpc
    domain=rpc.respeer.ai

    echo "{
        \"service\": {
            \"endpoint\": \"$endpoint\",
            \"servers\": [\"$LAN_IP:30080\"],
            \"domain\": \"$domain\",
            \"api_endpoint\": \"$endpoint\"
        }
    }" > ${CONFIG_DIR}/$endpoint.nginx.json

    jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
    echo "cp ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/"
}

# Generate service nginx conf
generate_rpc_nginx_conf

echo -e "\n\nService domain"
echo -e "   $LAN_IP api.rpc.respeer.ai"
echo -e "   http://api.rpc.respeer.ai/rpc\n\n"

function run_rpc_service() {
    linera --wallet $WALLET_DIR/rpc/wallet.json \
           --storage rocksdb://$WALLET_DIR/rpc/client.db \
           service \
           --listener-skip-process-inbox \
           --port 30080 &
}

run_rpc_service

read
