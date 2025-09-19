#!/bin/bash

####
## E.g. ./run_rpc_service.sh -f https://faucet.testnet-conway.linera.net -C 0 -W 0 -z testnet-conway
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=http://api.faucet.respeer.ai/api/faucet
COMPILE=1
CREATE_WALLET=1
CLUSTER=

options="f:c:C:W:z:"

while getopts $options opt; do
  case ${opt} in
    f) FAUCET_URL=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
    z) CLUSTER=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TEMPLATE_FILE=${SCRIPT_DIR}/../configuration/template/nginx.conf.j2

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../output/local"
mkdir -p $OUTPUT_DIR

# Generate config
CONFIG_DIR="${OUTPUT_DIR}/config"
mkdir -p $CONFIG_DIR

# Wallet directory
WALLET_DIR="${OUTPUT_DIR}/wallet"
mkdir -p $WALLET_DIR

BIN_DIR="${OUTPUT_DIR}/bin"
mkdir -p $BIN_DIR

export PATH=$BIN_DIR:$PATH

cd $SCRIPT_DIR/..

if [ "x$COMPILE" = "x1" ]; then
    cargo build --release --features storage-service,disable-native-rpc,enable-wallet-rpc
    mv $PWD/target/release/linera $BIN_DIR
    mv $PWD/target/release/linera-server $BIN_DIR
    mv $PWD/target/release/linera-storage-server $BIN_DIR
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
           --keystore $WALLET_DIR/rpc/keystore.json \
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
            \"servers\": [\"localhost:30080\"],
            \"domain\": \"$domain\",
            \"sub_domain\": \"$SUB_DOMAIN\",
            \"api_endpoint\": \"$endpoint\"
        }
    }" > ${CONFIG_DIR}/$endpoint.nginx.json

    jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
    sudo cp ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/
    sudo nginx -s reload
}

SUB_DOMAIN=$(echo "api.${CLUSTER}." | sed 's/\.\./\./g')

# Generate service nginx conf
generate_rpc_nginx_conf

echo -e "\n\nService domain"
echo -e "   $LAN_IP ${SUB_DOMAIN}rpc.respeer.ai"
echo -e "   http://${SUB_DOMAIN}rpc.respeer.ai/api/rpc\n\n"

function run_rpc_service() {
    linera --wallet $WALLET_DIR/rpc/wallet.json \
           --storage rocksdb://$WALLET_DIR/rpc/client.db \
           service \
           --listener-skip-process-inbox \
           --port 30080 &
}

run_rpc_service

read
