#!/bin/bash

####
## E.g. ./run_faucet_service.sh -f https://faucet.testnet-conway.linera.net -C 0 -W 0 -z testnet-conway
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=https://faucet.testnet-conway.linera.net
COMPILE=1
CREATE_WALLET=1
CLUSTER=testnet-conway

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
    cargo build --release --features storage-service,disable-native-rpc,enable-wallet-rpc -j 4
    mv $PWD/target/release/linera $BIN_DIR
    mv $PWD/target/release/linera-server $BIN_DIR
    mv $PWD/target/release/linera-storage-server $BIN_DIR
fi

# Make sure to clean up child processes on exit.
trap 'kill $(jobs -p)' EXIT

FAUCET_WALLET=$WALLET_DIR/faucet

if [ ! -d ${FAUCET_WALLET} ]; then
    CREATE_WALLET=1
fi

function create_faucet_wallet() {
    rm -rf $WALLET_DIR/faucet
    mkdir -p $WALLET_DIR/faucet

    # Init wallet from faucet
    linera --wallet $WALLET_DIR/faucet/wallet.json \
           --keystore $WALLET_DIR/faucet/keystore.json \
           --storage rocksdb://$WALLET_DIR/faucet/client.db \
           wallet init \
           --faucet $FAUCET_URL
    linera --wallet $WALLET_DIR/faucet/wallet.json \
           --keystore $WALLET_DIR/faucet/keystore.json \
           --storage rocksdb://$WALLET_DIR/faucet/client.db \
           wallet request-chain \
           --faucet $FAUCET_URL
}

# Create faucet wallet
if [ "x$CREATE_WALLET" = "x1" ]; then
    create_faucet_wallet
fi

function generate_faucet_nginx_conf() {
    endpoint=faucet
    domain=faucet.respeer.ai

    echo "{
        \"service\": {
            \"endpoint\": \"$endpoint\",
            \"servers\": [\"localhost:30090\"],
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
generate_faucet_nginx_conf

echo -e "\n\nService domain"
echo -e "   $LAN_IP ${SUB_DOMAIN}faucet.respeer.ai"
echo -e "   http://${SUB_DOMAIN}faucet.respeer.ai/api/faucet\n\n"

function run_faucet_service() {
    chain_id=$(linera --wallet $WALLET_DIR/faucet/wallet.json \
        --keystore $WALLET_DIR/faucet/keystore.json \
        --storage rocksdb://$WALLET_DIR/faucet/client.db \
        wallet show \
        | awk '/^Chain ID:/ {chain=$3} /^Default owner:/ {if ($3 != "No") print chain}')

    echo 'Query balance ===================================================================='
    echo "Chain: $chain_id"
    linera --wallet $WALLET_DIR/faucet/wallet.json \
        --keystore $WALLET_DIR/faucet/keystore.json \
        --storage rocksdb://$WALLET_DIR/faucet/client.db \
        query-balance
    echo 'Balance =========================================================================='

    linera --wallet $WALLET_DIR/faucet/wallet.json \
        --keystore $WALLET_DIR/faucet/keystore.json \
        --storage rocksdb://$WALLET_DIR/faucet/client.db \
        faucet \
        --amount 10 \
        --port 30090 \
        --storage-path $WALLET_DIR/faucet/faucet.sqlite &
}

run_faucet_service

read
