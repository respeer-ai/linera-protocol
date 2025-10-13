#!/bin/bash

####
## E.g. ./fund_faucet.sh -f https://faucet.testnet-conway.linera.net -C 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=http://api.faucet.respeer.ai/api/faucet
COMPILE=1

options="f:C:"

while getopts $options opt; do
  case ${opt} in
    f) FAUCET_URL=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
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

FAUCET_WALLET=$WALLET_DIR/faucet
FUND_WALLET=$WALLET_DIR/fund

mkdir -p $FUND_WALLET

FAUCET_CHAIN_ID=`cat $WALLET_DIR/faucet/wallet.json | jq -r '.chains | keys[]'`
FUND_CHAINS=100

function fund_faucet_one() {
    if [ ! -f $WALLET_DIR/fund/keystore.json ]; then
        linera --wallet $WALLET_DIR/fund/wallet.json \
            --keystore $WALLET_DIR/fund/keystore.json \
            --storage rocksdb://$WALLET_DIR/fund/client.db \
            wallet init \
            --faucet $FAUCET_URL
    fi

    fund_chain_id=`linera --wallet $WALLET_DIR/fund/wallet.json \
        --keystore $WALLET_DIR/fund/keystore.json \
        --storage rocksdb://$WALLET_DIR/fund/client.db \
        wallet request-chain \
        --faucet $FAUCET_URL | head -n 1`

    echo "From: $fund_chain_id"
    echo "To: $FAUCET_CHAIN_ID"

    linera --wallet $WALLET_DIR/fund/wallet.json \
        --keystore $WALLET_DIR/fund/keystore.json \
        --storage rocksdb://$WALLET_DIR/fund/client.db \
        transfer \
        --from $fund_chain_id \
        --to $FAUCET_CHAIN_ID \
        99.99
}

function fund_faucet() {
    for i in `seq 1 $FUND_CHAINS`; do
        fund_faucet_one
    done
}

fund_faucet
