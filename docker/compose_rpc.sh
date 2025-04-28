#!/bin/bash

####
## E.g. ./run_rpc_service.sh -f https://faucet.testnet-babbage.linera.net -C 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=https://faucet.testnet-babbage.linera.net
CLUSTER=

options="f:z:"

while getopts $options opt; do
  case ${opt} in
    f) FAUCET_URL=${OPTARG} ;;
    z) CLUSTER=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

OUTPUT_DIR="$SCRIPT_DIR"/../output
mkdir -p $OUTPUT_DIR

WALLET_DIR=$OUTPUT_DIR/wallet
rm $WALLET_DIR -rf
mkdir -p $WALLET_DIR

RPC_DIR=$WALLET_DIR/rpc
mkdir -p $RPC_DIR

CONFIG_DIR=$OUTPUT_DIR/config
mkdir -p $CONFIG_DIR

RESPEER_BIN_DIR=$OUTPUT_DIR/respeer/bin
mkdir -p $RESPEER_BIN_DIR

# Cleanup before building
docker stop rpc
docker rm rpc
docker rmi linera-respeer

ROOT_DIR=$SCRIPT_DIR/..

NGINX_TEMPLATE_FILE=$ROOT_DIR/configuration/template/nginx.conf.j2

# Run rpc service
cd "$ROOT_DIR"

GIT_COMMIT=$(git rev-parse --short HEAD)

docker build --no-cache --build-arg git_commit="$GIT_COMMIT" --build-arg features="scylladb,metrics,disable-native-rpc,enable-wallet-rpc" -f docker/Dockerfile . -t linera-respeer || exit 1

export PATH=$RESPEER_BIN_DIR:$PATH

LATEST_COMMIT=`git rev-parse HEAD`
LATEST_COMMIT=${LATEST_COMMIT:0:10}
INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}'`

# Compile official for local linera toolchain
if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
  cargo build --release
  mv $PWD/target/release/linera $RESPEER_BIN_DIR
fi

linera --wallet $RPC_DIR/wallet.json --storage rocksdb:$RPC_DIR/client.db wallet init --faucet $FAUCET_URL

cd $SCRIPT_DIR
# Compose up rpc
LINERA_IMAGE=linera-respeer docker compose -f docker-compose-rpc.yml up --wait

function generate_nginx_conf() {
  port_base=$1
  endpoint=$2
  domain=$3

  echo "{
      \"service\": {
      \"endpoint\": \"$endpoint\",
      \"servers\": [\"localhost:$port_base\"],
      \"domain\": \"$domain\",
      \"sub_domain\": \"$SUB_DOMAIN\",
      \"api_endpoint\": \"$endpoint\"
    }
  }" > ${CONFIG_DIR}/$endpoint.nginx.json

  jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
  cp -v ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/
}

SUB_DOMAIN=$(echo "api.${CLUSTER}." | sed 's/\.\./\./g')

generate_nginx_conf 30080 rpc rpc.respeer.ai

sudo nginx -s reload

echo -e "\n\nService domain"
echo -e "   $LAN_IP ${SUB_DOMAIN}rpc.respeer.ai"
echo -e "   $LAN_IP graphiql.rpc.respeer.ai"
echo -e "   http://graphiql.rpc.respeer.ai"
echo -e "   http://${SUB_DOMAIN}rpc.respeer.ai/api/rpc"
