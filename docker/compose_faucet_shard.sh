#!/bin/bash

####
## E.g. ./compose_faucet.sh -f https://faucet.testnet-conway.linera.net -g 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )

GENERATE=0
FAUCET_URL=https://faucet.testnet-conway.linera.net
CLUSTER=testnet-conway

options="f:z:g:"

while getopts $options opt; do
  case ${opt} in
    f) FAUCET_URL=${OPTARG} ;;
    z) CLUSTER=${OPTARG} ;;
    g) GENERATE=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

OUTPUT_DIR="$SCRIPT_DIR"/../output
mkdir -p $OUTPUT_DIR

WALLET_DIR=$OUTPUT_DIR/wallet
mkdir -p $WALLET_DIR

FAUCET_DIR=$WALLET_DIR/faucet
if [ "x$GENERATE" == "x1" ]; then
  sudo rm $FAUCET_DIR -rf
  sudo rm $WALLET_DIR/faucet-depositor -rf
fi
mkdir -p $FAUCET_DIR
mkdir -p $WALLET_DIR/faucet-depositor

CONFIG_DIR=$OUTPUT_DIR/config
mkdir -p $CONFIG_DIR

RESPEER_BIN_DIR=$OUTPUT_DIR/respeer/bin
mkdir -p $RESPEER_BIN_DIR

# Cleanup before building
docker stop faucet rpc
docker rm faucet rpc
docker stop `docker ps -a | grep linera-respeer | awk '{print $NF}'`
docker rm `docker ps -a | grep linera-respeer | awk '{print $NF}'`
docker rmi linera-respeer

ROOT_DIR=$SCRIPT_DIR/..

cd "$ROOT_DIR"

NGINX_TEMPLATE_FILE=$ROOT_DIR/configuration/template/nginx.conf.j2

GIT_COMMIT=$(git rev-parse --short HEAD)

docker build --no-cache --build-arg all_proxy=$all_proxy --build-arg git_commit="$GIT_COMMIT" --build-arg build_features="scylladb,metrics,memory-profiling,tempo,disable-native-rpc,enable-wallet-rpc" -f docker/Dockerfile . -t linera-respeer || exit 1

export PATH=$RESPEER_BIN_DIR:$PATH

LATEST_COMMIT=`git rev-parse HEAD`
LATEST_COMMIT=${LATEST_COMMIT:0:10}
INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}' | awk '{print $1}'`

# Compile respeer for local linera toolchain
if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
  cargo build --release -j 4
  mv $PWD/target/release/linera $RESPEER_BIN_DIR
fi

if [ "x$GENERATE" == "x1" ]; then
  linera --wallet $FAUCET_DIR/wallet.json --keystore $FAUCET_DIR/keystore.json --storage rocksdb:$FAUCET_DIR/client.db wallet init --faucet $FAUCET_URL
  linera --wallet $FAUCET_DIR/wallet.json --keystore $FAUCET_DIR/keystore.json --storage rocksdb:$FAUCET_DIR/client.db wallet request-chain --faucet $FAUCET_URL
fi

cd $SCRIPT_DIR
# Compose up faucet
LINERA_IMAGE=linera-respeer docker compose -f docker-compose-faucet-shard.yml up --wait

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
  sudo cp -v ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/
}

SUB_DOMAIN=$(echo "api.${CLUSTER}." | sed 's/\.\./\./g')

rm $OUTPUT_DIR/configuration -rf
cp -rvf $ROOT_DIR/configuration $OUTPUT_DIR/
generate_nginx_conf 31080 faucet faucet.respeer.ai

sudo nginx -s reload

echo -e "\n\nService domain"
echo -e "   $LAN_IP ${SUB_DOMAIN}faucet.respeer.ai"
echo -e "   $LAN_IP graphiql.faucet.respeer.ai"
echo -e "   http://graphiql.faucet.respeer.ai"
echo -e "   http://${SUB_DOMAIN}faucet.respeer.ai/api/faucet"
