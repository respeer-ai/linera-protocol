#!/bin/bash

GENERATE=1
FAUCET=http://api.faucet.respeer.ai/api/faucet

options="g:f:"

while getopts $options opt; do
  case ${opt} in
    g) GENERATE=${OPTARG} ;;
    f) FAUCET=${OPTARG} ;;
  esac
done

LAN_IP=$( hostname -I | awk '{print $1}' )

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

# Cleanup before building
docker stop rpc
docker rm rpc

ROOT_DIR=$SCRIPT_DIR/..

NGINX_TEMPLATE_FILE=$OUTPUT_DIR/configuration/template/nginx.conf.j2

# Run rpc service
cd "$ROOT_DIR"

if [ "x$GENERATE" == "x1" ]; then
  linera --wallet $RPC_DIR/wallet.json --storage rocksdb:$RPC_DIR/client.db wallet init --faucet $FAUCET
fi

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
      \"api_endpoint\": \"$endpoint\"
    }
  }" > ${CONFIG_DIR}/$endpoint.nginx.json

  jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
  cp -v ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/
}

generate_nginx_conf 30080 rpc rpc.respeer.ai

sudo nginx -s reload

echo -e "\n\nService domain"
echo -e "   $LAN_IP api.rpc.respeer.ai"
echo -e "   $LAN_IP graphiql.rpc.respeer.ai"
echo -e "   http://graphiql.rpc.respeer.ai"
echo -e "   http://api.rpc.respeer.ai/api/rpc"
