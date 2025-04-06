#!/bin/bash

LAN_IP=$( hostname -I | awk '{print $1}' )

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

OUTPUT_DIR="$SCRIPT_DIR"/../output
mkdir -p $OUTPUT_DIR

DOCKER_DIR=$OUTPUT_DIR/docker
mkdir -p $DOCKER_DIR

CONFIG_DIR=$OUTPUT_DIR/config
mkdir -p $CONFIG_DIR

NGINX_TEMPLATE_FILE=$OUTPUT_DIR/configuration/template/nginx.conf.j2

# Cleanup before building
docker stop prometheus docker-shard-4 docker-shard-3 docker-shard-2 proxy docker-shard-1 shard-init grafana watchtower scylla faucet
docker rm prometheus docker-shard-4 docker-shard-3 docker-shard-2 proxy docker-shard-1 shard-init grafana watchtower scylla faucet
# docker volume rm docker_linera-scylla-data docker_linera-shared

cd $DOCKER_DIR

docker compose -f docker-compose.yml down
docker compose -f docker-compose-faucet.yml down

LINERA_IMAGE=linera-official docker compose -f docker-compose.yml up --wait

# Compose up faucet
LINERA_IMAGE=linera-official docker compose -f docker-compose-faucet.yml up --wait

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

# Generate service nginx conf
generate_nginx_conf 19100 validator validator.genesis.respeer.ai
generate_nginx_conf 8080 faucet faucet.respeer.ai

sudo nginx -s reload

echo -e "\n\nService domain"
echo -e "   $LAN_IP api.validator.genesis.respeer.ai"
echo -e "   $LAN_IP api.faucet.respeer.ai"
echo -e "   $LAN_IP graphiql.faucet.respeer.ai"
echo -e "   http://graphiql.faucet.respeer.ai"
echo -e "   http://api.faucet.respeer.ai/api/faucet"
