#!/bin/bash

LAN_IP=$( hostname -I | awk '{print $1}' )

GIT_COMMIT=fd6b3cc0

options="c:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

OUTPUT_DIR="$SCRIPT_DIR"/../output
mkdir -p $OUTPUT_DIR

DOCKER_DIR=$OUTPUT_DIR/docker
mkdir -p $DOCKER_DIR

WALLET_DIR=$DOCKER_DIR/wallet
rm $WALLET_DIR -rf
mkdir -p $WALLET_DIR

FAUCET_DIR=$WALLET_DIR/faucet
mkdir -p $FAUCET_DIR

SOURCE_DIR=$OUTPUT_DIR/source
mkdir -p $SOURCE_DIR

CONFIG_DIR=$OUTPUT_DIR/config
mkdir -p $CONFIG_DIR

OFFICIAL_BIN_DIR=$OUTPUT_DIR/official/bin
mkdir -p $OFFICIAL_BIN_DIR

# Cleanup before building
docker stop prometheus docker-shard-4 docker-shard-3 docker-shard-2 proxy docker-shard-1 shard-init grafana watchtower scylla faucet rpc
docker rm prometheus docker-shard-4 docker-shard-3 docker-shard-2 proxy docker-shard-1 shard-init grafana watchtower scylla faucet rpc
docker rmi linera-official
docker volume rm docker_linera-scylla-data docker_linera-shared

cp -v \
  dashboards \
  provisioning \
  Dockerfile \
  compose-proxy-entrypoint.sh \
  compose-server-entrypoint.sh \
  compose-server-init.sh \
  compose.sh \
  docker-compose.yml \
  prometheus.yml \
  proxy-init.sh \
  server-entrypoint.sh \
  server-init.sh \
  faucet-entrypoint.sh \
  docker-compose-faucet.yml \
  rpc-entrypoint.sh \
  wallet-entrypoint.sh \
  docker-compose-rpc.yml \
  $DOCKER_DIR -rf
cp -v $SCRIPT_DIR/../configuration $OUTPUT_DIR -rf

CONF_DIR=$OUTPUT_DIR/configuration/compose
ROOT_DIR=$SCRIPT_DIR/..

NGINX_TEMPLATE_FILE=$OUTPUT_DIR/configuration/template/nginx.conf.j2
VALIDATOR_TEMPLATE_FILE=$OUTPUT_DIR/configuration/template/validator.toml.j2

# Build official version for genesis and faucet
cd $SOURCE_DIR
rm linera-protocol -rf
git clone https://github.com/linera-io/linera-protocol.git
cd linera-protocol
git checkout $GIT_COMMIT

export PATH=$OFFICIAL_BIN_DIR:$PATH

LATEST_COMMIT=`git rev-parse HEAD`
LATEST_COMMIT=${LATEST_COMMIT:0:10}
INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}'`

# Compile official for local linera toolchain
if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
  cargo build --release
  mv $PWD/target/release/linera $OFFICIAL_BIN_DIR
  mv $PWD/target/release/linera-server $OFFICIAL_BIN_DIR
fi

cp -v \
  $ROOT_DIR/docker/faucet-entrypoint.sh \
  $ROOT_DIR/docker/docker-compose-faucet.yml \
  $ROOT_DIR/docker/rpc-entrypoint.sh \
  $ROOT_DIR/docker/docker-compose-rpc.yml \
  $ROOT_DIR/docker/wallet-entrypoint.sh \
  $ROOT_DIR/docker/Dockerfile \
  ./docker -rf

GIT_COMMIT=$(git rev-parse --short HEAD)

docker build --no-cache --build-arg git_commit="$GIT_COMMIT" -f docker/Dockerfile . -t linera-official || exit 1

# We should generate config to docker dir
cd "$DOCKER_DIR"

## Generate validator configuration from template
function generate_validators() {
    # Generate validator configure of i
    echo "{
        \"validator\": {
            \"config_path\": \"$DOCKER_DIR/server.json\",
            \"host\": \"$LAN_IP\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"docker-pyroscope\",
            \"pyroscope_port\": 4040,
            \"internal_host\": \"proxy\",
            \"internal_port\": 20100
        },
        \"shards\": {
            \"shard_1\": {
                \"host\": \"docker-shard-1\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
          },
            \"shard_2\": {
                \"host\": \"docker-shard-2\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            },
            \"shard_3\": {
                \"host\": \"docker-shard-3\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            },
            \"shard_4\": {
                \"host\": \"docker-shard-4\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            }
        }
    }" > $CONFIG_DIR/validator.json

    jinja -d $CONFIG_DIR/validator.json $VALIDATOR_TEMPLATE_FILE > $CONFIG_DIR/validator.toml
}

generate_validators

# Create configuration files.
# * Private server states are stored in `server.json`.
# * `committee.json` is the public description of the Linera committee.
linera-server generate --validators "$CONFIG_DIR/validator.toml" --committee $DOCKER_DIR/committee.json --testing-prng-seed 1

# Create configuration files for 10 user chains.
# * Private chain states are stored in one local wallet `wallet.json`.
# * `genesis.json` will contain the initial balances of chains as well as the initial committee.

linera --wallet $FAUCET_DIR/wallet.json --storage rocksdb:$FAUCET_DIR/client.db create-genesis-config 1 --genesis $DOCKER_DIR/genesis.json --initial-funding 10000000 --committee $DOCKER_DIR/committee.json

cd $DOCKER_DIR

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
