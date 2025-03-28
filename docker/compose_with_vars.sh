#!/bin/bash

####
## ./compose_with_vars.sh -c 7b3ae0b6 -n 2 -v "192.168.110.101 192.168.110.102"
####

LAN_IP=$( hostname -I | awk '{print $1}' )

VALIDATORS=($LAN_IP)
NUM_VALIDATORS=1
RUN_VALIDATORS=1
SHARDS_PER_VALIDATOR=4
GIT_COMMIT=main
CREATE_WALLET=0
COMPILE=1
PERSISTENCE_DIR=/data/linera-project/compose/genesis

options="c:C:p:W:n:v:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    p) PERSISTENCE_DIR=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
    n) NUM_VALIDATORS=${OPTARG} ;;
    v) VALIDATORS=${OPTARG} ;;
  esac
done

VALIDATORS=($VALIDATORS)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VALIDATOR_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/validator.toml.j2"
DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-genesis.yml.j2"

[ ! -d $PERSISTENCE_DIR ] && CREATE_WALLET=1

if [ "x$CREATE_WALLET" = "x1" ]; then
  rm $PERSISTENCE_DIR -rf
  SCYLLA_VOLUME=linera-scylla-data
  docker rm validator-shard-1 validator-shard-2 validator-shard-3 validator-shard-4 shard-init proxy scylla prometheus grafana watchtower -f
  volume=`docker volume list | grep $SCYLLA_VOLUME |awk '{ print $2 }'`
  [ "x$volume" != "x" ] && docker volume rm $volume
fi

# All persistence data will be put here
mkdir -p $PERSISTENCE_DIR

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/docker"
mkdir -p $OUTPUT_DIR

# All validator config will be put here
VALIDATOR_DIR="${PERSISTENCE_DIR}/config"
mkdir -p $VALIDATOR_DIR

# All generated config files will be put here
CONFIG_DIR="${PERSISTENCE_DIR}/config"
mkdir -p $CONFIG_DIR

# Wallet directory
WALLET_DIR="${PERSISTENCE_DIR}/wallet"
mkdir -p $WALLET_DIR

# Prometheus directory
PROMETHEUS_DIR="${PERSISTENCE_DIR}/prometheus"
mkdir -p $PROMETHEUS_DIR

# Grafana directory
GRAFANA_DIR="${PERSISTENCE_DIR}/grafana"
mkdir -p $GRAFANA_DIR

# Source code directory
SOURCE_DIR="${OUTPUT_DIR}/source"
mkdir -p $SOURCE_DIR

cleanup_started=false

if [ "x$COMPILE" = "x1" ]; then
  # Install official linera for genesis cluster
  cd $SOURCE_DIR
  rm linera-protocol -rf
  git clone https://github.com/linera-io/linera-protocol.git
  cd linera-protocol

  git checkout $GIT_COMMIT

  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
      docker build --build-arg git_commit="$GIT_COMMIT" -f docker/Dockerfile . -t linera || exit 1
  elif [[ "$OSTYPE" == "darwin"* ]]; then
      CPU_ARCH=$(sysctl -n machdep.cpu.brand_string)
      if [[ "$CPU_ARCH" == *"Apple"* ]]; then
          docker build --build-arg git_commit="$GIT_COMMIT" --build-arg target=aarch64-unknown-linux-gnu -f docker/Dockerfile -t linera . || exit 1
      else
          echo "Unsupported Architecture: $CPU_ARCH"
          exit 1
      fi
  else
      echo "Unsupported OS: $OSTYPE"
      exit 1
  fi
fi

cd $SCRIPT_DIR/..

# Generate validator configuration from template
VALIDATOR_FILES=()
for i in $(seq 0 $((NUM_VALIDATORS - 1))); do
    mkdir -p $VALIDATOR_DIR/$i

    # Generate validator configure of i
    echo "{
        \"validator\": {
            \"config_path\": \"$VALIDATOR_DIR/$i/server.json\",
            \"host\": \"${VALIDATORS[$i]}\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"docker-pyroscope\",
            \"pyroscope_port\": 4040,
            \"internal_host\": \"proxy\",
            \"internal_port\": 20100
        },
        \"shards\": {
            \"shard_1\": {
                \"host\": \"validator-shard-1\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            },
            \"shard_2\": {
                \"host\": \"validator-shard-2\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            },
            \"shard_3\": {
                \"host\": \"validator-shard-3\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
            },
            \"shard_4\": {
                \"host\": \"validator-shard-4\",
                \"port\": 19100,
                \"metrics_port\": 21100,
                \"pyroscope_host\": \"docker-pyroscope\",
                \"pyroscope_port\": 4040
          }
        }
    }" > $VALIDATOR_DIR/$i/validator.json

    jinja -d $VALIDATOR_DIR/$i/validator.json $VALIDATOR_TEMPLATE_FILE > $VALIDATOR_DIR/$i/validator.toml

    VALIDATOR_FILES+=("$VALIDATOR_DIR/$i/validator.toml")
done

# Generate docker-compose.yml
echo "{
    \"validator\": {
        \"proxy_persistence_dir\": \"$VALIDATOR_DIR\",
        \"prometheus_persistence_dir\": \"$PROMETHEUS_DIR\",
        \"grafana_persistence_dir\": \"$GRAFANA_DIR\"
    }
}" > $OUTPUT_DIR/docker-compose-validator.json

jinja -d $OUTPUT_DIR/docker-compose-validator.json $DOCKER_COMPOSE_TEMPLATE_FILE > $VALIDATOR_DIR/0/docker-compose.yml


if [ "x$CREATE_WALLET" = "x1" ]; then
# Create configuration files.
# * Private server states are stored in `server.json`.
# * `committee.json` is the public description of the Linera committee.
    linera-server generate --validators "${VALIDATOR_FILES[@]}" --committee $CONFIG_DIR/committee.json --testing-prng-seed 1
# Create configuration files for 10 user chains.
# * Private chain states are stored in one local wallet `wallet.json`.
# * `genesis.json` will contain the initial balances of chains as well as the initial committee.
    linera --wallet $WALLET_DIR/wallet.json --storage rocksdb:$WALLET_DIR/client.db create-genesis-config 10 --genesis $CONFIG_DIR/genesis.json --initial-funding 100000000 --committee $CONFIG_DIR/committee.json --testing-prng-seed 2
fi

cd $SCRIPT_DIR
mkdir -p $GRAFANA_DIR/provisioning
cp provisioning/dashboards $GRAFANA_DIR/provisioning/ -R
cp dashboards $GRAFANA_DIR/ -R
cp prometheus.yml $PROMETHEUS_DIR/

cp $VALIDATOR_DIR/0/server.json $VALIDATOR_DIR/
cp $VALIDATOR_DIR/0/validator.toml $VALIDATOR_DIR/
docker compose -f $VALIDATOR_DIR/0/docker-compose.yml -p validator up --wait
