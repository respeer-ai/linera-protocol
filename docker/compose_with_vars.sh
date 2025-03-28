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
VALIDATOR_INDEX=0
PERSISTENCE_DIR=/data/linera-project/compose/genesis

options="c:C:p:W:n:v:N:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    p) PERSISTENCE_DIR=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
    n) NUM_VALIDATORS=${OPTARG} ;;
    v) VALIDATORS=${OPTARG} ;;
    N) VALIDATOR_INDEX=${OPTARG} ;;
  esac
done

VALIDATORS=($VALIDATORS)
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VALIDATOR_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/validator.toml.j2"
DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-genesis.yml.j2"

[ ! -d $PERSISTENCE_DIR ] && CREATE_WALLET=1

if [ "x$CREATE_WALLET" = "x1" ]; then
    SCYLLA_VOLUME=linera-scylla-data
    volume=`docker volume list | grep $SCYLLA_VOLUME |awk '{ print $2 }'`
    if [ "x$volume" != "x" ]; then
        docker volume rm $volume
	container_id=`docker ps -a -q --filter volume=$volume`
	[ "x$container_id" != "x" ] && docker rm $container_id -f
    fi
    rm $PERSISTENCE_DIR -rf
fi

# All persistence data will be put here
mkdir -p $PERSISTENCE_DIR

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/docker"
mkdir -p $OUTPUT_DIR

# All generated config files will be put here
CONFIG_DIR="${PERSISTENCE_DIR}/config"
mkdir -p $CONFIG_DIR

# Wallet directory
WALLET_DIR="${PERSISTENCE_DIR}/wallet"
mkdir -p $WALLET_DIR

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
    # All validator config will be put here
    VALIDATOR_DIR="${PERSISTENCE_DIR}/config/$i"
    mkdir -p $VALIDATOR_DIR

    # Prometheus directory
    PROMETHEUS_DIR="$VALIDATOR_DIR/prometheus"
    mkdir -p $PROMETHEUS_DIR

    # Grafana directory
    GRAFANA_DIR="$VALIDATOR_DIR/grafana"
    mkdir -p $GRAFANA_DIR


    # Generate validator configure of i
    echo "{
        \"validator\": {
            \"config_path\": \"$VALIDATOR_DIR/server.json\",
            \"host\": \"${VALIDATORS[$i]}\",
	    \"port\": $((19100 + i * 2)),
	    \"metrics_port\": $((20100 + i * 2)),
            \"pyroscope_host\": \"validator-$i-docker-pyroscope\",
	    \"pyroscope_port\": $((4040 + i * 2)),
            \"internal_host\": \"proxy-$i\",
	    \"internal_port\": $((21100 + i * 2))
        },
        \"shards\": {
            \"shard_1\": {
                \"host\": \"validator-$i-shard-1\",
                \"port\": $((19100 + i * 2)),
                \"metrics_port\": $((21100 + i * 2)),
                \"pyroscope_host\": \"validator-$i-docker-pyroscope\",
                \"pyroscope_port\": $((4040 + i * 2))
          },
            \"shard_2\": {
                \"host\": \"validator-$i-shard-2\",
                \"port\": $((19100 + i * 2)),
                \"metrics_port\": $((21100 + i * 2)),
                \"pyroscope_host\": \"validator-$i-docker-pyroscope\",
                \"pyroscope_port\": $((4040 + i * 2))
            },
            \"shard_3\": {
                \"host\": \"validator-$i-shard-3\",
                \"port\": $((19100 + i * 2)),
                \"metrics_port\": $((21100 + i * 2)),
                \"pyroscope_host\": \"validator-$i-docker-pyroscope\",
                \"pyroscope_port\": $((4040 + i * 2))
            },
            \"shard_4\": {
                \"host\": \"validator-$i-shard-4\",
                \"port\": $((19100 + i * 2)),
                \"metrics_port\": $((21100 + i * 2)),
                \"pyroscope_host\": \"validator-$i-docker-pyroscope\",
                \"pyroscope_port\": $((4040 + i * 2))
            }
        }
    }" > $VALIDATOR_DIR/validator.json

    jinja -d $VALIDATOR_DIR/validator.json $VALIDATOR_TEMPLATE_FILE > $VALIDATOR_DIR/validator.toml

    VALIDATOR_FILES+=("$VALIDATOR_DIR/validator.toml")

    # Generate docker-compose.yml
    echo "{
        \"validator\": {
	    \"validator_persistence_dir\": \"$VALIDATOR_DIR\",
	    \"prometheus_persistence_dir\": \"$PROMETHEUS_DIR\",
	    \"grafana_persistence_dir\": \"$GRAFANA_DIR\",
	    \"validator_name\": \"validator-$i\",
	    \"validator_port\": $((19100 + $i * 2)),
	    \"scylla_name\": \"validator-$i-scylla\",
	    \"scylla_volume\": \"validator-$i-scylla-data\",
	    \"shard_init_name\": \"validator-$i-shard-init\",
	    \"prometheus_name\": \"validator-$i-prometheus\",
	    \"prometheus_port\": $((19090 + $i * 2)),
	    \"grafana_name\": \"validator-$i-grafana\",
	    \"grafana_port\": $((3000 + $i * 2)),
	    \"grafana_volume\": \"validator-$i-grafana-data\",
	    \"watchtower_name\": \"validator-$i-watchtower\"
        }
    }" > $OUTPUT_DIR/docker-compose-validator.json

    jinja -d $OUTPUT_DIR/docker-compose-validator.json $DOCKER_COMPOSE_TEMPLATE_FILE > $VALIDATOR_DIR/docker-compose.yml

done

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
VALIDATOR_DIR="${PERSISTENCE_DIR}/config/$VALIDATOR_INDEX"
mkdir -p $VALIDATOR_DIR/grafana/provisioning
cp provisioning/dashboards $VALIDATOR_DIR/provisioning/ -R
cp dashboards $VALIDATOR_DIR/grafana/ -R
cp prometheus.yml $VALIDATOR_DIR/prometheus/
cp $CONFIG_DIR/committee.json $VALIDATOR_DIR/
cp $CONFIG_DIR/genesis.json $VALIDATOR_DIR/

echo docker compose -f $VALIDATOR_DIR/docker-compose.yml -p validator-$VALIDATOR_INDEX up --wait
