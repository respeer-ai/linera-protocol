#!/bin/bash

####
## ./compose_with_vars.sh -c 7b3ae0b6
####

LAN_IP=$( hostname -I | awk '{print $1}' )

VALIDATORS=($LAN_IP)
NUM_VALIDATORS=1
RUN_VALIDATORS=1
SHARDS_PER_VALIDATOR=4
GIT_COMMIT=main
CREATE_WALLET=0
COMPILE=1

options="c:C:p:W:n:v:N:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
    v) VALIDATORS=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VALIDATOR_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/validator.toml.j2"
GENESIS_DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-genesis.yml.j2"
FAUCET_DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-faucet.yml.j2"

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/docker"
# Source code directory
SOURCE_DIR="${OUTPUT_DIR}/source"
# Genesis config directory
GENESIS_DIR="${OUTPUT_DIR}/genesis"
# Release directory
TARGET_DIR="${SOURCE_DIR}/linera-protocol/target/release"

[ ! -d $GENESIS_DIR ] && CREATE_WALLET=1

if [ "x$CREATE_WALLET" = "x1" ]; then
    containers=`docker ps -a | grep linera-validator | awk '{ print $NF }'`
    [ "x$containers" != "x" ] && docker rm -f $containers
    volume=`docker volume list | grep linera-validator |awk '{ print $2 }'`
    [ "x$volume" != "x" ] && docker volume rm $volume
    rm $GENESIS_DIR -rf
fi

mkdir -p $OUTPUT_DIR
mkdir -p $SOURCE_DIR
mkdir -p $GENESIS_DIR

if [ "x$COMPILE" = "x1" ]; then
    cd $SOURCE_DIR
    # Get latest commit to avoid compilation for the same version
    LATEST_COMMIT=`git rev-parse HEAD`
    LATEST_COMMIT=${LATEST_COMMIT:0:10}
    INSTALLED_COMMIT=`$TARGET_DIR/linera --version | grep tree | awk -F '/' '{print $7}' | awk '{print $1}'`

    if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
        rm linera-protocol -rf
	git clone https://github.com/linera-io/linera-protocol.git
	cd linera-protocol
        git checkout $GIT_COMMIT

        cp $SCRIPT_DIR/faucet-entrypoint.sh docker/
	cargo build --release --features storage-service
    fi

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

# Generate validator configure
echo "{
    \"validator\": {
        \"config_path\": \"$GENESIS_DIR/server.json\",
        \"host\": \"$LAN_IP\",
        \"port\": 19100,
        \"metrics_port\": 20100,
        \"pyroscope_host\": \"validator-docker-pyroscope\",
        \"pyroscope_port\": 4040,
        \"internal_host\": \"proxy\",
        \"internal_port\": 21100
    },
    \"shards\": {
        \"shard_1\": {
            \"host\": \"linera-validator-shard-1\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"linera-validator-docker-pyroscope\",
            \"pyroscope_port\": 4040
      },
        \"shard_2\": {
            \"host\": \"linera-validator-shard-2\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"linera-validator-docker-pyroscope\",
            \"pyroscope_port\": 4040
        },
        \"shard_3\": {
            \"host\": \"linera-validator-shard-3\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"linera-validator-docker-pyroscope\",
            \"pyroscope_port\": 4040
        },
        \"shard_4\": {
            \"host\": \"linera-validator-shard-4\",
            \"port\": 19100,
            \"metrics_port\": 21100,
            \"pyroscope_host\": \"linera-validator-docker-pyroscope\",
            \"pyroscope_port\": 4040
        }
    }
}" > $GENESIS_DIR/validator.json

jinja -d $GENESIS_DIR/validator.json $VALIDATOR_TEMPLATE_FILE > $GENESIS_DIR/validator.toml

# Generate genesis docker-compose.yml
echo "{
    \"validator\": {
        \"validator_persistence_dir\": \"$GENESIS_DIR\",
        \"prometheus_persistence_dir\": \"$GENESIS_DIR/prometheus\",
        \"grafana_persistence_dir\": \"$GENESIS_DIR/grafana\",
        \"validator_name\": \"linera-validator\",
        \"scylla_name\": \"linera-validator-scylla\",
        \"scylla_volume\": \"linera-validator-scylla-data\",
        \"shard_init_name\": \"linera-validator-shard-init\",
        \"prometheus_name\": \"linera-validator-prometheus\",
        \"grafana_name\": \"linera-validator-grafana\",
        \"grafana_volume\": \"linera-validator-grafana-data\",
        \"watchtower_name\": \"linera-validator-watchtower\"
    }
}" > $GENESIS_DIR/docker-compose-validator.json

jinja -d $GENESIS_DIR/docker-compose-validator.json $GENESIS_DOCKER_COMPOSE_TEMPLATE_FILE > $GENESIS_DIR/docker-compose.yml


if [ "x$CREATE_WALLET" = "x1" ]; then
# Create configuration files.
# * Private server states are stored in `server.json`.
# * `committee.json` is the public description of the Linera committee.
    $TARGET_DIR/linera-server generate --validators $GENESIS_DIR/validator.toml --committee $GENESIS_DIR/committee.json --testing-prng-seed 1
# Create configuration files for 10 user chains.
# * Private chain states are stored in one local wallet `wallet.json`.
# * `genesis.json` will contain the initial balances of chains as well as the initial committee.
    $TARGET_DIR/linera --wallet $GENESIS_DIR/wallet.json --storage rocksdb:$GENESIS_DIR/client.db create-genesis-config 10 --genesis $GENESIS_DIR/genesis.json --initial-funding 100000000 --committee $GENESIS_DIR/committee.json --testing-prng-seed 2
fi

cd $SCRIPT_DIR
mkdir -p $GENESIS_DIR/grafana/provisioning
mkdir -p $GENESIS_DIR/prometheus
cp provisioning/dashboards $GENESIS_DIR/provisioning/ -R
cp dashboards $GENESIS_DIR/grafana/ -R
cp prometheus.yml $GENESIS_DIR/prometheus/

docker compose -f $GENESIS_DIR/docker-compose.yml -p linera-validator up --wait

# Generate docker-compose.yml
echo "{
    \"faucet\": {
        \"wallet_dir\": \"$GENESIS_DIR\"
    }
}" > $GENESIS_DIR/docker-compose-faucet.json

jinja -d $GENESIS_DIR/docker-compose-faucet.json $FAUCET_DOCKER_COMPOSE_TEMPLATE_FILE > $GENESIS_DIR/faucet-docker-compose.yml

cd $SCRIPT_DIR

docker rm faucet -f
docker compose -f $GENESIS_DIR/faucet-docker-compose.yml up --wait

function generate_nginx_conf() {
    endpoint=faucet
    domain=faucet.respeer.ai

    echo "{
        \"service\": {
            \"endpoint\": \"$endpoint\",
            \"servers\": [\"localhost:8080\"],
            \"domain\": \"$domain\",
            \"api_endpoint\": \"$endpoint\"
        }
    }" > ${GENESIS_DIR}/$endpoint.nginx.json

    jinja -d ${GENESIS_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${GENESIS_DIR}/$endpoint.nginx.conf
    echo "cp ${GENESIS_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/"
}

generate_nginx_conf
echo -e "\n\nFaucet domain"
echo -e "	$LAN_IP api.faucet.respeer.ai"
