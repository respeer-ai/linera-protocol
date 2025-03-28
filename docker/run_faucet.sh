#!/bin/bash

LAN_IP=$( hostname -I | awk '{print $1}' )

GIT_COMMIT=main
CREATE_WALLET=0
COMPILE=1
PERSISTENCE_DIR=/data/linera-project/compose/genesis

options="c:C:p:W:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    p) PERSISTENCE_DIR=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-faucet.yml.j2"
NGINX_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/nginx.conf.j2"

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

# Faucet directory
FAUCET_DIR="${PERSISTENCE_DIR}/faucet"
mkdir -p $FAUCET_DIR

# Source code directory
SOURCE_DIR="${OUTPUT_DIR}/source"
mkdir -p $SOURCE_DIR

if [ "x$COMPILE" = "x1" ]; then
    # Install official linera for genesis cluster
    cd $SOURCE_DIR
    rm linera-protocol -rf
    git clone https://github.com/linera-io/linera-protocol.git
    cd linera-protocol
    cp $SCRIPT_DIR/faucet-entrypoint.sh docker/

    git checkout $GIT_COMMIT
    # Get latest commit to avoid compilation for the same version
    LATEST_COMMIT=`git rev-parse HEAD`
    LATEST_COMMIT=${LATEST_COMMIT:0:10}
    INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}' | awk '{print $1}'`

    if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
        cargo install --path linera-service --features storage-service
        cargo install --path linera-storage-service --features storage-service
    fi

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        docker build --build-arg git_commit="$GIT_COMMIT" -f docker/Dockerfile . -t linera || exit 1
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        CPU_ARCH=$(sysctl -n machdep.cpu.brand_string)
        if [[ "$CPU_ARCH" == *"Apple"* ]]; then
            docker build --build-arg git_commit="$GIT_COMMIT" --build-arg target=aarch64-unknown-linux-gnu -f $SCRIPT_DIR/Dockerfile.faucet -t linera-faucet . || exit 1
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

# Generate docker-compose.yml
echo "{
    \"faucet\": {
        \"wallet_dir\": \"$WALLET_DIR\"
    }
}" > $OUTPUT_DIR/docker-compose-faucet.json

jinja -d $OUTPUT_DIR/docker-compose-faucet.json $DOCKER_COMPOSE_TEMPLATE_FILE > $FAUCET_DIR/docker-compose.yml


cd $SCRIPT_DIR

docker rm faucet -f
docker compose -f $FAUCET_DIR/docker-compose.yml up --wait

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
    }" > ${CONFIG_DIR}/$endpoint.nginx.json

    jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
    echo "cp ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/"
}

generate_nginx_conf
echo -e "\n\nFaucet domain"
echo -e "	$LAN_IP api.faucet.respeer.ai"
echo -e "	http://api.faucet.respeer.ai/api/faucet\n\n"
