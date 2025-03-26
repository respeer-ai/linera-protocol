#!/bin/bash

####
## E.g. ./run_rpc_service.sh -f http://172.16.31.73:8080 -C 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )
FAUCET_URL=https://faucet.testnet-archimedes.linera.io
GIT_COMMIT=main
CREATE_WALLET=0
COMPILE=1
IMAGE_COMPILE=1
PERSISTENCE_DIR=/data/linera-project/compose/rpc

options="c:C:p:W:f:I:"

while getopts $options opt; do
  case ${opt} in
    c) GIT_COMMIT=${OPTARG} ;;
    C) COMPILE=${OPTARG} ;;
    p) PERSISTENCE_DIR=${OPTARG} ;;
    W) CREATE_WALLET=${OPTARG} ;;
    f) FAUCET_URL=${OPTARG} ;;
    I) IMAGE_COMPILE=${OPTARG} ;;
  esac
done

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOCKER_COMPOSE_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/docker-compose-rpc.yml.j2"
NGINX_TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/nginx.conf.j2"

# All persistence data will be put here
mkdir -p $PERSISTENCE_DIR

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../target/output/docker"
mkdir -p $OUTPUT_DIR

# Wallet directory
WALLET_DIR="${PERSISTENCE_DIR}/wallet"
mkdir -p $WALLET_DIR

# All generated config files will be put here
CONFIG_DIR="${PERSISTENCE_DIR}/config"
mkdir -p $CONFIG_DIR

# Source code directory
SOURCE_DIR="${OUTPUT_DIR}/source"
mkdir -p $SOURCE_DIR

# Generate docker rpc nginx conf
function generate_docker_nginx_conf() {
    endpoint=rpc
    domain=rpc.respeer.ai

    echo "{
        \"service\": {
            \"endpoint\": \"$endpoint\",
            \"servers\": [\"localhost:30080\"],
	    \"listen_port\": 30082,
            \"domain\": \"$domain\",
            \"api_endpoint\": \"$endpoint\"
        }
    }" > ${CONFIG_DIR}/$endpoint.nginx.json

    jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${CONFIG_DIR}/docker.$endpoint.nginx.conf
}

generate_docker_nginx_conf


cd $SCRIPT_DIR/..

if [ "x$COMPILE" = "x1" ]; then
    # Get latest commit to avoid compilation for the same version
    LATEST_COMMIT=`git rev-parse HEAD`
    LATEST_COMMIT=${LATEST_COMMIT:0:10}
    INSTALLED_COMMIT=`linera --version | grep tree | awk -F '/' '{print $7}' | awk '{print $1}'`

    if [ "x$LATEST_COMMIT" != "x$INSTALLED_COMMIT" ]; then
        cargo install --path linera-service --features storage-service,disable-native-rpc,enable-wallet-rpc
        cargo install --path linera-storage-service --features storage-service
    fi
fi

if [ "x$IMAGE_COMPILE" = "x1" ]; then
  # Install official linera for genesis cluster
  cd $SOURCE_DIR
  rm linera-protocol -rf
  git clone https://github.com/respeer-ai/linera-protocol
  cd linera-protocol
  cp $SCRIPT_DIR/rpc-entrypoint.sh docker/
  cp ${CONFIG_DIR}/docker.$endpoint.nginx.conf docker/

  git checkout $GIT_COMMIT

  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
      docker build --build-arg git_commit="$GIT_COMMIT" -f $SCRIPT_DIR/Dockerfile.rpc . -t linera-rpc-service || exit 1
  elif [[ "$OSTYPE" == "darwin"* ]]; then
      CPU_ARCH=$(sysctl -n machdep.cpu.brand_string)
      if [[ "$CPU_ARCH" == *"Apple"* ]]; then
          docker build --build-arg git_commit="$GIT_COMMIT" --build-arg target=aarch64-unknown-linux-gnu -f $SCRIPT_DIR/Dockerfile.rpc -t linera-rpc-service . || exit 1
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

if [ ! -d ${WALLET_DIR} ]; then
    CREATE_WALLET=1
fi

function create_rpc_wallet() {
    rm -rf $WALLET_DIR
    mkdir -p $WALLET_DIR

    # Init wallet from faucet
    linera --wallet $WALLET_DIR/wallet.json \
           --storage rocksdb://$WALLET_DIR/client.db \
           wallet init \
           --faucet $FAUCET_URL
}

# Create rpc wallet
if [ "x$CREATE_WALLET" = "x1" ]; then
    create_rpc_wallet
fi

# Generate docker-compose.yml
echo "{
    \"rpc\": {
        \"wallet_dir\": \"$WALLET_DIR\"
    }
}" > $OUTPUT_DIR/docker-compose-rpc.json

jinja -d $OUTPUT_DIR/docker-compose-rpc.json $DOCKER_COMPOSE_TEMPLATE_FILE > $PERSISTENCE_DIR/docker-compose.yml

cd $SCRIPT_DIR

docker rm linera-rpc-service -f
docker compose -f $PERSISTENCE_DIR/docker-compose.yml up --wait

function generate_nginx_conf() {
    endpoint=rpc
    domain=rpc.respeer.ai

    echo "{
        \"service\": {
            \"endpoint\": \"$endpoint\",
            \"servers\": [\"localhost:30082\"],
            \"domain\": \"$domain\",
            \"api_endpoint\": \"$endpoint\"
        }
    }" > ${CONFIG_DIR}/$endpoint.nginx.json

    jinja -d ${CONFIG_DIR}/$endpoint.nginx.json $NGINX_TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint.nginx.conf
    echo "cp ${CONFIG_DIR}/$endpoint.nginx.conf /etc/nginx/sites-enabled/"
}

generate_nginx_conf

echo -e "\n\nService domain"
echo -e "   $LAN_IP api.rpc.respeer.ai"
echo -e "   http://api.rpc.respeer.ai/api/rpc\n\n"
