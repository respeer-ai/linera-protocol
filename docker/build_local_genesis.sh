#!/bin/bash

####
## E.g. ./compose_faucet.sh -f https://faucet.testnet-conway.linera.net -g 0
####

LAN_IP=$( hostname -I | awk '{print $1}' )

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
OUTPUT_DIR=$SCRIPT_DIR/../output

RESPEER_BIN_DIR=$OUTPUT_DIR/respeer/bin
mkdir -p $RESPEER_BIN_DIR

# Cleanup before building
docker stop linera-local-genesis
docker rm linera-local-genesis
docker rmi linera-local-genesis npool/linera-local-genesis

ROOT_DIR=$SCRIPT_DIR/..

cd "$ROOT_DIR"

GIT_COMMIT=$(git rev-parse --short HEAD)

docker build --no-cache --build-arg all_proxy=$all_proxy --build-arg git_commit="$GIT_COMMIT" --build-arg build_features="storage-service,metrics,memory-profiling,opentelemetry,disable-native-rpc,enable-wallet-rpc" -f docker/Dockerfile . -t linera-local-genesis || exit 1
docker tag linera-local-genesis:latest docker.io/npool/linera-local-genesis:latest

