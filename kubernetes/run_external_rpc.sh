#!/bin/bash

####
## export RPC_EXTERNAL_HOST=api.rpc.external.respeer.ai
## export RPC_HOST=api.rpc.respeer.ai
## ./run_external_rpc.sh
####

[ "x" == "x$RPC_EXTERNAL_HOST" ] && RPC_EXTERNAL_HOST=api.rpc.external.respeer.ai
[ "x" == "x$RPC_HOST" ] && RPC_HOST=api.rpc.respeer.ai

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
TEMPLATE_FILE="${SCRIPT_DIR}/../configuration/template/external-ingress.conf.j2"

# All generated files will be put here
OUTPUT_DIR="${SCRIPT_DIR}/../output/k8s"
mkdir -p $OUTPUT_DIR

# All generated config files will be put here
CONFIG_DIR="${OUTPUT_DIR}/config"
mkdir -p $CONFIG_DIR

function generate_external_ingress() {
    endpoint=rpc
    domain=`echo $host | sed 's/\./-/g'`
    echo "{
        \"service\": {
            \"name\": \"$endpoint\",
            \"external_name\": \"$RPC_EXTERNAL_HOST\",
            \"host\": \"$RPC_HOST\",
            \"domain\": \"$domain\"
        }
    }" > ${CONFIG_DIR}/$endpoint.external.ingress.json

    jinja -d ${CONFIG_DIR}/$endpoint.external.ingress.json $TEMPLATE_FILE > ${CONFIG_DIR}/$endpoint-external-ingress.yaml
    kubectl apply -f ${CONFIG_DIR}/$endpoint-external-ingress.yaml
}

generate_external_ingress
