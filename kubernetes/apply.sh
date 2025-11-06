#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

SERVICES="faucet rpc"

# Cleanup before building
# GIT_COMMIT=$(git rev-parse --short HEAD)

# image_exists=`docker images | grep "linera-respeer  " | wc -l`

# if [ $image_exists -ne 1 ]; then
#   ROOT_DIR=$SCRIPT_DIR/..

#   cd "$ROOT_DIR"
#   docker build \
#     --no-cache \
#     --build-grg all_proxy=$all_proxy \
#     --build-arg git_commit="$GIT_COMMIT" \
#     --build-arg build_features="scylladb,metrics,memory-profiling,tempo,disable-native-rpc,enable-wallet-rpc" \
#     -f docker/Dockerfile \
#     . \
#     -t linera-respeer || exit 1
# fi

# Modify flannel MTU to 1432 for Linera validators
# kubectl -n kube-system edit ds kube-flannel-ds-amd64 -o yaml
# ip link delete flannel.1
# kubectl -n kube-system rollout restart daemonset kube-flannel-ds-amd64
# kubectl -n kube-system edit configmap kube-flannel-cfg

export FAUCET_URL=https://faucet.testnet-conway.linera.net
# export FAUCET_URL=http://local-genesis-service:8080

######
## If contine deploy with testnet faucet, it should be 0
######
RE_GENERATE=1

wait_pods() {
  pod_name=$1
  replicas=$2
  status=$3

  while true; do
    count=$(kubectl get pods -A | grep $pod_name | grep "$status" | wc -l)
    if [ $count -eq $replicas ]; then
      break
    fi
    echo "Waiting for $pod_name be $status"
    sleep 10
  done
}

for service in $SERVICES; do
  if [ $RE_GENERATE -eq 1 ]; then
    pod_name=$(kubectl get pods -A | grep ${service}-service | awk '{print $2}')
    if [ ! -z "$pod_name" ]; then
      now=$(date -u | sed 's/ //g')
      kubectl exec -it $pod_name -n kube-system -- mkdir -p /wallet/backup/$now
      kubectl exec -it $pod_name -n kube-system -- cp -vrf /wallet/wallet.json /wallet/keystore.json /wallet/backup/$now
      kubectl exec -it $pod_name -n kube-system -- rm -vrf /wallet/wallet.json /wallet/keystore.json /wallet/client.db
    fi
  fi

  kubectl delete -f $service/02-deployment.yaml
  kubectl delete -f $service/03-ingress.yaml

  wait_pods ${service}-service 0 ""
done

for service in $SERVICES; do
  kubectl apply -f $service/00-strip-prefix.yaml
  kubectl apply -f $service/01-pvc.yaml
  envsubst '$FAUCET_URL' < $service/02-deployment.yaml | kubectl apply -f -
  kubectl apply -f $service/03-ingress.yaml

  wait_pods ${service}-service 1 Running
done
