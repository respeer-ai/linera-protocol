#!/bin/bash

kubectl delete -f local-genesis/02-deployment.yaml

count=1
while [ $count -eq 1 ]; do
  count=$(kubectl get pods -n kube-system | grep "local-genesis-service" | wc -l)
  sleep 30
done

kubectl apply -f local-genesis/02-deployment.yaml
