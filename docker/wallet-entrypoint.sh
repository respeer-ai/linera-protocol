#!/bin/bash

if [ -n "${LISTENER_SKIP_PERMISSIONLESS_CHAIN+x}" ]; then
  LISTENER_SKIP_PERMISSIONLESS_CHAIN="--listener-skip-permissionless-chain"
fi

exec ./linera \
  --with-application-logs \
  --wallet /wallet/wallet.json \
  --keystore /wallet/keystore.json \
  --storage rocksdb:/wallet/client.db \
  $LISTENER_SKIP_PERMISSIONLESS_CHAIN \
  service \
  --port 8080 \
  --metrics-port 8082
