#!/bin/bash

listener_args=(
  --listener-skip-process-inbox
)

if [ "${ENABLE_LISTENER_AUTO_IMPORT_OWNED_CHILD_CHAINS_WITHOUT_KEY:-false}" = "true" ]; then
  listener_args+=(
    --listener-auto-import-owned-child-chains-without-key
  )
fi

exec ./linera \
  --with-application-logs \
  --wallet /wallet/wallet.json \
  --keystore /wallet/keystore.json \
  --storage rocksdb:/wallet/client.db \
  --send-timeout-ms 30000 \
  --recv-timeout-ms 30000 \
  service \
  "${listener_args[@]}" \
  --port 30080 \
  --metrics-port 30082
