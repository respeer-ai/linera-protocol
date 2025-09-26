#!/bin/bash

exec ./linera \
  --wallet /wallet/wallet.json \
  --keystore /keystore/keystore.json \
  --storage rocksdb:/wallet/client.db \
  --send-timeout-ms 30000 \
  --recv-timeout-ms 30000 \
  service \
  --listener-skip-process-inbox \
  --port 30080
