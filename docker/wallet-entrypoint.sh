#!/bin/bash

exec ./linera \
  --wallet /wallet/wallet.json \
  --keystore /keystore/keystore.json \
  --storage rocksdb:/wallet/client.db \
  service \
  --port 8080 \
  --metrics-port 8082
