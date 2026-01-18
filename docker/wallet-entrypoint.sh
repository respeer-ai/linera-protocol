#!/bin/bash

exec ./linera \
  --with-application-logs \
  --wallet /wallet/wallet.json \
  --keystore /wallet/keystore.json \
  --storage rocksdb:/wallet/client.db \
  service \
  --port 8080 \
  --metrics-port 8082
