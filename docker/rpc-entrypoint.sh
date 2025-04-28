#!/bin/bash

exec ./linera \
  --wallet /wallet/wallet.json \
  --storage rocksdb:/wallet/client.db \
  service \
  --listener-skip-process-inbox \
  --port 30080
