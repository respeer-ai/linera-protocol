#!/bin/bash

exec ./linera \
  --wallet /wallet/wallet.json \
  --storage rocksdb:/wallet/client.db \
  --max-loaded-chains 10 \
  service \
  --port 8080
