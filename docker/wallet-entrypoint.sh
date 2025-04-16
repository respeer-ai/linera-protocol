#!/bin/bash

exec ./linera \
  --wallet /wallet/wallet.json \
  --storage rocksdb:/wallet/client.db \
  service \
  --port 8080
