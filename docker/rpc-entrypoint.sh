#!/bin/sh

nginx
exec ./linera \
  --wallet /config/wallet.json \
  --storage rocksdb:/config/client.db \
  service \
  --listener-skip-process-inbox \
  --port 30080
