#!/bin/sh

exec ./linera \
  --with-application-logs \
  --wallet /wallet/wallet.json \
  --keystore /wallet/keystore.json \
  --storage rocksdb:/wallet/client.db \
  faucet --amount 10 \
  --port 31080 \
  --storage-path /wallet/faucet.sqlite
