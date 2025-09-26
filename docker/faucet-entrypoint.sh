#!/bin/sh

exec ./linera \
  --wallet /wallet/wallet.json \
  --keystore /wallet/keystore.json \
  --storage rocksdb:/wallet/client.db \
  faucet --amount 10
