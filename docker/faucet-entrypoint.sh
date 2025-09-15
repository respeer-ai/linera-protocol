#!/bin/sh

exec ./linera \
  --wallet /wallet/wallet.json \
  --storage rocksdb:/wallet/client.db \
  faucet --amount 10
