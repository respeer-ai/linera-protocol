#!/bin/sh

exec ./linera \
  --wallet /config/wallet.json \
  --storage rocksdb:/config/client.db \
  faucet --amount 10
