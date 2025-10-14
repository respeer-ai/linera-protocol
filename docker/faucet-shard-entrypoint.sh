#!/bin/sh

./faucet-entrypoint.sh &

query_faucet_balance() {
  balance=`curl -d '{"query": "query { balance }"}' -X POST http://localhost:8080 | jq -r '.data.balance'`
  echo ${balance%%.*}
}

deposit_faucet() {
  wallet_id=`uuid`
  mkdir -p /depositor/$wallet_id
  ./linera \
      --wallet /depositor/$wallet_id/wallet.json \
      --keystore /depositor/$wallet_id/keystore.json \
      --storage rocksdb:/depositor/$wallet_id/client.db \
      wallet init \
      --faucet https://faucet.testnet-conway.linera.net

  faucet_chain_id=`cat /wallet/wallet.json | jq -r '.chains | keys[]'`

  fund_chain_id=`./linera \
      --wallet /depositor/$wallet_id/wallet.json \
      --keystore /depositor/$wallet_id/keystore.json \
      --storage rocksdb:/depositor/$wallet_id/client.db \
      wallet request-chain \
      --faucet https://faucet.testnet-conway.linera.net | head -n 1`

  echo "From: $fund_chain_id"
  echo "To: $faucet_chain_id"

  ./linera \
    --wallet /depositor/$wallet_id/wallet.json \
    --keystore /depositor/$wallet_id/keystore.json \
    --storage rocksdb:/depositor/$wallet_id/client.db \
    transfer \
    --from $fund_chain_id \
    --to $faucet_chain_id \
    99.99
}

try_deposit_faucet() {
  # Check balance
  balance=`query_faucet_balance`
  if [ -z "$balance" -o "$balance" -gt 100 ]; then
    return
  fi
  for i in `seq 1 100`; do
    deposit_faucet
  done
}

# Deposit faucet shard
while true; do
  sleep 60
  try_deposit_faucet
done
