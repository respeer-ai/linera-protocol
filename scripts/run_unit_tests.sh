#!/bin/bash

cd ..

export LINERA_STORAGE_SERVICE="127.0.0.1:1235"

killall -9 linera-storage-server

cargo run --release -p linera-storage-service -- memory --endpoint $LINERA_STORAGE_SERVICE &
cargo build -p linera-witty-test-modules --target wasm32-unknown-unknown
cargo test --no-default-features --features fs,macros,wasmer,rocksdb --locked -j 1 --lib --workspace --exclude linera-indexer
cargo test --no-default-features --features fs,macros,wasmer,rocksdb --locked -j 1 --bins
# TODO: DON'T TEST INDEXER RIGHT NOW DUE TO DOCKERTEST ERROR
cargo test --locked -j 1 --workspace --exclude linera-indexer --exclude linera-rpc

killall -9 linera-storage-server
