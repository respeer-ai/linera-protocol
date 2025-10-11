#!/bin/bash

cargo run --release -p linera-storage-service -- memory --endpoint $LINERA_STORAGE_SERVICE &
cargo build -p linera-witty-test-modules --target wasm32-unknown-unknown
cargo test --no-default-features --features fs,macros,wasmer,rocksdb --locked -j 1

killall -9 cargo
