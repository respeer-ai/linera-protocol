#!/bin/bash

exec ./linera net up
  --with-faucet \
  --faucet-port 8080
