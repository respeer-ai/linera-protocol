# Build arguments:
#
# - `git_commit` is the hash of the current git commit — used for
#   versioning information inside the binaries.
# - `build_date` is the date and time of when the docker image was
#   built
# - `binaries` is the path to the directory containing the Linera
#   binaries. Leave unset to build the binaries from scratch.
# - `build_flag` is either "--release" or an empty string.
# - `build_folder` is either "release" or "debug".
# - `build_features` is a comma-separated list of features to build the binaries with.

ARG git_commit
ARG build_date
ARG binaries=
ARG copy=${binaries:+_copy}
ARG build_flag=--release
ARG build_folder=release
ARG build_features=scylladb,metrics,opentelemetry
ARG rustflags="-C force-frame-pointers=yes"
ARG all_proxy

FROM rust:1.86-slim-bookworm AS builder
ARG git_commit
ARG build_flag
ARG build_folder
ARG build_features
ARG rustflags
ARG all_proxy

RUN all_proxy=$all_proxy \
    apt-get update && \
    all_proxy=$all_proxy \
    apt-get install -y \
    git \
    pkg-config \
    protobuf-compiler \
    clang \
    make

COPY . .

ENV GIT_COMMIT=${git_commit}
ENV RUSTFLAGS=${rustflags}

# Build without explicit --target to use host architecture
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true all_proxy=$all_proxy \
    cargo build ${build_flag:+"$build_flag"} \
    --bin linera-proxy \
    --features $build_features \
    -j 1
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true all_proxy=$all_proxy \
    cargo build ${build_flag:+"$build_flag"} \
    --bin linera-server \
    --features $build_features \
    -j 1
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true all_proxy=$all_proxy \
    cargo build ${build_flag:+"$build_flag"} \
    --bin linera \
    --features $build_features \
    -j 1
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true all_proxy=$all_proxy \
    cargo build ${build_flag:+"$build_flag"} \
    --bin linera-storage-server \
    --features $build_features \
    -j 1

RUN mv \
    target/"$build_folder"/linera \
    target/"$build_folder"/linera-proxy \
    target/"$build_folder"/linera-server \
    target/"$build_folder"/linera-storage-server \
    ./

# Optionally copy binaries instead of using the build images above
FROM scratch AS builder_copy
ARG binaries
COPY \
    "$binaries"/linera \
    "$binaries"/linera-server \
    "$binaries"/linera-proxy \
    "$binaries"/linera-storage-server \
    ./

FROM builder$copy AS binaries

# Setup running environment for container
FROM debian:bookworm-slim

ARG all_proxy

ARG git_commit
LABEL git_commit=$git_commit

ARG build_date
LABEL build_date=$build_date

RUN all_proxy=$all_proxy \
    apt-get update && \
    all_proxy=$all_proxy \
    apt-get install -y \
    ca-certificates \
    openssl \
    jq \
    curl \
    uuid
RUN all_proxy=$all_proxy update-ca-certificates

COPY --from=binaries \
    linera \
    linera-server \
    linera-proxy \
    linera-storage-server \
    ./

COPY --chmod=755 \
    docker/faucet-entrypoint.sh \
    docker/faucet-shard-entrypoint.sh \
    docker/rpc-entrypoint.sh \
    docker/wallet-entrypoint.sh \
    ./
