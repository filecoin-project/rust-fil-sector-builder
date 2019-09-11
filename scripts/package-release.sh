#!/usr/bin/env bash

set -e

target_dir="./target"

# respect CARGO_TARGET_DIR, if set
#
if [[ ! -z "$CARGO_TARGET_DIR" ]]; then
    (>&2 echo "CARGO_TARGET_DIR set to ${CARGO_TARGET_DIR}")
    target_dir=$CARGO_TARGET_DIR
fi

if [ -z "$1" ]; then
  TAR_FILE=`mktemp`.tar.gz
else
  TAR_FILE=$1
fi

TAR_PATH=`mktemp -d`

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/bin
mkdir -p $TAR_PATH/include
mkdir -p $TAR_PATH/lib/pkgconfig

find "${target_dir}" -type f -name sector_builder_ffi.h -exec cp -- "{}" $TAR_PATH/include/ \;
find "${target_dir}" -type f -name libsector_builder_ffi.a -exec cp -- "{}" $TAR_PATH/lib/ \;
find "${target_dir}" -type f -name sector_builder_ffi.pc -exec cp -- "{}" $TAR_PATH/lib/pkgconfig/ \;

cargo install filecoin-proofs \
  --bin paramcache \
  --force \
  --git=https://github.com/filecoin-project/rust-fil-proofs.git \
  --branch=master \
  --root $TAR_PATH

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd

rm -rf $TAR_PATH

echo $TAR_FILE
