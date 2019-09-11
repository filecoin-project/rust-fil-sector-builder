#!/usr/bin/env bash

set -Eex

if [[ -z "$1" ]]
then
    (>&2 echo 'Error: script requires a toolchain, e.g. ./build-release.sh +nightly-2019-04-19')
    exit 1
fi

build_output_tmp=$(mktemp)
linker_flag_cache=./target/release/linker-flags

# respect CARGO_TARGET_DIR, if set
#
if [[ ! -z "$CARGO_TARGET_DIR" ]]; then
    (>&2 echo "CARGO_TARGET_DIR set to ${CARGO_TARGET_DIR}")
    linker_flag_cache="${CARGO_TARGET_DIR}/release/linker-flags"
fi

# clean up temp file on exit
#
trap '{ rm -f $build_output_tmp; }' EXIT

# build with RUSTFLAGS configured to output linker flags for native libs
#
RUSTFLAGS='--print native-static-libs' \
    cargo +$1 build \
    --release ${@:2} 2>&1 | tee ${build_output_tmp}

# parse build output for linker flags
#
linker_flags=$(cat ${build_output_tmp} \
    | grep native-static-libs\: \
    | head -n 1 \
    | cut -d ':' -f 3)

# write linker flags to output dir if we found them in build output, or attempt
# to read them from output dir if not
#
if [[ -z "$linker_flags" ]]; then
    linker_flags=$(cat "${linker_flag_cache}")
    (>&2 echo "falling back to cached linker flags")
else
    echo "${linker_flags}" > "${linker_flag_cache}"
fi

# eject from build script if we don't have linker flags for our pkg-config file
#
if [[ -z "$linker_flags" ]]; then
    (>&2 echo "linker flags found in neither build output nor output dir")
    exit 1
fi

# generate pkg-config
#
sed -e "s;@VERSION@;$(git rev-parse HEAD);" \
    -e "s;@PRIVATE_LIBS@;${linker_flags};" sector_builder_ffi.pc.template > sector_builder_ffi.pc

# ensure header file was built
#
find . -type f -name sector_builder_ffi.h | read

# ensure the archive file was built
#
find . -type f -name libsector_builder_ffi.a | read
