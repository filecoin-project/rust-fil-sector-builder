STATIC_NAME=libsector_builder_ffi.a
BUILD_MODE=release
VERSION=$$(git rev-parse HEAD)
DUMMY_CRATE_OUTPUT=$$(mktemp)
RUST_TOOLCHAIN_VERSION=$$(cat rust-toolchain)

all: target/$(BUILD_MODE)/$(STATIC_NAME) sector_builder_ffi.pc include/sector_builder_ffi.h

clean:
	cargo clean
	-rm -f sector_builder_ffi.pc
	-rm -f include/sector_builder_ffi.h

include/sector_builder_ffi.h: target/$(BUILD_MODE)/$(STATIC_NAME)

target/$(BUILD_MODE)/$(STATIC_NAME): sector-builder-ffi/src/lib.rs sector-builder-ffi/Cargo.toml
	cargo +$(RUST_TOOLCHAIN_VERSION) build --$(BUILD_MODE) $(CARGO_FLAGS)

sector_builder_ffi.pc: sector_builder_ffi.pc.template Makefile Cargo.toml
	sed -e "s;@VERSION@;$(VERSION);" \
		-e "s;@PRIVATE_LIBS@;$$(rustc --print native-static-libs --crate-type staticlib /dev/null -o $(DUMMY_CRATE_OUTPUT) 2>&1 | grep native-static-libs | cut -d ':' -f 3);" sector_builder_ffi.pc.template > $@

.PHONY: all

.SILENT: sector_builder_ffi.pc
