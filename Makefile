STATIC_NAME=libsector_builder_ffi.a
BUILD_MODE=release
VERSION=$$(git rev-parse HEAD)
RUST_TOOLCHAIN_VERSION=$$(cat rust-toolchain)

all: sector_builder_ffi.pc include/sector_builder_ffi.h

clean:
	cargo clean
	-rm -f sector_builder_ffi.pc
	-rm -f include/sector_builder_ffi.h

include/sector_builder_ffi.h: sector_builder_ffi.pc

sector_builder_ffi.pc: sector_builder_ffi.pc.template Makefile Cargo.toml sector-builder-ffi/src/lib.rs sector-builder-ffi/Cargo.toml
	sed -e "s;@VERSION@;$(VERSION);" \
		-e "s;@PRIVATE_LIBS@;$(shell RUSTFLAGS='--print native-static-libs' cargo +$(RUST_TOOLCHAIN_VERSION) build --$(BUILD_MODE) $(CARGO_FLAGS) 2>&1 | grep native-static-libs | cut -d ':' -f 3);" sector_builder_ffi.pc.template > $@

.PHONY: all

.SILENT: sector_builder_ffi.pc
