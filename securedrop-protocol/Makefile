# Makefile

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# ===== Config =====
ITER ?= 100
TARGET_DIR ?= target
WASM_TARGET := wasm32-unknown-unknown
CRATE_WASM := $(TARGET_DIR)/$(WASM_TARGET)/release/securedrop_protocol.wasm
PKG_DIR := pkg

RUSTFLAGS := --cfg getrandom_backend="wasm_js"

# ===== Phony targets =====
.PHONY: all deps browsers rust-target build bench clean

all: deps build

deps: node_modules browsers rust-target
	@echo "Deps ok."

node_modules: package.json
	@if [ -f package-lock.json ]; then npm ci; else npm install; fi
	@# Touch marker so `make` knows it's up-to-date
	@touch node_modules

browsers: node_modules
	npx playwright install chromium firefox
	@touch browsers

rust-target:
	rustup target add $(WASM_TARGET)
	@if ! command -v wasm-bindgen >/dev/null 2>&1; then \
	  echo "Installing wasm-bindgen-cli..."; \
	  cargo install wasm-bindgen-cli; \
	fi
	@echo "Rust target and wasm-bindgen ready."

build: $(CRATE_WASM)
	@mkdir -p $(PKG_DIR)
	wasm-bindgen --target web --out-dir $(PKG_DIR) $(CRATE_WASM)
	@echo "WASM + bindings in $(PKG_DIR)/"

$(CRATE_WASM):
	RUSTFLAGS='$(RUSTFLAGS)' cargo build --target $(WASM_TARGET) --release --target-dir $(TARGET_DIR)

bench: deps build
	@echo "Running bench with ITER=$(ITER)"
	node bench.js -n $(ITER)

clean:
	cargo clean --target-dir $(TARGET_DIR)
	rm -rf $(PKG_DIR) node_modules browsers

