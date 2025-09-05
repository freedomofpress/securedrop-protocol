# Makefile (Selenium version)

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# ===== Config =====
ITER ?= 100
TARGET_DIR ?= target
WASM_TARGET := wasm32-unknown-unknown
CRATE_WASM := $(TARGET_DIR)/$(WASM_TARGET)/release/securedrop_protocol.wasm
PKG_DIR := pkg

RUSTFLAGS := --cfg getrandom_backend="wasm_js"

# Selenium cache lives inside the repo (change if you like)
SELENIUM_CACHE ?= .selenium-cache
SELENIUM_TOML  := $(SELENIUM_CACHE)/se-config.toml
SELENIUM_STAMP := $(SELENIUM_CACHE)/.ready

# ===== Phony targets =====
.PHONY: all deps rust-target build bench clean clean-cache warm-cache

all: deps build

deps: node_modules selenium-cache rust-target
	@echo "Deps ok."

node_modules: package.json
	@if [ -f package-lock.json ]; then npm ci; else npm install; fi
	@# Ensure Selenium is present (no-op if already installed)
	@npm ls selenium-webdriver --depth=0 >/dev/null 2>&1 || npm i -D selenium-webdriver
	@# Optional: pin drivers for offline use (uncomment if desired)
	# @npm ls chromedriver --depth=0 >/dev/null 2>&1 || npm i -D chromedriver
	# @npm ls geckodriver  --depth=0 >/dev/null 2>&1 || npm i -D geckodriver
	@touch node_modules

# Create a project-local Selenium Manager cache and config
selenium-cache: $(SELENIUM_STAMP)

$(SELENIUM_STAMP):
	@mkdir -p "$(SELENIUM_CACHE)"
	@echo 'cache-path = "$(abspath $(SELENIUM_CACHE))"' > "$(SELENIUM_TOML)"
	@echo 'force-browser-download = true'            >> "$(SELENIUM_TOML)"
	@touch "$(SELENIUM_STAMP)"

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

# Run benchmarks with Selenium and a local cache (no /Applications writes on macOS)
bench: deps build
	@echo "Running bench with ITER=$(ITER)"
	SE_CACHE_PATH="$(abspath $(SELENIUM_CACHE))" \
	SE_FORCE_BROWSER_DOWNLOAD=true \
	node bench.js -n $(ITER)

# (Optional) pre-warm the cache by launching/closing each browser once
warm-cache: selenium-cache node_modules
	SE_CACHE_PATH="$(abspath $(SELENIUM_CACHE))" \
	SE_FORCE_BROWSER_DOWNLOAD=true \
	node -e 'const {Builder}=require("selenium-webdriver");(async()=>{for(const b of["chrome","firefox"]){try{const d=await new Builder().forBrowser(b).build();await d.quit();}catch(e){console.error("warm-cache:",b,e.message)}}})();'

clean:
	cargo clean --target-dir $(TARGET_DIR)
	rm -rf $(PKG_DIR) node_modules

clean-cache:
	rm -rf "$(SELENIUM_CACHE)"

