# Makefile (Selenium version)

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# ===== Config =====
ITER ?= 1000
# Sweeps re-run the full per-point setup (500 keybundles, etc.) for every data
# point, so keep their iteration count low and independent of ITER.
SWEEP_ITER ?= 5
KEYBUNDLES_START ?= 50
KEYBUNDLES_END ?= 1000
KEYBUNDLES_STEP ?= 50
CHALLENGES_START ?= 250
CHALLENGES_END ?= 5000
CHALLENGES_STEP ?= 250
TARGET_DIR ?= target
WASM_TARGET := wasm32-unknown-unknown
CRATE_WASM := $(TARGET_DIR)/$(WASM_TARGET)/release/securedrop_protocol.wasm
PKG_DIR := pkg

# Keep consistent with wasm-bindgen version in Cargo.toml
WASM_BINDGEN_CLI_VERSION := 0.2.106

RUSTFLAGS := --cfg getrandom_backend="wasm_js"

SELENIUM_CACHE ?= .selenium-cache
SELENIUM_TOML  := $(SELENIUM_CACHE)/se-config.toml
SELENIUM_STAMP := $(SELENIUM_CACHE)/.ready

.PHONY: all setup deps rust-target build bench clean clean-cache warm-cache

all: deps build

# Detect the OS and install system-level prerequisites
# Requires sudo on Linux and Homebrew on macOS
setup:
	@OS="$$(uname -s)"; \
	if [ "$$OS" = "Darwin" ]; then \
	  echo "==> macOS detected"; \
	  xcode-select --install 2>/dev/null || true; \
	  if ! command -v brew >/dev/null 2>&1; then \
	    echo "ERROR: Homebrew is required (https://brew.sh/); install it and re-run 'make setup'."; exit 1; \
	  fi; \
	  brew install node; \
	elif [ "$$OS" = "Linux" ]; then \
	  ID=""; ID_LIKE=""; \
	  if [ -r /etc/os-release ]; then . /etc/os-release; fi; \
	  case " $$ID $$ID_LIKE " in \
	    *ubuntu*) echo "==> Ubuntu detected";; \
	    *debian*) echo "==> Debian-like ($$ID) detected; untested but should work, proceeding...";; \
	    *) echo "WARNING: unsupported distro ($$ID). Trying an apt-based setup anyway; if it fails, install deps manually.";; \
	  esac; \
	  if ! command -v apt-get >/dev/null 2>&1; then \
	    echo "ERROR: apt-get not found. Install build-essential, curl, git, Node 22 and libnss3/libgbm1/libasound2/libgtk-3-0 manually."; exit 1; \
	  fi; \
	  sudo apt-get update; \
	  sudo apt-get install -y build-essential curl git; \
	  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -; \
	  sudo apt-get install -y nodejs; \
	  sudo apt-get install -y libnss3 libgbm1 libasound2t64 libgtk-3-0t64 \
	    || sudo apt-get install -y libnss3 libgbm1 libasound2 libgtk-3-0; \
	else \
	  echo "ERROR: unsupported OS '$$OS'."; exit 1; \
	fi; \
	if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$$HOME/.cargo/bin/rustup" ]; then \
	  echo "==> Installing Rust via rustup"; \
	  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	fi; \
	echo "==> Installing project dependencies (make deps)"
	@PATH="$$HOME/.cargo/bin:$$PATH" $(MAKE) deps
	@echo; \
	echo "==> Setup complete."; \
	echo "    If cargo/rustup aren't found in new shells, add Rust to your PATH with:"; \
	echo "        . \"$$HOME/.cargo/env\""

deps: node_modules selenium-cache rust-target
	@echo "Deps ok."

node_modules: package.json
	@npm ci

selenium-cache: $(SELENIUM_STAMP)

$(SELENIUM_STAMP):
	@mkdir -p "$(SELENIUM_CACHE)"
	@echo 'cache-path = "$(abspath $(SELENIUM_CACHE))"' > "$(SELENIUM_TOML)"
	@echo 'force-browser-download = true'            >> "$(SELENIUM_TOML)"
	@touch "$(SELENIUM_STAMP)"

# Note: this does not update an outdated wasm-bindgen-cli version if
# already installed, but a warning is printed to the user's console
rust-target:
	rustup target add $(WASM_TARGET)
	@if ! command -v wasm-bindgen >/dev/null 2>&1; then \
	  echo "Installing wasm-bindgen-cli..."; \
	  cargo install wasm-bindgen-cli --version $(WASM_BINDGEN_CLI_VERSION); \
	fi
	@echo "Rust target and wasm-bindgen ready."

build: $(CRATE_WASM)
	@mkdir -p $(PKG_DIR)
	wasm-bindgen --target web --out-dir $(PKG_DIR) $(CRATE_WASM)
	@echo "WASM + bindings in $(PKG_DIR)/"

$(CRATE_WASM):
	RUSTFLAGS='$(RUSTFLAGS)' cargo build --target $(WASM_TARGET) --release --target-dir $(TARGET_DIR)

bench: deps build
	@echo "Running bench with ITER=$(ITER), SWEEP_ITER=$(SWEEP_ITER)"
	SE_CACHE_PATH="$(abspath $(SELENIUM_CACHE))" \
	SE_FORCE_BROWSER_DOWNLOAD=true \
	node bench.js -n $(ITER) --flavors firefox,chrome --mode profile
	# Benches for the sweeps charts
	node bench.js -n $(SWEEP_ITER) --sweeps-only --flavors firefox,chrome --mode profile --j-min $(CHALLENGES_START) --j-max $(CHALLENGES_END) --j-step $(CHALLENGES_STEP) --k-min $(KEYBUNDLES_START) --k-max $(KEYBUNDLES_END) --k-step $(KEYBUNDLES_STEP)

quick-bench: deps build
	@echo "Running bench with ITER=5"
	SE_CACHE_PATH="$(abspath $(SELENIUM_CACHE))" \
	SE_FORCE_BROWSER_DOWNLOAD=true \
	node bench.js -n 5 --flavors firefox,chrome --mode profile
	# Benches for the sweeps charts
	node bench.js -n 5 --sweeps-only --flavors firefox,chrome --mode profile --j-min 25 --j-max 100 --j-step 25 --k-min 25 --k-max 100 --k-step 25

warm-cache: selenium-cache node_modules
	SE_CACHE_PATH="$(abspath $(SELENIUM_CACHE))" \
	SE_FORCE_BROWSER_DOWNLOAD=true \
	node -e 'const {Builder}=require("selenium-webdriver");(async()=>{for(const b of["chrome","firefox"]){try{const d=await new Builder().forBrowser(b).build();await d.quit();}catch(e){console.error("warm-cache:",b,e.message)}}})();'

clean:
	cargo clean --target-dir $(TARGET_DIR)
	rm -rf $(PKG_DIR) node_modules

clean-cache:
	rm -rf "$(SELENIUM_CACHE)"

