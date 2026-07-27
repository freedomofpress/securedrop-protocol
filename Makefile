.DEFAULT_GOAL := help

# Specify lint tooling versions in lint-tools/versions.env
# (Allows us to hash the versions.env file and use it to
# cache dependencies in CI)
include lint-tools/versions.env
export

# Avoid conflicts with user's system directories
BIN_DIR := $(CURDIR)/lint-tools/bin/
TOOLS_DIR := $(CURDIR)/lint-tools/

.PHONY: check
check: lint clippy  ## Run all lint and code checks

.PHONY: lint
lint: deps-lint lint-ci lint-docs  ## Run all linters.
	@cargo fmt --check --all --manifest-path=securedrop-protocol/Cargo.toml

.PHONY: lint-ci
lint-ci: deps-lint  ## Lint GitHub Actions workflows.
	@$(BIN_DIR)/zizmor .github/ || { echo "INFO: Run 'make fix-ci' to try autofix"; exit 1; }

# Currently lints markdown, but can be configured to lint various formats:
# https://dprint.dev/config/
.PHONY: lint-docs
lint-docs: deps-lint  ## Lint Markdown-format documentation.
	@$(BIN_DIR)/dprint check || { echo "INFO: Run 'make fix-docs' to try autofix"; exit 1; }

.PHONY: fix
fix: fix-ci fix-docs  ## Apply all automatic formatting fixes.
	@cargo fmt --all

.PHONY: fix-ci
fix-ci: deps-lint  ## Apply automatic fixes to CI.
	@$(BIN_DIR)/zizmor --fix .github/

.PHONY: fix-docs
fix-docs: deps-lint  ## Apply automatic fixes to (Markdown-format) documentation.
	@$(BIN_DIR)/dprint fmt

.PHONY: deps-lint
deps-lint: deps-rust  ## Install project-level linters
	@cargo install --locked dprint --version $(DPRINT_VER) --root $(TOOLS_DIR)
	@cargo install --locked zizmor --version $(ZIZMOR_VER) --root $(TOOLS_DIR)

.PHONY: deps-rust
deps-rust:  ## Install clippy and rustfmt.
	@which cargo >> /dev/null || { echo "Please install the Rust toolchain"; exit 1; }
	@rustup component add clippy rustfmt

# future TODO: stricter clippy (append -D warnings)
.PHONY: clippy
clippy: deps-rust  ## Check Rust code with clippy
	@cargo clippy --manifest-path=securedrop-protocol/Cargo.toml --workspace --all-targets --all-features --

# Enforces build from a clean cache, to be used before running benchmarks.
.PHONY: build-wasm-bench
build-wasm:  ## Compile protocol-minimal and benchmark crates for wasm32-unknown-unknown (browser compat, requires rust toolchain).
	@echo "Build wasm32 crates and wasm-bindgen"
	$(MAKE) -C ./securedrop-protocol/bench/ clean build
	@echo "Build complete, run 'make quick-bench' for local benchmarks."

.PHONY: core-wasm
core-wasm: ## Compile just the protocol-minimal crate in release mode for wasm32-unknown-unknown
	@which cargo >> /dev/null || { echo "Please install the Rust toolchain"; exit 1; }
	@rustup target list --installed | grep wasm32-unknown-unknown || { echo "Install wasm32 target using \`rustup target add wasm32-unknown-unknown\`"; exit 1; }
	@echo "Compile protocol-minimal crate for wasm32-unknown-unknown."
	cargo build --quiet --manifest-path=securedrop-protocol/Cargo.toml --package=securedrop-protocol-minimal --target wasm32-unknown-unknown --release
	@echo "Build complete, artifacts in securedrop-protocol/target/wasm32-unknown-unknown/release/."

.PHONY: help
help: ## Prints this message and exits.
	@printf "Subcommands:\n\n"
	@perl -F':.*##\s+' -lanE '$$F[1] and say "\033[36m$$F[0]\033[0m : $$F[1]"' $(MAKEFILE_LIST) \
		| sort \
		| column -s ':' -t

